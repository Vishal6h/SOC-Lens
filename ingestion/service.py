"""High-level import orchestration with deterministic previews and error reports."""
from datetime import datetime, timezone
from pathlib import Path
import csv
import hashlib
import io
import json
import logging
import uuid

from engine import validate
from .adapters import AdapterError, parse_csv, parse_json
from .models import ImportIssue, ImportJob, IngestionLimits
from .normalization import MappingError, normalize_record
from .profiles import get_profile, profile_documents
from .staging import StagingStore


LOGGER = logging.getLogger("soclens.ingestion")


def limits_from_config(config):
    return IngestionLimits(config.ingestion_max_upload_bytes, config.ingestion_max_records,
                           config.ingestion_max_columns, config.ingestion_max_field_bytes,
                           config.ingestion_max_active_imports)


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def _canonical_digest(value):
    return _digest(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())


def _safe_filename(filename):
    if (not isinstance(filename, str) or not filename or filename != filename.strip()
            or len(filename) > 255 or filename in {".", ".."} or "/" in filename or "\\" in filename
            or any(ord(character) < 32 or ord(character) == 127 for character in filename)):
        raise ValueError("Invalid original filename")
    return filename


class ImportService:
    def __init__(self, config):
        self.config = config
        self.limits = limits_from_config(config)
        self.store = StagingStore(config.import_dir)

    def profiles(self):
        return profile_documents()

    def create(self, raw, *, filename, profile_key, source_format):
        filename = _safe_filename(filename)
        profile = get_profile(profile_key)
        source_format = str(source_format).casefold()
        if source_format not in profile.formats:
            raise ValueError("Selected profile does not support this source format")
        expected_suffix = ".csv" if source_format == "csv" else ".json"
        if Path(filename).suffix.casefold() != expected_suffix:
            raise ValueError(f"Filename extension must be {expected_suffix}")
        if not isinstance(raw, bytes) or not raw:
            raise ValueError("Uploaded evidence file is empty")
        if len(raw) > self.limits.max_upload_bytes:
            raise ValueError(f"Upload limit is {self.limits.max_upload_bytes} bytes")
        if self.store.active_count() >= self.limits.max_active_imports:
            raise ValueError("Maximum active staged imports reached; remove older imports first")
        job = ImportJob(
            import_id=uuid.uuid4().hex, created_at=datetime.now(timezone.utc).isoformat(),
            source_format=source_format, source_profile=profile.label, original_filename=filename,
            file_sha256=_digest(raw), mapping_profile_id=profile.identifier,
            mapping_profile_version=profile.version, field_mapping=dict(profile.mapping),
        )
        try:
            self._map(job, profile, raw)
        except AdapterError as exc:
            job.status = "failed"
            job.issues.append(ImportIssue("ERROR", exc.code, exc.reason, filename, exc.record_number, exc.field))
        self.store.save(job)
        LOGGER.info("Evidence import staged", extra={"event": "import_staged", "component": "ingestion", "import_id": job.import_id})
        return job

    def _map(self, job, profile, raw):
        if profile.category == "canonical":
            try:
                document = json.loads(raw.decode("utf-8-sig"), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
                validate(document)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError, KeyError) as exc:
                raise AdapterError("INVALID_CANONICAL_EVIDENCE", f"Canonical SOCLens evidence is invalid: {exc}") from exc
            count = sum(len(document.get(category, [])) for category in ("sources", "techniques", "cases", "controls", "lifecycles"))
            if count > self.limits.max_records:
                raise AdapterError("EXCESSIVE_RECORDS", f"Canonical evidence exceeds the {self.limits.max_records}-record limit.")
            job.record_count = job.accepted_records = count
            job.categories_produced = [category for category in ("sources", "techniques", "cases", "controls", "lifecycles") if category in document]
            job.fragment = {"canonical": document}
            job.canonical_output_sha256 = _canonical_digest(document)
            job.status = "ready"
            return
        headers, records, adapter_rejections = parse_csv(raw, self.limits) if job.source_format == "csv" else parse_json(raw, self.limits)
        job.record_count = len(records) + len(adapter_rejections)
        for record_number, code, reason in adapter_rejections:
            job.issues.append(ImportIssue("ERROR", code, reason, job.original_filename, record_number))
        missing = sorted(set(profile.required_fields) - set(headers))
        if missing:
            job.rejected_records = job.record_count
            raise AdapterError("MISSING_HEADERS", "Missing required field(s): " + ", ".join(missing))
        unknown = sorted(set(headers) - set(profile.required_fields) - set(profile.optional_fields))
        for field in unknown:
            job.issues.append(ImportIssue("WARNING", "UNMAPPED_FIELD", "Field is not used by this mapping profile.", job.original_filename, field=field))
        mapped, identifiers = [], set()
        for record_number, record in records:
            oversized = next((name for name, value in record.items()
                              if len(str(value).encode("utf-8")) > self.limits.max_field_bytes), None)
            if oversized:
                job.issues.append(ImportIssue("ERROR", "FIELD_TOO_LARGE", f"Value exceeds the {self.limits.max_field_bytes}-byte field limit.", job.original_filename, record_number, oversized))
                continue
            controlled = next((name for name, value in record.items()
                               if any(ord(character) < 32 or ord(character) == 127 for character in str(value))), None)
            if controlled:
                job.issues.append(ImportIssue("ERROR", "CONTROL_CHARACTER", "Control characters are not permitted in source fields.", job.original_filename, record_number, controlled))
                continue
            try:
                item = normalize_record(profile, record, self.limits.max_field_bytes)
                identifier = self._item_identifier(profile.category, item)
                if identifier in identifiers:
                    raise MappingError(None, "DUPLICATE_IDENTIFIER", "Identifier is duplicated within this import.")
                identifiers.add(identifier)
                mapped.append(item)
                if profile.category == "cases" and len(item["lifecycle_patch"]) == 1:
                    job.issues.append(ImportIssue("WARNING", "NO_LIFECYCLE_STAGES", "Case accepted without optional lifecycle stages.", job.original_filename, record_number))
            except MappingError as exc:
                job.issues.append(ImportIssue("ERROR", exc.code, exc.reason, job.original_filename, record_number, exc.field))
        job.accepted_records = len(mapped)
        job.rejected_records = job.record_count - job.accepted_records
        job.warnings = sum(issue.level == "WARNING" for issue in job.issues)
        job.issues.append(ImportIssue("INFO", "EXPLICIT_NORMALIZATION", "Whitespace, timestamps, booleans, and enumerations were normalized using the selected versioned profile.", job.original_filename))
        if profile.category == "cases":
            job.fragment = {"cases": [item["case"] for item in mapped],
                            "lifecycle_patches": [item["lifecycle_patch"] for item in mapped]}
            job.categories_produced = ["cases", "lifecycles"]
        elif profile.category == "lifecycle_detection":
            job.fragment = {"lifecycle_detections": mapped}
            job.categories_produced = ["lifecycles"]
        else:
            job.fragment = {profile.category: mapped}
            job.categories_produced = [profile.category]
        job.canonical_output_sha256 = _canonical_digest(job.fragment)
        job.status = "failed" if job.rejected_records else "ready"

    @staticmethod
    def _item_identifier(category, item):
        if category == "lifecycle_detection":
            return item["incident_id"]
        if category == "cases":
            return item["case"]["id"]
        return item["id"]

    def get(self, import_id):
        return self.store.load(import_id)

    def delete(self, import_id):
        self.store.delete(import_id)
        LOGGER.info("Staged import removed", extra={"event": "import_deleted", "component": "ingestion", "import_id": import_id})

    def cleanup(self, older_than_seconds):
        return self.store.cleanup(older_than_seconds=older_than_seconds)

    def error_report_json(self, import_id):
        job = self.get(import_id)
        return {"import_id": job.import_id, "source_file": job.original_filename,
                "errors": [issue.document() for issue in job.issues if issue.level == "ERROR"]}

    def error_report_csv(self, import_id):
        report = self.error_report_json(import_id)
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=("source_file", "record_number", "field", "code", "reason"), lineterminator="\n")
        writer.writeheader()
        for issue in report["errors"]:
            writer.writerow({name: issue.get(name, "") for name in writer.fieldnames})
        return output.getvalue().encode("utf-8")
