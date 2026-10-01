import copy
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from email.message import Message
from io import BytesIO
from pathlib import Path

import server as server_module
from assessment_history import initialize_database
from config import initialize_runtime_directories, load_config
from engine import assess
from ingestion import ImportService, assemble_imports
from ingestion.staging import ImportNotFound


ROOT = Path(__file__).parent
FIXTURES = ROOT / "data" / "ingestion"


class IngestionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.config = load_config({"SOCLENS_ENV": "test", "SOCLENS_DATA_DIR": self.temporary.name}, root=ROOT)
        initialize_runtime_directories(self.config)
        self.service = ImportService(self.config)

    def create(self, profile, filename, source_format=None, raw=None):
        source_format = source_format or ("json" if filename.endswith(".json") else "csv")
        raw = (FIXTURES / filename).read_bytes() if raw is None else raw
        return self.service.create(raw, filename=filename, profile_key=profile, source_format=source_format)

    def complete_jobs(self):
        return [
            self.create("generic-telemetry@1", "generic-telemetry.csv"),
            self.create("generic-techniques@1", "generic-techniques.csv"),
            self.create("generic-siem-alerts@1", "generic-siem-alerts.csv"),
            self.create("generic-cases@1", "generic-cases.csv"),
            self.create("generic-controls@1", "generic-controls.json"),
        ]

    def test_valid_csv_and_quoted_field(self):
        raw = (b"control_id,satisfied,critical,evidence_ref\n"
               b'CTRL-1,true,false,"synthetic://control,quoted"\n')
        job = self.create("generic-controls@1", "controls.csv", raw=raw)
        self.assertEqual((job.status, job.accepted_records, job.rejected_records), ("ready", 1, 0))
        self.assertEqual(job.fragment["controls"][0]["evidence_ref"], "synthetic://control,quoted")

    def test_malformed_csv_is_reported(self):
        job = self.create("generic-controls@1", "controls.csv", raw=b'control_id,satisfied,critical,evidence_ref\n"unterminated')
        self.assertEqual(job.status, "failed")
        self.assertEqual(job.issues[0].code, "MALFORMED_CSV")

    def test_malformed_source_records_are_rejected_without_hiding_valid_rows(self):
        csv_raw = (b"control_id,satisfied,critical,evidence_ref\n"
                   b"BROKEN,true\nC-1,true,false,ref://1\n")
        csv_job = self.create("generic-controls@1", "controls.csv", raw=csv_raw)
        self.assertEqual((csv_job.record_count, csv_job.accepted_records, csv_job.rejected_records), (2, 1, 1))
        self.assertEqual(next(issue for issue in csv_job.issues if issue.level == "ERROR").record_number, 2)
        json_raw = json.dumps(["broken", {"control_id": "C-2", "satisfied": True, "critical": False, "evidence_ref": "ref://2"}]).encode()
        json_job = self.create("generic-controls@1", "controls.json", "json", json_raw)
        self.assertEqual((json_job.record_count, json_job.accepted_records, json_job.rejected_records), (2, 1, 1))

    def test_valid_json_record_export(self):
        raw = json.dumps([{"control_id": "C-1", "satisfied": "yes", "critical": "0", "evidence_ref": "ref://1"}]).encode()
        job = self.create("generic-controls@1", "controls.json", "json", raw)
        self.assertEqual(job.fragment["controls"][0]["satisfied"], True)
        self.assertEqual(job.status, "ready")

    def test_canonical_json_passthrough_preserves_hash(self):
        raw = (ROOT / "data" / "baseline.json").read_bytes()
        job = self.create("canonical-soclens-json@1", "baseline.json", "json", raw)
        evidence = json.loads(raw)
        result = assemble_imports([job])
        self.assertEqual(result["evidence"], evidence)
        self.assertEqual(result["canonical_output_sha256"], assess(evidence)["sha256"])

    def test_unsupported_json_shape(self):
        job = self.create("generic-controls@1", "controls.json", "json", b'{"items": []}')
        self.assertEqual(job.issues[0].code, "UNSUPPORTED_JSON_SHAPE")

    def test_missing_duplicate_and_blank_headers(self):
        samples = (
            (b"control_id,satisfied\nC,true\n", "MISSING_HEADERS"),
            (b"control_id,satisfied,satisfied,critical,evidence_ref\nC,true,true,false,x\n", "DUPLICATE_HEADER"),
            (b"control_id,,critical,evidence_ref\nC,true,false,x\n", "BLANK_HEADER"),
        )
        for raw, code in samples:
            with self.subTest(code=code):
                job = self.create("generic-controls@1", "controls.csv", raw=raw)
                self.assertEqual(job.issues[0].code, code)

    def test_excessive_columns_records_and_fields(self):
        cases = (
            ({"SOCLENS_INGESTION_MAX_COLUMNS": "3"}, b"control_id,satisfied,critical,evidence_ref\nC,true,false,x\n", "EXCESSIVE_COLUMNS"),
            ({"SOCLENS_INGESTION_MAX_RECORDS": "1"}, b"control_id,satisfied,critical,evidence_ref\nC1,true,false,x\nC2,true,false,y\n", "EXCESSIVE_RECORDS"),
            ({"SOCLENS_INGESTION_MAX_FIELD_BYTES": "5"}, b"control_id,satisfied,critical,evidence_ref\nCONTROL,true,false,x\n", "FIELD_TOO_LARGE"),
        )
        for override, raw, code in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                env = {"SOCLENS_ENV": "test", "SOCLENS_DATA_DIR": directory, **override}
                service = ImportService(load_config(env, root=ROOT))
                job = service.create(raw, filename="controls.csv", profile_key="generic-controls@1", source_format="csv")
                self.assertIn(code, [issue.code for issue in job.issues])

    def test_invalid_timestamp_and_boolean_are_row_errors(self):
        job = self.create("generic-siem-alerts@1", "generic-siem-alerts-invalid.csv")
        self.assertEqual(job.rejected_records, 2)
        self.assertEqual({issue.code for issue in job.issues if issue.level == "ERROR"}, {"INVALID_TIMESTAMP", "INVALID_BOOLEAN"})

    def test_duplicate_identifiers_are_rejected(self):
        raw = (b"control_id,satisfied,critical,evidence_ref\n"
               b"C-1,true,false,ref://1\nC-1,true,false,ref://2\n")
        job = self.create("generic-controls@1", "controls.csv", raw=raw)
        self.assertEqual((job.accepted_records, job.rejected_records, job.status), (1, 1, "failed"))
        self.assertIn("DUPLICATE_IDENTIFIER", [issue.code for issue in job.issues])

    def test_mapping_is_deterministic_and_provenance_hashes_match(self):
        raw = (FIXTURES / "generic-telemetry.csv").read_bytes()
        first = self.create("generic-telemetry@1", "generic-telemetry.csv", raw=raw)
        second = self.create("generic-telemetry@1", "generic-telemetry.csv", raw=raw)
        self.assertEqual(first.fragment, second.fragment)
        self.assertEqual(first.canonical_output_sha256, second.canonical_output_sha256)
        self.assertEqual(first.file_sha256, hashlib.sha256(raw).hexdigest())

    def test_staging_contains_no_raw_upload_and_blocks_traversal(self):
        job = self.create("generic-controls@1", "generic-controls.json")
        directory = self.config.import_dir / job.import_id
        self.assertEqual([path.name for path in directory.iterdir()], ["metadata.json"])
        with self.assertRaises(ValueError):
            self.service.get("../escape")
        with self.assertRaises(ValueError):
            self.create("generic-controls@1", "../controls.json", raw=b"{}")

    def test_cleanup_removes_only_staged_imports(self):
        job = self.create("generic-controls@1", "generic-controls.json")
        future = datetime.now(timezone.utc) + timedelta(days=2)
        self.assertEqual(self.service.store.cleanup(older_than_seconds=1, now=future), [job.import_id])
        with self.assertRaises(ImportNotFound):
            self.service.get(job.import_id)

    def test_multifile_missing_categories_and_complete_assembly(self):
        jobs = self.complete_jobs()
        partial = assemble_imports(jobs[:2], scope="Synthetic export", as_of="2026-10-01T00:00:00Z", synthetic=True)
        self.assertFalse(partial["ready"])
        self.assertEqual(partial["missing_categories"], ["cases", "controls"])
        complete = assemble_imports(jobs, scope="Synthetic export", as_of="2026-10-01T00:00:00Z", synthetic=True)
        self.assertTrue(complete["ready"])
        self.assertEqual(len(complete["evidence"]["lifecycles"]), 2)
        self.assertEqual(assess(complete["evidence"])["score"], 95.8)

    def test_unmatched_lifecycle_is_partial(self):
        jobs = self.complete_jobs()
        jobs = [job for job in jobs if job.mapping_profile_id != "generic-cases"]
        result = assemble_imports(jobs, scope="Synthetic export", as_of="2026-10-01T00:00:00Z", synthetic=True)
        self.assertFalse(result["ready"])
        self.assertEqual(result["coverage"]["lifecycles"]["state"], "partial")

    def test_error_reports_are_bounded_and_exportable(self):
        job = self.create("generic-siem-alerts@1", "generic-siem-alerts-invalid.csv")
        document = self.service.error_report_json(job.import_id)
        csv_report = self.service.error_report_csv(job.import_id).decode()
        self.assertEqual(len(document["errors"]), 2)
        self.assertIn("INVALID_TIMESTAMP", csv_report)
        self.assertNotIn("Traceback", csv_report)

    def test_legacy_canonical_scoring_unchanged(self):
        baseline = json.loads((ROOT / "data" / "baseline.json").read_text())
        legacy = copy.deepcopy(baseline)
        legacy.pop("lifecycles")
        report = assess(legacy)
        self.assertEqual((report["score"], report["confidence"], report["maturity"]), (80.2, 94.4, "L3"))
        self.assertEqual(report["sha256"], "1823b55bc5698ea3632221dc476fb456f0764b56147ee7bf065f29f2a46cfd58")


class IngestionApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.config = load_config({"SOCLENS_ENV": "test", "SOCLENS_DATA_DIR": self.temporary.name}, root=ROOT)
        initialize_runtime_directories(self.config)
        initialize_database(self.config.database_path)
        self.original_config, self.original_database = server_module.CONFIG, server_module.DB
        server_module.CONFIG, server_module.DB = self.config, self.config.database_path

    def tearDown(self):
        server_module.CONFIG, server_module.DB = self.original_config, self.original_database

    def request(self, method, path, body=b"", content_type=None):
        handler = object.__new__(server_module.Handler)
        handler.command, handler.path = method, path
        handler.request_version, handler.requestline = "HTTP/1.1", f"{method} {path} HTTP/1.1"
        handler.client_address, handler.server = ("127.0.0.1", 1), object()
        handler.wfile, handler.rfile, handler.headers = BytesIO(), BytesIO(body), Message()
        if body:
            handler.headers["Content-Length"] = str(len(body))
        if content_type:
            handler.headers["Content-Type"] = content_type
        getattr(handler, f"do_{method}")()
        head, payload = handler.wfile.getvalue().split(b"\r\n\r\n", 1)
        return int(head.splitlines()[0].split()[1]), json.loads(payload)

    def test_profile_and_import_preview_apis(self):
        status, profiles = self.request("GET", "/api/import/profiles")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(profiles["profiles"]), 6)
        raw = (FIXTURES / "generic-controls.json").read_bytes()
        path = "/api/import?profile=generic-controls%401&filename=controls.json&format=json"
        status, job = self.request("POST", path, raw, "application/json")
        self.assertEqual((status, job["status"]), (201, "ready"))
        status, preview = self.request("GET", "/api/import/" + job["import_id"])
        self.assertEqual(preview["file_sha256"], hashlib.sha256(raw).hexdigest())

    def test_multifile_build_api_adds_lineage_without_changing_canonical_hash(self):
        service = ImportService(self.config)
        specifications = (
            ("generic-telemetry@1", "generic-telemetry.csv", "csv"),
            ("generic-techniques@1", "generic-techniques.csv", "csv"),
            ("generic-siem-alerts@1", "generic-siem-alerts.csv", "csv"),
            ("generic-cases@1", "generic-cases.csv", "csv"),
            ("generic-controls@1", "generic-controls.json", "json"),
        )
        jobs = [service.create((FIXTURES / filename).read_bytes(), filename=filename,
                               profile_key=profile, source_format=source_format)
                for profile, filename, source_format in specifications]
        request = {"import_ids": [job.import_id for job in jobs], "scope": "API ingestion test",
                   "as_of": "2026-10-01T00:00:00Z", "synthetic": True, "action": "preview"}
        status, preview = self.request("POST", "/api/assessment-build", json.dumps(request).encode(), "application/json")
        self.assertEqual((status, preview["ready"]), (200, True))
        request["action"] = "assess"
        status, report = self.request("POST", "/api/assessment-build", json.dumps(request).encode(), "application/json")
        self.assertEqual(status, 200)
        self.assertEqual(report["sha256"], preview["canonical_output_sha256"])
        self.assertEqual(len(report["ingestion_provenance"]["imports"]), 5)


if __name__ == "__main__":
    unittest.main()
