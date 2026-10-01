"""Filesystem-safe metadata staging for local import jobs."""
from datetime import datetime, timezone
from pathlib import Path
import json
import os
import re
import shutil
import tempfile

from .models import ImportJob


IMPORT_ID = re.compile(r"^[0-9a-f]{32}$")


class ImportNotFound(LookupError):
    pass


class StagingStore:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _directory(self, import_id):
        if not isinstance(import_id, str) or not IMPORT_ID.fullmatch(import_id):
            raise ValueError("Invalid import_id")
        directory = (self.root / import_id).resolve(strict=False)
        if not directory.is_relative_to(self.root.resolve()):
            raise ValueError("Invalid import_id")
        return directory

    def active_count(self):
        return sum(path.is_dir() and IMPORT_ID.fullmatch(path.name) is not None for path in self.root.iterdir())

    def save(self, job):
        directory = self._directory(job.import_id)
        directory.mkdir(mode=0o700, exist_ok=True)
        payload = (json.dumps(job.stored_document(), sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
        descriptor, temporary = tempfile.mkstemp(prefix="metadata-", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, directory / "metadata.json")
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def load(self, import_id):
        path = self._directory(import_id) / "metadata.json"
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ImportNotFound("Import not found") from exc
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            raise RuntimeError("Staged import metadata is unavailable") from exc
        return ImportJob.from_document(document)

    def delete(self, import_id):
        directory = self._directory(import_id)
        if not directory.is_dir():
            raise ImportNotFound("Import not found")
        shutil.rmtree(directory)

    def cleanup(self, *, older_than_seconds=None, now=None):
        now = datetime.now(timezone.utc) if now is None else now
        removed = []
        for directory in sorted(self.root.iterdir()):
            if not directory.is_dir() or not IMPORT_ID.fullmatch(directory.name):
                continue
            try:
                job = self.load(directory.name)
                created = datetime.fromisoformat(job.created_at.replace("Z", "+00:00"))
            except (ImportNotFound, RuntimeError, ValueError):
                continue
            if older_than_seconds is None or (now - created).total_seconds() >= older_than_seconds:
                self.delete(directory.name)
                removed.append(directory.name)
        return removed
