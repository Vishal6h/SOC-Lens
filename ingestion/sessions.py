"""Persisted local preparation sessions referencing staged imports."""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import json
import os
import re
import shutil
import tempfile
import uuid

from .builder import assemble_imports
from .staging import ImportNotFound, StagingStore


SESSION_ID = re.compile(r"^[0-9a-f]{32}$")


class PreparationNotFound(LookupError):
    pass


@dataclass
class PreparationSession:
    session_id: str
    created_at: str
    updated_at: str
    import_ids: list[str] = field(default_factory=list)
    scope: str = ""
    as_of: str | None = None
    synthetic: bool = False
    coverage: dict = field(default_factory=dict)
    correlation_readiness: str = "not_evaluated"
    status: str = "draft"
    errors: list[dict] = field(default_factory=list)

    def document(self):
        return asdict(self)


class FilesystemPreparationStore:
    """Atomic JSON implementation of the preparation storage contract."""

    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            os.chmod(self.root, 0o700)

    def _directory(self, session_id):
        if not isinstance(session_id, str) or not SESSION_ID.fullmatch(session_id):
            raise ValueError("Invalid session_id")
        directory = (self.root / session_id).resolve(strict=False)
        if not directory.is_relative_to(self.root.resolve()):
            raise ValueError("Invalid session_id")
        return directory

    def save(self, session):
        directory = self._directory(session.session_id)
        directory.mkdir(mode=0o700, exist_ok=True)
        payload = (json.dumps(session.document(), sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
        descriptor, temporary = tempfile.mkstemp(prefix="session-", suffix=".tmp", dir=directory)
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

    def get(self, session_id):
        try:
            document = json.loads((self._directory(session_id) / "metadata.json").read_text(encoding="utf-8"))
            return PreparationSession(**document)
        except FileNotFoundError as exc:
            raise PreparationNotFound("Preparation session not found") from exc
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            raise RuntimeError("Preparation session metadata is unavailable") from exc

    def latest(self):
        sessions = []
        for directory in self.root.iterdir():
            if directory.is_dir() and SESSION_ID.fullmatch(directory.name):
                try:
                    session = self.get(directory.name)
                except (PreparationNotFound, RuntimeError):
                    continue
                if session.status != "complete":
                    sessions.append(session)
        if not sessions:
            raise PreparationNotFound("No active preparation session")
        return max(sessions, key=lambda session: (session.updated_at, session.session_id))

    def delete(self, session_id):
        directory = self._directory(session_id)
        if not directory.is_dir():
            raise PreparationNotFound("Preparation session not found")
        shutil.rmtree(directory)

    def cleanup(self, older_than_seconds, *, now=None):
        now = datetime.now(timezone.utc) if now is None else now
        removed = []
        for directory in sorted(self.root.iterdir()):
            if not directory.is_dir() or not SESSION_ID.fullmatch(directory.name):
                continue
            try:
                session = self.get(directory.name)
                updated = datetime.fromisoformat(session.updated_at.replace("Z", "+00:00"))
            except (PreparationNotFound, RuntimeError, ValueError):
                continue
            if (now - updated).total_seconds() >= older_than_seconds:
                self.delete(directory.name)
                removed.append(directory.name)
        return removed


class PreparationService:
    def __init__(self, config, *, storage=None, import_storage=None):
        self.config = config
        self.storage = storage or FilesystemPreparationStore(Path(config.import_dir) / "sessions")
        self.imports = import_storage or StagingStore(config.import_dir)

    def create(self, values=None):
        now = datetime.now(timezone.utc).isoformat()
        session = PreparationSession(uuid.uuid4().hex, now, now)
        self.storage.save(session)
        return self.update(session.session_id, values or {}) if values else session

    def get(self, session_id):
        return self.storage.get(session_id)

    def latest(self):
        return self.storage.latest()

    def update(self, session_id, values):
        if not isinstance(values, dict):
            raise ValueError("Preparation update must be a JSON object")
        allowed = {"import_ids", "scope", "as_of", "synthetic"}
        if set(values) - allowed:
            raise ValueError("Unexpected preparation field(s): " + ", ".join(sorted(set(values) - allowed)))
        session = self.get(session_id)
        if session.status == "complete":
            raise ValueError("Completed preparation sessions cannot be modified")
        import_ids = values.get("import_ids", session.import_ids)
        if (not isinstance(import_ids, list) or len(import_ids) > self.config.ingestion_max_active_imports
                or len(set(import_ids)) != len(import_ids) or any(not isinstance(value, str) for value in import_ids)):
            raise ValueError("import_ids must be a unique bounded array")
        session.import_ids = list(import_ids)
        for name in ("scope", "as_of", "synthetic"):
            if name in values:
                setattr(session, name, values[name])
        session.updated_at = datetime.now(timezone.utc).isoformat()
        session.coverage = {category: {"state": "missing", "records": 0}
                            for category in ("sources", "techniques", "cases", "controls", "lifecycles")}
        session.correlation_readiness = "not_evaluated"
        session.errors = []
        session.status = "draft"
        if session.import_ids:
            try:
                jobs = [self.imports.load(import_id) for import_id in session.import_ids]
                result = assemble_imports(jobs, scope=session.scope, as_of=session.as_of, synthetic=session.synthetic)
                session.coverage = result["coverage"]
                correlation = result.get("correlation")
                session.correlation_readiness = correlation.get("status", "not_evaluated") if correlation else "legacy_or_not_applicable"
                session.errors = list(result.get("errors", []))
                session.status = "ready" if result["ready"] else "draft"
            except (ValueError, TypeError, KeyError, ImportNotFound) as exc:
                session.status = "blocked"
                session.correlation_readiness = "blocked"
                session.errors = [{"code": "PREPARATION_INCOMPLETE", "reason": str(exc)}]
        self.storage.save(session)
        return session

    def mark_complete(self, session_id):
        session = self.get(session_id)
        session.status = "complete"
        session.updated_at = datetime.now(timezone.utc).isoformat()
        self.storage.save(session)
        return session

    def delete(self, session_id):
        self.storage.delete(session_id)

    def cleanup(self, older_than_seconds, *, now=None):
        return self.storage.cleanup(older_than_seconds, now=now)
