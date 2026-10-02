"""SQLite assessment repository and schema owner."""

from __future__ import annotations

from pathlib import Path
import json
import logging
import os
import sqlite3

from .errors import (
    DatabaseUnavailable, DatabaseVersionUnsupported, PersistenceError,
    PersistenceIntegrityError,
)
from .sqlite import SQLiteConnectionFactory, SQLiteSettings, StorageCapability


SCHEMA_VERSION = 2
MIGRATION_PATHS = {0: SCHEMA_VERSION, 1: SCHEMA_VERSION}
REQUIRED_TABLES = {"assessments"}
LOGGER = logging.getLogger("soclens.database")


def _table_exists(connection, name):
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def _create_v2(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS assessments (
            assessment_id TEXT PRIMARY KEY,
            scope TEXT NOT NULL,
            assessed_at TEXT NOT NULL,
            evidence_as_of TEXT NOT NULL,
            policy_version TEXT NOT NULL,
            input_sha256 TEXT NOT NULL,
            scope_sha256 TEXT NOT NULL,
            overall_score REAL NOT NULL,
            confidence REAL NOT NULL,
            maturity TEXT NOT NULL,
            detection_score REAL NOT NULL,
            response_score REAL NOT NULL,
            telemetry_score REAL NOT NULL,
            quality_score REAL NOT NULL,
            governance_score REAL NOT NULL,
            lifecycle_enabled INTEGER NOT NULL CHECK (lifecycle_enabled IN (0, 1)),
            evidence TEXT NOT NULL,
            report TEXT NOT NULL,
            origin TEXT NOT NULL
        )
    """)
    connection.execute(
        "CREATE INDEX IF NOT EXISTS assessments_scope_time ON assessments(scope, assessed_at, assessment_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS assessments_compatibility ON assessments(scope, policy_version, scope_sha256, assessed_at)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS assessments_input_sha ON assessments(input_sha256)"
    )


def _legacy_value(report, key, default):
    value = report.get(key, default)
    return default if value is None else value


def _migrate_v1_rows(connection):
    if not _table_exists(connection, "assessments_legacy_v1"):
        return
    rows = connection.execute(
        "SELECT sha256, scope, as_of, evidence, report FROM assessments_legacy_v1 ORDER BY rowid"
    ).fetchall()
    for row in rows:
        try:
            report = json.loads(row["report"])
        except (TypeError, json.JSONDecodeError):
            report = {}
        domains = report.get("domains") if isinstance(report.get("domains"), dict) else {}
        policy = report.get("policy") if isinstance(report.get("policy"), dict) else {}
        lifecycle = report.get("lifecycle") if isinstance(report.get("lifecycle"), dict) else {}
        input_sha = str(_legacy_value(report, "sha256", row["sha256"]))
        values = (
            "legacy-" + str(row["sha256"]),
            str(_legacy_value(report, "scope", row["scope"])),
            str(_legacy_value(report, "as_of", row["as_of"])),
            str(_legacy_value(report, "as_of", row["as_of"])),
            str(policy.get("id", "legacy-unknown")),
            input_sha,
            str(_legacy_value(report, "scope_sha256", "legacy-unavailable-" + input_sha)),
            float(_legacy_value(report, "score", 0.0)),
            float(_legacy_value(report, "confidence", 0.0)),
            str(_legacy_value(report, "maturity", "Unknown")),
            float(domains.get("Detection", 0.0)),
            float(domains.get("Response", 0.0)),
            float(domains.get("Telemetry", 0.0)),
            float(domains.get("Quality", 0.0)),
            float(domains.get("Governance", 0.0)),
            int(lifecycle.get("enabled") is True),
            row["evidence"], row["report"], "migrated-v1",
        )
        connection.execute(
            "INSERT OR IGNORE INTO assessments VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            values,
        )


def _summary(row):
    return {
        "assessment_id": row["assessment_id"], "scope": row["scope"],
        "assessed_at": row["assessed_at"], "evidence_as_of": row["evidence_as_of"],
        "policy_version": row["policy_version"], "input_sha256": row["input_sha256"],
        "scope_sha256": row["scope_sha256"], "score": row["overall_score"],
        "confidence": row["confidence"], "maturity": row["maturity"],
        "domains": {
            "Detection": row["detection_score"], "Response": row["response_score"],
            "Telemetry": row["telemetry_score"], "Quality": row["quality_score"],
            "Governance": row["governance_score"],
        },
        "lifecycle_enabled": bool(row["lifecycle_enabled"]), "origin": row["origin"],
    }


class SQLiteAssessmentRepository:
    """Persistence-only assessment history implementation."""

    def __init__(self, path, *, settings: SQLiteSettings | None = None, factory=None):
        self.path = Path(path)
        self.factory = factory or SQLiteConnectionFactory(self.path, settings=settings)

    def initialize(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        current = self.schema_version()
        if current is not None and current > SCHEMA_VERSION:
            raise DatabaseVersionUnsupported(
                f"Database schema version {current} is newer than supported version {SCHEMA_VERSION}"
            )
        self.factory.configure_runtime()
        migration_needed = False
        with self.factory.transaction(operation="assessment_schema") as connection:
            current = connection.execute("PRAGMA user_version").fetchone()[0]
            if current > SCHEMA_VERSION:
                raise DatabaseVersionUnsupported(
                    f"Database schema version {current} is newer than supported version {SCHEMA_VERSION}"
                )
            if current not in (*MIGRATION_PATHS, SCHEMA_VERSION):
                raise DatabaseVersionUnsupported("Database schema has no supported migration path")
            migration_needed = current != SCHEMA_VERSION
            if _table_exists(connection, "assessments"):
                columns = {
                    row["name"] for row in connection.execute("PRAGMA table_info(assessments)")
                }
                if "assessment_id" not in columns:
                    if current == SCHEMA_VERSION:
                        raise DatabaseUnavailable("Database schema does not match its declared version")
                    if _table_exists(connection, "assessments_legacy_v1"):
                        raise DatabaseUnavailable("Database migration cannot be completed")
                    connection.execute("ALTER TABLE assessments RENAME TO assessments_legacy_v1")
            _create_v2(connection)
            _migrate_v1_rows(connection)
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        if os.name == "posix":
            os.chmod(self.path, 0o600)
        if migration_needed:
            LOGGER.info("Database schema initialized or migrated", extra={
                "event": "database_migration_complete", "component": "database",
                "schema_version": SCHEMA_VERSION,
            })

    def schema_version(self):
        if not self.path.is_file():
            return None
        with self.factory.connection(readonly=True, operation="assessment_schema_read") as connection:
            return connection.execute("PRAGMA user_version").fetchone()[0]

    def _ensure(self):
        version = self.schema_version()
        if version != SCHEMA_VERSION:
            self.initialize()

    def save(self, values, *, if_absent=False):
        self._ensure()
        statement = ("INSERT OR IGNORE" if if_absent else "INSERT") + \
            " INTO assessments VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        with self.factory.transaction(operation="assessment_save") as connection:
            connection.execute(statement, values)

    def exists(self, assessment_id):
        self._ensure()
        with self.factory.connection(readonly=True, operation="assessment_exists") as connection:
            return connection.execute(
                "SELECT 1 FROM assessments WHERE assessment_id=?", (assessment_id,)
            ).fetchone() is not None

    def list(self, scope, *, limit=100, chronological=False):
        self._ensure()
        direction = "ASC" if chronological else "DESC"
        with self.factory.connection(readonly=True, operation="assessment_history_read") as connection:
            rows = connection.execute(
                f"SELECT * FROM assessments WHERE scope=? ORDER BY assessed_at {direction}, assessment_id {direction} LIMIT ?",
                (scope, limit),
            ).fetchall()
        return [_summary(row) for row in rows]

    def get(self, assessment_id):
        self._ensure()
        with self.factory.connection(readonly=True, operation="assessment_read") as connection:
            row = connection.execute(
                "SELECT * FROM assessments WHERE assessment_id=?", (assessment_id,)
            ).fetchone()
        if row is None:
            return None
        try:
            report, evidence = json.loads(row["report"]), json.loads(row["evidence"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise PersistenceIntegrityError("Stored assessment content is invalid") from exc
        return {"summary": _summary(row), "report": report, "evidence": evidence}

    def capability(self):
        try:
            if not self.path.is_file():
                return StorageCapability("sqlite", None, False, False, "database_unavailable")
            with self.factory.connection(readonly=True, operation="assessment_readiness") as connection:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                connection.execute("SELECT 1").fetchone()
                tables = {row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )}
            if version != SCHEMA_VERSION:
                return StorageCapability("sqlite", version, False, False, "unsupported_schema")
            if not REQUIRED_TABLES.issubset(tables):
                return StorageCapability("sqlite", version, False, False, "schema_incomplete")
            writable = os.access(self.path, os.W_OK) and os.access(self.path.parent, os.W_OK)
            return StorageCapability("sqlite", version, writable, True, None)
        except (OSError, PersistenceError):
            return StorageCapability("sqlite", None, False, False, "database_unavailable")
