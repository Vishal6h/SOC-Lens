"""Dedicated persistence boundary for identities, sessions, and security audit."""

from __future__ import annotations

from pathlib import Path
import os

from persistence.errors import DatabaseVersionUnsupported, PersistenceError
from persistence.sqlite import SQLiteConnectionFactory, SQLiteSettings, StorageCapability


SECURITY_SCHEMA_VERSION = 1
UnsupportedSecurityDatabaseVersion = DatabaseVersionUnsupported
REQUIRED_TABLES = {
    "users", "sessions", "login_attempts", "security_audit_events",
    "security_audit_chain_state",
}
SCHEMA_STATEMENTS = (
    """CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL, role TEXT NOT NULL,
        password_credential TEXT NOT NULL, credential_version INTEGER NOT NULL DEFAULT 1,
        enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL, password_changed_at TEXT NOT NULL, last_login_at TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS sessions (
        session_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(user_id), credential_version INTEGER NOT NULL,
        csrf_hash TEXT NOT NULL, created_at TEXT NOT NULL, last_activity_at TEXT NOT NULL,
        idle_expires_at TEXT NOT NULL, absolute_expires_at TEXT NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0, revoked_at TEXT, client_context TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id, revoked)",
    """CREATE TABLE IF NOT EXISTS login_attempts (
        attempt_key TEXT PRIMARY KEY, window_started_at TEXT NOT NULL,
        failure_count INTEGER NOT NULL, blocked_until TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS security_audit_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
        timestamp TEXT NOT NULL, actor_user_id TEXT, event_type TEXT NOT NULL,
        target_type TEXT, target_id TEXT, outcome TEXT NOT NULL, context_json TEXT NOT NULL,
        previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL UNIQUE
    )""",
    """CREATE TABLE IF NOT EXISTS security_audit_chain_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton=1), entry_count INTEGER NOT NULL,
        head_hash TEXT NOT NULL
    )""",
    """INSERT OR IGNORE INTO security_audit_chain_state(singleton,entry_count,head_hash)
       VALUES (1,0,'0000000000000000000000000000000000000000000000000000000000000000')""",
)


class SecurityStorage:
    """Security schema owner using an isolated SQLite database."""

    def __init__(self, path, *, settings: SQLiteSettings | None = None, factory=None):
        self.path = Path(path)
        self.factory = factory or SQLiteConnectionFactory(self.path, settings=settings)

    def initialize(self, *, configure=False):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            os.chmod(self.path.parent, 0o700)
        if not configure and self.capability().healthy:
            return
        if self.path.is_file():
            with self.factory.connection(readonly=True, operation="security_schema_read") as connection:
                current = connection.execute("PRAGMA user_version").fetchone()[0]
            if current not in (0, SECURITY_SCHEMA_VERSION):
                raise UnsupportedSecurityDatabaseVersion(
                    "Security database schema version is not supported"
                )
        self.factory.configure_runtime()
        with self.factory.transaction(operation="security_schema") as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, SECURITY_SCHEMA_VERSION):
                raise UnsupportedSecurityDatabaseVersion(
                    "Security database schema version is not supported"
                )
            for statement in SCHEMA_STATEMENTS:
                connection.execute(statement)
            connection.execute(f"PRAGMA user_version={SECURITY_SCHEMA_VERSION}")
        if os.name == "posix" and self.path.exists():
            os.chmod(self.path, 0o600)

    def connection(self, *, readonly=False, operation="security_read"):
        return self.factory.connection(readonly=readonly, operation=operation)

    def transaction(self, *, operation="security_write", mode="IMMEDIATE"):
        return self.factory.transaction(mode=mode, operation=operation)

    def capability(self):
        try:
            if not self.path.is_file():
                return StorageCapability("sqlite", None, False, False, "security_database_unavailable")
            with self.connection(readonly=True, operation="security_readiness") as connection:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                connection.execute("SELECT 1").fetchone()
                tables = {row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )}
            if version != SECURITY_SCHEMA_VERSION or not REQUIRED_TABLES.issubset(tables):
                return StorageCapability("sqlite", version, False, False, "security_schema_invalid")
            writable = os.access(self.path, os.W_OK) and os.access(self.path.parent, os.W_OK)
            return StorageCapability("sqlite", version, writable, True, None)
        except (OSError, PersistenceError):
            return StorageCapability("sqlite", None, False, False, "security_database_unavailable")

    def diagnostics(self):
        capability = self.capability()
        result = capability.document()
        result["ready"] = result.pop("healthy")
        result["administrator_ready"] = False
        if result["ready"]:
            try:
                with self.connection(readonly=True, operation="security_admin_readiness") as connection:
                    result["administrator_ready"] = connection.execute(
                        "SELECT count(*) FROM users WHERE role='ADMIN' AND enabled=1"
                    ).fetchone()[0] > 0
            except PersistenceError:
                result.update(ready=False, writable=False, reason="security_database_unavailable")
        return result


def _storage(value, *, settings=None):
    return value if isinstance(value, SecurityStorage) else SecurityStorage(value, settings=settings)


def connect(path):
    """Compatibility helper; callers remain responsible for closing the connection."""
    return _storage(path).factory.open()


def initialize_security_database(path, *, settings=None):
    _storage(path, settings=settings).initialize(configure=True)


def security_diagnostics(path):
    return _storage(path).diagnostics()
