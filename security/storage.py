"""Dedicated SQLite persistence boundary for identities, sessions, and audit."""

from __future__ import annotations

from contextlib import closing
from pathlib import Path
import os
import sqlite3


SECURITY_SCHEMA_VERSION = 1


class UnsupportedSecurityDatabaseVersion(RuntimeError):
    pass


def connect(path):
    connection = sqlite3.connect(Path(path), timeout=10, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=10000")
    return connection


def _restrict_file(path):
    if os.name == "posix" and Path(path).exists():
        os.chmod(path, 0o600)


def initialize_security_database(path):
    database = Path(path)
    database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        os.chmod(database.parent, 0o700)
    with closing(connect(database)) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, SECURITY_SCHEMA_VERSION):
            raise UnsupportedSecurityDatabaseVersion(
                f"Security database schema version {version} is not supported"
            )
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    password_credential TEXT NOT NULL,
                    credential_version INTEGER NOT NULL DEFAULT 1,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    password_changed_at TEXT NOT NULL,
                    last_login_at TEXT
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    session_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(user_id),
                    credential_version INTEGER NOT NULL,
                    csrf_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_activity_at TEXT NOT NULL,
                    idle_expires_at TEXT NOT NULL,
                    absolute_expires_at TEXT NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    revoked_at TEXT,
                    client_context TEXT
                );
                CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id, revoked);
                CREATE TABLE IF NOT EXISTS login_attempts (
                    attempt_key TEXT PRIMARY KEY,
                    window_started_at TEXT NOT NULL,
                    failure_count INTEGER NOT NULL,
                    blocked_until TEXT
                );
                CREATE TABLE IF NOT EXISTS security_audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    actor_user_id TEXT,
                    event_type TEXT NOT NULL,
                    target_type TEXT,
                    target_id TEXT,
                    outcome TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS security_audit_chain_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton=1),
                    entry_count INTEGER NOT NULL,
                    head_hash TEXT NOT NULL
                );
                INSERT OR IGNORE INTO security_audit_chain_state(singleton,entry_count,head_hash)
                VALUES (1,0,'0000000000000000000000000000000000000000000000000000000000000000');
            """)
            connection.execute(f"PRAGMA user_version={SECURITY_SCHEMA_VERSION}")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    _restrict_file(database)


def security_diagnostics(path):
    database = Path(path)
    try:
        if not database.is_file():
            return {"ready": False, "schema_version": None, "reason": "security_database_unavailable"}
        uri = database.resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=2)) as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            tables = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        required = {"users", "sessions", "login_attempts", "security_audit_events",
                    "security_audit_chain_state"}
        if version != SECURITY_SCHEMA_VERSION or not required.issubset(tables):
            return {"ready": False, "schema_version": version, "reason": "security_schema_invalid"}
        with closing(sqlite3.connect(uri, uri=True, timeout=2)) as connection:
            administrator_ready = connection.execute(
                "SELECT count(*) FROM users WHERE role='ADMIN' AND enabled=1"
            ).fetchone()[0] > 0
        return {"ready": True, "schema_version": version, "reason": None,
                "administrator_ready": administrator_ready}
    except (OSError, sqlite3.Error):
        return {"ready": False, "schema_version": None, "reason": "security_database_unavailable"}
