"""Safe local SQLite backup and restore operations for SOCLens."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from contextlib import closing
import argparse
import hashlib
import json
import logging
import os
import sqlite3
import uuid

from assessment_history import SCHEMA_VERSION, UnsupportedDatabaseVersion
from config import ConfigurationError, initialize_runtime_directories, load_config
from operations import configure_logging
from security import SecurityAuditLog, initialize_security_database


LOGGER = logging.getLogger("soclens.database")


class DatabaseOperationError(RuntimeError):
    """Raised when a backup or restore cannot be completed safely."""


def _readonly_connection(path: Path):
    uri = path.resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def validate_database(path, *, require_current=True) -> dict:
    """Validate integrity and the minimum SOCLens schema contract."""
    database = Path(path)
    if not database.is_file():
        raise DatabaseOperationError("Database file does not exist")
    try:
        with closing(_readonly_connection(database)) as connection:
            integrity = connection.execute("PRAGMA quick_check").fetchone()[0]
            if integrity != "ok":
                raise DatabaseOperationError("Database integrity validation failed")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION or (require_current and version != SCHEMA_VERSION):
                raise UnsupportedDatabaseVersion(
                    f"Database schema version {version} is not supported for this operation"
                )
            table = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='assessments'"
            ).fetchone()
            if table is None:
                raise DatabaseOperationError("Database does not contain the SOCLens assessment schema")
            count = connection.execute("SELECT count(*) FROM assessments").fetchone()[0]
    except (DatabaseOperationError, UnsupportedDatabaseVersion):
        raise
    except sqlite3.Error as exc:
        raise DatabaseOperationError("Database validation failed") from exc
    return {"schema_version": version, "assessment_count": count}


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _reserved_path(directory: Path, prefix: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        os.chmod(directory, 0o700)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    candidate = directory / f"{prefix}-{timestamp}-{uuid.uuid4().hex[:8]}.sqlite3"
    descriptor = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    return candidate


def _sqlite_backup(source: Path, destination: Path) -> None:
    try:
        with closing(_readonly_connection(source)) as source_connection:
            with closing(sqlite3.connect(destination)) as destination_connection:
                source_connection.backup(destination_connection)
                destination_connection.commit()
    except sqlite3.Error as exc:
        raise DatabaseOperationError("SQLite backup operation failed") from exc


def backup_database(database, backup_dir, *, prefix="soclens-backup") -> dict:
    """Create and validate a consistent, uniquely named SQLite backup."""
    source = Path(database)
    destination = None
    metadata = validate_database(source)
    try:
        destination = _reserved_path(Path(backup_dir), prefix)
        _sqlite_backup(source, destination)
        backup_metadata = validate_database(destination)
        result = {
            "backup_path": str(destination),
            "backup_name": destination.name,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "schema_version": backup_metadata["schema_version"],
            "assessment_count": backup_metadata["assessment_count"],
            "bytes": destination.stat().st_size,
            "sha256": _digest(destination),
        }
    except Exception:
        if destination is not None:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    LOGGER.info(
        "Database backup completed",
        extra={
            "event": "database_backup_complete",
            "component": "database",
            "backup_name": result["backup_name"],
            "schema_version": metadata["schema_version"],
        },
    )
    return result


def restore_database(database, backup, backup_dir) -> dict:
    """Validate, safety-backup, stage, and atomically replace a stopped database."""
    active = Path(database)
    candidate = Path(backup)
    if active.resolve() == candidate.resolve():
        raise DatabaseOperationError("Backup and active database must be different files")
    candidate_metadata = validate_database(candidate)
    validate_database(active)

    safety = backup_database(active, backup_dir, prefix="soclens-pre-restore")
    staged = None
    lock = None
    try:
        staged = _reserved_path(active.parent, ".soclens-restore")
        _sqlite_backup(candidate, staged)
        validate_database(staged)

        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(active) + suffix)
            if sidecar.exists():
                raise DatabaseOperationError(
                    "Active database has SQLite WAL state; stop the service and checkpoint it before restore"
                )
        lock = sqlite3.connect(active, timeout=1)
        lock.execute("BEGIN EXCLUSIVE")
        os.replace(staged, active)
        staged = None
        lock.rollback()
        lock.close()
        lock = None
        try:
            descriptor = os.open(active.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError:
            # Atomic replacement has completed; lack of directory fsync support is not
            # a reason to report the valid restored database as failed.
            pass
    except Exception:
        if lock is not None:
            lock.rollback()
            lock.close()
        if staged is not None:
            try:
                staged.unlink(missing_ok=True)
            except OSError:
                pass
        raise

    restored = validate_database(active)
    result = {
        "restored": True,
        "schema_version": restored["schema_version"],
        "assessment_count": restored["assessment_count"],
        "source_backup_name": candidate.name,
        "safety_backup": safety,
        "restored_at": datetime.now(timezone.utc).isoformat(),
    }
    LOGGER.info(
        "Database restore completed",
        extra={
            "event": "database_restore_complete",
            "component": "database",
            "backup_name": candidate.name,
            "schema_version": candidate_metadata["schema_version"],
        },
    )
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="SOCLens SQLite backup and restore")
    subcommands = parser.add_subparsers(dest="operation", required=True)
    subcommands.add_parser("backup", help="create a consistent backup of the configured database")
    restore = subcommands.add_parser("restore", help="restore a validated backup while the service is stopped")
    restore.add_argument("backup", type=Path, help="SQLite backup file to restore")
    arguments = parser.parse_args(argv)
    try:
        config = load_config()
        initialize_runtime_directories(config)
        configure_logging(config)
        initialize_security_database(config.security_database_path)
        security_audit = SecurityAuditLog(config.security_database_path)
        if arguments.operation == "backup":
            result = backup_database(config.database_path, config.backup_dir)
            security_audit.append("BACKUP_CREATED", target_type="assessment_database",
                                  target_id=result["backup_name"], context={"method": "cli"})
        else:
            security_audit.append("RESTORE_ATTEMPTED", target_type="assessment_database",
                                  target_id=arguments.backup.name, outcome="ATTEMPTED",
                                  context={"method": "cli"})
            result = restore_database(config.database_path, arguments.backup, config.backup_dir)
            security_audit.append("RESTORE_COMPLETED", target_type="assessment_database",
                                  target_id=arguments.backup.name, context={"method": "cli"})
    except (ConfigurationError, DatabaseOperationError, UnsupportedDatabaseVersion, OSError) as exc:
        parser.exit(1, f"SOCLens database operation failed: {exc}\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
