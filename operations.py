"""Operational logging and diagnostics for the local SOCLens service."""
from __future__ import annotations

from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
import json
import logging
import os
import sys

from assessment_history import SCHEMA_VERSION
from config import AppConfig, sqlite_settings
from engine import POLICY
from persistence.assessment import SQLiteAssessmentRepository
from persistence.errors import PersistenceError
from reporting import REPORT_SCHEMA_VERSION
from security.audit import AuditChainError, SecurityAuditLog
from security.storage import SECURITY_SCHEMA_VERSION, SecurityStorage


APP_VERSION = "1.0.0"
LOGGER_NAME = "soclens"
LOG_FIELDS = (
    "event", "component", "version", "method", "path", "status_code", "assessment_id",
    "environment", "host", "port", "schema_version", "policy_version",
    "report_schema_version", "database_ready", "backup_name", "error_code", "import_id",
    "backend", "operation", "outcome", "duration_ms",
)


class JsonFormatter(logging.Formatter):
    """Emit one compact JSON object per line without application payloads."""

    def format(self, record):
        document = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "component": getattr(record, "component", record.name),
            "message": record.getMessage(),
        }
        for field in LOG_FIELDS:
            value = getattr(record, field, None)
            if value is not None and field != "component":
                document[field] = value
        if record.exc_info:
            document["exception"] = self.formatException(record.exc_info)
        return json.dumps(document, separators=(",", ":"), ensure_ascii=True)


def configure_logging(config: AppConfig) -> logging.Logger:
    """Configure bounded stderr and rotating-file JSON logging once."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(config.log_level)
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    formatter = JsonFormatter()
    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(formatter)
    logger.addHandler(stream)
    try:
        file_handler = RotatingFileHandler(
            config.log_dir / "soclens.log",
            maxBytes=5_000_000,
            backupCount=3,
            encoding="utf-8",
        )
        if os.name == "posix":
            os.chmod(config.log_dir / "soclens.log", 0o600)
    except OSError:
        logger.exception(
            "File logging could not be initialized",
            extra={"event": "logging_file_unavailable", "component": "startup"},
        )
    else:
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    return logger


def runtime_directories_ready(config: AppConfig) -> bool:
    directories = {
        config.data_dir,
        config.database_path.parent,
        config.security_database_path.parent,
        config.backup_dir,
        config.export_dir,
        config.log_dir,
        config.import_dir,
    }
    return all(
        path.is_dir() and os.access(path, os.R_OK | os.W_OK | os.X_OK)
        for path in directories
    )


def filesystem_permissions_status(config: AppConfig) -> dict:
    """Report restrictive POSIX modes without claiming equivalent Windows semantics."""
    if os.name != "posix":
        return {"supported": False, "restricted": None}
    paths = {
        config.data_dir, config.database_path.parent, config.security_database_path.parent,
        config.backup_dir, config.export_dir, config.log_dir, config.import_dir,
    }
    paths.update(path for path in (config.database_path, config.security_database_path) if path.exists())
    try:
        restricted = all((path.stat().st_mode & 0o077) == 0 for path in paths if path.exists())
    except OSError:
        restricted = False
    return {"supported": True, "restricted": restricted}


def database_diagnostics(database: Path) -> dict:
    """Perform only bounded, read-only database readiness checks."""
    capability = SQLiteAssessmentRepository(database).capability().document()
    capability["ready"] = capability.pop("healthy")
    return capability


def operational_status(config: AppConfig, database: Path) -> dict:
    settings = sqlite_settings(config)
    database_status = SQLiteAssessmentRepository(database, settings=settings).capability().document()
    database_status["ready"] = database_status.pop("healthy")
    security_storage = SecurityStorage(config.security_database_path, settings=settings)
    security_status = security_storage.diagnostics()
    try:
        audit_chain_ready = security_status["ready"] and SecurityAuditLog(
            config.security_database_path, storage=security_storage
        ).verify()["valid"]
    except (AuditChainError, OSError, PersistenceError):
        audit_chain_ready = False
    directories_ready = runtime_directories_ready(config)
    permissions = filesystem_permissions_status(config)
    permission_ready = permissions["restricted"] is not False or config.environment != "production"
    security_config_valid = config.auth_mode == "local" or config.environment == "test"
    administrator_ready = security_status.get("administrator_ready", False)
    identity_ready = administrator_ready or config.auth_mode == "disabled"
    ready = (database_status["ready"] and security_status["ready"] and audit_chain_ready and identity_ready
             and directories_ready and permission_ready and security_config_valid)
    return {
        "service": "SOCLens",
        "version": APP_VERSION,
        "status": "ready" if ready else "not_ready",
        "environment": config.environment,
        "database": {
            "backend": database_status["backend"],
            "ready": database_status["ready"],
            "schema_version": database_status["schema_version"],
            "writable": database_status["writable"],
        },
        "security": {
            "backend": security_status["backend"],
            "ready": security_status["ready"],
            "schema_version": security_status["schema_version"],
            "writable": security_status["writable"],
            "authentication": "enabled" if config.auth_mode == "local" else "test_bypass",
            "administrator_ready": administrator_ready,
            "audit_chain_ready": audit_chain_ready,
        },
        "directories_ready": directories_ready,
        "filesystem_permissions": permissions,
        "supported_schema_versions": [SCHEMA_VERSION],
        "supported_security_schema_versions": [SECURITY_SCHEMA_VERSION],
        "policy_version": POLICY["id"],
        "report_schema_version": REPORT_SCHEMA_VERSION,
    }
