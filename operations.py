"""Operational logging and diagnostics for the local SOCLens service."""
from __future__ import annotations

from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from contextlib import closing
import json
import logging
import os
import sqlite3
import sys

from assessment_history import SCHEMA_VERSION
from config import AppConfig
from engine import POLICY
from reporting import REPORT_SCHEMA_VERSION


APP_VERSION = "1.0.0"
LOGGER_NAME = "soclens"
LOG_FIELDS = (
    "event", "component", "version", "method", "path", "status_code", "assessment_id",
    "environment", "host", "port", "schema_version", "policy_version",
    "report_schema_version", "database_ready", "backup_name", "error_code",
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
        config.backup_dir,
        config.export_dir,
        config.log_dir,
    }
    return all(
        path.is_dir() and os.access(path, os.R_OK | os.W_OK | os.X_OK)
        for path in directories
    )


def database_diagnostics(database: Path) -> dict:
    """Perform only bounded, read-only database readiness checks."""
    try:
        if not database.is_file():
            return {"ready": False, "schema_version": None, "reason": "database_unavailable"}
        uri = f"file:{database.resolve().as_posix()}?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=2)) as connection:
            connection.execute("PRAGMA query_only=ON")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            connection.execute("SELECT 1").fetchone()
            table = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='assessments'"
            ).fetchone()
        if version != SCHEMA_VERSION:
            return {"ready": False, "schema_version": version, "reason": "unsupported_schema"}
        if table is None:
            return {"ready": False, "schema_version": version, "reason": "schema_incomplete"}
        return {"ready": True, "schema_version": version, "reason": None}
    except (OSError, sqlite3.Error):
        return {"ready": False, "schema_version": None, "reason": "database_unavailable"}


def operational_status(config: AppConfig, database: Path) -> dict:
    database_status = database_diagnostics(database)
    directories_ready = runtime_directories_ready(config)
    ready = database_status["ready"] and directories_ready
    return {
        "service": "SOCLens",
        "version": APP_VERSION,
        "status": "ready" if ready else "not_ready",
        "environment": config.environment,
        "database": {
            "ready": database_status["ready"],
            "schema_version": database_status["schema_version"],
        },
        "directories_ready": directories_ready,
        "supported_schema_versions": [SCHEMA_VERSION],
        "policy_version": POLICY["id"],
        "report_schema_version": REPORT_SCHEMA_VERSION,
    }
