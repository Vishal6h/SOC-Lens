"""Centralized, dependency-free SOCLens runtime configuration."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from tempfile import gettempdir
from typing import Mapping
import logging
import os
import uuid


ROOT = Path(__file__).resolve().parent
ENVIRONMENTS = {"development", "test", "production"}
LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
DEFAULT_REQUEST_SIZE_LIMIT = 2_000_000
MAX_REQUEST_SIZE_LIMIT = 100_000_000
DEFAULT_INGESTION_MAX_RECORDS = 10_000
DEFAULT_INGESTION_MAX_COLUMNS = 100
DEFAULT_INGESTION_MAX_FIELD_BYTES = 10_000
DEFAULT_INGESTION_MAX_ACTIVE_IMPORTS = 100


class ConfigurationError(ValueError):
    """Raised when runtime configuration is unsafe or invalid."""


@dataclass(frozen=True)
class AppConfig:
    environment: str
    host: str
    port: int
    database_path: Path
    data_dir: Path
    backup_dir: Path
    export_dir: Path
    log_dir: Path
    import_dir: Path
    log_level: str
    request_size_limit: int
    ingestion_max_upload_bytes: int
    ingestion_max_records: int
    ingestion_max_columns: int
    ingestion_max_field_bytes: int
    ingestion_max_active_imports: int
    auth_mode: str
    security_database_path: Path
    session_idle_minutes: int
    session_max_hours: int
    login_attempt_limit: int
    login_attempt_window_minutes: int
    login_block_seconds: int
    password_scrypt_n: int
    cookie_secure: bool
    legacy_database_default: bool = False


def _integer(name: str, raw: str, minimum: int, maximum: int) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return value


def _path(name: str, raw: str | None, default: Path, environment: str) -> Path:
    candidate = Path(raw).expanduser() if raw else default
    if environment == "production" and raw and not candidate.is_absolute():
        raise ConfigurationError(f"{name} must be an absolute path in production")
    try:
        return candidate.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ConfigurationError(f"{name} is not a valid filesystem path") from exc


def _boolean(name: str, raw: str) -> bool:
    value = str(raw).strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be true or false")


def _power_of_two(name: str, raw: str, minimum: int, maximum: int) -> int:
    value = _integer(name, raw, minimum, maximum)
    if value & (value - 1):
        raise ConfigurationError(f"{name} must be a power of two")
    return value


def load_config(environ: Mapping[str, str] | None = None, *, root: Path = ROOT) -> AppConfig:
    """Load and validate configuration from one environment mapping.

    Passing a mapping makes tests deterministic and prevents environment lookups from
    being scattered through application modules.
    """
    values = os.environ if environ is None else environ
    environment = values.get("SOCLENS_ENV", "development").strip().lower()
    if environment not in ENVIRONMENTS:
        raise ConfigurationError(
            "SOCLENS_ENV must be one of: development, test, production"
        )

    host = values.get("SOCLENS_HOST", "127.0.0.1").strip()
    if not host or any(character.isspace() for character in host):
        raise ConfigurationError("SOCLENS_HOST must be a nonempty host without whitespace")
    port = _integer("SOCLENS_PORT", values.get("SOCLENS_PORT", "8765"), 1, 65535)
    request_size_limit = _integer(
        "SOCLENS_REQUEST_SIZE_LIMIT",
        values.get("SOCLENS_REQUEST_SIZE_LIMIT", str(DEFAULT_REQUEST_SIZE_LIMIT)),
        1,
        MAX_REQUEST_SIZE_LIMIT,
    )
    ingestion_max_upload_bytes = _integer(
        "SOCLENS_INGESTION_MAX_UPLOAD_BYTES",
        values.get("SOCLENS_INGESTION_MAX_UPLOAD_BYTES", str(request_size_limit)),
        1, MAX_REQUEST_SIZE_LIMIT,
    )
    ingestion_max_records = _integer(
        "SOCLENS_INGESTION_MAX_RECORDS",
        values.get("SOCLENS_INGESTION_MAX_RECORDS", str(DEFAULT_INGESTION_MAX_RECORDS)),
        1, 100_000,
    )
    ingestion_max_columns = _integer(
        "SOCLENS_INGESTION_MAX_COLUMNS",
        values.get("SOCLENS_INGESTION_MAX_COLUMNS", str(DEFAULT_INGESTION_MAX_COLUMNS)),
        1, 1_000,
    )
    ingestion_max_field_bytes = _integer(
        "SOCLENS_INGESTION_MAX_FIELD_BYTES",
        values.get("SOCLENS_INGESTION_MAX_FIELD_BYTES", str(DEFAULT_INGESTION_MAX_FIELD_BYTES)),
        1, 1_000_000,
    )
    ingestion_max_active_imports = _integer(
        "SOCLENS_INGESTION_MAX_ACTIVE_IMPORTS",
        values.get("SOCLENS_INGESTION_MAX_ACTIVE_IMPORTS", str(DEFAULT_INGESTION_MAX_ACTIVE_IMPORTS)),
        1, 10_000,
    )
    auth_mode = values.get("SOCLENS_AUTH_MODE", "local").strip().lower()
    if auth_mode not in {"local", "disabled"}:
        raise ConfigurationError("SOCLENS_AUTH_MODE must be local (OIDC is not implemented)")
    if auth_mode == "disabled" and environment != "test":
        raise ConfigurationError("SOCLENS_AUTH_MODE=disabled is permitted only in explicit test mode")
    session_idle_minutes = _integer(
        "SOCLENS_SESSION_IDLE_MINUTES", values.get("SOCLENS_SESSION_IDLE_MINUTES", "30"), 1, 1440
    )
    session_max_hours = _integer(
        "SOCLENS_SESSION_MAX_HOURS", values.get("SOCLENS_SESSION_MAX_HOURS", "12"), 1, 168
    )
    login_attempt_limit = _integer(
        "SOCLENS_LOGIN_ATTEMPT_LIMIT", values.get("SOCLENS_LOGIN_ATTEMPT_LIMIT", "5"), 2, 100
    )
    login_attempt_window_minutes = _integer(
        "SOCLENS_LOGIN_ATTEMPT_WINDOW_MINUTES",
        values.get("SOCLENS_LOGIN_ATTEMPT_WINDOW_MINUTES", "15"), 1, 1440,
    )
    login_block_seconds = _integer(
        "SOCLENS_LOGIN_BLOCK_SECONDS", values.get("SOCLENS_LOGIN_BLOCK_SECONDS", "60"), 1, 3600
    )
    password_scrypt_n = _power_of_two(
        "SOCLENS_PASSWORD_SCRYPT_N", values.get("SOCLENS_PASSWORD_SCRYPT_N", "16384"),
        1 << 12, 1 << 20,
    )
    cookie_secure = _boolean(
        "SOCLENS_COOKIE_SECURE",
        values.get("SOCLENS_COOKIE_SECURE", "true" if environment == "production" else "false"),
    )
    if environment == "production" and not cookie_secure:
        raise ConfigurationError("SOCLENS_COOKIE_SECURE must be true in production")
    log_level = values.get("SOCLENS_LOG_LEVEL", "INFO").strip().upper()
    if log_level not in LOG_LEVELS or not isinstance(
        logging.getLevelName(log_level), int
    ):
        raise ConfigurationError(
            "SOCLENS_LOG_LEVEL must be one of: CRITICAL, ERROR, WARNING, INFO, DEBUG"
        )

    root = Path(root).resolve()
    if environment == "test" and "SOCLENS_DATA_DIR" not in values:
        default_data_dir = Path(gettempdir()) / (
            f"soclens-test-{os.getpid()}-{uuid.uuid4().hex}"
        )
    else:
        default_data_dir = root / "runtime"
    data_dir = _path(
        "SOCLENS_DATA_DIR", values.get("SOCLENS_DATA_DIR"), default_data_dir, environment
    )

    legacy_database = root / "assessments.sqlite3"
    use_legacy_default = (
        environment == "development"
        and "SOCLENS_DB_PATH" not in values
        and legacy_database.exists()
    )
    default_database = legacy_database if use_legacy_default else data_dir / "db" / "assessments.sqlite3"
    database_path = _path(
        "SOCLENS_DB_PATH", values.get("SOCLENS_DB_PATH"), default_database, environment
    )
    security_database_path = _path(
        "SOCLENS_SECURITY_DB_PATH", values.get("SOCLENS_SECURITY_DB_PATH"),
        data_dir / "security" / "security.sqlite3", environment,
    )
    export_dir = _path(
        "SOCLENS_EXPORT_DIR", values.get("SOCLENS_EXPORT_DIR"), data_dir / "exports", environment
    )
    backup_dir = _path(
        "SOCLENS_BACKUP_DIR", values.get("SOCLENS_BACKUP_DIR"), data_dir / "backups", environment
    )
    log_dir = _path(
        "SOCLENS_LOG_DIR", values.get("SOCLENS_LOG_DIR"), data_dir / "logs", environment
    )
    import_dir = _path(
        "SOCLENS_IMPORT_DIR", values.get("SOCLENS_IMPORT_DIR"), data_dir / "imports", environment
    )

    directory_paths = {data_dir, database_path.parent, security_database_path.parent,
                       export_dir, backup_dir, log_dir, import_dir}
    if database_path in directory_paths or security_database_path in directory_paths:
        raise ConfigurationError("Database paths must name files, not runtime directories")
    if database_path == security_database_path:
        raise ConfigurationError("Assessment and security databases must be separate files")
    if environment == "production":
        for name, path in (
            ("SOCLENS_DB_PATH", database_path),
            ("SOCLENS_SECURITY_DB_PATH", security_database_path),
            ("SOCLENS_EXPORT_DIR", export_dir),
            ("SOCLENS_BACKUP_DIR", backup_dir),
            ("SOCLENS_LOG_DIR", log_dir),
            ("SOCLENS_IMPORT_DIR", import_dir),
        ):
            if path != data_dir and data_dir not in path.parents:
                raise ConfigurationError(f"{name} must be within SOCLENS_DATA_DIR in production")

    return AppConfig(
        environment=environment,
        host=host,
        port=port,
        database_path=database_path,
        data_dir=data_dir,
        backup_dir=backup_dir,
        export_dir=export_dir,
        log_dir=log_dir,
        import_dir=import_dir,
        log_level=log_level,
        request_size_limit=request_size_limit,
        ingestion_max_upload_bytes=ingestion_max_upload_bytes,
        ingestion_max_records=ingestion_max_records,
        ingestion_max_columns=ingestion_max_columns,
        ingestion_max_field_bytes=ingestion_max_field_bytes,
        ingestion_max_active_imports=ingestion_max_active_imports,
        auth_mode=auth_mode,
        security_database_path=security_database_path,
        session_idle_minutes=session_idle_minutes,
        session_max_hours=session_max_hours,
        login_attempt_limit=login_attempt_limit,
        login_attempt_window_minutes=login_attempt_window_minutes,
        login_block_seconds=login_block_seconds,
        password_scrypt_n=password_scrypt_n,
        cookie_secure=cookie_secure,
        legacy_database_default=use_legacy_default,
    )


def initialize_runtime_directories(config: AppConfig) -> tuple[Path, ...]:
    """Create the bounded runtime directory set required by the application."""
    directories = (
        config.data_dir,
        config.database_path.parent,
        config.security_database_path.parent,
        config.backup_dir,
        config.export_dir,
        config.log_dir,
        config.import_dir,
    )
    unique = tuple(dict.fromkeys(directories))
    for directory in unique:
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ConfigurationError("A required runtime directory could not be created") from exc
        if not directory.is_dir():
            raise ConfigurationError("A configured runtime directory is not a directory")
        if not os.access(directory, os.R_OK | os.W_OK | os.X_OK):
            raise ConfigurationError("A required runtime directory is not accessible")
        managed_directory = directory == config.data_dir or config.data_dir in directory.parents
        if os.name == "posix" and managed_directory:
            try:
                os.chmod(directory, 0o700)
            except OSError as exc:
                if config.environment == "production":
                    raise ConfigurationError("A runtime directory could not be restricted") from exc
    return unique
