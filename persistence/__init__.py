"""SOCLens persistence contracts and SQLite implementations."""

from .errors import (
    DatabaseBusy,
    DatabaseUnavailable,
    DatabaseVersionUnsupported,
    PersistenceConflict,
    PersistenceError,
    PersistenceIntegrityError,
)
from .sqlite import SQLiteConnectionFactory, SQLiteSettings, StorageCapability

__all__ = (
    "DatabaseBusy",
    "DatabaseUnavailable",
    "DatabaseVersionUnsupported",
    "PersistenceConflict",
    "PersistenceError",
    "PersistenceIntegrityError",
    "SQLiteConnectionFactory",
    "SQLiteSettings",
    "StorageCapability",
)
