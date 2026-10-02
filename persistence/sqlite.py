"""Central SQLite connection and transaction lifecycle."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from time import monotonic
from typing import Callable, Iterator
import logging
import sqlite3

from .errors import (
    DatabaseBusy,
    DatabaseUnavailable,
    PersistenceConflict,
    PersistenceError,
    PersistenceIntegrityError,
)


LOGGER = logging.getLogger("soclens.persistence")
JOURNAL_MODES = {"delete", "wal"}
SYNCHRONOUS_MODES = {"FULL", "NORMAL"}
TRANSACTION_MODES = {"DEFERRED", "IMMEDIATE", "EXCLUSIVE"}


@dataclass(frozen=True)
class SQLiteSettings:
    busy_timeout_ms: int = 5_000
    journal_mode: str = "delete"
    synchronous: str = "FULL"

    def __post_init__(self):
        journal = str(self.journal_mode).lower()
        synchronous = str(self.synchronous).upper()
        if not 1 <= self.busy_timeout_ms <= 120_000:
            raise ValueError("SQLite busy timeout must be between 1 and 120000 milliseconds")
        if journal not in JOURNAL_MODES:
            raise ValueError("SQLite journal mode must be delete or wal")
        if synchronous not in SYNCHRONOUS_MODES:
            raise ValueError("SQLite synchronous mode must be FULL or NORMAL")
        object.__setattr__(self, "journal_mode", journal)
        object.__setattr__(self, "synchronous", synchronous)


@dataclass(frozen=True)
class StorageCapability:
    backend: str
    schema_version: int | None
    writable: bool
    healthy: bool
    reason: str | None = None

    def document(self) -> dict:
        return asdict(self)


def translate_sqlite_error(exc: sqlite3.Error) -> PersistenceError:
    message = str(exc).casefold()
    if "locked" in message or "busy" in message:
        return DatabaseBusy("Database is busy")
    if isinstance(exc, sqlite3.IntegrityError):
        if "unique" in message or "primary key" in message:
            return PersistenceConflict("Stored data conflicts with an existing record")
        return PersistenceIntegrityError("Stored data failed an integrity constraint")
    return DatabaseUnavailable("Database operation failed")


class SQLiteConnectionFactory:
    """Open one configured connection per bounded operation; never share it."""

    def __init__(self, path, *, settings: SQLiteSettings | None = None,
                 observer: Callable[[dict], None] | None = None):
        self.path = Path(path)
        self.settings = settings or SQLiteSettings()
        self.observer = observer

    def _emit(self, operation: str, started: float, *, outcome="success", error=None):
        event = {
            "event": "database_operation",
            "component": "persistence",
            "backend": "sqlite",
            "operation": operation,
            "outcome": outcome,
            "duration_ms": round((monotonic() - started) * 1000, 3),
        }
        if error:
            event["error_code"] = error
        if self.observer:
            self.observer(event)
        elif outcome != "success":
            LOGGER.info("Database operation failed", extra=event)

    def open(self, *, readonly=False, row_factory=True) -> sqlite3.Connection:
        connection = None
        try:
            if readonly:
                uri = self.path.resolve().as_uri() + "?mode=ro"
                connection = sqlite3.connect(
                    uri, uri=True, timeout=self.settings.busy_timeout_ms / 1000,
                    isolation_level=None,
                )
            else:
                connection = sqlite3.connect(
                    self.path, timeout=self.settings.busy_timeout_ms / 1000,
                    isolation_level=None,
                )
            if row_factory:
                connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(f"PRAGMA busy_timeout={self.settings.busy_timeout_ms}")
            connection.execute(f"PRAGMA synchronous={self.settings.synchronous}")
            if readonly:
                connection.execute("PRAGMA query_only=ON")
            return connection
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            raise translate_sqlite_error(exc) from exc

    @contextmanager
    def connection(self, *, readonly=False, row_factory=True,
                   operation="database") -> Iterator[sqlite3.Connection]:
        started = monotonic()
        connection = None
        try:
            connection = self.open(readonly=readonly, row_factory=row_factory)
            yield connection
        except sqlite3.Error as exc:
            error = translate_sqlite_error(exc)
            self._emit(operation, started, outcome="failure", error=type(error).__name__)
            raise error from exc
        except PersistenceError as exc:
            self._emit(operation, started, outcome="failure", error=type(exc).__name__)
            raise
        else:
            self._emit(operation, started)
        finally:
            if connection is not None:
                connection.close()

    @contextmanager
    def transaction(self, *, mode="IMMEDIATE", operation="write") -> Iterator[sqlite3.Connection]:
        mode = str(mode).upper()
        if mode not in TRANSACTION_MODES:
            raise ValueError("Unsupported SQLite transaction mode")
        with self.connection(operation=operation) as connection:
            try:
                connection.execute(f"BEGIN {mode}")
                yield connection
                connection.commit()
            except sqlite3.Error as exc:
                connection.rollback()
                raise translate_sqlite_error(exc) from exc
            except Exception:
                connection.rollback()
                raise

    def configure_runtime(self) -> str:
        """Apply allowlisted persistent/runtime settings outside a transaction."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection(operation="database_configuration") as connection:
            row = connection.execute(
                f"PRAGMA journal_mode={self.settings.journal_mode}"
            ).fetchone()
            actual = str(row[0]).lower()
            if actual != self.settings.journal_mode:
                raise DatabaseUnavailable("Database journal mode could not be configured")
            connection.execute(f"PRAGMA synchronous={self.settings.synchronous}")
        return actual

    def quick_read(self) -> None:
        with self.connection(readonly=True, operation="readiness") as connection:
            connection.execute("SELECT 1").fetchone()
