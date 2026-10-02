"""Phase 6A persistence boundaries, transactions, and local concurrency tests."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event, Thread
import json
import sqlite3
import tempfile
import unittest

from assessment_history import get_assessment, list_assessments, store_assessment
from config import ConfigurationError, load_config, sqlite_settings
from engine import assess
from ingestion.sessions import PreparationService
from persistence.assessment import SCHEMA_VERSION, SQLiteAssessmentRepository
from persistence.errors import DatabaseBusy, DatabaseVersionUnsupported
from persistence.sqlite import SQLiteConnectionFactory, SQLiteSettings
from security import IdentityService, SecurityAuditLog, SecurityStorage, SessionService
from security.storage import SECURITY_SCHEMA_VERSION


ROOT = Path(__file__).resolve().parent


def baseline():
    evidence = json.loads((ROOT / "data" / "baseline.json").read_text(encoding="utf-8"))
    return evidence, assess(evidence)


class ConnectionFactoryTests(unittest.TestCase):
    def test_production_connection_creation_is_centralized(self):
        offenders = []
        for path in ROOT.rglob("*.py"):
            relative = path.relative_to(ROOT).as_posix()
            if relative.startswith("test_") or relative == "persistence/sqlite.py":
                continue
            if "sqlite3.connect(" in path.read_text(encoding="utf-8"):
                offenders.append(relative)
        self.assertEqual(offenders, [])

    def test_connection_settings_foreign_keys_busy_timeout_wal_and_close(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.sqlite3"
            settings = SQLiteSettings(busy_timeout_ms=3210, journal_mode="wal", synchronous="NORMAL")
            factory = SQLiteConnectionFactory(path, settings=settings)
            self.assertEqual(factory.configure_runtime(), "wal")
            with factory.connection(operation="settings_test") as connection:
                retained = connection
                self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
                self.assertEqual(connection.execute("PRAGMA busy_timeout").fetchone()[0], 3210)
                self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
                self.assertEqual(connection.execute("PRAGMA synchronous").fetchone()[0], 1)
            with self.assertRaises(sqlite3.ProgrammingError):
                retained.execute("SELECT 1")

    def test_transaction_commit_rollback_and_no_partial_multi_step_write(self):
        with tempfile.TemporaryDirectory() as directory:
            factory = SQLiteConnectionFactory(Path(directory) / "transactions.sqlite3")
            factory.configure_runtime()
            with factory.transaction() as connection:
                connection.execute("CREATE TABLE items(id INTEGER PRIMARY KEY, value TEXT)")
                connection.execute("INSERT INTO items(value) VALUES ('committed')")
            with self.assertRaisesRegex(ValueError, "abort"):
                with factory.transaction() as connection:
                    connection.execute("INSERT INTO items(value) VALUES ('partial-1')")
                    connection.execute("INSERT INTO items(value) VALUES ('partial-2')")
                    raise ValueError("abort")
            with factory.connection(readonly=True) as connection:
                values = [row[0] for row in connection.execute("SELECT value FROM items")]
            self.assertEqual(values, ["committed"])

    def test_busy_condition_is_bounded_and_observable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "busy.sqlite3"
            settings = SQLiteSettings(busy_timeout_ms=25)
            first = SQLiteConnectionFactory(path, settings=settings)
            events = []
            second = SQLiteConnectionFactory(path, settings=settings, observer=events.append)
            first.configure_runtime()
            with first.transaction(mode="EXCLUSIVE") as connection:
                connection.execute("CREATE TABLE IF NOT EXISTS locked(id INTEGER)")
                with self.assertRaises(DatabaseBusy):
                    with second.transaction(operation="contended_write") as other:
                        other.execute("INSERT INTO locked VALUES (1)")
            self.assertTrue(any(event.get("error_code") == "DatabaseBusy" for event in events))

    def test_database_configuration_is_allowlisted(self):
        with self.assertRaises(ConfigurationError):
            load_config({"SOCLENS_ENV": "test", "SOCLENS_DB_JOURNAL_MODE": "wal;drop"}, root=ROOT)
        with self.assertRaises(ConfigurationError):
            load_config({"SOCLENS_ENV": "test", "SOCLENS_DB_SYNCHRONOUS": "OFF"}, root=ROOT)
        config = load_config({
            "SOCLENS_ENV": "test", "SOCLENS_DB_BUSY_TIMEOUT_MS": "777",
            "SOCLENS_DB_JOURNAL_MODE": "wal", "SOCLENS_DB_SYNCHRONOUS": "NORMAL",
        }, root=ROOT)
        self.assertEqual(sqlite_settings(config), SQLiteSettings(777, "wal", "NORMAL"))
        legacy = load_config({}, root=ROOT)
        self.assertTrue(legacy.legacy_database_default)
        self.assertEqual(
            (legacy.database_journal_mode, legacy.database_synchronous), ("delete", "FULL")
        )


class AssessmentRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "assessment.sqlite3"
        self.repository = SQLiteAssessmentRepository(
            self.path, settings=SQLiteSettings(journal_mode="wal", synchronous="NORMAL")
        )
        self.repository.initialize()
        self.evidence, self.report = baseline()

    def tearDown(self):
        self.temporary.cleanup()

    def test_repository_save_read_history_and_capability(self):
        identifier = store_assessment(
            self.repository, self.evidence, self.report, assessment_id="repository-test"
        )
        stored = get_assessment(self.repository, identifier, include_evidence=True)
        self.assertEqual(stored["report"], self.report)
        self.assertEqual(stored["evidence"], self.evidence)
        self.assertEqual(list_assessments(self.repository, self.report["scope"])[0]["assessment_id"], identifier)
        capability = self.repository.capability().document()
        self.assertEqual(capability["backend"], "sqlite")
        self.assertEqual(capability["schema_version"], SCHEMA_VERSION)
        self.assertTrue(capability["healthy"])
        self.assertTrue(capability["writable"])
        self.assertNotIn(str(self.path), json.dumps(capability))

    def test_future_schema_rejected_without_mutation(self):
        future = Path(self.temporary.name) / "future.sqlite3"
        with sqlite3.connect(future) as connection:
            connection.execute("PRAGMA user_version=99")
        with self.assertRaises(DatabaseVersionUnsupported):
            SQLiteAssessmentRepository(future).initialize()
        with sqlite3.connect(future) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 99)
            self.assertEqual(connection.execute(
                "SELECT count(*) FROM sqlite_master WHERE type='table'"
            ).fetchone()[0], 0)

    def test_concurrent_reads_use_independent_connections(self):
        store_assessment(self.repository, self.evidence, self.report, assessment_id="concurrent")
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(
                lambda _: get_assessment(self.repository, "concurrent")["report"]["sha256"],
                range(12),
            ))
        self.assertEqual(results, [self.report["sha256"]] * 12)

    def test_wal_read_continues_during_uncommitted_assessment_write(self):
        store_assessment(self.repository, self.evidence, self.report, assessment_id="visible")
        entered, release = Event(), Event()
        failures = []

        def writer():
            try:
                with self.repository.factory.transaction(operation="held_assessment_write") as connection:
                    connection.execute(
                        "UPDATE assessments SET origin='pending' WHERE assessment_id='visible'"
                    )
                    entered.set()
                    release.wait(5)
            except Exception as exc:  # surfaced in the main test thread
                failures.append(exc)

        thread = Thread(target=writer)
        thread.start()
        self.assertTrue(entered.wait(2))
        try:
            self.assertEqual(get_assessment(self.repository, "visible")["assessment"]["origin"], "assessment")
        finally:
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(get_assessment(self.repository, "visible")["assessment"]["origin"], "pending")


class SecurityPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "security.sqlite3"
        self.storage = SecurityStorage(
            self.path, settings=SQLiteSettings(journal_mode="wal", synchronous="NORMAL")
        )
        self.storage.initialize(configure=True)

    def tearDown(self):
        self.temporary.cleanup()

    def test_security_schema_is_idempotent_isolated_and_session_compatible(self):
        self.storage.initialize(configure=True)
        diagnostics = self.storage.diagnostics()
        self.assertEqual(diagnostics["backend"], "sqlite")
        self.assertEqual(diagnostics["schema_version"], SECURITY_SCHEMA_VERSION)
        identities = IdentityService(self.path, scrypt_n=4096, storage=self.storage)
        user = identities.create("phase6admin", "Phase 6 Admin", "ADMIN", "Valid Password 123!")
        sessions = SessionService(self.path, storage=self.storage)
        created = sessions.create(identities.get(user["user_id"], include_credential=True))
        self.assertEqual(sessions.authenticate(created["token"])["user_id"], user["user_id"])
        with sqlite3.connect(self.path) as connection:
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
        self.assertNotIn("assessments", tables)

    def test_concurrent_session_writes_and_audit_appends_remain_valid(self):
        identities = IdentityService(self.path, scrypt_n=4096, storage=self.storage)
        user = identities.create("concurrent", "Concurrent User", "ASSESSOR", "Valid Password 123!")
        private = identities.get(user["user_id"], include_credential=True)
        sessions = SessionService(self.path, storage=self.storage)
        audit = SecurityAuditLog(self.path, storage=self.storage)
        with ThreadPoolExecutor(max_workers=4) as pool:
            created = list(pool.map(lambda _: sessions.create(private), range(8)))
        self.assertEqual(len({item["token"] for item in created}), 8)
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda index: audit.append(
                "SESSION_REVOKED", actor_user_id=user["user_id"],
                target_type="test", target_id=str(index), context={"count": index},
            ), range(8)))
        self.assertEqual(audit.verify()["entries"], 8)


class RuntimeStorageBoundaryTests(unittest.TestCase):
    def test_concurrent_preparation_creates_preserve_each_session(self):
        with tempfile.TemporaryDirectory() as directory:
            config = load_config({"SOCLENS_ENV": "test", "SOCLENS_DATA_DIR": directory}, root=ROOT)
            service = PreparationService(config)
            with ThreadPoolExecutor(max_workers=4) as pool:
                sessions = list(pool.map(lambda _: service.create(), range(10)))
            identifiers = {session.session_id for session in sessions}
            self.assertEqual(len(identifiers), 10)
            self.assertEqual(
                identifiers,
                {path.name for path in (config.import_dir / "sessions").iterdir() if path.is_dir()},
            )

    def test_preparation_service_accepts_non_filesystem_storage(self):
        class MemoryStorage:
            def __init__(self):
                self.items = {}

            def save(self, session):
                self.items[session.session_id] = session

            def get(self, session_id):
                return self.items[session_id]

            def latest(self):
                return max(self.items.values(), key=lambda item: item.updated_at)

            def delete(self, session_id):
                del self.items[session_id]

            def cleanup(self, older_than_seconds, *, now=None):
                return []

        with tempfile.TemporaryDirectory() as directory:
            config = load_config({"SOCLENS_ENV": "test", "SOCLENS_DATA_DIR": directory}, root=ROOT)
            storage = MemoryStorage()
            service = PreparationService(config, storage=storage)
            session = service.create()
            self.assertIs(service.get(session.session_id), session)
            self.assertEqual(service.latest().session_id, session.session_id)
            service.delete(session.session_id)
            self.assertEqual(storage.items, {})


if __name__ == "__main__":
    unittest.main()
