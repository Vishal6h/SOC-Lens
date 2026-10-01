import hashlib
import json
import logging
import sqlite3
import tempfile
import unittest
from email.message import Message
from io import BytesIO
from pathlib import Path

from assessment_history import (
    SCHEMA_VERSION,
    UnsupportedDatabaseVersion,
    initialize_database,
    store_assessment,
)
from config import (
    ConfigurationError,
    initialize_runtime_directories,
    load_config,
)
from database_operations import (
    DatabaseOperationError,
    backup_database,
    restore_database,
    validate_database,
)
from engine import assess
from operations import JsonFormatter, operational_status
import server as server_module


ROOT = Path(__file__).parent


def file_sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class ConfigurationTests(unittest.TestCase):
    def test_default_configuration_preserves_local_behavior(self):
        config = load_config({}, root=ROOT)
        self.assertEqual((config.environment, config.host, config.port), ("development", "127.0.0.1", 8765))
        self.assertEqual(config.request_size_limit, 2_000_000)
        self.assertEqual(config.database_path, (ROOT / "assessments.sqlite3").resolve())
        self.assertTrue(config.legacy_database_default)

    def test_environment_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory).resolve()
            config = load_config({
                "SOCLENS_ENV": "production",
                "SOCLENS_HOST": "0.0.0.0",
                "SOCLENS_PORT": "9000",
                "SOCLENS_DATA_DIR": str(data),
                "SOCLENS_DB_PATH": str(data / "db" / "custom.sqlite3"),
                "SOCLENS_EXPORT_DIR": str(data / "out"),
                "SOCLENS_BACKUP_DIR": str(data / "safe"),
                "SOCLENS_LOG_DIR": str(data / "log"),
                "SOCLENS_LOG_LEVEL": "DEBUG",
                "SOCLENS_REQUEST_SIZE_LIMIT": "4096",
            }, root=ROOT)
            self.assertEqual((config.environment, config.host, config.port), ("production", "0.0.0.0", 9000))
            self.assertEqual(config.database_path, data / "db" / "custom.sqlite3")
            self.assertEqual(config.request_size_limit, 4096)
            self.assertEqual(config.log_level, "DEBUG")

    def test_invalid_configuration_fails_fast(self):
        invalid = (
            {"SOCLENS_ENV": "staging"},
            {"SOCLENS_PORT": "0"},
            {"SOCLENS_PORT": "word"},
            {"SOCLENS_LOG_LEVEL": "VERBOSE"},
            {"SOCLENS_REQUEST_SIZE_LIMIT": "100000001"},
            {"SOCLENS_ENV": "production", "SOCLENS_DATA_DIR": "relative"},
        )
        for environment in invalid:
            with self.subTest(environment=environment), self.assertRaises(ConfigurationError):
                load_config(environment, root=ROOT)

    def test_test_environment_uses_unique_temporary_paths(self):
        first = load_config({"SOCLENS_ENV": "test"}, root=ROOT)
        second = load_config({"SOCLENS_ENV": "test"}, root=ROOT)
        self.assertNotEqual(first.data_dir, second.data_dir)
        self.assertNotIn(ROOT, first.data_dir.parents)
        self.assertEqual(first.database_path.parent, first.data_dir / "db")

    def test_production_defaults_remain_localhost_safe(self):
        config = load_config({"SOCLENS_ENV": "production"}, root=ROOT)
        self.assertEqual(config.host, "127.0.0.1")
        self.assertEqual(config.database_path, ROOT / "runtime" / "db" / "assessments.sqlite3")

    def test_runtime_directory_initialization(self):
        with tempfile.TemporaryDirectory() as directory:
            config = load_config({"SOCLENS_ENV": "test", "SOCLENS_DATA_DIR": directory}, root=ROOT)
            initialize_runtime_directories(config)
            for path in (config.data_dir, config.database_path.parent, config.backup_dir, config.export_dir, config.log_dir):
                self.assertTrue(path.is_dir())


class LoggingTests(unittest.TestCase):
    def test_structured_formatter_is_json_and_ignores_payload_attributes(self):
        record = logging.LogRecord("soclens.test", logging.INFO, __file__, 1, "request complete", (), None)
        record.component = "test"
        record.method = "GET"
        record.path = "/api/health"
        record.evidence = {"secret": "must-not-appear"}
        document = json.loads(JsonFormatter().format(record))
        self.assertEqual(document["level"], "INFO")
        self.assertEqual(document["method"], "GET")
        self.assertNotIn("evidence", document)
        self.assertNotIn("must-not-appear", json.dumps(document))


class HandlerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.config = load_config({
            "SOCLENS_ENV": "test",
            "SOCLENS_DATA_DIR": self.temporary.name,
        }, root=ROOT)
        initialize_runtime_directories(self.config)
        initialize_database(self.config.database_path)
        self.original_config = server_module.CONFIG
        self.original_database = server_module.DB
        server_module.CONFIG = self.config
        server_module.DB = self.config.database_path

    def tearDown(self):
        server_module.CONFIG = self.original_config
        server_module.DB = self.original_database

    def request(self, method, path, body=None, headers=None):
        handler = object.__new__(server_module.Handler)
        handler.command = method
        handler.path = path
        handler.request_version = "HTTP/1.1"
        handler.requestline = f"{method} {path} HTTP/1.1"
        handler.client_address = ("127.0.0.1", 1)
        handler.server = object()
        handler.wfile = BytesIO()
        handler.rfile = BytesIO(body or b"")
        handler.headers = Message()
        for name, value in (headers or {}).items():
            handler.headers[name] = value
        getattr(handler, f"do_{method}")()
        raw = handler.wfile.getvalue()
        head, payload = raw.split(b"\r\n\r\n", 1)
        status = int(head.splitlines()[0].split()[1])
        return status, json.loads(payload)

    def test_health_endpoint(self):
        status, body = self.request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"status": "ok", "service": "SOCLens"})

    def test_readiness_endpoint_and_operational_status(self):
        status, body = self.request("GET", "/api/ready")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ready")
        self.assertTrue(body["database"]["ready"])
        self.assertEqual(body["database"]["schema_version"], SCHEMA_VERSION)
        self.assertEqual(body["policy_version"], "sat-sa-demo-2.0")
        self.assertNotIn(str(self.config.data_dir), json.dumps(body))

    def test_structured_validation_error(self):
        status, body = self.request("GET", "/api/history")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_request")
        self.assertIn("scope", body["error"]["message"])

    def test_internal_error_is_bounded_and_has_no_traceback(self):
        original = server_module.static_asset
        server_module.static_asset = lambda path: (_ for _ in ()).throw(RuntimeError("private detail"))
        try:
            with self.assertLogs("soclens.server", "ERROR"):
                status, body = self.request("GET", "/failure")
        finally:
            server_module.static_asset = original
        serialized = json.dumps(body)
        self.assertEqual(status, 500)
        self.assertEqual(body["error"]["code"], "internal_error")
        self.assertNotIn("Traceback", serialized)
        self.assertNotIn("private detail", serialized)


class BackupRestoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.backups = self.directory / "backups"
        self.data = json.loads((ROOT / "data" / "baseline.json").read_text())
        self.report = assess(self.data)

    def create_database(self, name, assessment_ids):
        database = self.directory / name
        initialize_database(database)
        for index, assessment_id in enumerate(assessment_ids):
            store_assessment(
                database, self.data, self.report, assessment_id=assessment_id,
                assessed_at=f"2026-09-{index + 1:02}T12:00:00+00:00", origin="test",
            )
        return database

    def test_successful_backup_does_not_change_active_database(self):
        database = self.create_database("active.sqlite3", ["one"])
        before = file_sha256(database)
        first = backup_database(database, self.backups)
        second = backup_database(database, self.backups)
        self.assertEqual(file_sha256(database), before)
        self.assertNotEqual(first["backup_name"], second["backup_name"])
        self.assertEqual(validate_database(first["backup_path"])["assessment_count"], 1)
        self.assertEqual(first["sha256"], file_sha256(first["backup_path"]))

    def test_restore_creates_safety_backup_and_replaces_database(self):
        active = self.create_database("active.sqlite3", ["old"])
        source = self.create_database("source.sqlite3", ["new-1", "new-2"])
        candidate = backup_database(source, self.backups)
        result = restore_database(active, candidate["backup_path"], self.backups)
        self.assertTrue(result["restored"])
        self.assertEqual(validate_database(active)["assessment_count"], 2)
        safety = result["safety_backup"]
        self.assertTrue(Path(safety["backup_path"]).is_file())
        self.assertEqual(validate_database(safety["backup_path"])["assessment_count"], 1)

    def test_invalid_restore_preserves_original_database(self):
        active = self.create_database("active.sqlite3", ["original"])
        before = file_sha256(active)
        invalid = self.directory / "invalid.sqlite3"
        invalid.write_bytes(b"not a sqlite database")
        with self.assertRaises(DatabaseOperationError):
            restore_database(active, invalid, self.backups)
        self.assertEqual(file_sha256(active), before)
        self.assertEqual(validate_database(active)["assessment_count"], 1)

    def test_restore_refuses_unsupported_schema_version(self):
        active = self.create_database("active.sqlite3", ["original"])
        future = self.directory / "future.sqlite3"
        with sqlite3.connect(future) as connection:
            connection.execute("CREATE TABLE assessments (assessment_id TEXT)")
            connection.execute("PRAGMA user_version=99")
        before = file_sha256(active)
        with self.assertRaises(UnsupportedDatabaseVersion):
            restore_database(active, future, self.backups)
        self.assertEqual(file_sha256(active), before)


class FoundationRegressionTests(unittest.TestCase):
    def test_operational_status_reports_not_ready_without_database(self):
        with tempfile.TemporaryDirectory() as directory:
            config = load_config({"SOCLENS_ENV": "test", "SOCLENS_DATA_DIR": directory}, root=ROOT)
            initialize_runtime_directories(config)
            status = operational_status(config, config.database_path)
            self.assertEqual(status["status"], "not_ready")
            self.assertFalse(status["database"]["ready"])

    def test_required_regression_scores_and_hashes(self):
        baseline_data = json.loads((ROOT / "data" / "baseline.json").read_text())
        degraded_data = json.loads((ROOT / "data" / "degraded.json").read_text())
        expected = json.loads((ROOT / "data" / "demo-results.json").read_text())
        baseline = assess(baseline_data)
        degraded = assess(degraded_data)
        legacy_data = dict(baseline_data)
        legacy_data.pop("lifecycles")
        legacy = assess(legacy_data)
        self.assertEqual((baseline["score"], baseline["confidence"], baseline["maturity"]), (83.4, 94.4, "L3"))
        self.assertEqual((degraded["score"], degraded["confidence"], degraded["maturity"]), (65.4, 59.6, "Provisional"))
        self.assertEqual(legacy["score"], 80.2)
        self.assertEqual(legacy["sha256"], "1823b55bc5698ea3632221dc476fb456f0764b56147ee7bf065f29f2a46cfd58")
        self.assertEqual(baseline["sha256"], expected["baseline"]["sha256"])
        self.assertEqual(degraded["sha256"], expected["degraded"]["sha256"])


if __name__ == "__main__":
    unittest.main()
