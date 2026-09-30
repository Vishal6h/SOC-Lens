import copy
import hashlib
import json
import sqlite3
import tempfile
import unittest
from email.message import Message
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

from assessment_history import (
    SCHEMA_VERSION,
    UnsupportedDatabaseVersion,
    get_assessment,
    initialize_database,
    store_assessment,
)
from engine import assess
from reporting import REPORT_SCHEMA_VERSION, audit_package, supervisor_summary
from server import Handler, MAX_BODY_BYTES, UnsupportedMediaType, history_api, read_json_request, static_asset


ROOT = Path(__file__).parent


def request_headers(content_type="application/json", content_length="2"):
    headers = Message()
    headers["Content-Type"] = content_type
    headers["Content-Length"] = content_length
    return headers


class ValidationHardeningTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "data" / "baseline.json").read_text())

    def test_whitespace_identifier_is_rejected(self):
        self.data["sources"][0]["id"] = " siem-1"
        with self.assertRaisesRegex(ValueError, "trimmed string"):
            assess(self.data)

    def test_excessive_identifier_is_rejected(self):
        self.data["techniques"][0]["id"] = "x" * 201
        with self.assertRaisesRegex(ValueError, "at most 200"):
            assess(self.data)

    def test_unknown_lifecycle_field_is_rejected(self):
        self.data["lifecycles"][0]["triage"] = {"timestamp": self.data["as_of"]}
        with self.assertRaisesRegex(ValueError, "Unknown lifecycle field"):
            assess(self.data)

    def test_unknown_stage_attribute_is_rejected(self):
        self.data["lifecycles"][0]["detection"]["analyst"] = "demo-user"
        with self.assertRaisesRegex(ValueError, "Unknown lifecycle detection field"):
            assess(self.data)

    def test_control_character_in_evidence_reference_is_rejected(self):
        self.data["controls"][0]["evidence_ref"] = "demo://control\nforged"
        with self.assertRaisesRegex(ValueError, "control characters"):
            assess(self.data)

    def test_valid_legacy_evidence_and_historical_hash_are_unchanged(self):
        self.data.pop("lifecycles")
        report = assess(self.data)
        self.assertEqual(report["score"], 80.2)
        self.assertEqual(report["sha256"], "1823b55bc5698ea3632221dc476fb456f0764b56147ee7bf065f29f2a46cfd58")


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "data" / "baseline.json").read_text())
        self.report = assess(self.data)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "reporting.sqlite3"
        store_assessment(
            self.database, self.data, self.report, assessment_id="audit-run",
            assessed_at="2026-09-30T12:05:00+00:00", origin="test",
        )
        self.stored = get_assessment(self.database, "audit-run")

    def test_report_version_and_synthetic_labels(self):
        self.assertEqual(self.report["report_schema_version"], REPORT_SCHEMA_VERSION)
        self.assertEqual(self.report["policy"]["id"], "sat-sa-demo-2.0")
        self.assertEqual(self.report["data_classification"], "SYNTHETIC DEMO DATA")
        self.assertIn("prototype", self.report["prototype_notice"].casefold())

    def test_non_synthetic_report_is_not_demo_labeled(self):
        data = copy.deepcopy(self.data)
        data["synthetic"] = False
        report = assess(data)
        self.assertEqual(report["data_classification"], "USER-SUPPLIED ASSESSMENT EVIDENCE")

    def test_manifest_contains_required_versions_and_identity(self):
        manifest = self.stored["manifest"]
        self.assertEqual(manifest["assessment_id"], "audit-run")
        self.assertEqual(manifest["policy_version"], "sat-sa-demo-2.0")
        self.assertEqual(manifest["report_schema_version"], REPORT_SCHEMA_VERSION)
        self.assertEqual(manifest["database_schema_version"], SCHEMA_VERSION)
        self.assertEqual(manifest["input_sha256"], self.report["sha256"])
        self.assertEqual(manifest["scope_sha256"], self.report["scope_sha256"])
        self.assertTrue(manifest["synthetic"])

    def test_supervisor_summary_is_deterministic_and_factual(self):
        first = supervisor_summary(self.report)
        second = supervisor_summary(copy.deepcopy(self.report))
        self.assertEqual(first, second)
        self.assertEqual(first["score"], self.report["score"])
        self.assertEqual(first["strongest_domain"], {"name": "Telemetry", "score": 100.0})
        self.assertEqual(first["weakest_domain"], {"name": "Detection", "score": 70.0})
        self.assertEqual(first["lifecycle"]["completeness_percent"], 100.0)
        self.assertEqual(first["drift"]["status"], "not_evaluated")
        self.assertLessEqual(len(first["top_evidence_backed_issues"]), 3)

    def test_audit_package_is_reproducible_and_excludes_raw_evidence(self):
        first = audit_package(self.stored["assessment"], self.report, SCHEMA_VERSION)
        second = audit_package(self.stored["assessment"], self.report, SCHEMA_VERSION)
        self.assertEqual(first, second)
        with ZipFile(BytesIO(first)) as archive:
            names = archive.namelist()
            self.assertEqual(names, [
                "manifest.json", "report.json", "findings.json",
                "lifecycle-summary.json", "supervisory-summary.json",
            ])
            self.assertNotIn("evidence.json", names)
            manifest = json.loads(archive.read("manifest.json"))
            for name, metadata in manifest["artifacts"].items():
                content = archive.read(name)
                self.assertEqual(metadata["sha256"], hashlib.sha256(content).hexdigest())
                self.assertEqual(metadata["bytes"], len(content))

    def test_audit_api_returns_zip_headers(self):
        status, body, content_type, headers = history_api("/api/audit/audit-run", self.database)
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "application/zip")
        self.assertTrue(body.startswith(b"PK"))
        self.assertIn("audit-run", headers["Content-Disposition"])


class ServerHardeningTests(unittest.TestCase):
    def test_static_allowlist_prevents_traversal(self):
        self.assertIsNone(static_asset("/../../etc/passwd"))
        self.assertIsNone(static_asset("/%2e%2e/%2e%2e/etc/passwd"))
        asset = static_asset("/app.js")
        self.assertEqual(asset[0].name, "app.js")

    def test_request_size_is_enforced_before_read(self):
        headers = request_headers(content_length=str(MAX_BODY_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "Upload limit"):
            read_json_request(headers, BytesIO())

    def test_malformed_json_and_media_type_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "valid UTF-8 JSON"):
            read_json_request(request_headers(content_length="1"), BytesIO(b"{"))
        with self.assertRaisesRegex(UnsupportedMediaType, "application/json"):
            read_json_request(request_headers("text/plain"), BytesIO(b"{}"))

    def test_transfer_encoding_and_short_body_are_rejected(self):
        headers = request_headers(content_length="2")
        headers["Transfer-Encoding"] = "chunked"
        with self.assertRaisesRegex(ValueError, "Transfer-Encoding"):
            read_json_request(headers, BytesIO(b"{}"))
        with self.assertRaisesRegex(ValueError, "ended before"):
            read_json_request(request_headers(content_length="3"), BytesIO(b"{}"))

    def test_malformed_history_query_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "history.sqlite3"
            with self.assertRaisesRegex(ValueError, "Unexpected query parameter"):
                history_api("/api/history?scope=demo&sql=select", database)
            query = "&".join(f"x{i}=1" for i in range(21))
            with self.assertRaises(ValueError):
                history_api("/api/history?" + query, database)

    def test_unsupported_method_returns_json_405(self):
        handler = object.__new__(Handler)
        handler.command = "DELETE"
        handler.request_version = "HTTP/1.1"
        handler.requestline = "DELETE /api/assess HTTP/1.1"
        handler.client_address = ("127.0.0.1", 1)
        handler.server = object()
        handler.wfile = BytesIO()
        handler.log_request = lambda *args: None
        handler.method_not_allowed()
        response = handler.wfile.getvalue()
        self.assertIn(b"405 Method Not Allowed", response)
        self.assertIn(b"Content-Type: application/json; charset=utf-8", response)
        self.assertIn(b'"error": "Method DELETE is not supported"', response)


class DatabaseSafetyTests(unittest.TestCase):
    def test_future_database_schema_is_rejected_without_downgrade(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "future.sqlite3"
            with sqlite3.connect(database) as connection:
                connection.execute("PRAGMA user_version=99")
            with self.assertRaisesRegex(UnsupportedDatabaseVersion, "newer than supported"):
                initialize_database(database)
            with sqlite3.connect(database) as connection:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 99)
                tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            self.assertEqual(tables, [])

    def test_failed_migration_rolls_back_schema_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "broken.sqlite3"
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE assessments (sha256 TEXT PRIMARY KEY, scope TEXT, as_of TEXT, evidence TEXT, report TEXT)")
                connection.execute(
                    "INSERT INTO assessments VALUES (?,?,?,?,?)",
                    ("bad", "scope", "2026-01-01T00:00:00+00:00", "{}", json.dumps({"score": "not-a-number"})),
                )
            with self.assertRaises(ValueError):
                initialize_database(database)
            with sqlite3.connect(database) as connection:
                columns = {row[1] for row in connection.execute("PRAGMA table_info(assessments)")}
                backup = connection.execute("SELECT name FROM sqlite_master WHERE name='assessments_legacy_v1'").fetchone()
                version = connection.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(columns, {"sha256", "scope", "as_of", "evidence", "report"})
            self.assertIsNone(backup)
            self.assertEqual(version, 0)


if __name__ == "__main__":
    unittest.main()
