import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from urllib.parse import quote

from assessment_history import (
    ComparisonUnavailable,
    analyze_drift,
    compare_reports,
    compare_stored,
    get_assessment,
    initialize_database,
    list_assessments,
    store_assessment,
    trend,
)
from engine import assess
import server as server_module
from server import history_api


ROOT = Path(__file__).parent


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "history.sqlite3"
        self.baseline_data = json.loads((ROOT / "data" / "baseline.json").read_text())
        self.degraded_data = json.loads((ROOT / "data" / "degraded.json").read_text())
        self.baseline = assess(self.baseline_data)
        self.degraded = assess(self.degraded_data)

    def store(self, assessment_id, report=None, data=None, day=1):
        report = report or self.baseline
        data = data or self.baseline_data
        return store_assessment(
            self.database, data, report, assessment_id=assessment_id,
            assessed_at=f"2026-09-{day:02}T12:00:00+00:00", origin="test",
        )

    def test_database_initialization(self):
        initialize_database(self.database)
        with sqlite3.connect(self.database) as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            columns = {row[1] for row in connection.execute("PRAGMA table_info(assessments)")}
        self.assertEqual(version, 2)
        self.assertTrue({"assessment_id", "input_sha256", "scope_sha256", "detection_score", "lifecycle_enabled"} <= columns)

    def create_v1_database(self):
        with sqlite3.connect(self.database) as connection:
            connection.execute("CREATE TABLE assessments (sha256 TEXT PRIMARY KEY, scope TEXT, as_of TEXT, evidence TEXT, report TEXT)")
            connection.execute(
                "INSERT INTO assessments VALUES (?,?,?,?,?)",
                (self.baseline["sha256"], self.baseline["scope"], self.baseline["as_of"],
                 json.dumps(self.baseline_data), json.dumps(self.baseline)),
            )

    def test_migration_from_old_schema_preserves_record_and_backup(self):
        self.create_v1_database()
        initialize_database(self.database)
        records = list_assessments(self.database, self.baseline["scope"])
        with sqlite3.connect(self.database) as connection:
            backup_count = connection.execute("SELECT count(*) FROM assessments_legacy_v1").fetchone()[0]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["input_sha256"], self.baseline["sha256"])
        self.assertEqual(backup_count, 1)

    def test_repeated_migration_does_not_duplicate_records(self):
        self.create_v1_database()
        initialize_database(self.database)
        initialize_database(self.database)
        with sqlite3.connect(self.database) as connection:
            count = connection.execute("SELECT count(*) FROM assessments").fetchone()[0]
        self.assertEqual(count, 1)

    def test_stores_multiple_assessments(self):
        self.store("run-1", day=1)
        self.store("run-2", self.degraded, self.degraded_data, day=2)
        self.assertEqual(len(list_assessments(self.database, self.baseline["scope"])), 2)

    def test_identical_evidence_can_be_separate_historical_runs(self):
        self.store("repeat-1", day=1)
        self.store("repeat-2", day=2)
        records = list_assessments(self.database, self.baseline["scope"])
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["input_sha256"], records[1]["input_sha256"])
        self.assertNotEqual(records[0]["assessment_id"], records[1]["assessment_id"])

    def test_history_ordering(self):
        self.store("middle", day=15)
        self.store("oldest", day=1)
        self.store("newest", day=30)
        newest_first = list_assessments(self.database, self.baseline["scope"])
        chronological = list_assessments(self.database, self.baseline["scope"], chronological=True)
        self.assertEqual([row["assessment_id"] for row in newest_first], ["newest", "middle", "oldest"])
        self.assertEqual([row["assessment_id"] for row in chronological], ["oldest", "middle", "newest"])

    def test_fetch_historical_report(self):
        self.store("fetch-me", day=1)
        stored = get_assessment(self.database, "fetch-me")
        self.assertEqual(stored["report"]["sha256"], self.baseline["sha256"])
        self.assertNotIn("evidence", stored)

    def test_compatible_comparison(self):
        self.store("before", day=1)
        self.store("after", self.degraded, self.degraded_data, day=2)
        result = compare_stored(self.database, "before", "after")
        self.assertTrue(result["comparable"])
        self.assertEqual(result["score_delta"], round(self.degraded["score"] - self.baseline["score"], 1))
        self.assertTrue(result["drift_detected"])

    def test_incompatible_policy_comparison_rejected(self):
        incompatible = copy.deepcopy(self.baseline)
        incompatible["policy"]["id"] = "different-policy"
        with self.assertRaisesRegex(ComparisonUnavailable, "policy version differs"):
            compare_reports(self.baseline, incompatible)

    def test_incompatible_scope_comparison_rejected(self):
        incompatible = copy.deepcopy(self.baseline)
        incompatible["scope_sha256"] = "0" * 64
        with self.assertRaisesRegex(ComparisonUnavailable, "scope_sha256 differs"):
            compare_reports(self.baseline, incompatible)

    def test_trend_calculations(self):
        self.store("healthy-old", day=1)
        self.store("degraded", self.degraded, self.degraded_data, day=2)
        self.store("healthy-current", day=3)
        result = trend(self.database, self.baseline["scope"])
        self.assertEqual([point["assessment_id"] for point in result["points"]], ["healthy-old", "degraded", "healthy-current"])
        self.assertEqual(result["summary"]["current"], self.baseline["score"])
        self.assertEqual(result["summary"]["worst"]["score"], self.degraded["score"])
        self.assertGreater(result["summary"]["previous_delta"]["score"], 0)
        self.assertEqual(result["summary"]["direction"], "improved")
        self.assertEqual(result["summary"]["streak"], 1)

    def test_drift_calculations(self):
        result = analyze_drift(self.baseline, self.degraded)
        self.assertTrue(result["detected"])
        self.assertTrue(result["overall_decline"])
        self.assertTrue(result["confidence_below_floor"])
        self.assertTrue(result["domain_declines"])
        self.assertTrue(result["new_high_priority_findings"])

    def test_reappearing_lifecycle_gap_is_identified(self):
        self.store("gap-old", self.degraded, self.degraded_data, day=1)
        self.store("gap-resolved", day=2)
        self.store("gap-new", self.degraded, self.degraded_data, day=3)
        result = compare_stored(self.database, "gap-resolved", "gap-new")
        self.assertTrue(result["drift"]["reappeared_lifecycle_gaps"])

    def test_history_api_list_and_fetch(self):
        self.store("api-run", day=1)
        status, body = history_api(
            "/api/history?scope=" + quote(self.baseline["scope"]), self.database
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["assessments"][0]["assessment_id"], "api-run")
        status, body = history_api("/api/history/api-run", self.database)
        self.assertEqual(status, 200)
        self.assertEqual(body["report"]["score"], self.baseline["score"])

    def test_history_api_rejects_incompatible_comparison(self):
        incompatible = copy.deepcopy(self.baseline)
        incompatible["policy"]["id"] = "different-policy"
        self.store("api-before", day=1)
        self.store("api-after", incompatible, day=2)
        with self.assertRaises(ComparisonUnavailable):
            history_api("/api/history/compare?before=api-before&after=api-after", self.database)

    def test_legacy_scoring_remains_unchanged(self):
        legacy = copy.deepcopy(self.baseline_data)
        legacy.pop("lifecycles")
        before = assess(legacy)
        initialize_database(self.database)
        after = assess(legacy)
        self.assertEqual(before, after)


class DemoHistoryTests(unittest.TestCase):
    def test_demo_history_is_synthetic_chronological_and_compatible(self):
        records = json.loads((ROOT / "data" / "demo-history.json").read_text())
        reports = [assess(record["evidence"]) for record in records]
        self.assertEqual(len(records), 3)
        self.assertTrue(all(report["synthetic"] for report in reports))
        self.assertEqual(len({report["scope_sha256"] for report in reports}), 1)
        self.assertLess(reports[1]["score"], reports[0]["score"])
        self.assertGreater(reports[2]["score"], reports[1]["score"])
        self.assertEqual([record["assessed_at"] for record in records], sorted(record["assessed_at"] for record in records))

    def test_demo_history_seed_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            original = server_module.DB
            server_module.DB = Path(directory) / "demo.sqlite3"
            try:
                server_module.seed_demo_history()
                server_module.seed_demo_history()
                with sqlite3.connect(server_module.DB) as connection:
                    count = connection.execute("SELECT count(*) FROM assessments").fetchone()[0]
                self.assertEqual(count, 3)
            finally:
                server_module.DB = original


if __name__ == "__main__":
    unittest.main()
