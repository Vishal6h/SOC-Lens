import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from assessment_history import compatibility
from config import initialize_runtime_directories, load_config
from engine import assess
from ingestion import ImportService, PreparationService, assemble_imports
from ingestion.correlation import CORRELATION_VERSION, correlate, enrich_report, stable_alert_identity
from ingestion.sessions import PreparationNotFound


ROOT = Path(__file__).parent


def alert(number=1, **changes):
    value = {
        "alert_id": f"ALERT-{number}", "external_record_id": f"EXT-{number}",
        "source_id": "SRC-1", "detected_at": f"2026-09-29T12:0{number}:00+00:00",
        "evidence_ref": f"synthetic://alert/{number}", "escalation_required": True,
        "incident_id": "INC-1", "case_id": "CASE-1", "provenance": [{"import_id": "import-a", "record_number": number, "file_sha256": "a" * 64}],
    }
    value.update(changes)
    return value


def patch(**changes):
    value = {
        "incident_id": "INC-1", "case_id": "CASE-1", "detected_at": "2026-09-29T12:00:00+00:00",
        "evidence_ref": "synthetic://case/1",
        "investigation": {"timestamp": "2026-09-29T12:05:00+00:00", "evidence_ref": "synthetic://investigation"},
        "escalation": {"timestamp": "2026-09-29T12:10:00+00:00", "evidence_ref": "synthetic://escalation"},
        "response": {"timestamp": "2026-09-29T12:30:00+00:00", "evidence_ref": "synthetic://response", "status": "contained"},
        "closure": {"timestamp": "2026-09-29T13:00:00+00:00", "evidence_ref": "synthetic://closure"},
    }
    value.update(changes)
    return value


class CorrelationModelTests(unittest.TestCase):
    def test_stable_external_alert_identity(self):
        first, basis = stable_alert_identity(alert())
        changed, _ = stable_alert_identity(alert(detected_at="2026-09-30T00:00:00+00:00"))
        self.assertEqual(first, changed)
        self.assertEqual(basis, "external_record_id")

    def test_deterministic_fallback_alert_identity(self):
        source = alert(external_record_id=None)
        first, basis = stable_alert_identity(source)
        second, _ = stable_alert_identity(copy.deepcopy(source))
        changed, _ = stable_alert_identity({**source, "detected_at": "2026-09-29T13:00:00+00:00"})
        self.assertEqual(first, second)
        self.assertNotEqual(first, changed)
        self.assertEqual(basis, "canonical_source_fields")

    def test_explicit_incident_many_alert_and_multiple_sources(self):
        output, lifecycles = correlate([alert(1), alert(2, source_id="SRC-2"), alert(3)], [patch()])
        incident = output["incidents"][0]
        self.assertEqual(incident["alert_ids"], ["ALERT-1", "ALERT-2", "ALERT-3"])
        self.assertEqual(incident["source_ids"], ["SRC-1", "SRC-2"])
        self.assertEqual(incident["rule_ids"], ["explicit_incident_id"])
        self.assertEqual(len(lifecycles), 1)

    def test_explicit_case_correlation_without_incident_id(self):
        alerts = [alert(1, incident_id=None), alert(2, incident_id=None)]
        output, _ = correlate(alerts, [])
        self.assertEqual(len(output["incidents"]), 1)
        self.assertEqual(output["incidents"][0]["correlation_strength"], "supported")
        self.assertIn("explicit_case_id", output["incidents"][0]["rule_ids"])

    def test_explicit_parent_relationship(self):
        child = alert(2, incident_id=None, case_id=None, parent_alert_id="ALERT-1")
        output, _ = correlate([alert(1), child], [patch()])
        self.assertEqual(len(output["incidents"][0]["alert_ids"]), 2)
        self.assertIn("explicit_parent_alert", output["incidents"][0]["rule_ids"])

    def test_unmatched_alert_is_not_forced_into_incident(self):
        output, lifecycles = correlate([alert(1, incident_id=None, case_id=None)], [])
        self.assertEqual((len(output["incidents"]), len(output["unmatched_alerts"]), lifecycles), (0, 1, []))

    def test_contradictory_duplicate_identity_is_excluded(self):
        first = alert(1)
        second = alert(1, detected_at="2026-09-29T14:00:00+00:00", incident_id="INC-2")
        output, _ = correlate([first, second], [])
        self.assertEqual(output["conflicts"][0]["code"], "CONTRADICTORY_ALERT_IDENTITY")
        self.assertEqual(output["incidents"], [])

    def test_identical_duplicate_identity_is_deduplicated(self):
        first, second = alert(1), copy.deepcopy(alert(1))
        second["provenance"] = [{"import_id": "import-b", "record_number": 2, "file_sha256": "a" * 64}]
        output, lifecycles = correlate([first, second], [patch()])
        self.assertEqual(output["warnings"][0]["code"], "DUPLICATE_ALERT_IDENTITY")
        self.assertEqual((len(output["incidents"][0]["alert_ids"]), len(lifecycles)), (1, 1))

    def test_conflicting_case_association_is_reported(self):
        output, _ = correlate([alert(1), alert(2, incident_id="INC-2")], [])
        self.assertTrue(any(item["code"] == "CONFLICTING_INCIDENT_ASSOCIATION" for item in output["conflicts"]))

    def test_conflicting_lifecycle_stages_are_not_overwritten(self):
        changed = patch(response={"timestamp": "2026-09-29T12:45:00+00:00", "evidence_ref": "synthetic://other"})
        output, lifecycles = correlate([alert(1)], [patch(), changed])
        self.assertEqual(lifecycles, [])
        self.assertTrue(any(item["code"] == "CONFLICTING_LIFECYCLE_STAGES" for item in output["conflicts"]))

    def test_rule_version_and_repeated_output_are_deterministic(self):
        first, _ = correlate([alert(1), alert(2)], [patch()])
        changed_imports = [alert(1), alert(2)]
        for item in changed_imports:
            item["provenance"][0]["import_id"] = "different-random-import"
        second, _ = correlate(changed_imports, [patch()])
        self.assertEqual(first["version"], CORRELATION_VERSION)
        self.assertEqual(first["correlation_output_sha256"], second["correlation_output_sha256"])

    def test_multiple_response_actions_and_recovery(self):
        actions = [
            {"action_id": "A1", "action_type": "isolate", "timestamp": "2026-09-29T12:20:00+00:00", "incident_id": "INC-1", "canonical_response": False, "milestone": "response"},
            {"action_id": "A2", "action_type": "contain", "timestamp": "2026-09-29T12:30:00+00:00", "incident_id": "INC-1", "canonical_response": True, "milestone": "response"},
            {"action_id": "A3", "action_type": "restore", "timestamp": "2026-09-29T12:50:00+00:00", "incident_id": "INC-1", "canonical_response": False, "milestone": "recovery"},
        ]
        output, _ = correlate([alert(1)], [patch()], actions)
        self.assertEqual(len(output["incidents"][0]["response_actions"]), 3)
        self.assertEqual(output["incidents"][0]["recovery_events"][0]["action_id"], "A3")

    def test_canonical_response_action_fills_missing_response(self):
        case = patch(); case.pop("response")
        action = {"action_id": "A1", "action_type": "contain", "timestamp": "2026-09-29T12:30:00+00:00",
                  "incident_id": "INC-1", "canonical_response": True, "milestone": "response", "evidence_ref": "synthetic://action"}
        _, lifecycles = correlate([alert(1)], [case], [action])
        self.assertEqual(lifecycles[0]["response"]["timestamp"], action["timestamp"])

    def test_multiple_incidents_remain_separate(self):
        output, _ = correlate([alert(1), alert(2, incident_id="INC-2", case_id="CASE-2")], [])
        self.assertEqual({item["incident_id"] for item in output["incidents"]}, {"INC-1", "INC-2"})

    def test_negative_space_missing_case_and_case_without_alert(self):
        no_case, _ = correlate([alert(1, case_id=None)], [])
        self.assertEqual(no_case["negative_space_findings"][0]["finding_type"], "missing_case")
        no_alert, _ = correlate([], [patch()])
        self.assertEqual(no_alert["negative_space_findings"][0]["finding_type"], "missing_alert")


class CorrelationIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.config = load_config({"SOCLENS_ENV": "test", "SOCLENS_DATA_DIR": self.temporary.name}, root=ROOT)
        initialize_runtime_directories(self.config)
        self.service = ImportService(self.config)

    def create(self, profile, relative, source_format="csv"):
        path = ROOT / relative
        return self.service.create(path.read_bytes(), filename=path.name, profile_key=profile, source_format=source_format)

    def advanced_jobs(self):
        return [
            self.create("generic-telemetry@1", "data/ingestion/generic-telemetry.csv"),
            self.create("generic-techniques@1", "data/ingestion/generic-techniques.csv"),
            self.create("generic-controls@1", "data/ingestion/generic-controls.json", "json"),
            self.create("generic-cases@1", "data/correlation/many-alert-case.csv"),
            self.create("generic-correlated-alerts@1", "data/correlation/many-alerts.csv"),
            self.create("generic-response-actions@1", "data/correlation/response-actions.csv"),
        ]

    def test_ingestion_builds_three_alerts_as_one_obligation(self):
        result = assemble_imports(self.advanced_jobs(), scope="Advanced synthetic", as_of="2026-10-01T00:00:00Z", synthetic=True)
        self.assertTrue(result["ready"])
        self.assertEqual(len(result["evidence"]["lifecycles"]), 1)
        self.assertEqual(len(result["correlation"]["incidents"][0]["alert_ids"]), 3)

    def test_no_double_lifecycle_penalty(self):
        jobs = self.advanced_jobs()
        case_job = next(job for job in jobs if job.mapping_profile_id == "generic-cases")
        case_job.fragment["lifecycle_patches"][0].pop("escalation")
        result = assemble_imports(jobs, scope="Advanced synthetic", as_of="2026-10-01T00:00:00Z", synthetic=True)
        report = assess(result["evidence"]); enrich_report(report, result["correlation"])
        missing = [finding for finding in report["findings"] if finding.get("stage") == "escalation" and finding.get("finding_type") == "missing"]
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0]["alert_ids"], ["ALERT-MA-001", "ALERT-MA-002", "ALERT-MA-003"])

    def test_legacy_one_alert_canonical_hash_is_unchanged(self):
        baseline = json.loads((ROOT / "data" / "baseline.json").read_text())
        report = assess(baseline)
        self.assertEqual(report["sha256"], "35054469ab2ce05825d407338bc44623d0357816d1d3134615c18fe3fdf0d46f")
        self.assertNotIn("correlation", report)

    def test_preparation_session_reload_and_completion(self):
        sessions = PreparationService(self.config)
        session = sessions.create()
        jobs = self.advanced_jobs()
        updated = sessions.update(session.session_id, {"import_ids": [job.import_id for job in jobs],
                                  "scope": "Advanced synthetic", "as_of": "2026-10-01T00:00:00Z", "synthetic": True})
        reloaded = PreparationService(self.config).get(session.session_id)
        self.assertEqual((updated.status, reloaded.import_ids, reloaded.correlation_readiness),
                         ("ready", [job.import_id for job in jobs], "ready"))
        self.assertEqual(sessions.mark_complete(session.session_id).status, "complete")

    def test_preparation_cleanup_does_not_remove_imports(self):
        sessions = PreparationService(self.config)
        session = sessions.create()
        job = self.create("generic-controls@1", "data/ingestion/generic-controls.json", "json")
        future = datetime.now(timezone.utc) + timedelta(days=2)
        self.assertEqual(sessions.cleanup(1, now=future), [session.session_id])
        self.assertEqual(self.service.get(job.import_id).import_id, job.import_id)
        with self.assertRaises(PreparationNotFound):
            sessions.get(session.session_id)

    def test_history_correlation_contract_compatibility(self):
        baseline = assess(json.loads((ROOT / "data" / "baseline.json").read_text()))
        correlated = copy.deepcopy(baseline)
        correlated["correlation"] = {"version": CORRELATION_VERSION, "correlation_scope_sha256": "a" * 64}
        different = copy.deepcopy(correlated); different["correlation"]["correlation_scope_sha256"] = "b" * 64
        self.assertFalse(compatibility(baseline, correlated)[0])
        self.assertFalse(compatibility(correlated, different)[0])
        self.assertTrue(compatibility(correlated, copy.deepcopy(correlated))[0])


if __name__ == "__main__":
    unittest.main()
