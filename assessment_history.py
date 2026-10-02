"""Versioned local assessment history and deterministic trend analysis."""
from datetime import datetime, timezone
import json
import re
import uuid

from engine import POLICY, compare
from persistence.assessment import SCHEMA_VERSION, SQLiteAssessmentRepository
from persistence.errors import DatabaseVersionUnsupported
from reporting import DOMAINS, assessment_manifest, supervisor_summary

OVERALL_DECLINE_THRESHOLD = 10.0
DOMAIN_DECLINE_THRESHOLD = 10.0
ASSESSMENT_ID = re.compile(r"^[A-Za-z0-9._-]{1,200}$")


class HistoryNotFound(LookupError):
    pass


class ComparisonUnavailable(ValueError):
    pass


UnsupportedDatabaseVersion = DatabaseVersionUnsupported


def _repository(value):
    return value if isinstance(value, SQLiteAssessmentRepository) else SQLiteAssessmentRepository(value)


def initialize_database(path):
    """Initialize through the assessment repository schema owner."""
    _repository(path).initialize()


def database_schema_version(path):
    """Return the declared schema version without changing the database."""
    return _repository(path).schema_version()


def _validated_time(value):
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    if not isinstance(value, str):
        raise ValueError("assessed_at must be an ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("assessed_at must be an ISO 8601 string") from exc
    if parsed.tzinfo is None:
        raise ValueError("assessed_at must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat()


def _validated_id(value, *, generate=False):
    if value is None and generate:
        value = str(uuid.uuid4())
    if not isinstance(value, str) or not ASSESSMENT_ID.fullmatch(value):
        raise ValueError("Invalid assessment_id")
    return value


def store_assessment(path, evidence, report, *, assessed_at=None, assessment_id=None, origin="assessment", if_absent=False):
    """Store one historical run. Input hashes are deliberately not unique."""
    repository = _repository(path)
    assessment_id = _validated_id(assessment_id, generate=True)
    assessed_at = _validated_time(assessed_at)
    domains = report["domains"]
    policy_version = report["policy"]["id"]
    values = (
        assessment_id,
        report["scope"],
        assessed_at,
        report["as_of"],
        policy_version,
        report["sha256"],
        report["scope_sha256"],
        report["score"],
        report["confidence"],
        report["maturity"],
        domains["Detection"],
        domains["Response"],
        domains["Telemetry"],
        domains["Quality"],
        domains["Governance"],
        int(report.get("lifecycle", {}).get("enabled") is True),
        json.dumps(evidence, sort_keys=True, separators=(",", ":"), allow_nan=False),
        json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False),
        str(origin),
    )
    repository.save(values, if_absent=if_absent)
    return assessment_id


def assessment_exists(path, assessment_id):
    return _repository(path).exists(_validated_id(assessment_id))


def list_assessments(path, scope, *, limit=100, chronological=False):
    if not isinstance(scope, str) or not scope or len(scope) > 100:
        raise ValueError("scope is required")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    return _repository(path).list(scope, limit=limit, chronological=chronological)


def get_assessment(path, assessment_id, *, include_evidence=False):
    assessment_id = _validated_id(assessment_id)
    stored = _repository(path).get(assessment_id)
    if stored is None:
        raise HistoryNotFound("Assessment not found")
    report = stored["report"]
    summary = stored["summary"]
    result = {
        "assessment": summary,
        "manifest": assessment_manifest(summary, report, SCHEMA_VERSION),
        "report": report,
        "supervisory_summary": supervisor_summary(report),
    }
    if include_evidence:
        result["evidence"] = stored["evidence"]
    return result


def compatibility(before, after):
    reasons = []
    if before.get("policy", {}).get("id") != after.get("policy", {}).get("id"):
        reasons.append("policy version differs")
    if before.get("scope_sha256") != after.get("scope_sha256"):
        reasons.append("scope_sha256 differs")
    if before.get("scope") != after.get("scope"):
        reasons.append("scope identifier differs")
    before_correlation = before.get("correlation") if isinstance(before.get("correlation"), dict) else None
    after_correlation = after.get("correlation") if isinstance(after.get("correlation"), dict) else None
    if bool(before_correlation) != bool(after_correlation):
        reasons.append("correlation model differs")
    elif before_correlation and after_correlation:
        if before_correlation.get("version") != after_correlation.get("version"):
            reasons.append("correlation version differs")
        if before_correlation.get("correlation_scope_sha256") != after_correlation.get("correlation_scope_sha256"):
            reasons.append("correlation scope differs")
    return not reasons, reasons


def _finding_key(finding):
    return (
        finding.get("title"), finding.get("owner"), finding.get("incident_id"),
        finding.get("stage"), finding.get("finding_type"),
    )


def _high_findings(report):
    return {
        _finding_key(finding): finding
        for finding in report.get("findings", [])
        if str(finding.get("priority", "")).casefold() in {"high", "critical"}
    }


def _lifecycle_gaps(report):
    gaps = set()
    for finding in report.get("findings", []):
        if finding.get("incident_id") and finding.get("stage") and finding.get("finding_type") in {"missing", "delayed", "unmeasured"}:
            gaps.add((finding["incident_id"], finding["stage"], finding["finding_type"]))
    return gaps


def analyze_drift(before, after, prior_reports=()):
    score_delta = round(after["score"] - before["score"], 1)
    confidence_floor = after.get("policy", {}).get("confidence_floor", POLICY["confidence_floor"])
    domain_delta = {
        name: round(after["domains"][name] - before["domains"][name], 1)
        for name in DOMAINS
    }
    domain_declines = {
        name: delta for name, delta in domain_delta.items()
        if delta <= -DOMAIN_DECLINE_THRESHOLD
    }
    before_high = _high_findings(before)
    after_high = _high_findings(after)
    new_high = [after_high[key] for key in sorted(after_high.keys() - before_high.keys(), key=str)]
    prior_gaps = set().union(*(_lifecycle_gaps(report) for report in prior_reports)) if prior_reports else set()
    reappeared = sorted((_lifecycle_gaps(after) - _lifecycle_gaps(before)) & prior_gaps)
    reasons = []
    if score_delta <= -OVERALL_DECLINE_THRESHOLD:
        reasons.append("overall score decline reached the 10-point drift threshold")
    if after["confidence"] < confidence_floor:
        reasons.append("confidence is below the policy floor")
    if domain_declines:
        reasons.append("one or more domains declined by at least 10 points")
    if new_high:
        reasons.append("new high-priority findings appeared")
    if reappeared:
        reasons.append("previously absent lifecycle gaps reappeared")
    return {
        "detected": bool(reasons),
        "reasons": reasons,
        "overall_decline": score_delta <= -OVERALL_DECLINE_THRESHOLD,
        "overall_decline_threshold_points": OVERALL_DECLINE_THRESHOLD,
        "confidence_below_floor": after["confidence"] < confidence_floor,
        "confidence_floor": confidence_floor,
        "domain_declines": domain_declines,
        "domain_decline_threshold_points": DOMAIN_DECLINE_THRESHOLD,
        "new_high_priority_findings": new_high,
        "reappeared_lifecycle_gaps": [
            {"incident_id": incident, "stage": stage, "finding_type": kind}
            for incident, stage, kind in reappeared
        ],
    }


def compare_reports(before, after, prior_reports=()):
    comparable, reasons = compatibility(before, after)
    if not comparable:
        raise ComparisonUnavailable("Comparison unavailable: " + "; ".join(reasons))
    result = compare(before, after)
    result["comparable"] = True
    result["drift"] = analyze_drift(before, after, prior_reports)
    result["drift_detected"] = result["drift"]["detected"]
    return result


def compare_stored(path, before_id, after_id):
    before_stored = get_assessment(path, before_id)
    after_stored = get_assessment(path, after_id)
    before = before_stored["report"]
    after = after_stored["report"]
    records = list_assessments(path, before_stored["assessment"]["scope"], limit=500, chronological=True)
    prior_reports = []
    for record in records:
        if record["assessment_id"] == before_id:
            break
        if (record["policy_version"] == before_stored["assessment"]["policy_version"]
                and record["scope_sha256"] == before_stored["assessment"]["scope_sha256"]):
            candidate = get_assessment(path, record["assessment_id"])["report"]
            if compatibility(candidate, before)[0]:
                prior_reports.append(candidate)
    result = compare_reports(before, after, prior_reports)
    result["before_assessment_id"] = before_id
    result["after_assessment_id"] = after_id
    return result


def _delta(before, after):
    return {
        "score": round(after["score"] - before["score"], 1),
        "confidence": round(after["confidence"] - before["confidence"], 1),
        "domains": {
            name: round(after["domains"][name] - before["domains"][name], 1)
            for name in DOMAINS
        },
    }


def trend(path, scope):
    all_records = list_assessments(path, scope, limit=500)
    all_records.reverse()
    if not all_records:
        return {"scope": scope, "points": [], "summary": None, "excluded_incompatible": 0}
    latest = all_records[-1]
    latest_report = get_assessment(path, latest["assessment_id"])["report"]
    compatible_pairs = []
    for record in all_records:
        if record["policy_version"] != latest["policy_version"] or record["scope_sha256"] != latest["scope_sha256"]:
            continue
        candidate = get_assessment(path, record["assessment_id"])["report"]
        if compatibility(candidate, latest_report)[0]:
            compatible_pairs.append((record, candidate))
    records = [record for record, _ in compatible_pairs]
    reports = [report for _, report in compatible_pairs]
    points = []
    for index, record in enumerate(records):
        point = dict(record)
        point["previous_delta"] = None if index == 0 else _delta(records[index - 1], record)
        point["drift"] = None if index == 0 else analyze_drift(
            reports[index - 1], reports[index], reports[:max(0, index - 1)]
        )
        points.append(point)
    best = max(records, key=lambda item: (item["score"], item["assessed_at"], item["assessment_id"]))
    worst = min(records, key=lambda item: (item["score"], item["assessed_at"], item["assessment_id"]))
    if len(records) == 1:
        direction, streak = "insufficient_history", 0
    else:
        latest_delta = records[-1]["score"] - records[-2]["score"]
        direction = "improved" if latest_delta > 0 else "declined" if latest_delta < 0 else "unchanged"
        sign = 1 if latest_delta > 0 else -1 if latest_delta < 0 else 0
        streak = 0
        for index in range(len(records) - 1, 0, -1):
            delta = records[index]["score"] - records[index - 1]["score"]
            current_sign = 1 if delta > 0 else -1 if delta < 0 else 0
            if current_sign != sign:
                break
            streak += 1
    return {
        "scope": scope,
        "policy_version": latest["policy_version"],
        "scope_sha256": latest["scope_sha256"],
        "points": points,
        "summary": {
            "current": records[-1]["score"],
            "previous_delta": points[-1]["previous_delta"],
            "best": {"assessment_id": best["assessment_id"], "score": best["score"]},
            "worst": {"assessment_id": worst["assessment_id"], "score": worst["score"]},
            "direction": direction,
            "streak": streak,
        },
        "excluded_incompatible": len(all_records) - len(records),
    }
