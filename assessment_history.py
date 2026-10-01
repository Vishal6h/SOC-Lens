"""Versioned local assessment history and deterministic trend analysis."""
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager
import json
import logging
import re
import sqlite3
import uuid

from engine import POLICY, compare
from reporting import DOMAINS, assessment_manifest, supervisor_summary

SCHEMA_VERSION = 2
MIGRATION_PATHS = {0: SCHEMA_VERSION, 1: SCHEMA_VERSION}
OVERALL_DECLINE_THRESHOLD = 10.0
DOMAIN_DECLINE_THRESHOLD = 10.0
ASSESSMENT_ID = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
LOGGER = logging.getLogger("soclens.database")


class HistoryNotFound(LookupError):
    pass


class ComparisonUnavailable(ValueError):
    pass


class UnsupportedDatabaseVersion(RuntimeError):
    pass


def _connect(path):
    connection = sqlite3.connect(Path(path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=5000")
    return connection


@contextmanager
def _database(path):
    connection = _connect(path)
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _table_exists(connection, name):
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def _create_v2(connection):
    connection.execute("""
        CREATE TABLE IF NOT EXISTS assessments (
            assessment_id TEXT PRIMARY KEY,
            scope TEXT NOT NULL,
            assessed_at TEXT NOT NULL,
            evidence_as_of TEXT NOT NULL,
            policy_version TEXT NOT NULL,
            input_sha256 TEXT NOT NULL,
            scope_sha256 TEXT NOT NULL,
            overall_score REAL NOT NULL,
            confidence REAL NOT NULL,
            maturity TEXT NOT NULL,
            detection_score REAL NOT NULL,
            response_score REAL NOT NULL,
            telemetry_score REAL NOT NULL,
            quality_score REAL NOT NULL,
            governance_score REAL NOT NULL,
            lifecycle_enabled INTEGER NOT NULL CHECK (lifecycle_enabled IN (0, 1)),
            evidence TEXT NOT NULL,
            report TEXT NOT NULL,
            origin TEXT NOT NULL
        )
    """)
    connection.execute(
        "CREATE INDEX IF NOT EXISTS assessments_scope_time ON assessments(scope, assessed_at, assessment_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS assessments_compatibility ON assessments(scope, policy_version, scope_sha256, assessed_at)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS assessments_input_sha ON assessments(input_sha256)"
    )


def _legacy_value(report, key, default):
    value = report.get(key, default)
    return default if value is None else value


def _migrate_v1_rows(connection):
    if not _table_exists(connection, "assessments_legacy_v1"):
        return
    rows = connection.execute(
        "SELECT sha256, scope, as_of, evidence, report FROM assessments_legacy_v1 ORDER BY rowid"
    ).fetchall()
    for row in rows:
        try:
            report = json.loads(row["report"])
        except (TypeError, json.JSONDecodeError):
            report = {}
        domains = report.get("domains") if isinstance(report.get("domains"), dict) else {}
        policy = report.get("policy") if isinstance(report.get("policy"), dict) else {}
        lifecycle = report.get("lifecycle") if isinstance(report.get("lifecycle"), dict) else {}
        input_sha = str(_legacy_value(report, "sha256", row["sha256"]))
        scope_hash = str(_legacy_value(report, "scope_sha256", "legacy-unavailable-" + input_sha))
        values = (
            "legacy-" + str(row["sha256"]),
            str(_legacy_value(report, "scope", row["scope"])),
            str(_legacy_value(report, "as_of", row["as_of"])),
            str(_legacy_value(report, "as_of", row["as_of"])),
            str(policy.get("id", "legacy-unknown")),
            input_sha,
            scope_hash,
            float(_legacy_value(report, "score", 0.0)),
            float(_legacy_value(report, "confidence", 0.0)),
            str(_legacy_value(report, "maturity", "Unknown")),
            float(domains.get("Detection", 0.0)),
            float(domains.get("Response", 0.0)),
            float(domains.get("Telemetry", 0.0)),
            float(domains.get("Quality", 0.0)),
            float(domains.get("Governance", 0.0)),
            int(lifecycle.get("enabled") is True),
            row["evidence"],
            row["report"],
            "migrated-v1",
        )
        connection.execute(
            "INSERT OR IGNORE INTO assessments VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            values,
        )


def initialize_database(path):
    """Create schema v2 or migrate the original SHA-keyed table without deleting it."""
    with _database(path) as connection:
        current_version = connection.execute("PRAGMA user_version").fetchone()[0]
        if current_version > SCHEMA_VERSION:
            raise UnsupportedDatabaseVersion(
                f"Database schema version {current_version} is newer than supported version {SCHEMA_VERSION}"
            )
        if current_version not in (*MIGRATION_PATHS, SCHEMA_VERSION):
            raise UnsupportedDatabaseVersion(
                f"Database schema version {current_version} has no supported migration path"
            )
        connection.execute("BEGIN IMMEDIATE")
        migration_needed = current_version != SCHEMA_VERSION
        if _table_exists(connection, "assessments"):
            columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(assessments)")
            }
            if "assessment_id" not in columns:
                if current_version == SCHEMA_VERSION:
                    raise RuntimeError("Database schema does not match its declared version")
                if _table_exists(connection, "assessments_legacy_v1"):
                    raise RuntimeError("Cannot migrate: assessments_legacy_v1 already exists")
                connection.execute("ALTER TABLE assessments RENAME TO assessments_legacy_v1")
        _create_v2(connection)
        _migrate_v1_rows(connection)
        connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    if migration_needed:
        LOGGER.info(
            "Database schema initialized or migrated",
            extra={
                "event": "database_migration_complete",
                "component": "database",
                "schema_version": SCHEMA_VERSION,
            },
        )


def database_schema_version(path):
    """Return the declared SQLite schema version without changing the database."""
    database = Path(path)
    if not database.is_file():
        return None
    connection = _connect(database)
    try:
        return connection.execute("PRAGMA user_version").fetchone()[0]
    finally:
        connection.close()


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
    initialize_database(path)
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
    with _database(path) as connection:
        connection.execute(
            ("INSERT OR IGNORE" if if_absent else "INSERT") + " INTO assessments VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            values,
        )
    return assessment_id


def assessment_exists(path, assessment_id):
    initialize_database(path)
    with _database(path) as connection:
        return connection.execute(
            "SELECT 1 FROM assessments WHERE assessment_id=?", (assessment_id,)
        ).fetchone() is not None


def _summary(row):
    return {
        "assessment_id": row["assessment_id"],
        "scope": row["scope"],
        "assessed_at": row["assessed_at"],
        "evidence_as_of": row["evidence_as_of"],
        "policy_version": row["policy_version"],
        "input_sha256": row["input_sha256"],
        "scope_sha256": row["scope_sha256"],
        "score": row["overall_score"],
        "confidence": row["confidence"],
        "maturity": row["maturity"],
        "domains": {
            "Detection": row["detection_score"],
            "Response": row["response_score"],
            "Telemetry": row["telemetry_score"],
            "Quality": row["quality_score"],
            "Governance": row["governance_score"],
        },
        "lifecycle_enabled": bool(row["lifecycle_enabled"]),
        "origin": row["origin"],
    }


def list_assessments(path, scope, *, limit=100, chronological=False):
    initialize_database(path)
    if not isinstance(scope, str) or not scope or len(scope) > 100:
        raise ValueError("scope is required")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    direction = "ASC" if chronological else "DESC"
    with _database(path) as connection:
        rows = connection.execute(
            f"SELECT * FROM assessments WHERE scope=? ORDER BY assessed_at {direction}, assessment_id {direction} LIMIT ?",
            (scope, limit),
        ).fetchall()
    return [_summary(row) for row in rows]


def get_assessment(path, assessment_id, *, include_evidence=False):
    initialize_database(path)
    assessment_id = _validated_id(assessment_id)
    with _database(path) as connection:
        row = connection.execute(
            "SELECT * FROM assessments WHERE assessment_id=?", (assessment_id,)
        ).fetchone()
    if row is None:
        raise HistoryNotFound("Assessment not found")
    report = json.loads(row["report"])
    summary = _summary(row)
    result = {
        "assessment": summary,
        "manifest": assessment_manifest(summary, report, SCHEMA_VERSION),
        "report": report,
        "supervisory_summary": supervisor_summary(report),
    }
    if include_evidence:
        result["evidence"] = json.loads(row["evidence"])
    return result


def compatibility(before, after):
    reasons = []
    if before.get("policy", {}).get("id") != after.get("policy", {}).get("id"):
        reasons.append("policy version differs")
    if before.get("scope_sha256") != after.get("scope_sha256"):
        reasons.append("scope_sha256 differs")
    if before.get("scope") != after.get("scope"):
        reasons.append("scope identifier differs")
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
            prior_reports.append(get_assessment(path, record["assessment_id"])["report"])
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
    records = [
        record for record in all_records
        if record["policy_version"] == latest["policy_version"]
        and record["scope_sha256"] == latest["scope_sha256"]
    ]
    reports = [get_assessment(path, record["assessment_id"])["report"] for record in records]
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
