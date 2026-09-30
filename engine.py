"""SAT-SA demonstrator: deterministic assessment over declared, synthetic or imported evidence."""
import hashlib
import json
import math
from datetime import datetime, timezone

POLICY = {"id": "sat-sa-demo-1.0", "weights": {"Detection": .30, "Response": .25, "Telemetry": .20, "Quality": .15, "Governance": .10}, "confidence_floor": 70, "minimum_reviewed_cases": 10, "max_test_age_days": 30}
KINDS = {"SIEM", "EDR", "SOAR", "UEBA", "CTI"}

def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("Timestamps must be ISO 8601 strings with a timezone")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid ISO 8601 timestamp") from exc
    if dt.tzinfo is None:
        raise ValueError("Timestamps must include a timezone")
    return dt

def number(value, lo, hi):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not lo <= value <= hi:
        raise ValueError(f"Number must be finite and between {lo} and {hi}")
    return value

def validate(data):
    if not isinstance(data, dict):
        raise ValueError("Evidence must be a JSON object")
    for key in ("scope", "as_of", "synthetic", "sources", "techniques", "cases", "controls"):
        if key not in data:
            raise ValueError(f"Missing field: {key}")
    if not isinstance(data["scope"], str) or not data["scope"].strip() or len(data["scope"]) > 100:
        raise ValueError("Scope must be a nonempty string of at most 100 characters")
    if not isinstance(data["synthetic"], bool):
        raise ValueError("synthetic must be a boolean")
    now = timestamp(data["as_of"])
    ids = set()
    for key in ("sources", "techniques", "cases", "controls"):
        rows = data[key]
        if not isinstance(rows, list) or len(rows) > 10000:
            raise ValueError(f"{key} must be an array with at most 10,000 rows")
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"]:
                raise ValueError("Each row requires a string id")
            if row["id"] in ids:
                raise ValueError("Row IDs must be globally unique")
            ids.add(row["id"])
            if not isinstance(row.get("evidence_ref", ""), str) or len(row.get("evidence_ref", "")) > 500:
                raise ValueError("Invalid evidence_ref")
    for s in data["sources"]:
        if s.get("kind") not in KINDS:
            raise ValueError("Unknown source kind")
        number(s.get("weight"), 1, 5)
        number(s.get("completeness"), 0, 1)
        if s.get("last_seen") is not None and timestamp(s["last_seen"]) > now:
            raise ValueError("Future source timestamps are invalid")
    source_ids = {s["id"] for s in data["sources"]}
    for t in data["techniques"]:
        if t.get("source_id") not in source_ids:
            raise ValueError("Unknown technique source_id")
        number(t.get("risk_weight"), 1, 5)
        if t.get("status") not in ("passed", "failed", "untested"):
            raise ValueError("Unknown technique status")
        if t.get("tested_at") is not None and timestamp(t["tested_at"]) > now:
            raise ValueError("Future test timestamps are invalid")
    for c in data["cases"]:
        number(c.get("sla_minutes"), 1, 10080)
        detected = timestamp(c.get("detected_at"))
        if detected > now:
            raise ValueError("Future case timestamps are invalid")
        if c.get("contained_at") is not None:
            contained = timestamp(c["contained_at"])
            if contained < detected or contained > now:
                raise ValueError("Containment timestamp is inconsistent")
        if c.get("disposition") not in ("true_positive", "false_positive", "unreviewed"):
            raise ValueError("Unknown disposition")
    for c in data["controls"]:
        if not isinstance(c.get("satisfied"), bool) or not isinstance(c.get("critical"), bool):
            raise ValueError("Control flags must be booleans")
    return now

def assess(data):
    now = validate(data)
    sources, techniques, cases, controls = (data[k] for k in ("sources", "techniques", "cases", "controls"))
    mean = lambda seq: sum(seq) / len(seq) if seq else 0
    ratio = lambda n, d: n / d if d else 0
    freshness = {}
    for s in sources:
        age = (now - timestamp(s["last_seen"])).total_seconds() / 3600 if s.get("last_seen") else float("inf")
        freshness[s["id"]] = max(0, min(1, 1 - max(0, age - 24) / 72))
    valid_tests = []
    findings = []
    for t in techniques:
        recent = t.get("tested_at") and (now - timestamp(t["tested_at"])).total_seconds() <= POLICY["max_test_age_days"] * 86400
        valid = bool(t["status"] == "passed" and recent and t.get("evidence_ref"))
        valid_tests.append(valid)
        if not valid:
            findings.append({"priority": "High" if t["risk_weight"] >= 4 else "Medium", "title": f"Validate {t['id']}", "reason": "Failed, untested, stale or unlinked test evidence", "evidence_ref": t.get("evidence_ref", ""), "owner": "Detection engineering"})
    eligible = [c for c in cases if c["disposition"] != "false_positive"]
    durations = []
    on_time = 0
    for c in eligible:
        if c.get("contained_at"):
            minutes = (timestamp(c["contained_at"]) - timestamp(c["detected_at"])).total_seconds() / 60
            durations.append(minutes)
            on_time += int(minutes <= c["sla_minutes"] and bool(c.get("evidence_ref")))
    reviewed = [c for c in cases if c["disposition"] != "unreviewed"]
    tp = sum(c["disposition"] == "true_positive" for c in reviewed)
    domain = {
        "Detection": 100 * ratio(sum(t["risk_weight"] for t, ok in zip(techniques, valid_tests) if ok), sum(t["risk_weight"] for t in techniques)),
        "Response": 100 * ratio(on_time, len(eligible)),
        "Telemetry": 100 * ratio(sum(s["weight"] * s["completeness"] * freshness[s["id"]] for s in sources), sum(s["weight"] for s in sources)),
        "Quality": 100 * ratio(tp, len(reviewed)),
        "Governance": 100 * ratio(sum(c["satisfied"] and bool(c.get("evidence_ref")) for c in controls), len(controls)),
    }
    all_rows = sources + techniques + cases + controls
    completeness = mean([mean([s["completeness"] for s in sources]), ratio(len(reviewed), len(cases)), ratio(sum(bool(t.get("tested_at")) for t in techniques), len(techniques))])
    fresh = mean(list(freshness.values()))
    traceability = ratio(sum(bool(r.get("evidence_ref")) for r in all_rows), len(all_rows))
    confidence = 100 * completeness * fresh * traceability
    score = sum(domain[k] * w for k, w in POLICY["weights"].items())
    critical_gap = any(c["critical"] and not (c["satisfied"] and c.get("evidence_ref")) for c in controls)
    provisional = confidence < POLICY["confidence_floor"] or len(reviewed) < POLICY["minimum_reviewed_cases"] or any(not data[k] for k in ("sources", "techniques", "cases", "controls"))
    level = 1 if score < 40 else 2 if score < 60 else 3 if score < 80 else 4
    if critical_gap:
        level = min(level, 2)
        findings.append({"priority": "High", "title": "Close critical control gap", "reason": "Critical control lacks verified evidence; maturity capped at L2", "owner": "SOC governance", "evidence_ref": ""})
    if level == 4 and (domain["Detection"] < 75 or any(not ok and t["risk_weight"] >= 4 for t, ok in zip(techniques, valid_tests))):
        level = 3
    for s in sources:
        if freshness[s["id"]] < 1:
            findings.append({"priority": "High", "title": f"Restore {s['kind']} freshness", "reason": "No events within 24-hour freshness target", "owner": "Platform engineering", "evidence_ref": s.get("evidence_ref", "")})
    payload = json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    scope_contract = {"sources": [(s["id"], s["kind"], s["weight"]) for s in sources], "techniques": [(t["id"], t["source_id"], t["risk_weight"]) for t in techniques], "controls": [(c["id"], c["critical"]) for c in controls]}
    scope_hash = hashlib.sha256(json.dumps(scope_contract, sort_keys=True).encode()).hexdigest()
    return {
        "scope": data["scope"], "as_of": data["as_of"], "synthetic": data["synthetic"], "policy": POLICY,
        "score": round(score, 1), "confidence": round(confidence, 1), "maturity": "Provisional" if provisional else f"L{level}",
        "domains": {k: round(v, 1) for k, v in domain.items()},
        "confidence_factors": {"completeness": round(completeness, 3), "freshness": round(fresh, 3), "traceability": round(traceability, 3)},
        "counts": {"sources": len(sources), "techniques": len(techniques), "validated_tests": sum(valid_tests), "cases": len(cases), "reviewed_cases": len(reviewed), "controls": len(controls), "on_time": on_time, "response_denominator": len(eligible)},
        "findings": sorted(findings, key=lambda f: f["priority"]), "sha256": hashlib.sha256(payload).hexdigest(), "scope_sha256": scope_hash,
        "limitations": ["Declared scope and references require assessor review", "Synthetic demo is not operational effectiveness evidence", "Precision is a quality proxy, not recall", "Confidence is an evidence index, not a statistical probability", "Policy weights and maturity bands require pilot calibration"],
    }

def compare(before, after):
    if before["scope"] != after["scope"] or before["scope_sha256"] != after["scope_sha256"] or before["policy"]["id"] != after["policy"]["id"]:
        raise ValueError("Comparison requires identical scope and policy")
    delta = round(after["score"] - before["score"], 1)
    return {"score_delta": delta, "confidence_delta": round(after["confidence"] - before["confidence"], 1), "domain_delta": {k: round(after["domains"][k] - before["domains"][k], 1) for k in before["domains"]}, "drift_alert": delta <= -10 or after["confidence"] < POLICY["confidence_floor"]}
