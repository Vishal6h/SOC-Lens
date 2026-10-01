"""SAT-SA demonstrator: deterministic assessment over declared, synthetic or imported evidence."""
import hashlib
import json
import math
from datetime import datetime
from reporting import REPORT_SCHEMA_VERSION, supervisor_summary

POLICY = {
    "id": "sat-sa-demo-2.0",
    "weights": {"Detection": .30, "Response": .25, "Telemetry": .20, "Quality": .15, "Governance": .10},
    "confidence_floor": 70,
    "minimum_reviewed_cases": 10,
    "max_test_age_days": 30,
    "lifecycle": {
        "investigation_target_minutes": 15,
        "escalation_target_minutes": 15,
        "response_target_minutes": 60,
        "closure_target_minutes": 240,
        "timely_credit": 1.0,
        "delayed_credit": 0.5,
        "missing_credit": 0.0,
    },
}
KINDS = {"SIEM", "EDR", "SOAR", "UEBA", "CTI"}
LIFECYCLE_STAGES = ("detection", "investigation", "escalation", "response", "closure")
LIFECYCLE_INTERVALS = (
    ("detection_to_investigation", "detection", "investigation"),
    ("investigation_to_escalation", "investigation", "escalation"),
    ("escalation_to_response", "escalation", "response"),
    ("response_to_closure", "response", "closure"),
    ("total_lifecycle", "detection", "closure"),
)
LIFECYCLE_KEYS = {"incident_id", "alert_id", "case_id", "source_id", "escalation_required", *LIFECYCLE_STAGES}
LIFECYCLE_STAGE_KEYS = {"timestamp", "evidence_ref", "status"}

def identifier(value, label, maximum=200):
    if (not isinstance(value, str) or not value or value != value.strip()
            or len(value) > maximum or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise ValueError(f"{label} must be a nonempty trimmed string of at most {maximum} characters")
    return value

def evidence_reference(value, label="evidence_ref"):
    if not isinstance(value, str) or len(value) > 500:
        raise ValueError(f"Invalid {label}")
    if value and (value != value.strip() or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise ValueError(f"Invalid {label}: nonempty references must be trimmed and contain no control characters")
    return value

def timestamp(value):
    if not isinstance(value, str) or not value or len(value) > 64 or value != value.strip():
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
    identifier(data["scope"], "Scope", 100)
    if not isinstance(data["synthetic"], bool):
        raise ValueError("synthetic must be a boolean")
    now = timestamp(data["as_of"])
    ids = set()
    for key in ("sources", "techniques", "cases", "controls"):
        rows = data[key]
        if not isinstance(rows, list) or len(rows) > 10000:
            raise ValueError(f"{key} must be an array with at most 10,000 rows")
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError(f"Each {key} row must be an object")
            identifier(row.get("id"), f"{key} id")
            if row["id"] in ids:
                raise ValueError("Row IDs must be globally unique")
            ids.add(row["id"])
            evidence_reference(row.get("evidence_ref", ""))
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
    lifecycles = data.get("lifecycles")
    if lifecycles is not None:
        if not isinstance(lifecycles, list) or len(lifecycles) > 10000:
            raise ValueError("lifecycles must be an array with at most 10,000 rows")
        cases_by_id = {c["id"]: c for c in data["cases"]}
        incident_ids, alert_ids, linked_case_ids = set(), set(), set()
        for lifecycle in lifecycles:
            if not isinstance(lifecycle, dict):
                raise ValueError("Each lifecycle must be an object")
            unknown = set(lifecycle) - LIFECYCLE_KEYS
            if unknown:
                raise ValueError("Unknown lifecycle field(s): " + ", ".join(sorted(unknown)))
            for key in ("incident_id", "alert_id", "case_id", "source_id"):
                identifier(lifecycle.get(key), f"Lifecycle {key}")
            if lifecycle["source_id"] not in source_ids:
                raise ValueError("Unknown lifecycle source_id")
            if lifecycle["case_id"] not in cases_by_id:
                raise ValueError("Unknown lifecycle case_id")
            if lifecycle["incident_id"] in incident_ids or lifecycle["alert_id"] in alert_ids or lifecycle["case_id"] in linked_case_ids:
                raise ValueError("Lifecycle incident_id, alert_id and case_id correlations must be unique")
            incident_ids.add(lifecycle["incident_id"])
            alert_ids.add(lifecycle["alert_id"])
            linked_case_ids.add(lifecycle["case_id"])
            if not isinstance(lifecycle.get("escalation_required", False), bool):
                raise ValueError("Lifecycle escalation_required must be a boolean")
            previous = None
            for stage_name in LIFECYCLE_STAGES:
                stage = lifecycle.get(stage_name)
                if stage is None:
                    if stage_name == "detection":
                        raise ValueError("Lifecycle detection stage is required")
                    continue
                if not isinstance(stage, dict):
                    raise ValueError(f"Lifecycle {stage_name} stage must be an object or null")
                unknown_stage_fields = set(stage) - LIFECYCLE_STAGE_KEYS
                if unknown_stage_fields:
                    raise ValueError(f"Unknown lifecycle {stage_name} field(s): " + ", ".join(sorted(unknown_stage_fields)))
                occurred = timestamp(stage.get("timestamp"))
                if occurred > now:
                    raise ValueError("Future lifecycle timestamps are invalid")
                if previous is not None and occurred < previous:
                    raise ValueError("Lifecycle stage timestamps must be chronological")
                previous = occurred
                evidence_reference(stage.get("evidence_ref", ""), "lifecycle evidence_ref")
                status = stage.get("status")
                if status is not None:
                    identifier(status, "Lifecycle status", 100)
            linked_case = cases_by_id[lifecycle["case_id"]]
            if timestamp(lifecycle["detection"]["timestamp"]) != timestamp(linked_case["detected_at"]):
                raise ValueError("Lifecycle detection timestamp must match linked case detected_at")
            response = lifecycle.get("response")
            if response is not None and linked_case.get("contained_at") is not None:
                response_time = timestamp(response["timestamp"])
                containment_time = timestamp(linked_case["contained_at"])
                if response_time > containment_time:
                    raise ValueError("Lifecycle response timestamp cannot follow linked case contained_at")
                if response.get("status", "").casefold() == "contained" and response_time != containment_time:
                    raise ValueError("Lifecycle contained response timestamp must match linked case contained_at")
    return now

def normalize(data):
    """Validate input and produce one internal representation for legacy and lifecycle evidence."""
    now = validate(data)
    incidents = []
    for lifecycle in data.get("lifecycles", []):
        stages = {}
        for stage_name in LIFECYCLE_STAGES:
            stage = lifecycle.get(stage_name)
            stages[stage_name] = None if stage is None else {
                "timestamp": stage["timestamp"],
                "evidence_ref": stage.get("evidence_ref", ""),
                "status": stage.get("status"),
            }
        incidents.append({
            "incident_id": lifecycle["incident_id"],
            "alert_id": lifecycle["alert_id"],
            "case_id": lifecycle["case_id"],
            "source_id": lifecycle["source_id"],
            "escalation_required": lifecycle.get("escalation_required", False),
            "stages": stages,
        })
    return now, {
        "mode": "lifecycle" if "lifecycles" in data else "legacy",
        "sources": data["sources"],
        "techniques": data["techniques"],
        "cases": data["cases"],
        "controls": data["controls"],
        "incidents": incidents,
    }

def assess_lifecycles(incidents):
    findings = []
    timing_values = {name: [] for name, _, _ in LIFECYCLE_INTERVALS}
    assessed = []
    policy = POLICY["lifecycle"]
    targets = {
        "investigation": policy["investigation_target_minutes"],
        "escalation": policy["escalation_target_minutes"],
        "response": policy["response_target_minutes"],
        "closure": policy["closure_target_minutes"],
    }
    components = {
        name: {"applicable": 0, "timely": 0, "delayed": 0, "missing": 0, "unmeasured": 0, "not_applicable": 0, "credits": 0.0, "target_minutes": target}
        for name, target in targets.items()
    }

    def stage_reference(incident, stage_name):
        stage = incident["stages"][stage_name]
        if stage and stage["evidence_ref"]:
            return stage["evidence_ref"]
        position = LIFECYCLE_STAGES.index(stage_name)
        for stage_name in reversed(LIFECYCLE_STAGES[:position]):
            stage = incident["stages"][stage_name]
            if stage and stage["evidence_ref"]:
                return stage["evidence_ref"]
        return ""

    def add_finding(incident, stage, kind, priority, reason, observed=None):
        findings.append({
            "priority": priority,
            "title": f"Address {stage} {kind} for {incident['incident_id']}",
            "reason": reason,
            "evidence_ref": stage_reference(incident, stage),
            "owner": "SOC operations",
            "incident_id": incident["incident_id"],
            "alert_id": incident["alert_id"],
            "case_id": incident["case_id"],
            "stage": stage,
            "finding_type": kind,
            "observed_minutes": observed,
            "policy_threshold_minutes": targets[stage],
        })

    def evaluate(component_name, observed=None, present=True, measurable=True):
        component = components[component_name]
        component["applicable"] += 1
        if not present:
            result, credit = "missing", policy["missing_credit"]
        elif not measurable:
            result, credit = "unmeasured", policy["delayed_credit"]
        elif observed <= component["target_minutes"]:
            result, credit = "timely", policy["timely_credit"]
        else:
            result, credit = "delayed", policy["delayed_credit"]
        component[result] += 1
        component["credits"] += credit
        return {"result": result, "observed_minutes": observed, "threshold_minutes": component["target_minutes"], "credit": credit}

    for incident in incidents:
        stages = incident["stages"]
        timings = {}
        for metric, start_name, end_name in LIFECYCLE_INTERVALS:
            start, end = stages[start_name], stages[end_name]
            value = None
            if start is not None and end is not None:
                value = round((timestamp(end["timestamp"]) - timestamp(start["timestamp"])).total_seconds() / 60, 1)
                timing_values[metric].append(value)
            timings[metric] = value
        investigation_delay = timings["detection_to_investigation"]
        investigation = evaluate("investigation", investigation_delay, stages["investigation"] is not None)
        if investigation["result"] == "missing":
            add_finding(incident, "investigation", "missing", "Medium", "Alert exists but no linked investigation stage was recorded")
        elif investigation["result"] == "delayed":
            add_finding(incident, "investigation", "delayed", "Medium", f"Investigation began after {investigation_delay:.1f} minutes, exceeding the {targets['investigation']}-minute target", investigation_delay)

        if incident["escalation_required"]:
            escalation_delay = timings["investigation_to_escalation"]
            escalation = evaluate("escalation", escalation_delay, stages["escalation"] is not None, stages["investigation"] is not None)
            if escalation["result"] == "missing" and stages["investigation"] is not None:
                add_finding(incident, "escalation", "missing", "High", "Investigation requires escalation but no linked escalation stage was recorded")
            elif escalation["result"] == "delayed":
                add_finding(incident, "escalation", "delayed", "Medium", f"Escalation occurred after {escalation_delay:.1f} minutes, exceeding the {targets['escalation']}-minute target", escalation_delay)
        else:
            components["escalation"]["not_applicable"] += 1
            escalation = {"result": "not_required", "observed_minutes": None, "threshold_minutes": targets["escalation"], "credit": None}

        response_delay = None
        if stages["response"] is not None:
            response_delay = round((timestamp(stages["response"]["timestamp"]) - timestamp(stages["detection"]["timestamp"])).total_seconds() / 60, 1)
        response = evaluate("response", response_delay, stages["response"] is not None)
        if response["result"] == "missing":
            add_finding(incident, "response", "missing", "High", "No linked response or containment stage was recorded")
        elif response["result"] == "delayed":
            add_finding(incident, "response", "delayed", "High", f"Response occurred after {response_delay:.1f} minutes, exceeding the {targets['response']}-minute target", response_delay)

        closure_delay = timings["response_to_closure"]
        closure = evaluate("closure", closure_delay, stages["closure"] is not None, stages["response"] is not None)
        if closure["result"] == "missing":
            add_finding(incident, "closure", "missing", "Medium", "No linked closure or recovery stage was recorded")
        elif closure["result"] == "delayed":
            add_finding(incident, "closure", "delayed", "Medium", f"Closure occurred after {closure_delay:.1f} minutes, exceeding the {targets['closure']}-minute target", closure_delay)

        complete = stages["investigation"] is not None and stages["response"] is not None and stages["closure"] is not None and (not incident["escalation_required"] or stages["escalation"] is not None)
        assessed.append({**incident, "complete": complete, "timing_minutes": timings, "stage_evaluation": {"investigation": investigation, "escalation": escalation, "response": response, "closure": closure}})

    metrics = {
        name: {"count": len(values), "average_minutes": round(sum(values) / len(values), 1) if values else None}
        for name, values in timing_values.items()
    }
    for component in components.values():
        component["credits"] = round(component["credits"], 1)
        component["score"] = round(100 * component["credits"] / component["applicable"], 1) if component["applicable"] else None
        component["met"] = component["timely"]
    operational_names = ("investigation", "escalation", "response")
    operational_applicable = sum(components[name]["applicable"] for name in operational_names)
    operational_credits = sum(components[name]["credits"] for name in operational_names)
    return {
        "incident_count": len(incidents),
        "complete_incidents": sum(incident["complete"] for incident in assessed),
        "incidents": assessed,
        "timing_metrics": metrics,
        "scoring": {
            "applied": bool(incidents),
            "credit_policy": {"timely": policy["timely_credit"], "delayed": policy["delayed_credit"], "missing": policy["missing_credit"]},
            "components": components,
            "operational_response": {"applicable": operational_applicable, "credits": round(operational_credits, 1), "score": round(100 * operational_credits / operational_applicable, 1) if operational_applicable else None},
            "closure_discipline": {"applicable": components["closure"]["applicable"], "credits": components["closure"]["credits"], "score": components["closure"]["score"]},
        },
    }, findings

def assess(data):
    now, normalized = normalize(data)
    sources, techniques, cases, controls = (normalized[k] for k in ("sources", "techniques", "cases", "controls"))
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
    on_time = 0
    for c in eligible:
        if c.get("contained_at"):
            minutes = (timestamp(c["contained_at"]) - timestamp(c["detected_at"])).total_seconds() / 60
            on_time += int(minutes <= c["sla_minutes"] and bool(c.get("evidence_ref")))
    reviewed = [c for c in cases if c["disposition"] != "unreviewed"]
    tp = sum(c["disposition"] == "true_positive" for c in reviewed)
    lifecycle, lifecycle_findings = assess_lifecycles(normalized["incidents"])
    lifecycle["enabled"] = normalized["mode"] == "lifecycle"
    findings.extend(lifecycle_findings)
    legacy_response = 100 * ratio(on_time, len(eligible))
    legacy_quality = 100 * ratio(tp, len(reviewed))
    domain = {
        "Detection": 100 * ratio(sum(t["risk_weight"] for t, ok in zip(techniques, valid_tests) if ok), sum(t["risk_weight"] for t in techniques)),
        "Response": legacy_response,
        "Telemetry": 100 * ratio(sum(s["weight"] * s["completeness"] * freshness[s["id"]] for s in sources), sum(s["weight"] for s in sources)),
        "Quality": legacy_quality,
        "Governance": 100 * ratio(sum(c["satisfied"] and bool(c.get("evidence_ref")) for c in controls), len(controls)),
    }
    scoring = lifecycle["scoring"]
    if lifecycle["enabled"] and lifecycle["incident_count"]:
        operational = scoring["operational_response"]
        response_requirements = len(eligible) + operational["applicable"]
        response_credits = on_time + operational["credits"]
        domain["Response"] = 100 * ratio(response_credits, response_requirements)
        closure = scoring["closure_discipline"]
        quality_requirements = len(reviewed) + closure["applicable"]
        quality_credits = tp + closure["credits"]
        domain["Quality"] = 100 * ratio(quality_credits, quality_requirements)
        scoring["domain_impact"] = {
            "Response": {"legacy_score": round(legacy_response, 1), "legacy_requirements": len(eligible), "legacy_credits": on_time, "lifecycle_score": operational["score"], "lifecycle_requirements": operational["applicable"], "lifecycle_credits": operational["credits"], "combined_score": round(domain["Response"], 1), "effect_points": round(domain["Response"] - legacy_response, 1)},
            "Quality": {"legacy_score": round(legacy_quality, 1), "legacy_requirements": len(reviewed), "legacy_credits": tp, "lifecycle_score": closure["score"], "lifecycle_requirements": closure["applicable"], "lifecycle_credits": closure["credits"], "combined_score": round(domain["Quality"], 1), "effect_points": round(domain["Quality"] - legacy_quality, 1)},
        }
    else:
        scoring["applied"] = False
        scoring["domain_impact"] = {
            "Response": {"legacy_score": round(legacy_response, 1), "combined_score": round(legacy_response, 1), "effect_points": 0.0},
            "Quality": {"legacy_score": round(legacy_quality, 1), "combined_score": round(legacy_quality, 1), "effect_points": 0.0},
        }
    lifecycle_evidence_rows = [stage for incident in normalized["incidents"] for stage in incident["stages"].values() if stage is not None]
    all_rows = sources + techniques + cases + controls + lifecycle_evidence_rows
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
    if lifecycle["enabled"]:
        scope_contract["lifecycles"] = [(i["incident_id"], i["alert_id"], i["case_id"], i["source_id"], i["escalation_required"]) for i in normalized["incidents"]]
    scope_hash = hashlib.sha256(json.dumps(scope_contract, sort_keys=True).encode()).hexdigest()
    report = {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "scope": data["scope"], "as_of": data["as_of"], "synthetic": data["synthetic"], "policy": POLICY,
        "data_classification": "SYNTHETIC DEMO DATA" if data["synthetic"] else "USER-SUPPLIED ASSESSMENT EVIDENCE",
        "prototype_notice": "SOCLens is a supervisory analytics prototype, not a SOC, SIEM, certification, or real-time monitor",
        "score": round(score, 1), "confidence": round(confidence, 1), "maturity": "Provisional" if provisional else f"L{level}",
        "domains": {k: round(v, 1) for k, v in domain.items()},
        "confidence_factors": {"completeness": round(completeness, 3), "freshness": round(fresh, 3), "traceability": round(traceability, 3)},
        "counts": {"sources": len(sources), "techniques": len(techniques), "validated_tests": sum(valid_tests), "cases": len(cases), "reviewed_cases": len(reviewed), "controls": len(controls), "on_time": on_time, "response_denominator": len(eligible)},
        "lifecycle": lifecycle,
        "findings": sorted(findings, key=lambda f: f["priority"]), "sha256": hashlib.sha256(payload).hexdigest(), "scope_sha256": scope_hash,
        "limitations": ["Declared scope and references require assessor review", "Synthetic demo is not operational effectiveness evidence", "Precision is a quality proxy, not recall", "Confidence is an evidence index, not a statistical probability", "Policy weights and maturity bands require pilot calibration"],
    }
    report["supervisory_summary"] = supervisor_summary(report)
    return report

def compare(before, after):
    if before["scope"] != after["scope"] or before["scope_sha256"] != after["scope_sha256"] or before["policy"]["id"] != after["policy"]["id"]:
        raise ValueError("Comparison requires identical scope and policy")
    delta = round(after["score"] - before["score"], 1)
    return {"score_delta": delta, "confidence_delta": round(after["confidence"] - before["confidence"], 1), "domain_delta": {k: round(after["domains"][k] - before["domains"][k], 1) for k in before["domains"]}, "drift_alert": delta <= -10 or after["confidence"] < POLICY["confidence_floor"]}
