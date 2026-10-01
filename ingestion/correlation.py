"""Deterministic, evidence-driven alert-to-incident correlation."""
from collections import defaultdict
import hashlib
import json


CORRELATION_VERSION = "soclens-correlation-1.0"


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _hash(value):
    return hashlib.sha256(_json(value).encode()).hexdigest()


def stable_alert_identity(alert):
    """Return an identity derived from stable source fields, never display text alone."""
    external = alert.get("external_record_id")
    if external:
        contract = {"source_id": alert["source_id"], "external_record_id": external}
        basis = "external_record_id"
    else:
        contract = {key: alert.get(key) for key in (
            "source_id", "alert_id", "detected_at", "evidence_ref"
        )}
        basis = "canonical_source_fields"
    return "alert-" + _hash(contract), basis


def _generated_id(prefix, value):
    return prefix + "-" + _hash(value)[:20].upper()


def _without_provenance(alert):
    return {key: value for key, value in alert.items() if key not in {"provenance", "identity", "identity_basis"}}


def _semantic_hash_document(value):
    """Exclude generated local import IDs while retaining stable file/record lineage."""
    if isinstance(value, dict):
        return {key: _semantic_hash_document(item) for key, item in value.items()
                if key not in {"import_id", "source_import_ids", "correlation_output_sha256"}}
    if isinstance(value, list):
        return [_semantic_hash_document(item) for item in value]
    return value


def _conflict(code, reason, alerts=(), **extra):
    document = {"code": code, "reason": reason,
                "alert_identities": sorted(alert["identity"] for alert in alerts),
                "source_import_ids": sorted({item.get("import_id") for alert in alerts
                                             for item in alert.get("provenance", []) if item.get("import_id")}),
                "evidence_refs": sorted({alert.get("evidence_ref") for alert in alerts if alert.get("evidence_ref")})}
    document.update(extra)
    return document


def correlate(alerts, case_patches=(), response_actions=()):
    """Correlate only explicit identifiers/relationships and emit compatibility lifecycles."""
    prepared = []
    for source in alerts:
        alert = dict(source)
        identity, basis = stable_alert_identity(alert)
        alert["identity"], alert["identity_basis"] = identity, basis
        if not alert.get("alert_id"):
            alert["alert_id"] = "ALERT-" + identity[-12:].upper()
        prepared.append(alert)

    conflicts, warnings = [], []
    excluded = set()
    by_identity = defaultdict(list)
    for alert in prepared:
        by_identity[alert["identity"]].append(alert)
    unique = []
    for identity, duplicates in sorted(by_identity.items()):
        if len(duplicates) == 1:
            unique.append(duplicates[0])
            continue
        semantics = {_json(_without_provenance(alert)) for alert in duplicates}
        if len(semantics) != 1:
            conflicts.append(_conflict(
                "CONTRADICTORY_ALERT_IDENTITY",
                "The same stable alert identity has contradictory source fields; all copies were excluded.",
                duplicates,
            ))
            excluded.add(identity)
            continue
        retained = dict(duplicates[0])
        provenance = {_json(item): item for alert in duplicates for item in alert.get("provenance", [])}
        retained["provenance"] = sorted(provenance.values(),
                                        key=lambda item: (item.get("import_id", ""), item.get("record_number", 0)))
        unique.append(retained)
        warnings.append(_conflict(
            "DUPLICATE_ALERT_IDENTITY",
            "Identical copies of one alert were de-duplicated before correlation.",
            duplicates,
        ))

    # An explicit case or external case must not point to different explicit incidents.
    for field in ("case_id", "external_case_id", "external_incident_id"):
        associations = defaultdict(list)
        for alert in unique:
            if alert.get(field):
                associations[alert[field]].append(alert)
        for value, related in associations.items():
            incident_ids = {alert.get("incident_id") for alert in related if alert.get("incident_id")}
            if len(incident_ids) > 1:
                conflicts.append(_conflict(
                    "CONFLICTING_INCIDENT_ASSOCIATION",
                    f"Shared {field} is associated with multiple explicit incident IDs.", related,
                    field=field, value=value, incident_ids=sorted(incident_ids),
                ))
                excluded.update(alert["identity"] for alert in related)

    display_index = defaultdict(list)
    for alert in unique:
        display_index[alert["alert_id"]].append(alert)

    memberships = {}
    rules = defaultdict(set)
    reasons = defaultdict(list)
    for alert in unique:
        if alert["identity"] in excluded:
            continue
        if alert.get("incident_id"):
            key = "incident:" + alert["incident_id"]
            rules[alert["identity"]].add("explicit_incident_id")
            reasons[alert["identity"]].append("Source record declared incident_id " + alert["incident_id"])
        elif alert.get("external_incident_id"):
            key = "external-incident:" + alert["external_incident_id"]
            rules[alert["identity"]].add("external_incident_id")
            reasons[alert["identity"]].append("Source records share stable external_incident_id " + alert["external_incident_id"])
        elif alert.get("case_id"):
            key = "case:" + alert["case_id"]
            rules[alert["identity"]].add("explicit_case_id")
            reasons[alert["identity"]].append("Source records share explicit case_id " + alert["case_id"])
        elif alert.get("external_case_id"):
            key = "external-case:" + alert["external_case_id"]
            rules[alert["identity"]].add("external_case_id")
            reasons[alert["identity"]].append("Source records share stable external_case_id " + alert["external_case_id"])
        else:
            key = None
        memberships[alert["identity"]] = key

    # A declared parent relationship may attach an otherwise unmatched child.
    for alert in unique:
        parent_id = alert.get("parent_alert_id")
        if not parent_id or alert["identity"] in excluded:
            continue
        parents = display_index.get(parent_id, [])
        if len(parents) != 1:
            conflicts.append(_conflict(
                "AMBIGUOUS_PARENT_ALERT",
                "The declared parent alert could not be resolved uniquely.", [alert], parent_alert_id=parent_id,
            ))
            excluded.add(alert["identity"])
            continue
        parent_key = memberships.get(parents[0]["identity"])
        child_key = memberships.get(alert["identity"])
        if parent_key is None:
            continue
        if child_key is not None and child_key != parent_key:
            conflicts.append(_conflict(
                "CONFLICTING_PARENT_RELATIONSHIP",
                "The parent relationship contradicts the alert's explicit incident/case association.", [alert, parents[0]],
            ))
            excluded.add(alert["identity"])
            continue
        memberships[alert["identity"]] = parent_key
        rules[alert["identity"]].add("explicit_parent_alert")
        reasons[alert["identity"]].append("Source record declared parent_alert_id " + parent_id)

    groups = defaultdict(list)
    unmatched = []
    for alert in unique:
        if alert["identity"] in excluded:
            continue
        key = memberships.get(alert["identity"])
        if key is None:
            unmatched.append(alert)
        else:
            groups[key].append(alert)

    patches_by_incident, patches_by_case = defaultdict(list), defaultdict(list)
    for patch in case_patches:
        if patch.get("incident_id"):
            patches_by_incident[patch["incident_id"]].append(patch)
        if patch.get("case_id"):
            patches_by_case[patch["case_id"]].append(patch)

    actions_by_incident, actions_by_case = defaultdict(list), defaultdict(list)
    for action in response_actions:
        if action.get("incident_id"):
            actions_by_incident[action["incident_id"]].append(action)
        if action.get("case_id"):
            actions_by_case[action["case_id"]].append(action)

    incidents, lifecycles, negative_findings = [], [], []
    for key, related in sorted(groups.items()):
        related = sorted(related, key=lambda alert: (alert["detected_at"], alert["identity"]))
        explicit_ids = sorted({alert["incident_id"] for alert in related if alert.get("incident_id")})
        if len(explicit_ids) > 1:
            conflicts.append(_conflict("CONFLICTING_INCIDENT_IDS", "Correlated alerts declare incompatible incident IDs.", related,
                                       incident_ids=explicit_ids))
            continue
        incident_id = explicit_ids[0] if explicit_ids else _generated_id("INC", key)
        case_ids = sorted({alert["case_id"] for alert in related if alert.get("case_id")})
        if len(case_ids) > 1:
            conflicts.append(_conflict("CONFLICTING_CASE_ASSOCIATION", "One correlated incident declares multiple primary case IDs.", related,
                                       case_ids=case_ids))
        primary_case = case_ids[0] if len(case_ids) == 1 else None
        source_ids = sorted({alert["source_id"] for alert in related})
        applied_rules = sorted({rule for alert in related for rule in rules[alert["identity"]]})
        applied_reasons = sorted({reason for alert in related for reason in reasons[alert["identity"]]})
        strength = "exact" if any(rule in applied_rules for rule in ("explicit_incident_id", "external_incident_id")) else "supported"
        patches = list(patches_by_incident.get(incident_id, []))
        if primary_case:
            patches.extend(patch for patch in patches_by_case.get(primary_case, []) if patch not in patches)
        semantic_patches = {_json({k: v for k, v in patch.items() if k != "provenance"}) for patch in patches}
        patch = patches[0] if len(semantic_patches) == 1 else None
        if len(semantic_patches) > 1:
            conflicts.append(_conflict("CONFLICTING_LIFECYCLE_STAGES", "Case/lifecycle exports disagree about stages for this incident.", related,
                                       incident_id=incident_id))
        actions = list(actions_by_incident.get(incident_id, []))
        if primary_case:
            actions.extend(action for action in actions_by_case.get(primary_case, []) if action not in actions)
        actions = sorted(actions, key=lambda item: (item["timestamp"], item["action_id"]))
        recovery = [action for action in actions if action.get("milestone") == "recovery"]
        response_candidates = [action for action in actions if action.get("canonical_response") is True]
        if len(response_candidates) > 1:
            conflicts.append(_conflict("MULTIPLE_CANONICAL_RESPONSES", "More than one response action is marked as the canonical response milestone.", related,
                                       incident_id=incident_id, action_ids=[action["action_id"] for action in response_candidates]))
        escalation_values = {alert["escalation_required"] for alert in related if alert.get("escalation_required") is not None}
        if len(escalation_values) > 1:
            conflicts.append(_conflict("CONFLICTING_ESCALATION_REQUIREMENT", "Correlated alerts disagree about whether escalation is required.", related,
                                       incident_id=incident_id))
        incident = {
            "incident_id": incident_id,
            "alert_ids": [alert["alert_id"] for alert in related],
            "alert_identities": [alert["identity"] for alert in related],
            "primary_case_id": primary_case,
            "related_case_ids": case_ids,
            "source_ids": source_ids,
            "first_detection_at": related[0]["detected_at"],
            "latest_detection_at": related[-1]["detected_at"],
            "correlation_version": CORRELATION_VERSION,
            "correlation_strength": "ambiguous" if len(case_ids) > 1 else strength,
            "rule_ids": applied_rules,
            "reasons": applied_reasons,
            "response_actions": actions,
            "recovery_events": recovery,
            "lifecycle_stages": ({stage: patch.get(stage) for stage in ("investigation", "escalation", "response", "closure")}
                                 if patch is not None else {}),
            "source_import_ids": sorted({p.get("import_id") for alert in related for p in alert.get("provenance", []) if p.get("import_id")}),
            "evidence_refs": sorted({alert.get("evidence_ref") for alert in related if alert.get("evidence_ref")}),
        }
        incidents.append(incident)
        if primary_case is None:
            negative_findings.append({
                "priority": "High", "title": f"Create or link a case for {incident_id}",
                "reason": f"{len(related)} correlated alert(s) have incident evidence but no unambiguous case association.",
                "owner": "SOC operations", "evidence_ref": incident["evidence_refs"][0] if incident["evidence_refs"] else "",
                "incident_id": incident_id, "alert_ids": incident["alert_ids"], "stage": "investigation",
                "finding_type": "missing_case",
            })
        elif patch is None:
            negative_findings.append({
                "priority": "High", "title": f"Link case evidence for {incident_id}",
                "reason": "The incident declares a case association, but no compatible case lifecycle evidence was supplied.",
                "owner": "SOC operations", "evidence_ref": incident["evidence_refs"][0] if incident["evidence_refs"] else "",
                "incident_id": incident_id, "case_id": primary_case, "alert_ids": incident["alert_ids"],
                "stage": "investigation", "finding_type": "missing_case_evidence",
            })
        if primary_case and patch is not None and len(case_ids) == 1 and len(escalation_values) <= 1 and len(response_candidates) <= 1:
            detection = {"timestamp": patch.get("detected_at", related[0]["detected_at"]),
                         "evidence_ref": related[0].get("evidence_ref", "")}
            if related[0].get("detection_status"):
                detection["status"] = related[0]["detection_status"]
            lifecycle = {
                "incident_id": incident_id, "alert_id": related[0]["alert_id"], "case_id": primary_case,
                "source_id": related[0]["source_id"],
                "escalation_required": next(iter(escalation_values), False), "detection": detection,
            }
            for stage in ("investigation", "escalation", "response", "closure"):
                if patch.get(stage) is not None:
                    lifecycle[stage] = patch[stage]
            if lifecycle.get("response") is None and len(response_candidates) == 1:
                action = response_candidates[0]
                lifecycle["response"] = {"timestamp": action["timestamp"], "evidence_ref": action.get("evidence_ref", ""),
                                         "status": action.get("status") or action["action_type"]}
            lifecycles.append(lifecycle)

    correlated_cases = {incident["primary_case_id"] for incident in incidents if incident["primary_case_id"]}
    for patch in case_patches:
        case_id = patch.get("case_id")
        if case_id and case_id not in correlated_cases:
            negative_findings.append({
                "priority": "Medium", "title": f"Link alert evidence to {case_id}",
                "reason": "Case evidence exists without a deterministically correlated alert.",
                "owner": "SOC operations", "evidence_ref": patch.get("evidence_ref", ""),
                "case_id": case_id, "finding_type": "missing_alert", "stage": "detection",
            })

    scope_contract = {
        "correlation_version": CORRELATION_VERSION,
        "incidents": [{key: incident[key] for key in ("incident_id", "alert_identities", "primary_case_id", "related_case_ids", "source_ids", "rule_ids")}
                      for incident in incidents],
        "unmatched_alert_identities": sorted(alert["identity"] for alert in unmatched),
    }
    public_alert = lambda alert: {key: alert.get(key) for key in (
        "identity", "identity_basis", "alert_id", "source_id", "detected_at", "external_record_id",
        "incident_id", "case_id", "external_incident_id", "external_case_id", "evidence_ref", "severity", "risk_weight", "provenance"
    ) if alert.get(key) is not None}
    output = {
        "version": CORRELATION_VERSION,
        "status": "ready_with_warnings" if conflicts or warnings or unmatched else "ready",
        "incidents": incidents,
        "unmatched_alerts": [public_alert(alert) for alert in unmatched],
        "conflicts": conflicts,
        "warnings": warnings,
        "excluded_alert_identities": sorted(excluded),
        "negative_space_findings": negative_findings,
        "correlation_scope_sha256": _hash(scope_contract),
    }
    output["correlation_output_sha256"] = _hash(_semantic_hash_document(output))
    return output, lifecycles


def enrich_report(report, correlation):
    """Attach advanced context without changing engine-calculated score/hash fields."""
    report["correlation"] = correlation
    by_incident = {incident["incident_id"]: incident for incident in correlation["incidents"]}
    for assessed in report.get("lifecycle", {}).get("incidents", []):
        context = by_incident.get(assessed.get("incident_id"))
        if context:
            assessed.update(context)
    for finding in report.get("findings", []):
        context = by_incident.get(finding.get("incident_id"))
        if context:
            finding["alert_ids"] = context["alert_ids"]
            finding["source_ids"] = context["source_ids"]
            finding["correlation_version"] = context["correlation_version"]
    report["findings"].extend(correlation["negative_space_findings"])
    report["findings"].sort(key=lambda finding: (str(finding.get("priority", "")), str(finding.get("title", ""))))
    return report
