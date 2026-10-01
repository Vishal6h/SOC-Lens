"""Explicit source-value normalization into canonical evidence fragments."""
from datetime import datetime, timezone
import math

from engine import KINDS


class MappingError(ValueError):
    def __init__(self, field, code, reason):
        super().__init__(reason)
        self.field, self.code, self.reason = field, code, reason


def _text(record, field, maximum, *, required=True):
    value = record.get(field)
    if value is None:
        value = ""
    if not isinstance(value, str):
        value = str(value)
    value = value.strip()
    if required and not value:
        raise MappingError(field, "MISSING_VALUE", "A non-empty value is required.")
    if len(value.encode("utf-8")) > maximum:
        raise MappingError(field, "FIELD_TOO_LARGE", f"Value exceeds the {maximum}-byte field limit.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise MappingError(field, "CONTROL_CHARACTER", "Control characters are not permitted.")
    return value


def _identifier(record, field, maximum=200):
    return _text(record, field, maximum)


def _optional_identifier(record, field, maximum=200):
    return _text(record, field, maximum, required=False) or None


def _timestamp(record, field, *, required=True):
    value = _text(record, field, 64, required=required)
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MappingError(field, "INVALID_TIMESTAMP", "Expected a timezone-aware ISO timestamp.") from exc
    if parsed.tzinfo is None:
        raise MappingError(field, "INVALID_TIMESTAMP", "Expected a timezone-aware ISO timestamp.")
    return parsed.astimezone(timezone.utc).isoformat()


def _number(record, field, minimum, maximum):
    raw = record.get(field)
    if isinstance(raw, bool):
        raise MappingError(field, "INVALID_NUMBER", f"Expected a number from {minimum} to {maximum}.")
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise MappingError(field, "INVALID_NUMBER", f"Expected a number from {minimum} to {maximum}.") from exc
    if not math.isfinite(value) or not minimum <= value <= maximum:
        raise MappingError(field, "INVALID_NUMBER", f"Expected a number from {minimum} to {maximum}.")
    return int(value) if value.is_integer() else value


TRUE_VALUES = {"true", "yes", "1"}
FALSE_VALUES = {"false", "no", "0"}


def _boolean(record, field):
    value = record.get(field)
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().casefold()
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False
    raise MappingError(field, "INVALID_BOOLEAN", "Expected true/false, yes/no, or 1/0.")


def _reference(record, field="evidence_ref"):
    return _text(record, field, 500, required=False)


def _stage(record, name, field_limit):
    timestamp_field = f"{name}_at"
    reference_field = f"{name}_evidence_ref"
    status_field = f"{name}_status"
    values = (record.get(timestamp_field), record.get(reference_field), record.get(status_field))
    if all(value is None or str(value).strip() == "" for value in values):
        return None
    result = {
        "timestamp": _timestamp(record, timestamp_field),
        "evidence_ref": _text(record, reference_field, min(500, field_limit), required=False),
    }
    status = _text(record, status_field, 100, required=False)
    if status:
        result["status"] = status
    return result


def normalize_record(profile, record, field_limit):
    """Return one canonical fragment item for an explicitly selected profile."""
    category = profile.category
    if category == "sources":
        kind = _text(record, "source_type", 20).upper()
        if kind not in KINDS:
            raise MappingError("source_type", "UNKNOWN_SOURCE_TYPE", "Expected SIEM, EDR, SOAR, UEBA, or CTI.")
        return {"id": _identifier(record, "source_id"), "kind": kind,
                "weight": _number(record, "weight", 1, 5),
                "completeness": _number(record, "completeness", 0, 1),
                "last_seen": _timestamp(record, "last_seen"), "evidence_ref": _reference(record)}
    if category == "techniques":
        status = _text(record, "status", 20).casefold()
        if status not in {"passed", "failed", "untested"}:
            raise MappingError("status", "UNKNOWN_TECHNIQUE_STATUS", "Expected passed, failed, or untested.")
        return {"id": _identifier(record, "technique_id"), "source_id": _identifier(record, "source_id"),
                "risk_weight": _number(record, "risk_weight", 1, 5), "status": status,
                "tested_at": _timestamp(record, "tested_at"), "evidence_ref": _reference(record)}
    if category == "lifecycle_detection":
        stage = {"timestamp": _timestamp(record, "detected_at"), "evidence_ref": _reference(record)}
        status = _text(record, "detection_status", 100, required=False)
        if status:
            stage["status"] = status
        return {"incident_id": _identifier(record, "incident_id"), "alert_id": _identifier(record, "alert_id"),
                "case_id": _identifier(record, "case_id"), "source_id": _identifier(record, "source_id"),
                "escalation_required": _boolean(record, "escalation_required"), "detection": stage}
    if category == "alerts":
        alert_id = _optional_identifier(record, "alert_id")
        external_record_id = _optional_identifier(record, "external_record_id")
        if not alert_id and not external_record_id:
            raise MappingError("alert_id", "MISSING_ALERT_IDENTITY", "Provide alert_id or external_record_id.")
        item = {
            "alert_id": alert_id, "external_record_id": external_record_id,
            "source_id": _identifier(record, "source_id"), "detected_at": _timestamp(record, "detected_at"),
            "evidence_ref": _reference(record), "escalation_required": _boolean(record, "escalation_required"),
        }
        for field in ("incident_id", "external_incident_id", "case_id", "external_case_id", "parent_alert_id"):
            value = _optional_identifier(record, field)
            if value:
                item[field] = value
        status = _text(record, "detection_status", 100, required=False)
        severity = _text(record, "severity", 30, required=False)
        if status:
            item["detection_status"] = status
        if severity:
            item["severity"] = severity.casefold()
        if record.get("risk_weight") not in (None, ""):
            item["risk_weight"] = _number(record, "risk_weight", 1, 5)
        return item
    if category == "cases":
        disposition = _text(record, "disposition", 30).casefold()
        if disposition not in {"true_positive", "false_positive", "unreviewed"}:
            raise MappingError("disposition", "UNKNOWN_DISPOSITION", "Expected true_positive, false_positive, or unreviewed.")
        contained = _timestamp(record, "contained_at", required=False)
        case = {"id": _identifier(record, "case_id"), "detected_at": _timestamp(record, "detected_at"),
                "contained_at": contained, "sla_minutes": _number(record, "sla_minutes", 1, 10080),
                "disposition": disposition, "evidence_ref": _reference(record)}
        patch = {"incident_id": _identifier(record, "incident_id"), "case_id": case["id"],
                 "detected_at": case["detected_at"], "evidence_ref": case["evidence_ref"]}
        for name in ("investigation", "escalation", "response", "closure"):
            stage = _stage(record, name, field_limit)
            if stage is not None:
                patch[name] = stage
        return {"case": case, "lifecycle_patch": patch}
    if category == "controls":
        return {"id": _identifier(record, "control_id"), "satisfied": _boolean(record, "satisfied"),
                "critical": _boolean(record, "critical"), "evidence_ref": _reference(record)}
    if category == "response_actions":
        incident_id = _optional_identifier(record, "incident_id")
        case_id = _optional_identifier(record, "case_id")
        if not incident_id and not case_id:
            raise MappingError("incident_id", "MISSING_ACTION_ASSOCIATION", "Provide incident_id or case_id for the response action.")
        milestone = _text(record, "milestone", 30, required=False).casefold()
        if milestone and milestone not in {"response", "recovery", "informational"}:
            raise MappingError("milestone", "UNKNOWN_ACTION_MILESTONE", "Expected response, recovery, or informational.")
        item = {"action_id": _identifier(record, "action_id"), "action_type": _text(record, "action_type", 100),
                "timestamp": _timestamp(record, "action_at"), "evidence_ref": _reference(record),
                "canonical_response": _boolean(record, "canonical_response")}
        for field, value in (("incident_id", incident_id), ("case_id", case_id),
                             ("source_id", _optional_identifier(record, "source_id")),
                             ("status", _text(record, "status", 100, required=False)), ("milestone", milestone)):
            if value:
                item[field] = value
        return item
    raise MappingError(None, "UNSUPPORTED_PROFILE", "The selected profile cannot map source records.")
