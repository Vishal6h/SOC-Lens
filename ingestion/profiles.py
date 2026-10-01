"""Explicit versioned mappings for supported offline export shapes."""
from dataclasses import dataclass


@dataclass(frozen=True)
class MappingProfile:
    identifier: str
    version: int
    label: str
    category: str
    formats: tuple[str, ...]
    required_fields: tuple[str, ...]
    optional_fields: tuple[str, ...]
    mapping: tuple[tuple[str, str], ...]
    description: str

    @property
    def key(self):
        return f"{self.identifier}@{self.version}"

    def public_document(self):
        return {
            "id": self.identifier, "version": self.version, "key": self.key,
            "label": self.label, "category": self.category,
            "formats": list(self.formats), "required_fields": list(self.required_fields),
            "optional_fields": list(self.optional_fields),
            "field_mapping": dict(self.mapping), "description": self.description,
        }


PROFILES = (
    MappingProfile(
        "canonical-soclens-json", 1, "SOCLens JSON", "canonical", ("json",), (), (), (),
        "Existing canonical SOCLens evidence JSON; no source-field mapping is applied.",
    ),
    MappingProfile(
        "generic-telemetry", 1, "Generic Telemetry / Source Health Export", "sources", ("csv", "json"),
        ("source_id", "source_type", "weight", "completeness", "last_seen", "evidence_ref"), (),
        (("source_id", "sources[].id"), ("source_type", "sources[].kind"),
         ("weight", "sources[].weight"), ("completeness", "sources[].completeness"),
         ("last_seen", "sources[].last_seen"), ("evidence_ref", "sources[].evidence_ref")),
        "One row per declared telemetry source and its observed health.",
    ),
    MappingProfile(
        "generic-techniques", 1, "Generic Detection Validation Export", "techniques", ("csv", "json"),
        ("technique_id", "source_id", "risk_weight", "status", "tested_at", "evidence_ref"), (),
        (("technique_id", "techniques[].id"), ("source_id", "techniques[].source_id"),
         ("risk_weight", "techniques[].risk_weight"), ("status", "techniques[].status"),
         ("tested_at", "techniques[].tested_at"), ("evidence_ref", "techniques[].evidence_ref")),
        "One row per explicit detection validation result; alert occurrence is not treated as validation.",
    ),
    MappingProfile(
        "generic-siem-alerts", 1, "Generic SIEM Alert Export", "lifecycle_detection", ("csv", "json"),
        ("incident_id", "alert_id", "case_id", "source_id", "detected_at", "evidence_ref", "escalation_required"),
        ("detection_status",),
        (("incident_id", "lifecycles[].incident_id"), ("alert_id", "lifecycles[].alert_id"),
         ("case_id", "lifecycles[].case_id"), ("source_id", "lifecycles[].source_id"),
         ("escalation_required", "lifecycles[].escalation_required"),
         ("detected_at", "lifecycles[].detection.timestamp"),
         ("evidence_ref", "lifecycles[].detection.evidence_ref"),
         ("detection_status", "lifecycles[].detection.status")),
        "One exported alert per incident correlation. This profile does not perform multi-alert correlation.",
    ),
    MappingProfile(
        "generic-cases", 1, "Generic Case Management Export", "cases", ("csv", "json"),
        ("case_id", "incident_id", "detected_at", "sla_minutes", "disposition", "evidence_ref"),
        ("contained_at", "investigation_at", "investigation_evidence_ref", "investigation_status",
         "escalation_at", "escalation_evidence_ref", "escalation_status", "response_at",
         "response_evidence_ref", "response_status", "closure_at", "closure_evidence_ref", "closure_status"),
        (("case_id", "cases[].id"), ("detected_at", "cases[].detected_at"),
         ("contained_at", "cases[].contained_at"), ("sla_minutes", "cases[].sla_minutes"),
         ("disposition", "cases[].disposition"), ("evidence_ref", "cases[].evidence_ref"),
         ("incident_id", "lifecycle stages matched by incident_id"),
         ("investigation_at", "lifecycles[].investigation.timestamp"),
         ("investigation_evidence_ref", "lifecycles[].investigation.evidence_ref"),
         ("investigation_status", "lifecycles[].investigation.status"),
         ("escalation_at", "lifecycles[].escalation.timestamp"),
         ("escalation_evidence_ref", "lifecycles[].escalation.evidence_ref"),
         ("escalation_status", "lifecycles[].escalation.status"),
         ("response_at", "lifecycles[].response.timestamp"),
         ("response_evidence_ref", "lifecycles[].response.evidence_ref"),
         ("response_status", "lifecycles[].response.status"),
         ("closure_at", "lifecycles[].closure.timestamp"),
         ("closure_evidence_ref", "lifecycles[].closure.evidence_ref"),
         ("closure_status", "lifecycles[].closure.status")),
        "Case outcomes and optional investigation, escalation, response, and closure stages.",
    ),
    MappingProfile(
        "generic-controls", 1, "Generic Control Evidence Export", "controls", ("csv", "json"),
        ("control_id", "satisfied", "critical", "evidence_ref"), (),
        (("control_id", "controls[].id"), ("satisfied", "controls[].satisfied"),
         ("critical", "controls[].critical"), ("evidence_ref", "controls[].evidence_ref")),
        "One row per declared governance control result.",
    ),
)
REGISTRY = {profile.key: profile for profile in PROFILES}


def get_profile(key):
    try:
        return REGISTRY[key]
    except KeyError as exc:
        raise ValueError("Unknown or unsupported mapping profile") from exc


def profile_documents():
    return [profile.public_document() for profile in PROFILES]
