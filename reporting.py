"""Deterministic report summaries, manifests, and local audit packages."""
from io import BytesIO
from zipfile import ZIP_STORED, ZipFile, ZipInfo
import hashlib
import json

REPORT_SCHEMA_VERSION = "sat-sa-report-1.0"
MANIFEST_SCHEMA_VERSION = "sat-sa-manifest-1.0"
AUDIT_PACKAGE_VERSION = "sat-sa-audit-1.0"
DOMAINS = ("Detection", "Response", "Telemetry", "Quality", "Governance")
PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def supervisor_summary(report, drift=None):
    """Derive a concise factual summary solely from calculated report fields."""
    domains = report.get("domains", {})
    ranked = [(name, domains.get(name)) for name in DOMAINS if isinstance(domains.get(name), (int, float))]
    strongest = max(ranked, key=lambda item: item[1]) if ranked else (None, None)
    weakest = min(ranked, key=lambda item: item[1]) if ranked else (None, None)
    findings = report.get("findings", []) if isinstance(report.get("findings"), list) else []
    high_count = sum(
        str(finding.get("priority", "")).casefold() in {"high", "critical"}
        for finding in findings if isinstance(finding, dict)
    )
    evidence_backed = [
        finding for finding in findings
        if isinstance(finding, dict) and bool(finding.get("evidence_ref"))
    ]
    evidence_backed.sort(key=lambda finding: (
        PRIORITY_ORDER.get(str(finding.get("priority", "")).casefold(), 99),
        str(finding.get("title", "")), str(finding.get("incident_id", "")),
    ))
    top_issues = []
    for finding in evidence_backed[:3]:
        issue = {
            "priority": finding.get("priority"),
            "title": finding.get("title"),
            "owner": finding.get("owner"),
            "evidence_ref": finding.get("evidence_ref"),
        }
        for key in ("incident_id", "stage", "finding_type"):
            if finding.get(key) is not None:
                issue[key] = finding[key]
        top_issues.append(issue)
    lifecycle = report.get("lifecycle", {}) if isinstance(report.get("lifecycle"), dict) else {}
    incident_count = lifecycle.get("incident_count", 0) if lifecycle.get("enabled") else 0
    complete = lifecycle.get("complete_incidents", 0) if lifecycle.get("enabled") else 0
    completeness = round(100 * complete / incident_count, 1) if incident_count else None
    if drift is None:
        drift_summary = {"status": "not_evaluated", "detected": None, "reasons": []}
    else:
        detected = drift.get("detected") is True
        drift_summary = {
            "status": "detected" if detected else "clear",
            "detected": detected,
            "reasons": list(drift.get("reasons", [])),
        }
    return {
        "score": report.get("score"),
        "maturity": report.get("maturity"),
        "confidence": report.get("confidence"),
        "strongest_domain": {"name": strongest[0], "score": strongest[1]},
        "weakest_domain": {"name": weakest[0], "score": weakest[1]},
        "high_critical_findings": high_count,
        "lifecycle": {
            "enabled": lifecycle.get("enabled") is True,
            "incident_count": incident_count,
            "complete_incidents": complete,
            "completeness_percent": completeness,
        },
        "drift": drift_summary,
        "top_evidence_backed_issues": top_issues,
    }


def assessment_manifest(assessment, report, database_schema_version):
    """Build the stable manifest for one persisted assessment."""
    return {
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "audit_package_version": AUDIT_PACKAGE_VERSION,
        "report_schema_version": report.get("report_schema_version", "legacy-unversioned"),
        "database_schema_version": database_schema_version,
        "assessment_id": assessment["assessment_id"],
        "scope": assessment["scope"],
        "assessed_at": assessment["assessed_at"],
        "evidence_as_of": assessment["evidence_as_of"],
        "policy_version": assessment["policy_version"],
        "input_sha256": assessment["input_sha256"],
        "scope_sha256": assessment["scope_sha256"],
        "score": assessment["score"],
        "confidence": assessment["confidence"],
        "maturity": assessment["maturity"],
        "lifecycle_enabled": assessment["lifecycle_enabled"],
        "synthetic": report.get("synthetic") is True,
        "data_classification": report.get("data_classification") or (
            "SYNTHETIC DEMO DATA" if report.get("synthetic") is True else "legacy-unclassified"
        ),
        "prototype_notice": "SOCLens supervisory analytics prototype; not certification or real-time monitoring",
    }


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _lifecycle_summary(report):
    lifecycle = report.get("lifecycle", {})
    incidents = []
    for incident in lifecycle.get("incidents", []):
        incidents.append({
            "incident_id": incident.get("incident_id"),
            "alert_id": incident.get("alert_id"),
            "case_id": incident.get("case_id"),
            "source_id": incident.get("source_id"),
            "complete": incident.get("complete"),
            "escalation_required": incident.get("escalation_required"),
            "timing_minutes": incident.get("timing_minutes"),
        })
    return {
        "enabled": lifecycle.get("enabled") is True,
        "incident_count": lifecycle.get("incident_count", 0),
        "complete_incidents": lifecycle.get("complete_incidents", 0),
        "timing_metrics": lifecycle.get("timing_metrics", {}),
        "scoring": lifecycle.get("scoring", {}),
        "incidents": incidents,
    }


def audit_package(assessment, report, database_schema_version, drift=None):
    """Return a byte-reproducible ZIP without raw submitted evidence."""
    artifacts = {
        "report.json": _json_bytes(report),
        "findings.json": _json_bytes(report.get("findings", [])),
        "lifecycle-summary.json": _json_bytes(_lifecycle_summary(report)),
        "supervisory-summary.json": _json_bytes(supervisor_summary(report, drift)),
    }
    manifest = assessment_manifest(assessment, report, database_schema_version)
    manifest["artifacts"] = {
        name: {"sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}
        for name, content in artifacts.items()
    }
    files = {"manifest.json": _json_bytes(manifest), **artifacts}
    output = BytesIO()
    with ZipFile(output, "w", compression=ZIP_STORED) as archive:
        for name, content in files.items():
            info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o644 << 16
            archive.writestr(info, content)
    return output.getvalue()
