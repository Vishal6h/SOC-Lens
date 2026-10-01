"""Assemble independently mapped fragments into one canonical evidence object."""
import hashlib
import json

from engine import validate


CATEGORIES = ("sources", "techniques", "cases", "controls", "lifecycles")
REQUIRED_CATEGORIES = CATEGORIES[:4]


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _coverage(document, lifecycle_partial=False):
    coverage = {}
    for category in CATEGORIES:
        count = len(document.get(category, []))
        state = "ready" if count else "missing"
        if category == "lifecycles" and lifecycle_partial:
            state = "partial"
        coverage[category] = {"state": state, "records": count}
    return coverage


def assemble_imports(jobs, *, scope=None, as_of=None, synthetic=None):
    if not jobs:
        raise ValueError("At least one import_id is required")
    if len({job.import_id for job in jobs}) != len(jobs):
        raise ValueError("import_ids must be unique")
    jobs = sorted(jobs, key=lambda job: (job.mapping_profile_id, job.file_sha256, job.import_id))
    if any(job.status != "ready" for job in jobs):
        raise ValueError("Every import must be ready before assessment assembly")
    canonical = [job for job in jobs if "canonical" in job.fragment]
    if canonical:
        if len(jobs) != 1:
            raise ValueError("Canonical SOCLens JSON cannot be combined with mapped source imports")
        evidence = canonical[0].fragment["canonical"]
        validate(evidence)
        return {"ready": True, "evidence": evidence, "canonical_output_sha256": _hash(evidence),
                "coverage": _coverage(evidence), "missing_categories": []}
    if not isinstance(scope, str) or not scope.strip() or scope != scope.strip() or len(scope) > 100:
        raise ValueError("scope must be a nonempty trimmed string of at most 100 characters")
    if not isinstance(synthetic, bool):
        raise ValueError("synthetic must be a boolean")
    document = {"scope": scope, "as_of": as_of, "synthetic": synthetic,
                "sources": [], "techniques": [], "cases": [], "controls": []}
    detections, patches = [], []
    for job in jobs:
        fragment = job.fragment
        for category in REQUIRED_CATEGORIES:
            document[category].extend(fragment.get(category, []))
        detections.extend(fragment.get("lifecycle_detections", []))
        patches.extend(fragment.get("lifecycle_patches", []))
    patch_by_incident = {}
    duplicate_patches = set()
    for patch in patches:
        incident_id = patch["incident_id"]
        if incident_id in patch_by_incident:
            duplicate_patches.add(incident_id)
        patch_by_incident[incident_id] = patch
    if duplicate_patches:
        raise ValueError("Duplicate lifecycle case mapping for incident_id: " + ", ".join(sorted(duplicate_patches)))
    lifecycles, unmatched = [], []
    for detection in detections:
        patch = patch_by_incident.pop(detection["incident_id"], None)
        if patch is None:
            unmatched.append(detection["incident_id"])
            continue
        lifecycle = dict(detection)
        lifecycle.update({key: value for key, value in patch.items() if key != "incident_id"})
        lifecycles.append(lifecycle)
    unmatched.extend(patch_by_incident)
    if detections or patches:
        document["lifecycles"] = lifecycles
    missing = [category for category in REQUIRED_CATEGORIES if not document[category]]
    lifecycle_partial = bool(unmatched)
    coverage = _coverage(document, lifecycle_partial)
    if missing or lifecycle_partial:
        return {"ready": False, "coverage": coverage, "missing_categories": missing,
                "errors": ([{"code": "INCOMPLETE_LIFECYCLE", "reason": "Lifecycle fragments are not fully correlated.",
                             "incident_ids": sorted(set(unmatched))}] if lifecycle_partial else [])}
    validate(document)
    return {"ready": True, "evidence": document, "canonical_output_sha256": _hash(document),
            "coverage": coverage, "missing_categories": []}
