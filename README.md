# SAT-SA local demonstrator

A reproducible medium-scope project supporting the SIH 2026 SAT-SA presentation. All supplied records are synthetic. No claims of deployment, certification, detection accuracy or operational savings follow from this demo.

## Run

Python 3.10 or newer. No external Python packages or API keys are required.

```text
python server.py
```

Open http://127.0.0.1:8765. Compare Baseline with Telemetry outage, import a JSON file following `data/baseline.json`, and export the resulting evidence report. Assessments persist locally in `assessments.sqlite3`. Keep that database private. The demo binds only to localhost.

```text
python -m unittest -v
python make_demo.py
```

## Implemented

- Bounded JSON import with range, timestamp, identifier and reference validation.
- Five source categories: SIEM, EDR, SOAR, UEBA, CTI. These are declared JSON adapters, not live vendor integrations.
- Optional canonical incident lifecycles linking a source, alert, case and incident through detection, investigation, escalation, response and closure.
- Deterministic domain scores, missing-evidence penalties, maturity gates, and scope-locked scenario comparison.
- Prioritized findings, evidence references, canonical input SHA-256, versioned scoring policy and SQLite assessment history.
- Interactive browser console and JSON report export. The digest identifies input content; it does not attest source authenticity or make the database immutable.

## Optional lifecycle evidence

Inputs may include a `lifecycles` array. Each row requires unique `incident_id`, `alert_id` and `case_id` correlations, a valid `source_id`, and a detection stage. Investigation, escalation, response and closure stages are optional objects with a timezone-aware `timestamp`, optional `evidence_ref`, and optional status. `escalation_required` defaults to false.

Lifecycle detection must identify the same instant as the linked case `detected_at`. When both a lifecycle response and case `contained_at` exist, response cannot follow containment; a response whose status is `contained` must identify exactly the same instant as `contained_at`. This permits an earlier initial-response event without allowing contradictory containment evidence.

Lifecycle-enabled reports expose normalized incidents, missing-stage findings and per-incident plus aggregate timing metrics. Lifecycle data does not yet change the existing domain scores or maturity policy. Inputs without `lifecycles` retain the legacy assessment behavior.

## Scoring contract

Each domain is 0–100. Overall score = .30 Detection + .25 Response + .20 Telemetry + .15 Quality + .10 Governance.

Detection = risk weight of passed tests with linked evidence and age at most 30 days / all in-scope technique risk weight. In-scope untested or stale tests receive no credit. Weights 1–5 represent the supervisor's declared threat relevance and asset impact; they are not inferred automatically.

Response = linked, contained cases within their SLA / all cases except reviewed false positives. Open and unreviewed cases remain in the denominator. SLA targets are part of the input.

Telemetry = weighted average of completeness times freshness. Freshness is 1 through 24 hours, then decays linearly to 0 at 96 hours. These are demo policy choices, not general recommendations for all CTI or telemetry cadences.

Quality = true positives / reviewed cases. This is precision only. It does not estimate false negatives or recall. A low-sample gate prevents fewer than 10 reviewed cases from receiving a maturity rating.

Governance = evidenced satisfied controls / applicable controls. Evidence references require human verification.

Confidence = 100 × completeness × freshness × traceability. Completeness is the mean of source completeness, case review fraction and technique test fraction. Freshness is the unweighted mean source freshness. Traceability is the fraction of all evidence rows with a reference. This is an evidence-quality index, not a confidence interval or calibrated probability.

Bands: L1 <40, L2 40–<60, L3 60–<80, L4 >=80. Confidence below 70, fewer than 10 reviewed cases, or an empty evidence domain makes the rating Provisional. Missing critical governance controls cap the rating at L2. L4 additionally requires Detection >=75 and no unvalidated technique with risk weight >=4. These are proposed SAT-SA gates, not NIST CSF implementation tiers.

Drift alert: overall score drops by at least 10 points or confidence is below 70. This is a deterministic threshold, not machine learning. Scenario comparison requires matching scope, policy, sources, technique weights, critical controls and, when supplied, lifecycle correlations.

## Pilot and production work still required

Live authenticated connectors; OCSF mappings; STIX/TAXII ingestion; deduplication and pagination; configurable source-specific freshness budgets; peer-group calibration; case-mix adjustment; temporal persistence of scope; RBAC/SSO; encryption and protected evidence retention; external tamper-evident storage; adversary emulation; sensitivity analysis; independent assessor agreement and measured operating costs. Do not expose this demo server to a network.

## References

- NIST SP 800-61 Rev. 3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- MITRE ATT&CK assessment and engineering: https://attack.mitre.org/resources/get-started/assessment-and-engineering/
- MITRE ATT&CK data: https://attack.mitre.org/resources/working-with-attack/
- Open Cybersecurity Schema Framework: https://schema.ocsf.io/
- CISA logging guidance: https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems

No traffic leaves the local browser/server in the provided demo. The UI loads no third-party resources.
