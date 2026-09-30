# SAT-SA local demonstrator

A reproducible medium-scope project supporting the SIH 2026 SAT-SA presentation. All supplied records are synthetic. No claims of deployment, certification, detection accuracy or operational savings follow from this demo.

## Run

Python 3.10 or newer. No external Python packages or API keys are required.

```text
python server.py
```

Open http://127.0.0.1:8765. Compare Baseline with Degraded execution, import a JSON file following `data/baseline.json`, and export the resulting evidence report. Assessments persist locally in `assessments.sqlite3`. Keep that database private. The demo binds only to localhost.

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

Lifecycle-enabled reports expose normalized incidents, missing-stage and delayed-stage findings, per-incident timing and stage evaluations, aggregate timing metrics, component scores, and domain-impact calculations. Inputs without `lifecycles` retain the legacy assessment behavior.

## Lifecycle scoring policy

The versioned `sat-sa-demo-2.0` policy uses these prototype targets:

| Requirement | Measured interval | Target |
| --- | --- | ---: |
| Investigation | Detection to investigation | 15 minutes |
| Required escalation | Investigation to escalation | 15 minutes |
| Response / containment | Detection to response | 60 minutes |
| Closure / recovery | Response to closure | 240 minutes |

Each applicable requirement receives 1 credit when present and within target, 0.5 when present but delayed, and 0 when missing. A later stage that is present but cannot be timed because its prerequisite is missing receives 0.5 credit. Escalation is excluded when `escalation_required` is false. Threshold equality is timely.

For lifecycle-enabled inputs containing incidents, Response pools the existing legacy containment-SLA credits with investigation, applicable escalation, and lifecycle response credits. Quality pools the existing reviewed-case true-positive credits with closure-discipline credits. Each evidence obligation has equal weight inside its domain; the five overall domain weights do not change. The report exposes every requirement count, credit, sub-score, and resulting domain effect.

Confidence remains an evidence-quality measure rather than a performance score. Missing or delayed stages do not directly lower confidence. Present lifecycle stages join the traceability calculation, so a present stage without an evidence reference can lower confidence. Lifecycle performance introduces no new maturity gate; score changes flow through the existing maturity bands and gates.

## Dashboard evidence drill-down

The dashboard presents the report as a score-to-evidence path: overall score, affected Response or Quality domain, lifecycle component, correlated incident, evaluated stage, and related finding or evidence reference. It displays values already calculated by the assessment engine and does not reproduce scoring policy in JavaScript.

All findings are shown. Optional trace fields—including owner, incident, alert, case, lifecycle stage, finding type, observed delay, policy threshold, and evidence reference—appear only when the report supplies them. Evidence references are displayed exactly as identifiers for copying and human verification. In particular, `demo://` references are not hyperlinks, and the application does not retrieve or fabricate evidence content.

For lifecycle-enabled assessments, the dashboard includes:

- final, legacy, lifecycle, and lifecycle-effect values for the Response and Quality domains;
- investigation, escalation, response, and closure requirement counts and scores;
- operational-response and closure-discipline sub-scores;
- complete and incomplete incident counts plus aggregate lifecycle timing averages;
- expandable incident records containing correlation IDs, stage timestamps and status, timing results, policy targets, earned credit, and evidence references; and
- the active policy version and its prototype supervisory lifecycle thresholds.

Timely, delayed, missing, unmeasured, and not-required outcomes are visibly distinguished. For legacy reports without lifecycle evidence, lifecycle drill-down is replaced with an explicit unavailable message; existing score cards, domain values, confidence factors, findings, provenance, import, and export remain available.

## Scoring contract

Each domain is 0–100. Overall score = .30 Detection + .25 Response + .20 Telemetry + .15 Quality + .10 Governance.

Detection = risk weight of passed tests with linked evidence and age at most 30 days / all in-scope technique risk weight. In-scope untested or stale tests receive no credit. Weights 1–5 represent the supervisor's declared threat relevance and asset impact; they are not inferred automatically.

Legacy Response = linked, contained cases within their SLA / all cases except reviewed false positives. Open and unreviewed cases remain in the denominator. For lifecycle-enabled inputs, the final Response domain pools those legacy credits with lifecycle investigation, required-escalation and response credits as described above.

Telemetry = weighted average of completeness times freshness. Freshness is 1 through 24 hours, then decays linearly to 0 at 96 hours. These are demo policy choices, not general recommendations for all CTI or telemetry cadences.

Legacy Quality = true positives / reviewed cases. This is precision only and does not estimate false negatives or recall. For lifecycle-enabled inputs, the final Quality domain pools those credits with closure-discipline credits. A low-sample gate still prevents fewer than 10 reviewed cases from receiving a maturity rating.

Governance = evidenced satisfied controls / applicable controls. Evidence references require human verification.

Confidence = 100 × completeness × freshness × traceability. Completeness is the mean of source completeness, case review fraction and technique test fraction. Freshness is the unweighted mean source freshness. Traceability is the fraction of legacy evidence rows and present lifecycle stages with a reference. This is an evidence-quality index, not a confidence interval or calibrated probability.

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
