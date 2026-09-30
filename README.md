# SAT-SA supervisory analytics demonstrator

SAT-SA (Supervisory Analytics Tool for SOC Assessment) is a local, deterministic prototype for assessing how effectively a Security Operations Center executes detection, investigation, escalation, response, closure, telemetry, governance, and evidence discipline. It converts declared operational evidence into explainable supervisory scores, findings, lifecycle evaluations, and historical comparisons.

SAT-SA is **not** a SIEM, SOC, real-time monitor, certification engine, evidence repository, peer benchmark, or production security platform. It does not collect events, operate controls, retrieve referenced evidence, predict performance, or use AI/ML. Scores and references require assessor review.

All bundled datasets and history records are synthetic. They are labelled `SYNTHETIC DEMO DATA` in reports, manifests, audit packages, and the dashboard.

## Run locally

Requirements: Python 3.10 or newer. No packages, API keys, network services, build tools, or internet connection are required.

```text
python3 server.py
```

Open `http://127.0.0.1:8765`. The server binds only to localhost. Do not expose this demonstrator to a network.

To run all tests and validate the frontend source:

```text
python3 -B -m unittest discover -s . -v
node --check app.js
git diff --check
```

To regenerate canonical synthetic fixtures:

```text
python3 -B make_demo.py
```

## Architecture

- `engine.py` validates and normalizes evidence, correlates lifecycles, calculates scores/confidence/maturity, and emits findings.
- `assessment_history.py` owns SQLite schema version 2, migration, history, compatibility, trend, and drift logic.
- `reporting.py` creates deterministic supervisory summaries, manifests, and audit ZIP packages.
- `server.py` provides the localhost static server and bounded JSON/history/audit APIs.
- `index.html`, `app.js`, and `style.css` provide a dependency-free dashboard.
- `make_demo.py` recreates deterministic synthetic evidence and history fixtures under `data/`.

The evidence flow is:

```text
SOC evidence JSON
→ strict validation
→ legacy/lifecycle normalization
→ incident correlation
→ detection / investigation / escalation / response / closure evaluation
→ negative-space findings
→ five-domain scoring
→ confidence and maturity gates
→ persisted assessment run
→ evidence drill-down / history / trend / audit package
```

No backend score is recalculated in JavaScript.

## Evidence contract

Use `data/baseline.json` as the canonical input example. Required top-level fields are `scope`, `as_of`, `synthetic`, `sources`, `techniques`, `cases`, and `controls`; `lifecycles` is optional. Inputs are bounded to 2 MB at HTTP ingestion and collection sizes are bounded in the engine.

Validation rejects malformed types, non-finite or out-of-range numbers, duplicate or whitespace-padded identifiers, unsupported source kinds, timestamps without timezones, future/impossible timestamps, invalid links, oversized/control-containing references, unknown lifecycle fields, unknown lifecycle stage attributes, and contradictory case/lifecycle timestamps. Invalid evidence is rejected rather than repaired.

The canonical lifecycle links stable `incident_id`, `alert_id`, `case_id`, and `source_id` values through:

```text
detection → investigation → escalation → response → closure
```

Each present stage has a timestamp and may include status and an opaque `evidence_ref`. Detection must match the linked case's `detected_at`. A contained lifecycle response must match the linked case's `contained_at`; an earlier initial-response event is allowed. Escalation is required only when `escalation_required` is true. Inputs without `lifecycles` retain the legacy calculation path.

Evidence references are identifiers for human verification. SAT-SA does not open `demo://` references, access external systems, or fabricate evidence content.

## Scoring, confidence, and maturity

Scoring policy `sat-sa-demo-2.0` retains five domains:

```text
Overall = 30% Detection + 25% Response + 20% Telemetry
        + 15% Quality + 10% Governance
```

- Detection is risk-weighted validated technique coverage.
- Response pools eligible legacy containment-SLA obligations with lifecycle investigation, required-escalation, and response obligations.
- Telemetry is weighted completeness multiplied by source freshness.
- Quality pools reviewed-case precision with lifecycle closure discipline.
- Governance is the proportion of applicable controls satisfied with evidence references.

Lifecycle prototype targets are 15 minutes for investigation, 15 minutes for required escalation, 60 minutes from detection to response, and 240 minutes from response to closure. Timely stages earn 1 credit, delayed or present-but-unmeasurable stages earn 0.5, and missing stages earn 0. Escalation that is not required is excluded. These are prototype supervisory thresholds, not universal SOC service levels.

Confidence is an evidence-quality index: completeness × freshness × traceability. Poor operational performance does not directly lower confidence, but missing references can. It is not a statistical probability.

Maturity bands are L1 below 40, L2 from 40–59.9, L3 from 60–79.9, and L4 from 80. Confidence below 70, fewer than 10 reviewed cases, or an empty evidence domain makes maturity Provisional. Critical governance gaps cap maturity at L2. L4 also requires Detection of at least 75 and no unvalidated risk-weight-4/5 technique.

## Explainability and dashboard

The dashboard separates Assessment, Evidence, Findings, Lifecycle, History, and Policy/provenance. It exposes:

- a deterministic supervisory summary with strongest/weakest domain, High/Critical finding count, lifecycle completeness, drift status, and up to three evidence-backed issues;
- every finding and its available owner, correlation IDs, stage, observed delay, threshold, and evidence reference;
- Response/Quality legacy and lifecycle components and domain effects;
- per-stage lifecycle result, timestamp, status, delay, threshold, credit, and evidence reference;
- lifecycle counts and timing averages; and
- active policy and prototype thresholds.

Synthetic and user-supplied evidence are labelled distinctly. Provisional maturity receives a visible warning state. Legacy reports without lifecycle evidence remain usable and show a clear lifecycle-empty state.

## History, trend, and drift

SQLite schema version 2 gives every run an independent `assessment_id`; `input_sha256` is an indexed integrity identifier, not a unique key. Reassessing identical evidence can therefore create a separate observation. A row stores run/evidence timestamps, scope, policy and scope hashes, score, confidence, maturity, all domains, lifecycle mode, origin, and serialized evidence/report.

The original SHA-keyed table migrates transactionally to `assessments_legacy_v1`, which is retained as a backup. Migrated rows use evidence `as_of` as their best available run time. Startup is idempotent. A database whose `PRAGMA user_version` is newer than supported version 2 is rejected without downgrade.

Read-only local routes are:

- `GET /api/history?scope=<scope>`
- `GET /api/history/<assessment_id>`
- `GET /api/history/compare?before=<id>&after=<id>`
- `GET /api/history/trend?scope=<scope>`

Comparisons require the same policy version, scope identifier, and `scope_sha256`; incompatible requests return HTTP 409 instead of deltas. Trends expose chronological overall/confidence/domain observations, previous deltas, best/worst score, deterministic direction/streak, and excluded incompatible rows. The SVG chart shows observed overall scores only and implies no forecast.

Historical drift triggers on an overall decline of at least 10 points, confidence below the policy floor, a domain decline of at least 10 points, a new High/Critical finding, or an identifiable lifecycle gap reappearing after resolution.

## Manifest and audit package

Every persisted assessment exposes a manifest through its history response. The manifest distinguishes:

- scoring policy version: rules and thresholds producing the score;
- report schema version: `sat-sa-report-1.0`, the JSON report contract;
- database schema version: currently `2`, the SQLite storage layout;
- manifest/audit package versions: local export contracts.

The dashboard's **Export audit package** control downloads a deterministic ZIP from `GET /api/audit/<assessment_id>`. It contains:

- `manifest.json`
- `report.json`
- `findings.json`
- `lifecycle-summary.json`
- `supervisory-summary.json`

The manifest records artifact SHA-256 values and sizes. ZIP timestamps and ordering are fixed, so the same stored assessment and historical context produce identical bytes. Raw submitted evidence and external evidence files are deliberately excluded.

The existing **Export report** control remains available for plain report JSON.

## Synthetic demonstration

`data/baseline.json`, `data/degraded.json`, and all records in `data/demo-history.json` are synthetic. The fixed history shows healthy (83.4), degraded (65.4), and current healthy (83.4) observations. Stable demo IDs prevent page refreshes from creating duplicate history. `demo://` values are labels only.

## Offline operation and handling

Browser assets are local and the Content Security Policy permits only same-origin resources. Static paths are allow-listed, uploads are size/content-type bounded, unsupported methods return JSON errors, and API exceptions are converted to bounded responses. SQLite and exported reports may contain sensitive operational metadata; keep them on an authorized workstation and protect them appropriately.

## Current limitations

This prototype has no live connectors, vendor adapters, multi-alert incidents, peer/CSE benchmarking, fleet/national aggregation, RBAC/SSO, encryption at rest, protected retention, external evidence retrieval, tamper-evident remote storage, forecasting, ML anomaly detection, or AI/LLM capability. It does not estimate false-negative recall without controlled validation evidence. The 500-point trend cap, fixed prototype thresholds, synthetic demo, and assessor-supplied scope require pilot calibration and independent validation before operational use.

Useful standards references include NIST SP 800-61 Rev. 3, MITRE ATT&CK assessment and engineering guidance, OCSF, and CISA logging guidance.
