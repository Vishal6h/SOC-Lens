# SOCLens

**Supervisory Analytics for SOC Assessment**

SOCLens is a local, evidence-based supervisory analytics platform designed to assess how effectively a Security Operations Center performs using declared operational evidence rather than relying only on policies, dashboards, or self-assessments. It turns structured SOC records into explainable scores, lifecycle findings, trends, and audit artifacts. SOCLens implements the SAT-SA (Supervisory Analytics Tool for SOC Assessment) concept/problem statement.

## 1. The problem

Organizations may have documented SOC procedures, but supervisors also need evidence that those procedures work in day-to-day operations. SOCLens analyzes operational records to identify:

- missing or delayed actions;
- weak investigation and missing escalation;
- slow response and missing closure;
- telemetry and governance gaps; and
- operational drift over time.

The result is a supervisory assessment that remains tied to the evidence identifiers supplied for review.

## 2. What SOCLens does

```text
SOC Evidence
    ↓
Validation
    ↓
Normalization / Correlation
    ↓
Detection → Investigation → Escalation → Response → Closure
    ↓
Gap Detection
    ↓
Supervisory Scoring
    ↓
Evidence Drill-down
    ↓
History / Trend / Drift
    ↓
Audit Export
```

SOCLens validates submitted JSON, correlates lifecycle records, evaluates operational execution, and persists each assessment locally. Invalid or contradictory evidence is rejected rather than silently repaired.

## 3. Key features

- Evidence-based SOC assessment
- Incident lifecycle correlation
- Detection, investigation, escalation, response, and closure analysis
- Missing-stage and negative-space detection
- Lifecycle timing analysis
- Explainable five-domain scoring
- Evidence confidence scoring
- Maturity assessment and policy gates
- Evidence traceability through opaque references
- Incident-level drill-down
- Local assessment history
- Trend analysis and compatible assessment comparison
- Deterministic drift detection
- Deterministic supervisory summaries
- Reproducible audit ZIP export
- Synthetic baseline and degraded demo scenarios
- Fully local and offline operation
- Deterministic CSV and structured-JSON evidence ingestion
- Versioned, inspectable source-to-canonical mappings

## 4. Assessment domains

The current scoring policy is `sat-sa-demo-2.0`.

| Domain | Weight | What it evaluates |
| --- | ---: | --- |
| Detection | 30% | Risk-weighted validated technique coverage |
| Response | 25% | Eligible containment and lifecycle execution obligations |
| Telemetry | 20% | Weighted source completeness and freshness |
| Quality | 15% | Reviewed-case precision and lifecycle closure discipline |
| Governance | 10% | Applicable controls supported by evidence references |

The overall score is the weighted combination of these five domains:

```text
Overall = 30% Detection + 25% Response + 20% Telemetry
        + 15% Quality + 10% Governance
```

When lifecycle data is available, lifecycle execution influences the Response and Quality domains. The scoring policy and weights are fixed prototype policy, not universal SOC benchmarks.

## 5. Lifecycle analysis

SOCLens correlates stable incident, alert, case, and source identifiers across the operational sequence:

```text
Detection → Investigation → Escalation → Response → Closure
```

The current prototype timing targets are:

| Stage | Target |
| --- | ---: |
| Investigation | 15 minutes |
| Required escalation | 15 minutes |
| Response | 60 minutes |
| Closure | 240 minutes |

Timely stages receive full credit, delayed or present-but-unmeasurable stages receive partial credit, and missing required stages receive no credit. Escalation is evaluated only when it is required.

These values are **prototype supervisory policy thresholds** and require calibration against real operating environments, risk profiles, and service expectations.

## 6. Confidence and maturity

Performance score and confidence measure different things:

- **Performance** represents the evaluated operational outcome.
- **Confidence** represents evidence quality through completeness, freshness, and traceability.

Operational failures reduce performance. Missing, stale, incomplete, or weakly linked evidence affects confidence. Confidence is an evidence-quality index, not a statistical probability.

| Maturity | Score range |
| --- | ---: |
| L1 | Below 40 |
| L2 | 40–59.9 |
| L3 | 60–79.9 |
| L4 | 80 or above |

An assessment becomes **Provisional** when confidence is below 70, fewer than 10 cases have been reviewed, or a required evidence domain is empty. Critical governance gaps cap maturity at L2. L4 also requires Detection of at least 75 and no unvalidated risk-weight-4/5 technique.

## 7. Explainability

```text
Overall Score
    ↓
Domain
    ↓
Lifecycle Component
    ↓
Incident
    ↓
Stage
    ↓
Finding
    ↓
Evidence Reference
```

Supervisors can move from an overall result to domain effects, lifecycle outcomes, individual findings, and the exact evidence identifiers supplied for verification. SOCLens does not retrieve or fabricate the underlying evidence represented by those identifiers.

## 8. History, trend, and drift

SOCLens stores assessment runs locally in SQLite and supports:

- historical assessment retrieval;
- comparison of compatible assessments;
- overall, confidence, and domain deltas;
- an observed overall-score trend;
- deterministic drift detection; and
- detection of lifecycle gaps that recur after previously being absent.

Comparisons require the same policy version, scope identifier, and scope hash. Drift rules evaluate score and domain declines, confidence below the policy floor, new High/Critical findings, and recurring lifecycle gaps.

The trend is historical only. SOCLens does not forecast performance or provide predictive analytics.

## 9. Auditability

Each persisted assessment carries the information required to identify its input, scope, policy, and storage contracts:

| Audit field | Current meaning or value |
| --- | --- |
| Input SHA-256 | Integrity digest of the submitted assessment input |
| Scope SHA-256 | Compatibility digest of the assessed scope |
| Policy version | `sat-sa-demo-2.0` |
| Report schema version | `sat-sa-report-1.0` |
| Database schema version | `2` |
| Manifest version | `sat-sa-manifest-1.0` |
| Audit package version | `sat-sa-audit-1.0` |

The deterministic audit ZIP contains:

- `manifest.json`
- `report.json`
- `findings.json`
- `lifecycle-summary.json`
- `supervisory-summary.json`

The manifest records artifact hashes and sizes. Raw submitted evidence and external evidence files are intentionally excluded from the package.

## 10. Architecture

```text
Browser
   ↓
Local Python HTTP Server
   ↓
Bounded Import Adapters / Versioned Mappings
   ↓
Canonical SOCLens Evidence
   ↓
Assessment Engine
   ↓
Lifecycle / Scoring / Findings
   ↓
SQLite Assessment History
   ↓
Dashboard / Reports / Audit Package
```

The backend uses the Python standard library and SQLite. The frontend uses vanilla JavaScript, HTML, and CSS. Core functionality has no external runtime package, API-key, network-service, or build-tool dependency, and backend scores are not recalculated in the browser.

### Application navigation

The browser interface follows the principle **“very simple at the top, deeply
technical underneath.”** A persistent application shell uses local hash navigation,
so direct links and browser back/forward work without reloading the service:

- **Dashboard** — current score, maturity, evidence quality, priority issues,
  incident completion, performance change, and a concise supervisory explanation.
- **Assessments** — current details, synthetic scenarios, guided CSV/JSON import,
  multi-file evidence coverage, and reopening previous assessments.
- **Incidents** — assessed incident process stages and timings, with correlation IDs,
  exact timestamps, credits, targets, and supporting evidence under technical details.
- **Findings** — supervisor-oriented issues, affected areas and incidents, expected
  targets, observed results, and supporting evidence.
- **History** — performance trend, compatible comparison, technical drift reasons,
  and historical assessment records.
- **Reports** — assessment JSON and deterministic audit-package exports, with
  hashes and schema provenance in an advanced disclosure.
- **Policy** — human-readable prototype weights, operational targets, maturity
  levels, and confidence gates, followed by exact technical policy details.
- **Settings** — non-sensitive environment, version, policy, database, and readiness
  status sourced from the Phase 1 diagnostics endpoint.

Detailed metadata is progressively disclosed from summary to explanation, finding
or incident, lifecycle stage, supporting evidence, and finally technical provenance.
Navigation does not trigger repeated API calls; history and readiness data are cached
for the active assessment context.

## 11. Project structure

| Path | Purpose |
| --- | --- |
| `engine.py` | Evidence validation, normalization, lifecycle correlation, scoring, confidence, maturity, and findings |
| `assessment_history.py` | SQLite schema, persistence, migration, comparison, trend, and drift |
| `config.py` | Centralized environment, network, path, logging, and request-limit configuration |
| `database_operations.py` | Validated SQLite backup/restore CLI and helper functions |
| `operations.py` | Structured logging and bounded operational readiness diagnostics |
| `reporting.py` | Supervisory summaries, manifests, and deterministic audit packages |
| `ingestion/` | Offline adapters, mappings, normalization, staging, previews, and canonical assembly |
| `server.py` | Local HTTP server and bounded assessment, ingestion, history, and audit APIs |
| `make_demo.py` | Recreates deterministic synthetic fixtures |
| `index.html` | Accessible application shell and eight section structures |
| `app.js` | Hash navigation, lazy section rendering, assessment interaction, history, and export |
| `style.css` | Responsive shell, supervisory pages, disclosures, tables, and status presentation |
| `test_engine.py` | Scoring, validation, and lifecycle tests |
| `test_history.py` | Persistence, history, comparison, trend, and migration tests |
| `test_hardening.py` | Input, database, server, report, and audit hardening tests |
| `test_foundation.py` | Configuration, status, error, runtime, backup, restore, and regression tests |
| `test_frontend.py` | DOM integrity, application routes, hash navigation, and semantic-control tests |
| `test_ingestion.py` | CSV/JSON adapters, profiles, staging, assembly, API, and ingestion regression tests |
| `data/` | Synthetic baseline, degraded, history, generated result, and ingestion fixtures |

## 12. How to run

Requirements: Python 3.10 or newer. No external Python packages are required.

From WSL or Linux:

```bash
cd ~/SIH/SAT-SA-Prototype
python3 server.py
```

Open:

```text
http://127.0.0.1:8765
```

The server binds only to localhost. Do not expose this prototype directly to a network.

### Production Foundation

Phase 1 adds an operational foundation without changing assessment, lifecycle,
confidence, maturity, policy, or report semantics. The foundation audit retained
the existing localhost binding, bounded request parsing, security headers, static
allowlist, transactional schema-v2 migration, rollback behavior, deterministic
audit package, and clean Ctrl+C shutdown. Configuration, structured logging,
health/readiness, stable API errors, runtime directories, and safe database
backup/restore are now explicit.

#### Environments

- `development` is the default. It preserves `127.0.0.1:8765` and uses the existing
  repository `assessments.sqlite3` when that legacy database is present.
- `test` chooses a unique operating-system temporary data directory when no data
  directory is supplied. Tests and test databases do not use repository runtime data.
- `production` remains bound to `127.0.0.1` unless the host is explicitly changed,
  uses `runtime/db/assessments.sqlite3` by default, requires absolute explicit paths,
  and requires configured database, backup, export, and log paths to remain under
  the configured data directory.

Environment selection never changes scoring or report results.

#### Configuration

All environment variables are read and validated in `config.py`. Invalid values stop
startup with a clear error.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SOCLENS_ENV` | `development` | `development`, `test`, or `production` |
| `SOCLENS_HOST` | `127.0.0.1` | HTTP bind host; production is localhost-safe by default |
| `SOCLENS_PORT` | `8765` | HTTP port, 1–65535 |
| `SOCLENS_DATA_DIR` | `runtime/` | Persistent runtime root (unique temporary root in test mode) |
| `SOCLENS_DB_PATH` | environment-specific | SQLite database file |
| `SOCLENS_BACKUP_DIR` | `<data>/backups` | Database backup destination |
| `SOCLENS_EXPORT_DIR` | `<data>/exports` | Operator-managed export destination |
| `SOCLENS_LOG_DIR` | `<data>/logs` | Rotating service log destination |
| `SOCLENS_IMPORT_DIR` | `<data>/imports` | Staged import metadata and normalized fragments |
| `SOCLENS_LOG_LEVEL` | `INFO` | `CRITICAL`, `ERROR`, `WARNING`, `INFO`, or `DEBUG` |
| `SOCLENS_REQUEST_SIZE_LIMIT` | `2000000` | Maximum JSON request bytes (maximum configurable value: 100 MB) |
| `SOCLENS_INGESTION_MAX_UPLOAD_BYTES` | request-size limit | Maximum bytes in one evidence file |
| `SOCLENS_INGESTION_MAX_RECORDS` | `10000` | Maximum source records in one import |
| `SOCLENS_INGESTION_MAX_COLUMNS` | `100` | Maximum CSV columns or distinct JSON fields |
| `SOCLENS_INGESTION_MAX_FIELD_BYTES` | `10000` | Maximum encoded source-field size |
| `SOCLENS_INGESTION_MAX_ACTIVE_IMPORTS` | `100` | Maximum staged imports retained at once |

The runtime layout is created at startup and ignored by Git:

```text
runtime/
  db/
  backups/
  exports/
  imports/
  logs/
```

Source-controlled synthetic fixtures remain under `data/`. The legacy repository
database is not moved automatically; set `SOCLENS_DB_PATH` when an operator is ready
to place it in the runtime layout.

#### Logging and diagnostics

Operational logs are compact JSON lines written to stderr and to the rotating
`runtime/logs/soclens.log` file. They include UTC timestamp, level, component, event,
request method/path and status where relevant, and assessment identifiers when
available. Raw evidence payloads are not logged.

- `GET /api/health` is a liveness check and returns compact JSON.
- `GET /api/ready` verifies runtime directories, database access, schema version,
  policy version, and report version. It returns HTTP 503 when not ready and never
  exposes configured filesystem paths.

API failures use a stable shape and do not return tracebacks or internal SQL/path
details:

```json
{"error":{"code":"invalid_request","message":"scope is required exactly once"}}
```

#### Database initialization and migrations

Startup creates schema version 2 deterministically. The original SHA-keyed schema
has an explicit transactional migration path to version 2, remains preserved as
`assessments_legacy_v1`, and is not duplicated on repeated startup. Migration
failures roll back. A database declaring a newer or mismatched schema fails safely;
it is never downgraded.

#### Backup and restore

Create a consistent SQLite backup with the service running or stopped:

```bash
SOCLENS_ENV=production python3 database_operations.py backup
```

The command uses SQLite's backup API, creates a unique file under the configured
backup directory, validates integrity and schema, and prints metadata including its
SHA-256 digest. It does not copy a live database file directly.

Restore only while the service is stopped:

```bash
SOCLENS_ENV=production python3 database_operations.py restore runtime/backups/<backup>.sqlite3
```

Restore validates the candidate before touching the active database, refuses an
unsupported schema, creates a uniquely named safety backup of the active database,
stages and revalidates the candidate, obtains an exclusive SQLite lock, and performs
an atomic replacement. Restore is intentionally unavailable over HTTP. If active WAL
state is present, restore refuses the operation and asks the operator to stop and
checkpoint the database first.

#### Production startup

For a local production-mode service using the default persistent layout:

```bash
SOCLENS_ENV=production SOCLENS_LOG_LEVEL=INFO python3 server.py
```

Startup logs the service version, environment, bind address/port, database readiness
and schema, scoring policy, and report schema. Keep the default localhost bind until
authentication, authorization, TLS/reverse-proxy controls, and deployment hardening
are implemented in a later phase.

### Real evidence ingestion

Phase 3 places an auditable adapter layer before the unchanged assessment engine:

```text
Source CSV / JSON export
    → bounded adapter and explicit profile
    → row validation and normalization
    → canonical SOCLens evidence
    → existing correlation and sat-sa-demo-2.0 scoring
```

On **Assessments**, choose a versioned mapping profile, upload a local export, review
its preview and row issues, combine the required evidence categories, check coverage,
then run the assessment. Existing canonical SOCLens JSON remains supported both by
the `SOCLens JSON` profile and the backward-compatible `POST /api/assess` endpoint.

Supported offline profiles are:

- Generic Telemetry / Source Health Export (`sources`)
- Generic Detection Validation Export (`techniques`)
- Generic SIEM Alert Export (lifecycle detection and explicit identifiers)
- Generic Case Management Export (`cases` and optional lifecycle stages)
- Generic Control Evidence Export (`controls`)
- canonical SOCLens JSON passthrough

Profiles are Python-defined, versioned, exact mappings. CSV and source-record JSON
(`[{...}]` or `{"records":[...]}`) use the same field contracts. SOCLens does not
fuzzily match headers, execute spreadsheet formulas, infer missing evidence, or treat
an alert occurrence as proof of detection validation. Timestamp, Boolean, enumeration,
whitespace, and identifier conversions are explicit in `ingestion/normalization.py`.

Each import receives a random identifier and records its filename (never an absolute
client path), file SHA-256, selected profile/version, record counts, warnings/errors,
produced categories, normalized-fragment SHA-256, and status. Only this metadata and
the normalized fragment are written atomically under `runtime/imports/<import-id>/`;
raw uploaded content is not retained or web-served. Operators can remove an import in
the UI/API, or invoke `ImportService.cleanup(older_than_seconds)` from a bounded local
maintenance script. Test mode uses its isolated temporary runtime root.

Rejected rows report source file, record number, field, stable code, and reason. Error
reports are available as JSON or CSV at `GET /api/import/<id>/errors?format=json|csv`.
Warnings identify accepted records or unmapped fields that require review; information
messages describe deterministic normalization. An import containing rejected records
cannot enter an assessment build.

Multi-file preparation combines canonical categories without placeholders. Sources,
techniques, cases, and controls must be present; any supplied lifecycle alert/case
fragments must correlate completely. Build preview exposes missing/partial coverage.
Reports created by `POST /api/assessment-build` add non-breaking lineage containing
import IDs, source file hashes, profile versions, ingestion time, and canonical hash.
Legacy canonical assessment hashes and scoring remain unchanged.

All files under `data/ingestion/` are explicitly synthetic examples. The valid five-file
set demonstrates complete assembly, `generic-telemetry.csv` demonstrates an accepted
unmapped-column warning, and `generic-siem-alerts-invalid.csv` demonstrates rejected
timestamp and Boolean values.

SOCLens does not yet connect live to external SIEM/EDR/SOAR systems. Phase 3 does not
provide credentials, polling, archives, fuzzy or AI-assisted mapping, multi-alert
correlation, or official vendor compatibility.

## 13. Testing

Run the complete Python test suite:

```bash
python3 -B -m unittest discover -s . -v
```

Current validated status: **125 tests passing**, including production-foundation,
application-shell, ingestion, staging, mapping, assembly, and regression coverage.

Validate the frontend JavaScript syntax:

```bash
node --check app.js
```

No continuous-integration service is claimed or required by this repository.

## 14. Demo flow

1. Open the synthetic baseline scenario.
2. Review the overall score and five domain scores.
3. Open the findings and evidence-traceability view.
4. Drill into a correlated lifecycle incident.
5. Inspect its stage results and evidence references.
6. Switch to the degraded scenario.
7. Show the resulting score and confidence changes.
8. View assessment history, trend, and drift status.
9. Compare compatible assessments.
10. Export the audit package.

## 15. Screenshots

### Assessment Dashboard

![SOCLens Assessment Dashboard](docs/images/dashboard.png)

The baseline assessment shows the overall supervisory score, evidence confidence,
maturity gate, assessed evidence, and evidence-backed supervisory summary.

### Incident Lifecycle Assessment

![SOCLens Incident Lifecycle Assessment](docs/images/lifecycle.png)

SOCLens correlates operational evidence across detection, investigation, escalation,
response, and closure while exposing lifecycle timing and traceability.

### History & Drift

![SOCLens Assessment History and Drift](docs/images/history.png)

Historical assessments show how SOC performance changes over time and highlight
deterministic supervisory drift between compatible assessments.


## 16. Synthetic data

All bundled datasets and history records are synthetic. They are labelled `SYNTHETIC DEMO DATA` in reports, manifests, audit packages, and the dashboard.

The bundled examples must not be interpreted as real CSE or SOC operational evidence, certification, or proof of operational effectiveness. Values using the `demo://` scheme are labels only.

## 17. What SOCLens is not

SOCLens is:

- not a SIEM;
- not a replacement for a SOC;
- not a real-time monitoring system;
- not a centralized national SOC;
- not an autonomous decision-maker; and
- not a production-ready security platform.

It supports human supervisory assessment. Scores, findings, evidence references, and policy thresholds require assessor review.

## 18. Current limitations

- No authentication, RBAC, or SSO
- No encryption at rest
- No live SIEM, EDR, or vendor connectors
- Evidence references are opaque identifiers and are not retrieved
- One alert is correlated per lifecycle incident
- Fixed prototype policy weights and timing thresholds
- SQLite data and local exports require appropriate workstation-level protection
- The overall score is the primary graphed trend
- Trend retrieval is capped at 500 observations

The prototype also does not provide peer benchmarking, protected evidence retention, multi-alert incident correlation, forecasting, ML anomaly detection, or AI/LLM decision-making.

## 19. Post-hackathon roadmap

Potential next steps, subject to design and validation, include:

- controlled pilot validation with authorized SOC data;
- independent assessor agreement testing;
- RBAC and SSO;
- encryption at rest;
- protected evidence retention;
- an open connector schema such as OCSF;
- configurable policy profiles;
- multi-alert incident support; and
- real-world threshold calibration.

These items are not implemented in the current prototype.

## 20. License and project status

SOCLens is an experimental, SIH-ready working prototype implementing the SAT-SA concept. It is intended for demonstration, evaluation, and further validation—not production deployment.

No license file is currently included in this repository.
