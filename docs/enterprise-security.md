# SOCLens Enterprise Security

## Phase 5 threat model and security boundary

This document records the security boundary established before Phase 5 implementation.
SOCLens remains a local/offline service and is not approved for direct public-Internet
exposure. The assessment engine, `sat-sa-demo-2.0`, lifecycle calculations, confidence,
maturity, correlation, and deterministic report contracts are outside the security
change boundary.

### Assets

| Asset | Sensitivity and required protection |
| --- | --- |
| Assessment results, findings, and incident data | Confidential operational assessment data; authenticated, role-authorized read/export only. |
| Imported evidence and preparation sessions | Potentially sensitive normalized SOC records; bounded parsing, restrictive storage, authorized import/read/delete only. |
| Reports and audit packages | Portable sensitive exports; server-side export authorization and audit events are required. |
| Assessment database and backups | Contains evidence and reports; local filesystem protection, privileged backup, CLI-only restore, and host/volume protection are required. |
| Session credentials | Bearer authority; opaque random cookie, hash-only server persistence, expiry/revocation, HttpOnly, SameSite, and HTTPS Secure-cookie support are required. |
| Configuration and future secrets | Must not be committed, logged, or returned by readiness. Runtime/environment input is the integration boundary. |
| Security audit records | Security evidence; append-only-style storage, bounded non-sensitive context, role-restricted reads, and hash-chain verification are required. |

### Existing controls found in the Phase 4 repository

- The service binds to `127.0.0.1` by default and has a static-file allowlist.
- Request bodies have declared-size limits, reject transfer encoding, and enforce media
  types. CSV/JSON evidence has record, column, and field limits.
- Import and preparation identifiers are strict random hex values; filenames and path
  containment are validated. Raw uploads are not retained.
- SQLite uses parameterized queries and explicit schema/version checks. Backup and
  restore validate databases; restore is CLI-only, staged, and atomic.
- API errors generally suppress SQL errors, stack traces, and filesystem paths.
- Responses already set CSP, `X-Content-Type-Options`, `Referrer-Policy`,
  `Permissions-Policy`, and `Cache-Control: no-store`.
- Operational JSON logging uses an allowlist of metadata fields and does not log request
  bodies. Audit ZIPs intentionally exclude raw submitted evidence and are deterministic.
- Cross-site POST/PUT/DELETE requests with `Sec-Fetch-Site: cross-site` are rejected.

### Missing controls at the audit checkpoint

- There is no identity store, authentication, password hashing, session authority,
  authorization, role model, CSRF token, login abuse protection, account administration,
  or credential-change flow.
- Every assessment, demo, import, preparation, history, report, and audit-package API is
  anonymously callable. Readiness also exposes operational state anonymously.
- `SameSite`, HttpOnly/Secure cookies, session expiry/revocation, and disabled-account
  enforcement do not exist.
- Cross-site metadata checks cover only some methods and are not a CSRF token defense.
- Operational logs are not a security audit trail. There is no tamper-evident chain.
- Runtime directories are commonly mode `0755`; the assessment database and log may be
  created mode `0644`. No readiness diagnostic covers security persistence.
- SQLite data and backups are plaintext at rest. No vetted transparent database
  encryption dependency is present.
- Frontend navigation and controls are not identity- or role-aware.

### Threats and planned controls

| Threat | Control decision |
| --- | --- |
| Unauthenticated access | Default-deny request guard; only login assets and health are public. |
| Privilege escalation / identifier guessing | Central permission matrix and server-side check on every protected route, independent of UI and object identifier. |
| Session theft or stale/revoked sessions | 256-bit opaque token, SHA-256 token persistence, HttpOnly Strict cookie, idle/absolute expiry, revocation, account-enabled and password-version checks, rotation after credential change. HTTPS is mandatory before network deployment. |
| CSRF and login CSRF | Session-bound random CSRF token for POST/PUT/PATCH/DELETE plus same-origin/Fetch Metadata checks; login uses strict origin/site checks. |
| Credential guessing and user enumeration | Generic login error, bounded per-principal/client failure window and temporary throttling, dummy password verification, audited failures. |
| Insecure password storage | Versioned `hashlib.scrypt` credential with random salt, bounded password input, configurable work factor, and constant-time comparison. |
| Sensitive-data logging | Operational log field allowlist; security-audit context denylist and size bounds; never record credentials, raw tokens, secrets, or raw evidence. |
| Unauthorized export | `report.export` checked before report/error/audit download generation; export audit event. |
| Unauthorized backup or restore | Backup permission reserved for Admin if a web API is added (none in Phase 5); restore stays CLI-only. CLI backup/restore events are recorded. |
| Path abuse | Preserve strict IDs, filename validation, resolved-path containment, static allowlist, and bounded query parameters. |
| Tampered audit records | Canonical SHA-256 previous-entry chain and verification CLI. This is tamper-evident, not tamper-proof or non-repudiating. |
| Malicious imported evidence | Preserve bounded parsers, UTF-8/finite JSON enforcement, explicit profiles, control-character rejection, no code/formula execution, and no raw-file serving. |
| Excessive error detail | Stable uppercase security codes and generic client messages; internal exceptions remain in restricted operational logs only. |

## Endpoint inventory and classification

Classification is evaluated before request parsing or object lookup so denied callers
cannot use validation differences to enumerate records.

| Method and path | Classification | Permission |
| --- | --- | --- |
| `GET /`, `/app.js`, `/style.css` | Public | Login/application assets only |
| `GET /api/health` | Public | None; compact liveness only |
| `POST /api/auth/login` | Public | Same-origin login boundary and rate limit |
| `GET /api/auth/session` | Authenticated | Valid session |
| `POST /api/auth/logout` | Authenticated | Valid session + CSRF |
| `POST /api/auth/password` | Authenticated | Valid session + CSRF |
| `GET /api/ready` | Privileged | `operations.status.read` |
| `GET /api/demo` | Privileged | `assessment.read` |
| `POST /api/assess` | Privileged | `assessment.run` |
| `GET /api/history...` | Privileged | `history.read` |
| `GET /api/report/<assessment-id>` | Privileged | `assessment.export` |
| `GET /api/audit/<assessment-id>` | Privileged | `report.export` |
| `GET /api/import/profiles` | Privileged | `evidence.import` |
| `POST /api/import` | Privileged | `evidence.import` + CSRF |
| `GET /api/import/<id>[/errors]` | Privileged | `evidence.import` |
| `DELETE /api/import/<id>` | Privileged | `evidence.delete_staged` + CSRF |
| `GET/POST/PUT/DELETE /api/preparation...` | Privileged | `assessment.create` (+ CSRF for changes) |
| `POST /api/assessment-build` | Privileged | `assessment.run` + CSRF |
| `GET/POST/PATCH /api/security/users...` | Privileged | Corresponding `security.user.*` + CSRF for changes |
| `GET /api/security/audit` | Privileged | `security.audit.read` |

Unknown `/api/` routes remain default-denied for anonymous callers and return a normal
not-found response only after authentication.

## Permission matrix

`ADMIN` has every defined permission. Other roles receive only the following grants;
absence means deny.

| Permission | Supervisor | Assessor | Reviewer | Auditor |
| --- | :---: | :---: | :---: | :---: |
| `assessment.read` | yes | yes | yes | yes |
| `assessment.create` / `assessment.run` | yes | yes | no | no |
| `assessment.export` / `report.export` | yes | no | no | yes |
| `incident.read` / `finding.read` | yes | yes | yes | yes |
| `history.read` | yes | no | yes | yes |
| `evidence.import` / `evidence.delete_staged` | yes | yes | no | no |
| `report.read` / `policy.read` | yes | yes | yes | yes |
| `security.audit.read` | no | no | no | yes |
| `operations.status.read` | yes | yes | yes | yes |
| `security.user.*`, `operations.backup`, `operations.restore` | no | no | no | no |

The Admin role also has `security.audit.read`. Restore is deliberately not exposed by
HTTP even though a permission is reserved for future separation of operator duties.

## Trust and deployment boundaries

- Local authentication is the only implemented identity provider mode. `oidc` is a
  documented future mode and is not accepted by configuration in Phase 5.
- Security identities/sessions/audit events use a dedicated SQLite database and are
  never stored in assessment history.
- The browser holds only the HttpOnly session cookie and an in-memory CSRF token. No
  authentication token is placed in Web Storage, URLs, or DOM-visible fields.
- Plain SQLite is not encrypted at rest. Use an encrypted host volume today. A future
  persistence adapter may use SQLCipher or PostgreSQL with vetted encryption controls;
  Phase 5 makes no encrypted-at-rest claim.
- `Secure` cookies protect HTTPS deployments, but the Python development server does
  not terminate TLS. Any controlled-network deployment requires HTTPS at a trusted
  reverse proxy, restrictive host firewalling, and correct secure-cookie configuration.
- The hash chain detects missing, reordered, or edited entries when the attacker has
  not also recomputed all following hashes. Without an external signed anchor it is not
  tamper-proof and does not provide cryptographic non-repudiation.
