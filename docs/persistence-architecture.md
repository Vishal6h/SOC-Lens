# SOCLens persistence architecture

## Phase 6A persistence audit

Before Phase 6A, assessment schema, migration, queries, and connection creation
were combined in `assessment_history.py`; domain comparison and trend analysis
were in that file as well. `operations.py` and `database_operations.py` opened
additional SQLite connections for readiness, backup, and restore. The security
database had a dedicated module, but identity, session, login-attempt, and audit
services each owned SQL and repeated manual transaction handling. Import staging
and preparation sessions were durable JSON filesystem implementations without
explicit storage protocols.

Connection lifetimes were short and there were no unsafe process-global SQLite
connections. The important gaps were duplicated timeout/row-factory setup,
write-capable schema initialization on assessment read paths, implicit
autocommit for several security writes, SQLite exceptions crossing layer
boundaries, and no single capability model. SQLite-specific dependencies were
`PRAGMA user_version`, `sqlite_master`, `ALTER TABLE`, `last_insert_rowid()`, URI
read-only mode, and the SQLite online-backup API. Repeated initialization could
increase lock contention. Session authenticate/touch and audit append also need
explicit atomic transaction ownership under contention.

Schema ownership is now explicit:

- `persistence.assessment` owns assessment schema version 2, its supported
  0/1-to-2 migration, and assessment SQL.
- `security.storage` owns security schema version 1 and the separate security
  database. Identity, credential, session, rate-limit state, and audit-chain
  data are never merged with assessment history.
- `ingestion.storage` defines import and preparation storage contracts. The
  existing filesystem formats and cleanup behavior remain unchanged.

## Connection and transaction model

`persistence.sqlite.SQLiteConnectionFactory` is the only production component
that calls `sqlite3.connect`. Every use gets a new connection and deterministically
closes it. All connections enable foreign keys, apply a bounded busy timeout,
and use `sqlite3.Row` by default. Read-only connections use SQLite URI read-only
mode and `query_only`; writes use an explicit `BEGIN`, `BEGIN IMMEDIATE`, or
`BEGIN EXCLUSIVE` transaction which commits only on success and rolls back on
failure. Nested transactions are intentionally unsupported.

Managed runtime databases default to WAL with `synchronous=NORMAL`, which keeps
readers from blocking an ordinary writer while retaining SQLite's documented
WAL durability model. The tracked legacy development database stays in its
existing journal mode unless an operator explicitly configures otherwise.
`foreign_keys=ON` and `busy_timeout` are connection-local. Journal mode is
applied during database initialization, not on every read. The accepted journal
and synchronous values are allowlisted; environment values cannot inject an
arbitrary PRAGMA.

SQLite online backup produces a consistent snapshot, including committed WAL
content. Restore remains an offline CLI operation: it validates and safety-backs
up the current database, rejects active WAL/SHM sidecars, stages a validated
copy, and atomically replaces the stopped database. Assessment backups do not
include the security database.

## Boundaries

The assessment repository saves and loads immutable assessment records, lists
history inputs, reports schema state, and exposes a backend-neutral capability
description. Scoring, compatibility decisions, drift analysis, and trend
calculation stay in the application/domain layer.

Security services use a `SecurityStorage` instance backed by the same connection
factory principles but a different database. Multi-step user changes, credential
resets, session state transitions, login-attempt updates, and audit-chain appends
use explicit transactions. Password credentials remain confined to the identity
service and are not exposed by generic persistence diagnostics.

Import and preparation storage remain local filesystem stores. Their protocols
cover save/load/delete/list-or-cleanup behavior so a future implementation can
be substituted without changing parsing, canonical mapping, or assessment
logic. Atomic temporary-file replacement and existing JSON contracts are
preserved.

## Errors, health, and concurrency

The persistence layer translates database unavailable, busy, integrity,
conflict, and unsupported-version conditions into bounded errors. API handling
returns structured generic failures and never exposes SQL, table names, paths,
or SQLite exception text. Lightweight structured events cover migrations,
busy/locked failures, operation duration, and persistence failures without SQL
or record values.

Readiness performs only a schema-version check, required-table check, and
`SELECT 1`. Capability data contains `backend`, `schema_version`, `writable`, and
`healthy`, never a filesystem path. Connections are per operation; no connection
is shared between request threads. WAL, short read scopes, explicit write
transactions, and a bounded busy timeout improve local concurrency. This is not
a claim of distributed, multi-process orchestration, or multi-node safety.

## Future PostgreSQL contract

A PostgreSQL assessment backend must implement the repository protocol: schema
initialization/version reporting, capability/readiness, assessment existence,
atomic save, one-record retrieval, and bounded ordered history retrieval. It
must provide transaction scopes with commit-on-success/rollback-on-failure and
map driver failures into the same bounded persistence errors.

PostgreSQL migrations will have their own ordered migration owner; SQLite
`user_version` is not part of the interface. The implementation must account for
UUID/text identifier choices, timezone-aware timestamps, JSON/JSONB canonical
round-tripping, row-level concurrency and isolation, uniqueness/conflict
semantics, and database-native backup/point-in-time recovery. Security data may
remain independently deployed or gain a separate PostgreSQL database/schema,
but its isolation, credential restrictions, session revocation, and serialized
audit-chain append must remain intact. No PostgreSQL backend or placeholder is
implemented in Phase 6A.

## Recovery boundary and limitations

Security recovery is independent from assessment backup. A future procedure
must consistently back up users, password credentials, sessions, login-attempt
state, audit events, and audit-chain head. Sessions and transient rate-limit
state generally should be revoked/reset after recovery rather than blindly
replayed; users, credentials, and the complete verified audit chain must be
restored atomically. Phase 6A defines this boundary but does not add the full
security backup/restore workflow.

SQLite files are not encrypted by SOCLens. Use an encrypted host filesystem or
volume where encryption at rest is required. Phase 6A adds no pooling, scheduled
backup, retention, distributed locking, full load testing, or PostgreSQL support.
