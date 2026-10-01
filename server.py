"""SOCLens local service. Python 3.10+, no pip packages required."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse
import json
import logging
import sqlite3
from datetime import datetime, timezone

from config import ConfigurationError, initialize_runtime_directories, load_config
from engine import POLICY, assess, compare
from assessment_history import (
    ComparisonUnavailable,
    HistoryNotFound,
    SCHEMA_VERSION,
    UnsupportedDatabaseVersion,
    assessment_exists,
    compare_stored,
    get_assessment,
    initialize_database,
    list_assessments,
    store_assessment,
    trend,
)
from operations import APP_VERSION, configure_logging, operational_status
from reporting import REPORT_SCHEMA_VERSION, audit_package, supervisor_summary
from ingestion import ImportService, PreparationService, assemble_imports
from ingestion.correlation import enrich_report
from ingestion.sessions import PreparationNotFound
from ingestion.staging import ImportNotFound


ROOT = Path(__file__).resolve().parent
try:
    CONFIG = load_config()
except ConfigurationError as exc:
    if __name__ == "__main__":
        raise SystemExit(f"SOCLens configuration failed: {exc}") from None
    raise
DB = CONFIG.database_path
MAX_BODY_BYTES = CONFIG.request_size_limit
LOGGER = logging.getLogger("soclens.server")
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/sample.json": ("data/baseline.json", "application/json; charset=utf-8"),
}


class UnsupportedMediaType(ValueError):
    pass


class ServiceServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def save(data, report, **metadata):
    return store_assessment(DB, data, report, **metadata)


def static_asset(path):
    parsed = urlparse(path)
    entry = STATIC_FILES.get(parsed.path) if not parsed.query else None
    if entry is None:
        return None
    relative, content_type = entry
    target = (ROOT / relative).resolve()
    if not target.is_relative_to(ROOT):
        return None
    return target, content_type


def read_json_request(headers, stream, limit=None):
    request_limit = MAX_BODY_BYTES if limit is None else limit
    if headers.get("Transfer-Encoding"):
        raise ValueError("Transfer-Encoding is not supported")
    if headers.get_content_type() != "application/json":
        raise UnsupportedMediaType("Content-Type must be application/json")
    try:
        length = int(headers.get("Content-Length", "0"))
    except (TypeError, ValueError) as exc:
        raise ValueError("Content-Length must be an integer") from exc
    if not 0 < length <= request_limit:
        raise ValueError(f"Upload limit is {request_limit} bytes")
    raw = stream.read(length)
    if len(raw) != length:
        raise ValueError("Request body ended before Content-Length bytes were received")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("Request body must contain valid UTF-8 JSON") from exc


def read_upload_request(headers, stream, limit, allowed_content_types):
    if headers.get("Transfer-Encoding"):
        raise ValueError("Transfer-Encoding is not supported")
    if headers.get_content_type() not in allowed_content_types:
        raise UnsupportedMediaType("Unsupported evidence Content-Type")
    try:
        length = int(headers.get("Content-Length", "0"))
    except (TypeError, ValueError) as exc:
        raise ValueError("Content-Length must be an integer") from exc
    if not 0 < length <= limit:
        raise ValueError(f"Upload limit is {limit} bytes")
    raw = stream.read(length)
    if len(raw) != length:
        raise ValueError("Request body ended before Content-Length bytes were received")
    return raw


def seed_demo_history(database=None):
    database = DB if database is None else Path(database)
    initialize_database(database)
    history_file = ROOT / "data" / "demo-history.json"
    if not history_file.exists():
        raise FileNotFoundError("Bundled demo history fixture is missing")
    for item in json.loads(history_file.read_text(encoding="utf-8")):
        assessment_id = item["assessment_id"]
        if assessment_exists(database, assessment_id):
            continue
        evidence = item["evidence"]
        store_assessment(
            database, evidence, assess(evidence), assessment_id=assessment_id,
            assessed_at=item["assessed_at"], origin="synthetic-demo", if_absent=True,
        )


def _one(query, name, *, required=True):
    values = query.get(name, [])
    if len(values) != 1 or not values[0]:
        if required:
            raise ValueError(f"{name} is required exactly once")
        return None
    return values[0]


def _only(query, *allowed):
    unexpected = set(query) - set(allowed)
    if unexpected:
        raise ValueError("Unexpected query parameter(s): " + ", ".join(sorted(unexpected)))


def _drift_for_assessment(database, stored):
    history = trend(database, stored["assessment"]["scope"])
    for point in history["points"]:
        if point["assessment_id"] == stored["assessment"]["assessment_id"]:
            return point.get("drift")
    return None


def history_api(path, database=DB):
    """Return (status, body) for history routes, or None for other paths."""
    parsed = urlparse(path)
    query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=20)
    audit_prefix = "/api/audit/"
    if parsed.path.startswith(audit_prefix):
        _only(query)
        assessment_id = unquote(parsed.path[len(audit_prefix):])
        if not assessment_id or "/" in assessment_id:
            raise ValueError("Invalid assessment_id")
        stored = get_assessment(database, assessment_id)
        package = audit_package(
            stored["assessment"], stored["report"], SCHEMA_VERSION,
            _drift_for_assessment(database, stored),
        )
        return 200, package, "application/zip", {
            "Content-Disposition": f'attachment; filename="soclens-audit-{assessment_id}.zip"'
        }
    if parsed.path == "/api/history":
        _only(query, "scope", "limit")
        scope = _one(query, "scope")
        limit_value = _one(query, "limit", required=False)
        limit = int(limit_value) if limit_value is not None else 100
        return 200, {"scope": scope, "assessments": list_assessments(database, scope, limit=limit)}
    if parsed.path == "/api/history/trend":
        _only(query, "scope")
        scope = _one(query, "scope")
        return 200, trend(database, scope)
    if parsed.path == "/api/history/compare":
        _only(query, "before", "after")
        before = _one(query, "before")
        after = _one(query, "after")
        return 200, compare_stored(database, before, after)
    prefix = "/api/history/"
    if parsed.path.startswith(prefix):
        _only(query)
        assessment_id = unquote(parsed.path[len(prefix):])
        if not assessment_id or "/" in assessment_id:
            raise ValueError("Invalid assessment_id")
        return 200, get_assessment(database, assessment_id)
    return None


def error_document(code, message):
    return {"error": {"code": code, "message": message}}


class Handler(BaseHTTPRequestHandler):
    server_version = "SOCLens"
    sys_version = ""

    def log_request(self, code="-", size="-"):
        return None

    def log_message(self, format, *args):
        LOGGER.warning(
            "HTTP protocol message",
            extra={
                "event": "http_protocol_message",
                "component": "server",
                "method": getattr(self, "command", None),
                "path": urlparse(getattr(self, "path", "")).path,
            },
        )

    def reply(self, status, body, content_type="application/json; charset=utf-8", headers=None, assessment_id=None):
        raw = body if isinstance(body, bytes) else json.dumps(body, allow_nan=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)
        LOGGER.info(
            "HTTP request completed",
            extra={
                "event": "http_request",
                "component": "server",
                "method": self.command,
                "path": urlparse(getattr(self, "path", "")).path,
                "status_code": status,
                "assessment_id": assessment_id,
            },
        )

    def reply_error(self, status, code, message):
        return self.reply(status, error_document(code, message))

    def _handle_expected_error(self, exc):
        if isinstance(exc, HistoryNotFound):
            self.reply_error(404, "assessment_not_found", str(exc))
            return True
        if isinstance(exc, ImportNotFound):
            self.reply_error(404, "import_not_found", str(exc))
            return True
        if isinstance(exc, PreparationNotFound):
            self.reply_error(404, "preparation_not_found", str(exc))
            return True
        if isinstance(exc, ComparisonUnavailable):
            body = error_document("comparison_unavailable", str(exc))
            body["comparable"] = False
            self.reply(409, body)
            return True
        if isinstance(exc, UnsupportedDatabaseVersion):
            LOGGER.error(
                "Unsupported database version",
                extra={"event": "database_unsupported", "component": "database", "error_code": "database_unavailable"},
            )
            self.reply_error(503, "database_unavailable", "Local persistence is not ready")
            return True
        if isinstance(exc, sqlite3.Error):
            LOGGER.exception(
                "Local persistence operation failed",
                extra={"event": "database_error", "component": "database", "error_code": "persistence_error"},
            )
            self.reply_error(500, "persistence_error", "Local persistence operation failed")
            return True
        if isinstance(exc, UnsupportedMediaType):
            self.reply_error(415, "unsupported_media_type", str(exc))
            return True
        if isinstance(exc, (ValueError, TypeError, KeyError)):
            self.reply_error(400, "invalid_request", str(exc))
            return True
        return False

    def _dispatch(self, action):
        try:
            return action()
        except Exception as exc:
            if self._handle_expected_error(exc):
                return None
            LOGGER.exception(
                "Unhandled request failure",
                extra={
                    "event": "request_error",
                    "component": "server",
                    "method": self.command,
                    "path": urlparse(self.path).path,
                    "error_code": "internal_error",
                },
            )
            return self.reply_error(500, "internal_error", "The request could not be completed")

    def do_GET(self):
        return self._dispatch(self._do_GET)

    def _do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/health" and not parsed.query:
            return self.reply(200, {"status": "ok", "service": "SOCLens"})
        if parsed.path == "/api/ready" and not parsed.query:
            status = operational_status(CONFIG, Path(DB))
            return self.reply(200 if status["status"] == "ready" else 503, status)
        if parsed.path == "/api/import/profiles" and not parsed.query:
            return self.reply(200, {"profiles": ImportService(CONFIG).profiles()})
        if parsed.path == "/api/preparation/latest" and not parsed.query:
            return self.reply(200, PreparationService(CONFIG).latest().document())
        if parsed.path.startswith("/api/preparation/") and not parsed.query:
            session_id = unquote(parsed.path[len("/api/preparation/"):])
            if not session_id or "/" in session_id:
                raise ValueError("Invalid session_id")
            return self.reply(200, PreparationService(CONFIG).get(session_id).document())
        if parsed.path.startswith("/api/import/"):
            query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=5)
            suffix = unquote(parsed.path[len("/api/import/"):])
            error_export = suffix.endswith("/errors")
            import_id = suffix[:-7] if error_export else suffix
            if not import_id or "/" in import_id:
                raise ValueError("Invalid import_id")
            service = ImportService(CONFIG)
            if error_export:
                _only(query, "format")
                export_format = _one(query, "format", required=False) or "json"
                if export_format == "csv":
                    return self.reply(200, service.error_report_csv(import_id), "text/csv; charset=utf-8",
                                      {"Content-Disposition": f'attachment; filename="soclens-import-errors-{import_id}.csv"'})
                if export_format != "json":
                    raise ValueError("format must be json or csv")
                return self.reply(200, service.error_report_json(import_id))
            _only(query)
            return self.reply(200, service.get(import_id).public_document())

        history_response = history_api(self.path, DB)
        if history_response is not None:
            return self.reply(*history_response)
        asset = static_asset(self.path)
        if asset:
            file, mime = asset
            return self.reply(200, file.read_bytes(), mime)
        if parsed.path == "/api/demo" and not parsed.query:
            try:
                before = json.loads((ROOT / "data/baseline.json").read_text(encoding="utf-8"))
                after = json.loads((ROOT / "data/degraded.json").read_text(encoding="utf-8"))
                a, b = assess(before), assess(after)
                seed_demo_history()
            except (UnsupportedDatabaseVersion, sqlite3.Error):
                raise
            except (OSError, ValueError, TypeError, KeyError) as exc:
                LOGGER.exception(
                    "Bundled demonstration initialization failed",
                    extra={"event": "demo_initialization_error", "component": "server"},
                )
                raise RuntimeError("Demo initialization failed") from exc
            return self.reply(200, {
                "baseline": a, "degraded": b, "comparison": compare(a, b),
                "assessment_ids": {"baseline": "demo-history-003", "degraded": "demo-history-002"},
                "synthetic": True,
                "notice": "Bundled synthetic demonstration data; not real CSE evidence",
            })
        return self.reply_error(404, "not_found", "Not found")

    def do_POST(self):
        return self._dispatch(self._do_POST)

    def _do_POST(self):
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            return self.reply_error(403, "cross_site_rejected", "Cross-site requests rejected")
        parsed = urlparse(self.path)
        if parsed.path == "/api/assess" and not parsed.query:
            data = read_json_request(self.headers, self.rfile, CONFIG.request_size_limit)
            report = assess(data)
            assessment_id = save(data, report, origin="import")
            return self.reply(200, report, headers={"X-Assessment-ID": assessment_id}, assessment_id=assessment_id)
        if parsed.path == "/api/import":
            query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=5)
            _only(query, "profile", "filename", "format")
            profile = _one(query, "profile")
            filename = _one(query, "filename")
            source_format = _one(query, "format")
            if source_format not in {"csv", "json"}:
                raise ValueError("format must be csv or json")
            allowed = {"text/csv", "application/csv"} if source_format == "csv" else {"application/json"}
            raw = read_upload_request(self.headers, self.rfile, CONFIG.ingestion_max_upload_bytes, allowed)
            job = ImportService(CONFIG).create(raw, filename=filename, profile_key=profile, source_format=source_format)
            return self.reply(201, job.public_document(), assessment_id=None)
        if parsed.path == "/api/preparation" and not parsed.query:
            request = read_json_request(self.headers, self.rfile, CONFIG.request_size_limit)
            session = PreparationService(CONFIG).create(request)
            return self.reply(201, session.document())
        if parsed.path == "/api/assessment-build" and not parsed.query:
            request = read_json_request(self.headers, self.rfile, CONFIG.request_size_limit)
            if not isinstance(request, dict):
                raise ValueError("Assessment build request must be a JSON object")
            allowed = {"import_ids", "session_id", "scope", "as_of", "synthetic", "action"}
            if set(request) - allowed:
                raise ValueError("Unexpected assessment build field(s): " + ", ".join(sorted(set(request) - allowed)))
            session_id = request.get("session_id")
            if session_id is not None:
                if "import_ids" in request or any(name in request for name in ("scope", "as_of", "synthetic")):
                    raise ValueError("A session build must use its persisted preparation fields")
                session = PreparationService(CONFIG).get(session_id)
                import_ids, scope, as_of, synthetic = session.import_ids, session.scope, session.as_of, session.synthetic
            else:
                import_ids = request.get("import_ids")
                scope, as_of, synthetic = request.get("scope"), request.get("as_of"), request.get("synthetic")
            if not isinstance(import_ids, list) or not import_ids or len(import_ids) > CONFIG.ingestion_max_active_imports:
                raise ValueError("import_ids must be a nonempty bounded array")
            service = ImportService(CONFIG)
            jobs = [service.get(import_id) for import_id in import_ids]
            result = assemble_imports(jobs, scope=scope, as_of=as_of, synthetic=synthetic)
            action = request.get("action", "preview")
            if action not in {"preview", "assess"}:
                raise ValueError("action must be preview or assess")
            if action == "preview":
                return self.reply(200, {key: value for key, value in result.items() if key != "evidence"})
            if not result["ready"]:
                body = error_document("incomplete_evidence", "Canonical evidence coverage is incomplete")
                body.update({key: value for key, value in result.items() if key != "evidence"})
                return self.reply(422, body)
            evidence = result["evidence"]
            report = assess(evidence)
            if result.get("correlation"):
                enrich_report(report, result["correlation"])
                report["supervisory_summary"] = supervisor_summary(report)
            report["ingestion_provenance"] = {
                "ingested_at": datetime.now(timezone.utc).isoformat(),
                "canonical_evidence_sha256": result["canonical_output_sha256"],
                "imports": [{"import_id": job.import_id, "filename": job.original_filename,
                             "file_sha256": job.file_sha256, "source_profile": job.source_profile,
                             "mapping_profile_id": job.mapping_profile_id,
                             "mapping_profile_version": job.mapping_profile_version} for job in jobs],
            }
            if result.get("correlation"):
                report["ingestion_provenance"]["correlation_version"] = result["correlation"]["version"]
                report["ingestion_provenance"]["correlation_output_sha256"] = result["correlation"]["correlation_output_sha256"]
            assessment_id = save(evidence, report, origin="ingestion")
            if session_id is not None:
                PreparationService(CONFIG).mark_complete(session_id)
            return self.reply(200, report, headers={"X-Assessment-ID": assessment_id}, assessment_id=assessment_id)
        return self.reply_error(404, "not_found", "Not found")

    def do_DELETE(self):
        return self._dispatch(self._do_DELETE)

    def _do_DELETE(self):
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            return self.reply_error(403, "cross_site_rejected", "Cross-site requests rejected")
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/preparation/") and not parsed.query:
            session_id = unquote(parsed.path[len("/api/preparation/"):])
            if not session_id or "/" in session_id:
                raise ValueError("Invalid session_id")
            PreparationService(CONFIG).delete(session_id)
            return self.reply(200, {"deleted": True, "session_id": session_id})
        if not parsed.path.startswith("/api/import/") or parsed.query:
            return self.reply_error(404, "not_found", "Not found")
        import_id = unquote(parsed.path[len("/api/import/"):])
        if not import_id or "/" in import_id:
            raise ValueError("Invalid import_id")
        ImportService(CONFIG).delete(import_id)
        return self.reply(200, {"deleted": True, "import_id": import_id})

    def do_PUT(self):
        return self._dispatch(self._do_PUT)

    def _do_PUT(self):
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            return self.reply_error(403, "cross_site_rejected", "Cross-site requests rejected")
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/preparation/") or parsed.query:
            return self.reply_error(404, "not_found", "Not found")
        session_id = unquote(parsed.path[len("/api/preparation/"):])
        if not session_id or "/" in session_id:
            raise ValueError("Invalid session_id")
        request = read_json_request(self.headers, self.rfile, CONFIG.request_size_limit)
        return self.reply(200, PreparationService(CONFIG).update(session_id, request).document())

    def method_not_allowed(self):
        return self.reply(
            405,
            error_document("method_not_allowed", f"Method {self.command} is not supported"),
            headers={"Allow": "GET, POST, PUT, DELETE"},
        )

    do_PATCH = method_not_allowed
    do_OPTIONS = method_not_allowed
    do_HEAD = method_not_allowed
    do_TRACE = method_not_allowed
    do_CONNECT = method_not_allowed


def initialize_service(config=CONFIG):
    initialize_runtime_directories(config)
    configure_logging(config)
    initialize_database(config.database_path)
    seed_demo_history(config.database_path)
    status = operational_status(config, config.database_path)
    if status["status"] != "ready":
        raise RuntimeError("SOCLens readiness checks failed during startup")
    return status


def main() -> int:
    try:
        status = initialize_service(CONFIG)
    except (ConfigurationError, UnsupportedDatabaseVersion, OSError, ValueError, TypeError, KeyError, sqlite3.Error, RuntimeError) as exc:
        LOGGER.exception(
            "SOCLens initialization failed",
            extra={"event": "service_start_failed", "component": "startup"},
        )
        raise SystemExit(f"SOCLens initialization failed: {exc}") from None
    LOGGER.info(
        "SOCLens service starting",
        extra={
            "event": "service_start",
            "component": "startup",
            "version": APP_VERSION,
            "environment": CONFIG.environment,
            "host": CONFIG.host,
            "port": CONFIG.port,
            "schema_version": status["database"]["schema_version"],
            "database_ready": status["database"]["ready"],
            "policy_version": POLICY["id"],
            "report_schema_version": REPORT_SCHEMA_VERSION,
        },
    )
    try:
        local_server = ServiceServer((CONFIG.host, CONFIG.port), Handler)
    except OSError as exc:
        LOGGER.error(
            "SOCLens bind failed",
            extra={"event": "service_bind_failed", "component": "startup", "host": CONFIG.host, "port": CONFIG.port},
        )
        raise SystemExit("SOCLens could not bind the configured host and port") from None
    try:
        local_server.serve_forever()
    except KeyboardInterrupt:
        LOGGER.info(
            "SOCLens service shutdown requested",
            extra={"event": "service_shutdown_requested", "component": "shutdown"},
        )
    finally:
        local_server.server_close()
        LOGGER.info(
            "SOCLens service stopped",
            extra={"event": "service_stopped", "component": "shutdown"},
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
