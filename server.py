"""SOCLens local service. Python 3.10+, no pip packages required."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse
import json
import logging
import sqlite3

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
from reporting import REPORT_SCHEMA_VERSION, audit_package


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
        if self.path != "/api/assess":
            return self.reply_error(404, "not_found", "Not found")
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            return self.reply_error(403, "cross_site_rejected", "Cross-site requests rejected")
        data = read_json_request(self.headers, self.rfile, CONFIG.request_size_limit)
        report = assess(data)
        assessment_id = save(data, report, origin="import")
        return self.reply(
            200, report, headers={"X-Assessment-ID": assessment_id}, assessment_id=assessment_id
        )

    def method_not_allowed(self):
        return self.reply(
            405,
            error_document("method_not_allowed", f"Method {self.command} is not supported"),
            headers={"Allow": "GET, POST"},
        )

    do_PUT = method_not_allowed
    do_PATCH = method_not_allowed
    do_DELETE = method_not_allowed
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
