"""SOCLens local demonstrator. Python 3.10+, no pip packages required."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse
import json
import sqlite3
from engine import assess, compare
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
from reporting import audit_package

ROOT = Path(__file__).parent
DB = ROOT / "assessments.sqlite3"
MAX_BODY_BYTES = 2_000_000
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/sample.json": ("data/baseline.json", "application/json; charset=utf-8"),
}


class UnsupportedMediaType(ValueError):
    pass

def save(data, report, **metadata):
    return store_assessment(DB, data, report, **metadata)


def static_asset(path):
    parsed = urlparse(path)
    entry = STATIC_FILES.get(parsed.path) if not parsed.query else None
    if entry is None:
        return None
    relative, content_type = entry
    target = (ROOT / relative).resolve()
    if not target.is_relative_to(ROOT.resolve()):
        return None
    return target, content_type


def read_json_request(headers, stream):
    if headers.get("Transfer-Encoding"):
        raise ValueError("Transfer-Encoding is not supported")
    if headers.get_content_type() != "application/json":
        raise UnsupportedMediaType("Content-Type must be application/json")
    try:
        length = int(headers.get("Content-Length", "0"))
    except (TypeError, ValueError) as exc:
        raise ValueError("Content-Length must be an integer") from exc
    if not 0 < length <= MAX_BODY_BYTES:
        raise ValueError("Upload limit is 2 MB")
    raw = stream.read(length)
    if len(raw) != length:
        raise ValueError("Request body ended before Content-Length bytes were received")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("Request body must contain valid UTF-8 JSON") from exc


def seed_demo_history():
    initialize_database(DB)
    history_file = ROOT / "data" / "demo-history.json"
    if not history_file.exists():
        raise FileNotFoundError("Bundled demo history fixture is missing")
    for item in json.loads(history_file.read_text()):
        assessment_id = item["assessment_id"]
        if assessment_exists(DB, assessment_id):
            continue
        evidence = item["evidence"]
        store_assessment(
            DB, evidence, assess(evidence), assessment_id=assessment_id,
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
        record = get_assessment(database, assessment_id)
        return 200, record
    return None

class Handler(BaseHTTPRequestHandler):
    def reply(self, status, body, content_type="application/json; charset=utf-8", headers=None):
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

    def do_GET(self):
        try:
            history_response = history_api(self.path, DB)
            if history_response is not None:
                return self.reply(*history_response)
        except HistoryNotFound as exc:
            return self.reply(404, {"error": str(exc)})
        except ComparisonUnavailable as exc:
            return self.reply(409, {"error": str(exc), "comparable": False})
        except UnsupportedDatabaseVersion as exc:
            return self.reply(503, {"error": str(exc)})
        except sqlite3.Error:
            return self.reply(500, {"error": "Local persistence operation failed"})
        except (ValueError, TypeError, KeyError) as exc:
            return self.reply(400, {"error": str(exc)})
        parsed = urlparse(self.path)
        asset = static_asset(self.path)
        if asset:
            file, mime = asset
            return self.reply(200, file.read_bytes(), mime)
        if parsed.path == "/api/demo" and not parsed.query:
            try:
                before = json.loads((ROOT / "data/baseline.json").read_text())
                after = json.loads((ROOT / "data/degraded.json").read_text())
                a, b = assess(before), assess(after)
                seed_demo_history()
            except UnsupportedDatabaseVersion as exc:
                return self.reply(503, {"error": str(exc)})
            except sqlite3.Error:
                return self.reply(500, {"error": "Local persistence operation failed"})
            except (OSError, ValueError, TypeError, KeyError):
                return self.reply(500, {"error": "Bundled synthetic demonstration data could not be initialized"})
            return self.reply(200, {
                "baseline": a, "degraded": b, "comparison": compare(a, b),
                "assessment_ids": {"baseline": "demo-history-003", "degraded": "demo-history-002"},
                "synthetic": True,
                "notice": "Bundled synthetic demonstration data; not real CSE evidence",
            })
        return self.reply(404, {"error": "Not found"})

    def do_POST(self):
        if self.path != "/api/assess":
            return self.reply(404, {"error": "Not found"})
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            return self.reply(403, {"error": "Cross-site requests rejected"})
        try:
            data = read_json_request(self.headers, self.rfile)
            report = assess(data)
            assessment_id = save(data, report, origin="import")
            self.reply(200, report, headers={"X-Assessment-ID": assessment_id})
        except UnsupportedDatabaseVersion as exc:
            self.reply(503, {"error": str(exc)})
        except sqlite3.Error:
            self.reply(500, {"error": "Local persistence operation failed"})
        except UnsupportedMediaType as exc:
            self.reply(415, {"error": str(exc)})
        except (ValueError, TypeError, KeyError) as exc:
            self.reply(400, {"error": str(exc)})

    def method_not_allowed(self):
        self.reply(405, {"error": f"Method {self.command} is not supported"}, headers={"Allow": "GET, POST"})

    do_PUT = method_not_allowed
    do_PATCH = method_not_allowed
    do_DELETE = method_not_allowed
    do_OPTIONS = method_not_allowed
    do_HEAD = method_not_allowed
    do_TRACE = method_not_allowed
    do_CONNECT = method_not_allowed

if __name__ == "__main__":
    try:
        initialize_database(DB)
        seed_demo_history()
    except UnsupportedDatabaseVersion as exc:
        raise SystemExit(str(exc))
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error) as exc:
        raise SystemExit(f"SOCLens initialization failed: {exc}")
    print("SOCLens local demo: http://127.0.0.1:8765", flush=True)
    local_server = ThreadingHTTPServer(("127.0.0.1", 8765), Handler)
    try:
        local_server.serve_forever()
    except KeyboardInterrupt:
        print("\nSOCLens local demo stopped.", flush=True)
    finally:
        local_server.server_close()
