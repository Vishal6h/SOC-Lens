"""Local demonstrator. Python 3.10+, no pip packages required."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse
import json
from engine import assess, compare
from assessment_history import (
    ComparisonUnavailable,
    HistoryNotFound,
    assessment_exists,
    compare_stored,
    get_assessment,
    initialize_database,
    list_assessments,
    store_assessment,
    trend,
)

ROOT = Path(__file__).parent
DB = ROOT / "assessments.sqlite3"

def save(data, report, **metadata):
    return store_assessment(DB, data, report, **metadata)


def seed_demo_history():
    initialize_database(DB)
    history_file = ROOT / "data" / "demo-history.json"
    if not history_file.exists():
        return
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


def history_api(path, database=DB):
    """Return (status, body) for history routes, or None for other paths."""
    parsed = urlparse(path)
    query = parse_qs(parsed.query, keep_blank_values=True)
    if parsed.path == "/api/history":
        scope = _one(query, "scope")
        limit_value = _one(query, "limit", required=False)
        limit = int(limit_value) if limit_value is not None else 100
        return 200, {"scope": scope, "assessments": list_assessments(database, scope, limit=limit)}
    if parsed.path == "/api/history/trend":
        scope = _one(query, "scope")
        return 200, trend(database, scope)
    if parsed.path == "/api/history/compare":
        before = _one(query, "before")
        after = _one(query, "after")
        return 200, compare_stored(database, before, after)
    prefix = "/api/history/"
    if parsed.path.startswith(prefix):
        assessment_id = unquote(parsed.path[len(prefix):])
        if not assessment_id or "/" in assessment_id:
            raise ValueError("Invalid assessment_id")
        record = get_assessment(database, assessment_id)
        return 200, record
    return None

class Handler(BaseHTTPRequestHandler):
    def reply(self, status, body, content_type="application/json"):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'")
        self.end_headers()
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
        except (ValueError, TypeError, KeyError) as exc:
            return self.reply(400, {"error": str(exc)})
        parsed = urlparse(self.path)
        files = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript"), "/style.css": ("style.css", "text/css"), "/sample.json": ("data/baseline.json", "application/json")}
        if parsed.path in files and not parsed.query:
            file, mime = files[parsed.path]
            return self.reply(200, (ROOT / file).read_bytes(), mime)
        if parsed.path == "/api/demo" and not parsed.query:
            before = json.loads((ROOT / "data/baseline.json").read_text())
            after = json.loads((ROOT / "data/degraded.json").read_text())
            a, b = assess(before), assess(after)
            seed_demo_history()
            return self.reply(200, {"baseline": a, "degraded": b, "comparison": compare(a, b)})
        return self.reply(404, {"error": "Not found"})

    def do_POST(self):
        if self.path != "/api/assess":
            return self.reply(404, {"error": "Not found"})
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            return self.reply(403, {"error": "Cross-site requests rejected"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 2_000_000:
                raise ValueError("Upload limit is 2 MB")
            data = json.loads(self.rfile.read(length))
            report = assess(data)
            save(data, report, origin="import")
            self.reply(200, report)
        except (ValueError, TypeError, KeyError) as exc:
            self.reply(400, {"error": str(exc)})

if __name__ == "__main__":
    initialize_database(DB)
    seed_demo_history()
    print("SAT-SA local demo: http://127.0.0.1:8765", flush=True)
    ThreadingHTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
