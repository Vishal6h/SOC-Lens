"""Local demonstrator. Python 3.10+, no pip packages required."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import sqlite3
from engine import assess, compare

ROOT = Path(__file__).parent
DB = ROOT / "assessments.sqlite3"

def save(data, report):
    with sqlite3.connect(DB) as con:
        con.execute("CREATE TABLE IF NOT EXISTS assessments (sha256 TEXT PRIMARY KEY, scope TEXT, as_of TEXT, evidence TEXT, report TEXT)")
        con.execute("INSERT OR IGNORE INTO assessments VALUES (?,?,?,?,?)", (report["sha256"], report["scope"], report["as_of"], json.dumps(data), json.dumps(report)))

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
        files = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript"), "/style.css": ("style.css", "text/css"), "/sample.json": ("data/baseline.json", "application/json")}
        if self.path in files:
            file, mime = files[self.path]
            return self.reply(200, (ROOT / file).read_bytes(), mime)
        if self.path == "/api/demo":
            before = json.loads((ROOT / "data/baseline.json").read_text())
            after = json.loads((ROOT / "data/degraded.json").read_text())
            a, b = assess(before), assess(after)
            save(before, a)
            save(after, b)
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
            save(data, report)
            self.reply(200, report)
        except (ValueError, TypeError, KeyError) as exc:
            self.reply(400, {"error": str(exc)})

if __name__ == "__main__":
    print("SAT-SA local demo: http://127.0.0.1:8765", flush=True)
    ThreadingHTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
