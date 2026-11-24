"""Dashboard server: `python3 ui/server.py` then open http://127.0.0.1:8088

Pure standard library (http.server) plus the project's own modules. Binds to 127.0.0.1 only.
"""
import argparse
import json
import mimetypes
import os
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import keystore
from attacks import demo_attacks
from ui.lab import Hub, Lab

STATIC = os.path.join(ROOT, "ui", "static")
hub = Hub()
lab = None
attack_lock = threading.Lock()


def read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def results():
    """Official netns results if present, otherwise the shipped loopback sample (flagged)."""
    for rel, source in (("results", "netns"), ("results/sample_loopback", "sample")):
        s = read_json(os.path.join(ROOT, rel, "summary.json"))
        if s:
            return dict(source=source, summary=s, meta=read_json(os.path.join(ROOT, rel, "meta.json")),
                        overhead={n[len("overhead_"):-5]: read_json(os.path.join(ROOT, rel, n))
                                  for n in os.listdir(os.path.join(ROOT, rel)) if n.startswith("overhead_")})
    return dict(source="none", summary=None, meta=None, overhead={})


def evidence():
    out = {}
    for sub in ("evidence/captures", "evidence", "results/plots", "results/sample_loopback/plots", "docs"):
        d = os.path.join(ROOT, sub)
        if os.path.isdir(d):
            out[sub] = sorted(f for f in os.listdir(d) if os.path.isfile(os.path.join(d, f)))
    return out


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    # ------------------------------------------------------------ helpers
    def send_body(self, body, ctype="application/json", code=200):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, default=str).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}") if n else {}

    def file(self, base, rel):
        path = os.path.normpath(os.path.join(base, rel))
        if not path.startswith(base) or not os.path.isfile(path):
            return self.send_body({"error": "not found"}, code=404)
        ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        with open(path, "rb") as f:
            self.send_body(f.read(), ctype)

    # ------------------------------------------------------------ routes
    def do_GET(self):
        p = unquote(urlparse(self.path).path)
        if p in ("/", "/index.html"):
            return self.file(STATIC, "index.html")
        if p.startswith("/static/"):
            return self.file(STATIC, p[8:])
        if p.startswith("/files/"):                      # evidence, plots, docs (read-only)
            rel = p[7:]
            if rel == "README.md" or rel.split("/")[0] in ("evidence", "results", "docs"):
                return self.file(ROOT, rel)
            return self.send_body({"error": "forbidden"}, code=403)
        if p == "/api/state":
            return self.send_body(lab.state())
        if p == "/api/results":
            return self.send_body(results())
        if p == "/api/evidence":
            return self.send_body(evidence())
        if p == "/api/attacks":
            return self.send_body([dict(id=k) for k in demo_attacks.ALL])
        if p == "/api/events":
            return self.sse()
        self.send_body({"error": "not found"}, code=404)

    def do_POST(self):
        p = urlparse(self.path).path
        try:
            data = self.body()
            if p == "/api/lab":
                return self.send_body(lab.rebuild(**{k: data[k] for k in ("mode", "tamper", "evil", "pin") if k in data}))
            if p == "/api/send":
                return self.send_body(dict(ok=lab.send(data["who"], data["text"][:500])))
            if p == "/api/rogue-client":
                return self.send_body(lab.rogue_client())
            if p.startswith("/api/attack/"):
                name = p.rsplit("/", 1)[1]
                if name not in demo_attacks.ALL:
                    return self.send_body({"error": "unknown attack"}, code=404)
                with attack_lock:                        # scenarios swap the key directory
                    saved = keystore.KEY_DIR
                    try:
                        import tempfile
                        keystore.KEY_DIR = tempfile.mkdtemp()
                        res = demo_attacks.ALL[name]()
                    finally:
                        keystore.KEY_DIR = saved
                return self.send_body(res)
        except Exception as e:                           # surface errors to the UI instead of dropping the socket
            return self.send_body({"error": f"{type(e).__name__}: {e}"}, code=500)
        self.send_body({"error": "not found"}, code=404)

    def sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        q = hub.subscribe()
        try:
            self.wfile.write(b": hello\n\n"); self.wfile.flush()
            while True:
                try:
                    evt = q.get(timeout=15)
                    chunk = f"data: {json.dumps(evt, default=str)}\n\n".encode()
                except Exception:
                    chunk = b": keepalive\n\n"
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            hub.unsubscribe(q)


def main():
    global lab
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--open", action="store_true", help="open the browser")
    a = ap.parse_args()
    lab = Lab(hub)
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    srv.daemon_threads = True
    url = f"http://127.0.0.1:{a.port}"
    print(f"dashboard: {url}   (Ctrl+C to stop)")
    if a.open:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
