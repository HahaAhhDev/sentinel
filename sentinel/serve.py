import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from . import baseline, respond
from .report import build_html, scan_files


class Top(BaseHTTPRequestHandler):
    # dead simple page server
    folder = "."

    def log_message(self, *a):
        pass

    def do_GET(self):
        root = os.path.abspath(self.folder)
        if self.path.startswith("/json"):
            import json

            try:
                v = baseline.verify(root)
            except FileNotFoundError:
                v = {"changed": [], "new": [], "deleted": [], "meta": {}}
            rows = scan_files(root)
            body = json.dumps({"verify": v, "scan": rows[:50]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        try:
            v = baseline.verify(root)
        except FileNotFoundError:
            v = {"changed": [], "new": [], "deleted": [], "meta": {}}
        rows = scan_files(root)
        evts = respond.read_json_log(root, 100)
        html = build_html(root, v, rows, evts).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)


def serve(root, port=8000):
    # block here, ctrl-c stops
    Top.folder = os.path.abspath(root)
    srv = HTTPServer(("127.0.0.1", port), Top)
    print(f"serving {root} on http://127.0.0.1:{port}  (json at /json)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


def serve_bg(root, port=8000):
    # for tests
    Top.folder = os.path.abspath(root)
    srv = HTTPServer(("127.0.0.1", port), Top)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv
