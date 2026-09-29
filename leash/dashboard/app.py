"""Dashboard HTTP server (stdlib only).

Serves a single-page UI plus a small JSON API over a live Session:
  GET  /api/state             -> snapshot (events, policy, proposals, counts)
  POST /api/approve {id}      -> approve a proposal (adds the rule to the policy)
  POST /api/deny {id, reason} -> deny a proposal
  GET  /api/policy.yaml       -> current policy as OpenShell YAML
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ..policy import render_yaml
from ..session import Session

STATIC = Path(__file__).parent / "static"


def make_handler(session: Session):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code: int = 200) -> None:
            self._send(code, json.dumps(obj).encode(), "application/json")

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length", 0) or 0)
            if not n:
                return {}
            try:
                return json.loads(self.rfile.read(n))
            except ValueError:
                return {}

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
            elif self.path == "/api/state":
                self._json(session.snapshot())
            elif self.path == "/api/policy.yaml":
                snap = session.snapshot()
                y = render_yaml(snap["policy"], snap["explanations"])
                self._send(200, y.encode(), "text/plain; charset=utf-8")
            else:
                self._json({"error": "not found"}, 404)

        def do_POST(self):
            body = self._body()
            if self.path == "/api/approve":
                self._json(session.approve(body.get("id", "")))
            elif self.path == "/api/deny":
                self._json(session.deny(body.get("id", ""), body.get("reason", "")))
            else:
                self._json({"error": "not found"}, 404)
    return H


def serve(session: Session, host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), make_handler(session))
    return httpd


def run(session: Session, host: str = "127.0.0.1", port: int = 8787) -> None:
    httpd = serve(session, host, port)
    print(f"Leash dashboard on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
