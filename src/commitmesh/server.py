"""Hosted *check-only* service: verifies records offline. It never holds signing keys."""
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import schema as s
from .record import decode_public_key, verify_record

MAX_BODY = 128 * 1024
_slots = threading.BoundedSemaphore(32)  # cap concurrent requests


def check_body(body: bytes, now=None):
    doc = s.loads_strict(body)
    s.keys(doc, ["record", "public_key"], name="request")
    pub = decode_public_key(s.text(doc["public_key"], "public_key", 100))
    ok, reason, payload = verify_record(doc["record"], pub, int(now or time.time()))
    return {"valid": ok, "reason": reason, "outcome_mark": (payload or {}).get("outcome_mark"),
            "record_id": (payload or {}).get("record_id"),
            "note": "valid means authentic, unexpired and unmodified; check revocation separately."}


class Handler(BaseHTTPRequestHandler):
    server_version = "commitmesh"
    sys_version = ""
    timeout = 10  # slow-client protection

    def _send(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        for k, v in (("Content-Type", "application/json"), ("Content-Length", str(len(data))),
                     ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"),
                     ("Content-Security-Policy", "default-src 'none'")):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"status": "ok"})
        if self.path == "/":
            return self._send(200, {"service": "commitmesh record checker", "post": "/v1/check-record"})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/v1/check-record":
            return self._send(404, {"error": "not found"})
        if not _slots.acquire(blocking=False):
            return self._send(503, {"error": "busy"})
        try:
            if "json" not in (self.headers.get("Content-Type") or ""):
                return self._send(415, {"error": "content-type must be application/json"})
            try:
                n = int(self.headers.get("Content-Length", ""))
            except ValueError:
                return self._send(411, {"error": "Content-Length required"})
            if not 0 < n <= MAX_BODY:
                return self._send(413, {"error": "body too large"})
            try:
                self._send(200, check_body(self.rfile.read(n)))
            except (s.ValidationError, ValueError) as e:
                self._send(400, {"error": str(e)[:200]})
        finally:
            _slots.release()

    def log_message(self, fmt, *args):  # never log bodies
        print(f"{self.command} {self.path.split('?')[0]}", flush=True)


def main():
    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
