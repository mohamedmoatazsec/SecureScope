"""A tiny configurable HTTP(S) server for end-to-end tests. No network needed."""

from __future__ import annotations

import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Profile:
    """What the test server should answer with."""

    def __init__(
        self,
        headers: dict[str, str] | None = None,
        cookies: list[str] | None = None,
        body: str = "<!doctype html><html><body><h1>test</h1></body></html>",
        content_type: str = "text/html; charset=utf-8",
        reflect_origin: bool = False,
        allow_credentials: bool = False,
        trace: bool = False,
        allow_header: str = "GET, HEAD, OPTIONS",
        robots: str | None = None,
        security_txt: str | None = None,
        status: int = 200,
    ):
        self.headers = headers or {}
        self.cookies = cookies or []
        self.body = body
        self.content_type = content_type
        self.reflect_origin = reflect_origin
        self.allow_credentials = allow_credentials
        self.trace = trace
        self.allow_header = allow_header
        self.robots = robots
        self.security_txt = security_txt
        self.status = status


class Handler(BaseHTTPRequestHandler):
    profile = Profile()
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # silence
        pass

    def version_string(self):  # a clean Server header unless the profile sets one
        return self.profile.headers.get("Server", "testserver")

    def send_response(self, code, message=None):
        # BaseHTTPRequestHandler adds its own Server header; profiles that set one would duplicate it.
        self.log_request(code)
        self.send_response_only(code, message)
        if "Server" not in self.profile.headers:
            self.send_header("Server", self.version_string())
        self.send_header("Date", self.date_time_string())

    def _send(self, status: int, body: bytes, content_type: str, extra: dict[str, str] | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _common_headers(self) -> dict[str, str]:
        headers = dict(self.profile.headers)
        origin = self.headers.get("Origin")
        if origin and self.profile.reflect_origin:
            headers["Access-Control-Allow-Origin"] = origin
            if self.profile.allow_credentials:
                headers["Access-Control-Allow-Credentials"] = "true"
        return headers

    def do_GET(self):
        p = self.profile
        if self.path == "/robots.txt":
            if p.robots is None:
                return self._send(404, b"not found", "text/plain")
            return self._send(200, p.robots.encode(), "text/plain")
        if self.path in ("/.well-known/security.txt", "/security.txt"):
            if p.security_txt is None:
                return self._send(404, b"not found", "text/plain")
            return self._send(200, p.security_txt.encode(), "text/plain")

        self.send_response(p.status)
        body = p.body.encode()
        self.send_header("Content-Type", p.content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in self._common_headers().items():
            self.send_header(name, value)
        for cookie in p.cookies:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        headers = self._common_headers()
        headers["Allow"] = self.profile.allow_header
        self._send(204, b"", "text/plain", headers)

    def do_TRACE(self):
        if not self.profile.trace:
            return self._send(405, b"", "text/plain", {"Allow": self.profile.allow_header})
        echo = f"TRACE {self.path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in self.headers.items())
        self._send(200, echo.encode(), "message/http")


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):  # protocol probes hang up mid-handshake; expected
        pass


class TestServer:
    def __init__(self, profile: Profile, tls: bool = False):
        Handler.profile = profile
        self.httpd = QuietServer(("127.0.0.1", 0), Handler)
        self.tls = tls
        self._tmp = None
        if tls:
            self._tmp = tempfile.TemporaryDirectory()
            cert = Path(self._tmp.name) / "cert.pem"
            key = Path(self._tmp.name) / "key.pem"
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-days",
                    "2",
                    "-subj",
                    "/CN=localhost",
                    "-addext",
                    "subjectAltName=DNS:localhost,IP:127.0.0.1",
                ],
                check=True,
                capture_output=True,
            )
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(cert), str(key))
            self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    @property
    def url(self) -> str:
        return f"{'https' if self.tls else 'http'}://127.0.0.1:{self.port}/"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._tmp:
            self._tmp.cleanup()
