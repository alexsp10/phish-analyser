"""Drag-and-drop interface: a tiny local web server plus a single page.

Run ``phishcheck --gui`` (or double-click ``PhishCheck.bat``). The page opens
in your browser; drop an ``.eml`` file on it and the result appears in a pop-up.

Security model, because a local server is still a server:

* it listens on 127.0.0.1 only, so other machines can't reach it;
* every request must carry a random per-session token that is only embedded
  in the page this server served, so other websites open in your browser
  can't submit files to it (CSRF);
* the Host header must be 127.0.0.1/localhost, which blocks DNS-rebinding;
* uploads are size-limited and only analysed in memory (mbox archives go to a
  temporary file that is deleted straight after);
* the page has a strict Content-Security-Policy and renders all email text
  with ``textContent``, never as HTML.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from . import __version__
from .checks import analyse
from .intel import IntelClient
from .lookalike import BrandCatalog
from .parser import iter_file, parse_bytes
from .report import to_dict

MAX_UPLOAD = 25 * 1024 * 1024  # Gmail's own attachment limit


class AppState:
    def __init__(
        self,
        catalog: BrandCatalog,
        intel: IntelClient | None = None,
        max_lookups: int = 4,
        allow_vscode: bool = False,
    ):
        self.catalog = catalog
        self.intel = intel
        self.max_lookups = max_lookups
        # The page normally refuses to be framed (anti-clickjacking). With --vscode it may be
        # framed only by VS Code's Simple Browser (vscode-webview: inside the vscode-file: workbench).
        self.frame_ancestors = "'self' vscode-webview: vscode-file:" if allow_vscode else "'none'"
        self.token = secrets.token_urlsafe(32)
        self.nonce = secrets.token_urlsafe(16)
        self.lock = threading.Lock()

    def page(self) -> bytes:
        template = resources.files("phishcheck").joinpath("ui.html").read_text(encoding="utf-8")
        return (
            template.replace("<!--CSP-->", "")  # the server sends its CSP as an HTTP header
            .replace("__TOKEN__", self.token)
            .replace("__NONCE__", self.nonce)
            .replace("__VERSION__", __version__)
            .replace("__MAX_UPLOAD__", str(MAX_UPLOAD))
            .encode("utf-8")
        )

    def analyse_upload(self, data: bytes, filename: str) -> list[dict[str, Any]]:
        if data[:5] == b"From ":  # mbox archive (Gmail Takeout)
            handle, temp_path = tempfile.mkstemp(suffix=".mbox")
            try:
                with os.fdopen(handle, "wb") as temp:
                    temp.write(data)
                emails = list(iter_file(Path(temp_path)))
            finally:
                os.unlink(temp_path)
        else:
            emails = [parse_bytes(data, filename)]
        for email in emails:
            email.source = filename if len(emails) == 1 else f"{filename} #{emails.index(email) + 1}"

        results = []
        for email in emails:
            extra = []
            if self.intel:
                with self.lock:  # shared lookup budget and rate limits
                    self.intel.remaining = self.max_lookups
                    extra = self.intel.lookup(email, self.catalog)
            results.append(to_dict(analyse(email, self.catalog, extra)))
        return results


def make_handler(state: AppState, allowed_hosts: set[str]) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "phishcheck"
        sys_version = ""

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - keep the console quiet
            return

        def _headers(self, status: int, content_type: str, length: int) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()

        def _json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self._headers(status, "application/json; charset=utf-8", len(body))
            self.wfile.write(body)

        def _host_ok(self) -> bool:
            return (self.headers.get("Host") or "").lower() in allowed_hosts

        def do_GET(self) -> None:  # noqa: N802 - http.server naming
            if not self._host_ok():
                self._json(HTTPStatus.FORBIDDEN, {"error": "bad host"})
                return
            if self.path not in ("/", "/index.html"):
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            body = state.page()
            self.send_response(HTTPStatus.OK)
            self.send_header(
                "Content-Security-Policy",
                f"default-src 'none'; script-src 'nonce-{state.nonce}'; style-src 'unsafe-inline'; "
                "img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; "
                f"frame-ancestors {state.frame_ancestors}",
            )
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            if not self._host_ok():
                self._json(HTTPStatus.FORBIDDEN, {"error": "bad host"})
                return
            if self.path != "/api/analyze":
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            if not secrets.compare_digest(self.headers.get("X-Phishcheck-Token", ""), state.token):
                self._json(HTTPStatus.FORBIDDEN, {"error": "missing or invalid session token; reload the page"})
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._json(HTTPStatus.LENGTH_REQUIRED, {"error": "Content-Length required"})
                return
            if length <= 0:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "the file is empty"})
                return
            if length > MAX_UPLOAD:
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "file is larger than 25 MB"})
                return
            data = self.rfile.read(length)
            filename = unquote(self.headers.get("X-Filename", "email.eml"))[:200] or "email.eml"
            try:
                results = state.analyse_upload(data, filename)
            except Exception as exc:  # noqa: BLE001 - report any parsing failure to the page
                self._json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": f"could not analyse this file: {exc}"})
                return
            if not results:
                self._json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": "no emails found in this file"})
                return
            self._json(HTTPStatus.OK, {"results": results})

    return Handler


def create_server(state: AppState, port: int = 0) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state, set()))
    actual = server.server_address[1]
    server.RequestHandlerClass = make_handler(state, {f"127.0.0.1:{actual}", f"localhost:{actual}"})
    return server


def serve(state: AppState, port: int = 8765, open_browser: bool = True) -> int:
    try:
        server = create_server(state, port)
    except OSError:
        server = create_server(state, 0)  # preferred port busy: pick a free one
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"PhishCheck is running at {url}")
    if state.frame_ancestors != "'none'":
        print("To open it inside VS Code: Ctrl+Shift+P > 'Simple Browser: Show' > paste the address above.")
        print("When dropping a file into VS Code's Simple Browser, hold Shift while you let go.")
    print("Drop an .eml file on the page. Everything stays on this computer.")
    print("Press Ctrl+C here to stop.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0


def main() -> int:
    """Entry point for the ``phishcheck-gui`` command."""
    from .cli import main as cli_main

    return cli_main(["--gui"])
