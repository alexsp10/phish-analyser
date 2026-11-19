"""The drag-and-drop server: functionality and its security controls."""

from __future__ import annotations

import http.client
import json
import re
import threading

import pytest
from conftest import SAMPLES

from phishcheck import web
from phishcheck.web import AppState, create_server


@pytest.fixture()
def server(catalog):
    state = AppState(catalog)
    srv = create_server(state, 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield state, srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def request(port, method, path, body=None, headers=None, host=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.putrequest(method, path, skip_host=True)
    conn.putheader("Host", host or f"127.0.0.1:{port}")
    for name, value in (headers or {}).items():
        conn.putheader(name, value)
    conn.putheader("Content-Length", str(len(body or b"")))
    conn.endheaders(body or b"")
    response = conn.getresponse()
    data = response.read()
    conn.close()
    return response, data


def upload(port, token, data, filename="mail.eml", **kwargs):
    headers = {"X-Phishcheck-Token": token, "X-Filename": filename}
    return request(port, "POST", "/api/analyze", data, headers, **kwargs)


def test_page_is_served_with_token_and_strict_csp(server):
    state, port = server
    response, body = request(port, "GET", "/")
    html = body.decode()
    assert response.status == 200
    assert state.token in html and "__TOKEN__" not in html
    csp = response.getheader("Content-Security-Policy")
    assert "default-src 'none'" in csp and f"nonce-{state.nonce}" in csp
    assert f'<script nonce="{state.nonce}">' in html
    assert "frame-ancestors 'none'" in csp
    # Email text is only ever rendered with textContent: no HTML-injection sinks in the page script.
    script = html.split("<script", 1)[1]
    assert not re.search(r"\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write", script)


def test_analyse_phishing_sample(server):
    state, port = server
    data = (SAMPLES / "phishing" / "02-display-name-and-link-tricks.eml").read_bytes()
    response, body = upload(port, state.token, data, "suspicious%20mail.eml")
    result = json.loads(body)["results"][0]
    assert response.status == 200
    assert result["verdict"] == "phishing" and result["verdict_label"] == "Likely phishing"
    assert result["source"] == "suspicious mail.eml"
    assert "Report phishing" in result["advice"]
    assert all("hxxp" in link["url"] for link in result["links"])  # defanged


def test_analyse_mbox_upload(server):
    state, port = server
    data = (SAMPLES / "mbox" / "takeout-sample.mbox").read_bytes()
    response, body = upload(port, state.token, data, "Spam.mbox")
    results = json.loads(body)["results"]
    assert response.status == 200 and len(results) == 2
    assert {r["verdict"] for r in results} == {"clean", "phishing"}


def test_requests_without_valid_token_are_rejected(server):
    state, port = server
    data = (SAMPLES / "clean" / "01-bank-statement.eml").read_bytes()
    assert upload(port, "wrong-token", data)[0].status == 403
    assert request(port, "POST", "/api/analyze", data)[0].status == 403


def test_foreign_host_header_is_rejected(server):
    """Blocks DNS-rebinding: a malicious site resolving its own name to 127.0.0.1."""
    state, port = server
    assert request(port, "GET", "/", host=f"evil.example:{port}")[0].status == 403
    assert upload(port, state.token, b"x", host="evil.example")[0].status == 403
    assert request(port, "GET", "/", host=f"localhost:{port}")[0].status == 200


def test_size_and_empty_limits(server, monkeypatch):
    state, port = server
    monkeypatch.setattr(web, "MAX_UPLOAD", 10)
    response, body = upload(port, state.token, b"x" * 11)
    assert response.status == 413
    assert upload(port, state.token, b"")[0].status == 400


def test_unknown_paths(server):
    state, port = server
    assert request(port, "GET", "/etc/passwd")[0].status == 404
    assert request(port, "GET", "/../README.md")[0].status == 404
    response, _ = request(port, "POST", "/other", b"x", {"X-Phishcheck-Token": state.token})
    assert response.status == 404


def test_garbage_upload_does_not_crash(server):
    state, port = server
    response, body = upload(port, state.token, bytes(range(256)) * 10, "junk.eml")
    assert response.status in (200, 422)
    assert json.loads(body)


def test_server_binds_to_localhost_only(catalog):
    srv = create_server(AppState(catalog), 0)
    try:
        assert srv.server_address[0] == "127.0.0.1"
    finally:
        srv.server_close()


def test_framing_is_denied_unless_vscode_mode(catalog):
    assert AppState(catalog).frame_ancestors == "'none'"
    allowed = AppState(catalog, allow_vscode=True).frame_ancestors
    assert "vscode-webview:" in allowed and "http" not in allowed and "*" not in allowed


def test_each_session_gets_a_fresh_token(catalog):
    assert AppState(catalog).token != AppState(catalog).token
