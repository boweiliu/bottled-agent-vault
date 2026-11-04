"""End-to-end checks of auth_proxy.py against a real agent-vault binary.

Run with AGENT_VAULT_BIN pointing at an agent-vault release binary:

    AGENT_VAULT_BIN=/path/to/agent-vault pytest tests/

Skipped when no binary is available.
"""

from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
BINARY = os.environ.get("AGENT_VAULT_BIN") or shutil.which("agent-vault")

pytestmark = pytest.mark.skipif(not BINARY, reason="needs an agent-vault binary (set AGENT_VAULT_BIN)")

OWNER = {"X-OpenHost-Is-Owner": "true", "Accept": "text/html"}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def request(port: int, method: str, path: str, headers: dict | None = None, body: bytes | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, resp.headers, resp.read()
    finally:
        conn.close()


def session_from(headers) -> str | None:
    for value in headers.get_all("Set-Cookie") or []:
        if value.startswith("av_session="):
            return value.split(";", 1)[0].split("=", 1)[1]
    return None


def start(data_dir: Path, ports: dict) -> subprocess.Popen:
    env = {
        **os.environ,
        "BOTTLE_APP_NAME": "agent-vault",
        "BOTTLE_ZONE_DOMAIN": "example.test",
        "BOTTLE_ROUTER_PUBLIC_URL": "https://example.test",
        "BOTTLE_OWNER_USERNAME": "alice",
        "BOTTLE_APP_DATA_DIR": str(data_dir),
        "AGENT_VAULT_BIN": BINARY,
        "AUTH_PROXY_LISTEN_PORT": str(ports["listen"]),
        "AGENT_VAULT_INTERNAL_PORT": str(ports["internal"]),
        "AGENT_VAULT_MITM_PORT": str(ports["mitm"]),
    }
    script = (REPO / "entrypoint.sh").read_text().replace("/app/auth_proxy.py", str(REPO / "auth_proxy.py"))
    proc = subprocess.Popen(["sh", "-c", script], env=env)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if request(ports["listen"], "GET", "/health")[0] == 200:
                return proc
        except OSError:
            pass
        time.sleep(0.3)
    proc.kill()
    raise AssertionError("auth proxy did not come up")


@pytest.fixture
def app(tmp_path):
    ports = {"listen": free_port(), "internal": free_port(), "mitm": free_port()}
    proc = start(tmp_path, ports)
    yield tmp_path, ports, proc
    proc.terminate()
    proc.wait(timeout=15)


def test_first_boot_registers_owner_with_private_credentials(app):
    data_dir, ports, _ = app
    creds_file = data_dir / "owner-credentials.json"
    creds = json.loads(creds_file.read_text())
    assert creds["email"] == "alice@example.test"
    assert len(creds["password"]) >= 16
    assert creds_file.stat().st_mode & 0o077 == 0
    status, _, body = request(ports["listen"], "GET", "/discover")
    assert json.loads(body).get("error") != "not_initialized"


def test_owner_page_load_gets_signed_in(app):
    _, ports, _ = app
    status, headers, _ = request(ports["listen"], "GET", "/vaults", OWNER)
    assert status == 302
    assert headers["Location"] == "/vaults"
    token = session_from(headers)
    assert token
    status, _, body = request(ports["listen"], "GET", "/v1/auth/me", {"Cookie": f"av_session={token}"})
    assert status == 200
    me = json.loads(body)
    assert me["email"] == "alice@example.test" and me["is_owner"]


def test_owner_with_valid_session_is_passed_through(app):
    _, ports, _ = app
    _, headers, _ = request(ports["listen"], "GET", "/", OWNER)
    token = session_from(headers)
    status, headers, _ = request(ports["listen"], "GET", "/", {**OWNER, "Cookie": f"av_session={token}"})
    assert status == 200
    assert session_from(headers) is None
    # A second sign-in reuses the same session instead of minting a new one.
    _, headers, _ = request(ports["listen"], "GET", "/", OWNER)
    assert session_from(headers) == token


def test_owner_is_sent_past_the_login_form(app):
    _, ports, _ = app
    status, headers, _ = request(ports["listen"], "GET", "/login", OWNER)
    assert status == 302 and headers["Location"] == "/"


def test_redirect_loop_guard(app):
    _, ports, _ = app
    status, _, _ = request(ports["listen"], "GET", "/", {**OWNER, "Cookie": "av_bottle_autologin=1"})
    assert status == 200


def test_non_owner_is_not_signed_in(app):
    _, ports, _ = app
    status, headers, _ = request(ports["listen"], "GET", "/", {"Accept": "text/html"})
    assert status == 200
    assert session_from(headers) is None


def test_credentials_page_is_owner_only(app):
    data_dir, ports, _ = app
    creds = json.loads((data_dir / "owner-credentials.json").read_text())
    status, _, body = request(ports["listen"], "GET", "/_bottle/owner-login", {"X-OpenHost-Is-Owner": "true"})
    assert status == 200 and creds["password"].encode() in body
    status, _, body = request(ports["listen"], "GET", "/_bottle/owner-login")
    assert status == 403 and creds["password"].encode() not in body


def test_api_is_proxied_for_agents(app):
    data_dir, ports, _ = app
    creds = json.loads((data_dir / "owner-credentials.json").read_text())
    status, _, body = request(
        ports["listen"],
        "POST",
        "/v1/auth/login",
        {"Content-Type": "application/json"},
        json.dumps({"email": creds["email"], "password": creds["password"]}).encode(),
    )
    assert status == 200 and json.loads(body)["token"]
    status, headers, body = request(ports["listen"], "GET", "/v1/mitm/ca.pem")
    assert status == 200 and body.startswith(b"-----BEGIN CERTIFICATE-----")
    assert headers["X-MITM-Port"] == str(ports["mitm"])


def test_restart_keeps_the_owner_and_still_signs_in(tmp_path):
    ports = {"listen": free_port(), "internal": free_port(), "mitm": free_port()}
    proc = start(tmp_path, ports)
    first = json.loads((tmp_path / "owner-credentials.json").read_text())
    proc.terminate()
    proc.wait(timeout=15)
    proc = start(tmp_path, ports)
    try:
        assert json.loads((tmp_path / "owner-credentials.json").read_text()) == first
        status, headers, _ = request(ports["listen"], "GET", "/", OWNER)
        assert status == 302 and session_from(headers)
    finally:
        proc.terminate()
        proc.wait(timeout=15)
