"""Cloud in a Bottle owner sign-in for Agent Vault.

Runs as the container's main process. It starts the Agent Vault server on an
internal port and sits in front of its web UI/API on the port the router
forwards to:

    router (sets X-OpenHost-Is-Owner: true on owner requests)
       |
       v
    :14321  auth_proxy.py  --->  127.0.0.1:14331  agent-vault server
                                 0.0.0.0:14322    agent-vault MITM proxy

First boot: once the server is up and has no owner yet, the proxy registers
the Agent Vault owner account itself (email <owner-username>@<zone>, a
generated password) and keeps those credentials in the app data dir, mode
0600.

Every owner page load without a working Agent Vault session gets one: the
proxy logs in with the stored credentials, sets Agent Vault's own
``av_session`` cookie, and redirects back, so the owner never sees Agent
Vault's sign-in form. Everyone else (agents and CLIs on the public API paths)
is proxied untouched and authenticated by Agent Vault itself.

The router strips client-supplied X-OpenHost-* headers on every path, public
ones included, so X-OpenHost-Is-Owner can be trusted here.
"""

from __future__ import annotations

import html
import http.client
import json
import logging
import os
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OWNER_HEADER = "x-openhost-is-owner"
SESSION_COOKIE = "av_session"
# Short-lived marker that stops a redirect loop when the browser does not send
# av_session back (it is SameSite=Strict, so a navigation that started on
# another site arrives without it even after we set it).
TRIED_COOKIE = "av_bottle_autologin"
CREDENTIALS_PAGE = "/_bottle/owner-login"
SESSION_MAX_AGE = 365 * 24 * 3600
MAX_BODY_BYTES = 32 * 1024 * 1024
CHUNK = 64 * 1024

HOP_BY_HOP = frozenset(
    (
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    )
)

logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")


class Config:
    def __init__(self) -> None:
        self.listen_port = int(os.environ.get("AUTH_PROXY_LISTEN_PORT", "14321"))
        self.upstream_port = int(os.environ.get("AGENT_VAULT_INTERNAL_PORT", "14331"))
        self.mitm_port = int(os.environ.get("AGENT_VAULT_MITM_PORT", "14322"))
        self.binary = os.environ.get("AGENT_VAULT_BIN", "agent-vault")
        self.data_dir = os.environ["HOME"]
        self.credentials_file = os.path.join(self.data_dir, "owner-credentials.json")
        self.owner_email = os.environ["AGENT_VAULT_OWNER_EMAIL"]
        self.secure_cookie = os.environ.get("AGENT_VAULT_ADDR", "").startswith("https://")


CONFIG: Config


# --- Agent Vault calls -------------------------------------------------------


def upstream_json(method: str, path: str, body: dict | None = None, cookie: str | None = None) -> tuple[int, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", CONFIG.upstream_port, timeout=30)
    try:
        headers = {"Accept": "application/json"}
        payload = None
        if body is not None:
            payload = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if cookie:
            headers["Cookie"] = f"{SESSION_COOKIE}={cookie}"
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        try:
            data = json.loads(raw) if raw else {}
        except ValueError:
            data = {}
        return resp.status, data if isinstance(data, dict) else {}
    finally:
        conn.close()


def load_credentials() -> dict | None:
    try:
        with open(CONFIG.credentials_file) as f:
            creds = json.load(f)
    except FileNotFoundError:
        return None
    if not creds.get("email") or not creds.get("password"):
        return None
    return creds


def save_credentials(creds: dict) -> None:
    tmp = CONFIG.credentials_file + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(creds, f)
    os.replace(tmp, CONFIG.credentials_file)


def wait_for_upstream(proc: subprocess.Popen, timeout: float = 120) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and proc.poll() is None:
        try:
            status, _ = upstream_json("GET", "/health")
            if status == 200:
                return True
        except OSError:
            pass
        time.sleep(0.5)
    return False


def bootstrap_owner() -> None:
    """Create the Agent Vault owner account the first time the server runs."""
    status, body = upstream_json("GET", "/discover")
    initialized = not (status == 503 and body.get("error") == "not_initialized")
    creds = load_credentials()
    if initialized:
        if creds is None:
            log.warning(
                "Agent Vault already has an owner but %s is missing; owner auto-login is off",
                CONFIG.credentials_file,
            )
        return
    if creds is None:
        # Persist before registering, so a crash in between cannot lose the
        # password of an account that now exists.
        creds = {"email": CONFIG.owner_email, "password": secrets.token_urlsafe(24)}
        save_credentials(creds)
    status, body = upstream_json(
        "POST",
        "/v1/auth/register",
        {"email": creds["email"], "password": creds["password"], "device_label": "cloud-in-a-bottle"},
    )
    if status in (200, 201):
        log.info("registered Agent Vault owner %s", creds["email"])
    else:
        log.error("owner registration failed (%s): %s", status, body.get("error") or body)


class SessionCache:
    """One Agent Vault session for the owner, reused across page loads."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._token: str | None = None

    def valid(self, token: str) -> bool:
        try:
            status, _ = upstream_json("GET", "/v1/auth/me", cookie=token)
        except OSError:
            return False
        return status == 200

    def get(self) -> str | None:
        with self._lock:
            if self._token and self.valid(self._token):
                return self._token
            creds = load_credentials()
            if creds is None:
                return None
            try:
                status, body = upstream_json(
                    "POST", "/v1/auth/login", {"email": creds["email"], "password": creds["password"]}
                )
            except OSError as exc:
                log.warning("owner login failed: %s", exc)
                return None
            if status != 200 or not body.get("token"):
                log.warning("owner login refused (%s): %s", status, body.get("error"))
                return None
            self._token = body["token"]
            return self._token


SESSIONS = SessionCache()


# --- HTTP front --------------------------------------------------------------


def session_cookie_header(name: str, value: str, max_age: int, same_site: str) -> str:
    parts = [f"{name}={value}", "Path=/", "HttpOnly", f"SameSite={same_site}", f"Max-Age={max_age}"]
    if CONFIG.secure_cookie:
        parts.append("Secure")
    return "; ".join(parts)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        if self.path.startswith("/health"):
            return
        log.info("%s - " + format, self.address_string(), *args)

    def do_GET(self) -> None:  # noqa: N802
        self.handle_request()

    do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_GET

    def cookies(self) -> dict[str, str]:
        jar = SimpleCookie()
        for raw in self.headers.get_all("Cookie") or []:
            try:
                jar.load(raw)
            except Exception:  # noqa: BLE001 - a malformed cookie is just ignored
                continue
        return {k: m.value for k, m in jar.items()}

    def handle_request(self) -> None:
        self.connection.settimeout(60)
        is_owner = self.headers.get(OWNER_HEADER, "").lower() == "true"
        path = self.path.split("?", 1)[0]

        if path == CREDENTIALS_PAGE:
            if is_owner and self.command == "GET":
                self.send_credentials_page()
            else:
                self.send_plain(403, "owner only\n")
            return

        if is_owner and self.is_page_load(path) and self.ensure_owner_session(path):
            return
        self.proxy()

    def is_page_load(self, path: str) -> bool:
        if self.command != "GET" or "text/html" not in self.headers.get("Accept", ""):
            return False
        return not path.startswith(("/v1/", "/assets/", "/fonts/", "/health", "/discover"))

    def ensure_owner_session(self, path: str) -> bool:
        """Give the owner a working Agent Vault session. True if a response was sent."""
        cookies = self.cookies()
        current = cookies.get(SESSION_COOKIE)
        if current and SESSIONS.valid(current):
            if path in ("/login", "/register"):
                self.redirect("/")
                return True
            return False
        if cookies.get(TRIED_COOKIE):
            # We already set the cookie moments ago and the browser did not
            # send it back; serve the page rather than loop.
            return False
        token = SESSIONS.get()
        if token is None:
            return False
        target = "/" if path in ("/login", "/register") else self.path
        self.redirect(
            target,
            [
                session_cookie_header(SESSION_COOKIE, token, SESSION_MAX_AGE, "Strict"),
                session_cookie_header(TRIED_COOKIE, "1", 30, "Lax"),
            ],
        )
        return True

    def redirect(self, location: str, set_cookies: list[str] | None = None) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        for c in set_cookies or []:
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def send_plain(self, status: int, text: str, content_type: str = "text/plain; charset=utf-8") -> None:
        data = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def send_credentials_page(self) -> None:
        creds = load_credentials()
        addr = os.environ.get("AGENT_VAULT_ADDR", "")
        if creds is None:
            body = "<p>No generated owner credentials are stored for this Agent Vault.</p>"
        else:
            body = (
                "<p>Agent Vault owner account created by Cloud in a Bottle. You are signed in to the web UI "
                "automatically; use these only for the <code>agent-vault</code> CLI on another machine:</p>"
                f"<pre>agent-vault auth login --address {html.escape(addr)}</pre>"
                f"<p>Email: <code>{html.escape(creds['email'])}</code><br>"
                f"Password: <code>{html.escape(creds['password'])}</code></p>"
                "<p>If you change the password in Agent Vault, automatic sign-in stops working.</p>"
            )
        page = (
            "<!doctype html><meta charset=utf-8><meta name=robots content=noindex>"
            "<title>Agent Vault owner login</title>"
            "<body style='font-family:system-ui,sans-serif;max-width:40em;margin:2em auto'>"
            f"<h1>Agent Vault owner login</h1>{body}<p><a href='/'>Back to Agent Vault</a></p>"
        )
        self.send_plain(200, page, "text/html; charset=utf-8")

    def proxy(self) -> None:
        if self.headers.get("Transfer-Encoding", "").lower() not in ("", "identity"):
            self.send_plain(501, "chunked request bodies are not supported\n")
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self.send_plain(400, "bad Content-Length\n")
            return
        if length < 0 or length > MAX_BODY_BYTES:
            self.send_plain(413, "request body too large\n")
            return
        body = self.rfile.read(length) if length else b""
        if len(body) != length:
            self.send_plain(400, "incomplete request body\n")
            return

        conn = http.client.HTTPConnection("127.0.0.1", CONFIG.upstream_port, timeout=120)
        try:
            try:
                conn.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
                conn.putheader("Host", self.headers.get("Host", f"127.0.0.1:{CONFIG.upstream_port}"))
                for key, value in self.headers.items():
                    lower = key.lower()
                    if lower in HOP_BY_HOP or lower.startswith("x-openhost-"):
                        continue
                    conn.putheader(key, value)
                if body or self.command in ("POST", "PUT", "PATCH"):
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(message_body=body or None)
                upstream = conn.getresponse()
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream error: %s", exc)
                self.send_plain(502, "Agent Vault is not reachable\n")
                return
            self.relay(upstream)
        finally:
            conn.close()

    def relay(self, upstream: http.client.HTTPResponse) -> None:
        length = upstream.getheader("Content-Length")
        try:
            self.send_response(upstream.status, upstream.reason or "")
            for key, value in upstream.getheaders():
                # send_response already wrote our own Server and Date.
                if key.lower() not in HOP_BY_HOP and key.lower() not in ("server", "date"):
                    self.send_header(key, value)
            if length is not None:
                self.send_header("Content-Length", length)
            elif self.command != "HEAD" and upstream.status not in (204, 304):
                # Unknown length: stream until upstream closes, then close.
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            if self.command == "HEAD":
                return
            while chunk := upstream.read(CHUNK):
                self.wfile.write(chunk)
        except (OSError, http.client.HTTPException) as exc:
            log.debug("relay aborted: %s", exc)
            self.close_connection = True


class Server(ThreadingHTTPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


# --- supervision -------------------------------------------------------------


def start_agent_vault() -> subprocess.Popen:
    # Both listeners share one --host; it must be 0.0.0.0 for the MITM proxy
    # to reach the published host port. The API port is not published, so
    # from outside the container it is only reachable through this proxy.
    args = [
        CONFIG.binary,
        "server",
        "--host",
        "0.0.0.0",
        "--port",
        str(CONFIG.upstream_port),
        "--mitm-port",
        str(CONFIG.mitm_port),
    ]
    if os.environ.get("AGENT_VAULT_MASTER_PASSWORD"):
        return subprocess.Popen(args, stdin=subprocess.DEVNULL)
    # No master password: an empty line on --password-stdin selects
    # passwordless mode without a TTY.
    proc = subprocess.Popen([*args, "--password-stdin"], stdin=subprocess.PIPE)
    assert proc.stdin is not None
    proc.stdin.write(b"\n")
    proc.stdin.close()
    return proc


def main() -> int:
    global CONFIG
    CONFIG = Config()
    proc = start_agent_vault()

    def stop(signum: int, _frame: object) -> None:
        proc.send_signal(signum)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    if wait_for_upstream(proc):
        try:
            bootstrap_owner()
        except OSError as exc:
            log.error("owner bootstrap failed: %s", exc)
    else:
        log.error("agent-vault did not become healthy")

    server = Server(("0.0.0.0", CONFIG.listen_port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log.info("listening on :%d -> 127.0.0.1:%d", CONFIG.listen_port, CONFIG.upstream_port)

    code = proc.wait()
    log.info("agent-vault exited (%s); stopping", code)
    server.shutdown()
    return code if code >= 0 else 128 - code


if __name__ == "__main__":
    sys.exit(main())
