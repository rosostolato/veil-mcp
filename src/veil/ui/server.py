"""Loopback secure-input UI (SPEC.md §7, §8, §9, §34).

This is the trusted boundary the human interacts with. It binds to the loopback
interface only, rejects non-loopback ``Host`` headers (DNS rebinding), never
places credential material in a URL or a log line, uses POST/redirect/GET so the
back button cannot resubmit a secret, and passes every rendered page through the
broker's tripwire before it is sent.
"""

from __future__ import annotations

import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from veil.broker import SecretBroker, SecretRequest
from veil.config import VeilConfig
from veil.errors import ErrorCode, VeilError, veil_error
from veil.ids import token_equals
from veil.logging_ import AuditLogger, get_logger
from veil.model import RequestState
from veil.secret_buffer import MAX_SECRET_BYTES, wipe
from veil.ui import render

MAX_BODY_BYTES = MAX_SECRET_BYTES + 4096
DRAIN_LIMIT_BYTES = 1 << 20
#: Above this many pending requests Veil stops opening windows by itself: an
#: agent that spams `secret.store` must not be able to carpet the screen.
MAX_AUTO_OPENED_WINDOWS = 3
ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})

_STATUS_FOR_CODE = {
    ErrorCode.REQUEST_NOT_FOUND: 404,
    ErrorCode.UNAUTHORIZED: 403,
    ErrorCode.REQUEST_EXPIRED: 410,
    ErrorCode.REQUEST_CANCELLED: 410,
    ErrorCode.REQUEST_NOT_ACTIVE: 410,
    ErrorCode.INVALID_STATE: 409,
    ErrorCode.EMPTY_SECRET: 400,
    ErrorCode.SECRET_TOO_LARGE: 413,
}


class SecureInputUI:
    def __init__(
        self,
        broker: SecretBroker,
        config: VeilConfig,
        *,
        logger: AuditLogger | None = None,
    ) -> None:
        self.broker = broker
        self.config = config
        self.log = logger or get_logger()
        self.identity = render.new_identity_phrase()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._base_url: str | None = None

    @property
    def base_url(self) -> str | None:
        return self._base_url

    def start(self) -> str:
        handler = _make_handler(self)
        server = ThreadingHTTPServer((self.config.ui_host, self.config.ui_port), handler)
        server.daemon_threads = True
        address = server.server_address
        host = address[0].decode() if isinstance(address[0], bytes) else str(address[0])
        port = int(address[1])
        display_host = f"[{host}]" if ":" in host else host
        self._base_url = f"http://{display_host}:{port}"
        self._server = server
        self.broker.set_ui_base_url(self._base_url)
        self._thread = threading.Thread(target=server.serve_forever, name="veil-ui", daemon=True)
        self._thread.start()
        self.broker.set_authorization_notifier(self.present)
        self.log.event(
            "ui_started",
            component="ui",
            detail={"url": self._base_url, "identity": self.identity},
        )
        return self._base_url

    def present(self, request_id: str, url: str) -> None:
        """Show a new request to the human, not to the agent.

        The URL is printed to Veil's own console — the operator's channel — and,
        unless disabled, opened directly in the user's browser. It is not
        returned through MCP by default (SPEC.md §4.2, §7).
        """

        self.log.event(
            "authorization_requested",
            request_id=request_id,
            component="ui",
            detail={"url": url, "identity": self.identity},
        )
        if not self.config.open_browser:
            return
        if len(self.broker.active_ids()) > MAX_AUTO_OPENED_WINDOWS:
            self.log.event("browser_open_suppressed", request_id=request_id, component="ui")
            return
        try:
            webbrowser.open(url, new=1, autoraise=True)
        except Exception:
            self.log.event("browser_open_failed", request_id=request_id, component="ui")

    def stop(self) -> None:
        self.broker.set_authorization_notifier(None)
        server, self._server = self._server, None
        if server is not None:
            server.shutdown()
            server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        self.broker.set_ui_base_url(None)


def _make_handler(ui: SecureInputUI) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "Veil"
        sys_version = ""

        # -- plumbing ------------------------------------------------------

        def log_message(self, format: str, *args: Any) -> None:
            """Silence the default access log; it writes to stderr unstructured."""

        def _host_ok(self) -> bool:
            host = self.headers.get("Host", "")
            hostname = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
            hostname = hostname.strip("[]") or host
            return hostname in ALLOWED_HOSTS or host in ALLOWED_HOSTS

        def _send(self, status: int, html_body: str, extra: dict[str, str] | None = None) -> None:
            if ui.broker.contains_live_secret(html_body):
                ui.log.security("ui_response_blocked", component="ui", status_code=status)
                html_body = render.message_page(
                    "Blocked",
                    "The page could not be rendered safely and was suppressed.",
                    nonce=render.new_nonce(),
                    identity=ui.identity,
                )
                status = 500
            payload = html_body.encode("utf-8")
            self.send_response(status)
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _send_page(self, status: int, body_factory: Any) -> None:
            nonce = render.new_nonce()
            headers = render.security_headers(nonce)
            self._send(status, body_factory(nonce), headers)

        def _redirect(self, location: str) -> None:
            self.send_response(303)
            self.send_header("Location", location)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _error_page(self, status: int, message: str) -> None:
            self._send_page(
                status,
                lambda nonce: render.message_page(
                    "Credential request",
                    message,
                    nonce=nonce,
                    identity=ui.identity,
                ),
            )

        def _resolve(self, request_id: str, token: str) -> SecretRequest:
            request = ui.broker.get(request_id)
            if not (
                token_equals(request.submit_token, token)
                or token_equals(request.confirm_token, token)
            ):
                ui.log.security("ui_token_mismatch", request_id=request.request_id, component="ui")
                raise _unauthorized()
            return request

        # -- routes --------------------------------------------------------

        def do_GET(self) -> None:
            if not self._host_ok():
                self._error_page(400, "Invalid Host header.")
                return
            parts = _split_path(self.path)
            if len(parts) == 3 and parts[0] == "r":
                self._view(parts[1], parts[2])
                return
            self._error_page(404, "Nothing to see here.")

        def do_POST(self) -> None:
            if not self._host_ok():
                self._error_page(400, "Invalid Host header.")
                return
            parts = _split_path(self.path)
            if len(parts) != 4 or parts[0] != "r":
                self._error_page(404, "Nothing to see here.")
                return
            _, request_id, token, action = parts
            if self._declared_length() > MAX_BODY_BYTES:
                # Drain a bounded amount so the client sees the refusal rather
                # than a reset, wiping as we go, then drop the connection.
                self._drain(DRAIN_LIMIT_BYTES)
                self.close_connection = True
                self._error_page(413, "The submitted value is too large.")
                return
            body = self._read_body()
            try:
                if action == "submit":
                    self._submit(request_id, token, body)
                elif action == "confirm":
                    self._confirm(request_id, token, body)
                elif action == "cancel":
                    self._cancel(request_id, token)
                else:
                    self._error_page(404, "Unsupported action.")
                    return
            except VeilError as exc:
                self._fail(exc)
                return
            finally:
                wipe(body)
            self._redirect(f"/r/{request_id}/{token}")

        # -- handlers ------------------------------------------------------

        def _view(self, request_id: str, token: str) -> None:
            try:
                request = self._resolve(request_id, token)
            except VeilError as exc:
                self._fail(exc)
                return
            base_path = f"/r/{request.request_id}/{token}"
            if request.state is RequestState.AWAITING_SECRET_AUTHORIZATION:
                self._send_page(
                    200,
                    lambda nonce: render.stage_a_page(
                        request, nonce=nonce, identity=ui.identity, base_path=base_path
                    ),
                )
            elif request.state is RequestState.AWAITING_EXECUTION_CONFIRMATION:
                self._send_page(
                    200,
                    lambda nonce: render.stage_b_page(
                        request,
                        nonce=nonce,
                        identity=ui.identity,
                        base_path=base_path,
                        confirm_token=request.confirm_token,
                    ),
                )
            else:
                self._send_page(
                    200,
                    lambda nonce: render.status_page(request, nonce=nonce, identity=ui.identity),
                )

        def _submit(self, request_id: str, token: str, body: bytearray) -> None:
            request = self._resolve(request_id, token)
            value = _form_value(body, b"secret")
            try:
                ui.broker.submit_secret(request.request_id, request.submit_token, value)
            finally:
                wipe(value)
            ui.log.event(
                "ui_secret_submitted",
                request_id=request.request_id,
                component="ui",
                state=str(request.state),
            )

        def _confirm(self, request_id: str, token: str, body: bytearray) -> None:
            request = self._resolve(request_id, token)
            provided = bytes(_form_value(body, b"confirm_token")).decode("utf-8", "replace")
            ui.broker.confirm_execution(request.request_id, provided)

        def _cancel(self, request_id: str, token: str) -> None:
            request = self._resolve(request_id, token)
            ui.broker.cancel(request.request_id, token=token, reason="user_cancelled")

        def _fail(self, exc: VeilError) -> None:
            status = _STATUS_FOR_CODE.get(exc.public.code, 400)
            self._error_page(status, exc.public.message)

        # -- body ----------------------------------------------------------

        def _declared_length(self) -> int:
            try:
                return int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return 0

        def _drain(self, limit: int) -> None:
            remaining = min(self._declared_length(), limit)
            while remaining > 0:
                chunk = bytearray(self.rfile.read(min(remaining, 65536)))
                if not chunk:
                    return
                remaining -= len(chunk)
                wipe(chunk)

        def _read_body(self) -> bytearray:
            length = self._declared_length()
            if length <= 0:
                return bytearray()
            if length > MAX_BODY_BYTES:
                self.close_connection = True
                return bytearray()
            data = bytearray()
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                data.extend(chunk)
                remaining -= len(chunk)
            return data

    return Handler


def _split_path(path: str) -> list[str]:
    raw = urllib.parse.urlsplit(path).path
    return [urllib.parse.unquote(p) for p in raw.split("/") if p]


def _form_value(body: bytearray, field: bytes) -> bytearray:
    """Extract one urlencoded field as raw, wipeable bytes.

    Parsed by hand rather than with ``parse_qs`` so the credential is never
    materialised as a ``str`` inside a parser's data structures. CPython still
    creates one immutable ``bytes`` object during percent-decoding that we
    cannot wipe; that limitation is documented in the README rather than
    hidden.
    """

    prefix = field + b"="
    for part in body.split(b"&"):
        if part.startswith(prefix):
            raw = bytearray(part[len(prefix) :]).replace(b"+", b" ")
            decoded = bytearray(urllib.parse.unquote_to_bytes(bytes(raw)))
            wipe(raw)
            wipe(part)
            return decoded
        wipe(part)
    return bytearray()


def _unauthorized() -> VeilError:
    return veil_error(ErrorCode.UNAUTHORIZED, "Invalid or expired authorization link.")
