"""Full-stack test harness: MCP server + broker + live loopback UI.

Everything that crosses a boundary is recorded into a :class:`LeakScanner`, so
any test can end with ``harness.scanner.assert_clean(canary)``.
"""

from __future__ import annotations

import http.client
import io
import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from tests.support.canary import LeakScanner
from veil.adapters.registry import AdapterRegistry
from veil.broker import SecretBroker
from veil.config import VeilConfig
from veil.logging_ import AuditLogger
from veil.mcp_server.server import MCPServer
from veil.ui.server import SecureInputUI


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: str


@dataclass
class Harness:
    config: VeilConfig
    registry: AdapterRegistry
    broker: SecretBroker
    server: MCPServer
    ui: SecureInputUI
    log_stream: io.StringIO
    log_records: list[dict[str, Any]]
    scanner: LeakScanner = field(default_factory=LeakScanner)
    _next_id: int = 0

    # -- MCP ---------------------------------------------------------------

    def rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._next_id += 1
        message = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        if params is not None:
            message["params"] = params
        self.scanner.add("mcp_traffic", json.dumps(message))
        self.scanner.add("mcp_tool_arguments", json.dumps(params or {}))
        response = self.server.handle_message(message)
        rendered = json.dumps(response)
        self.scanner.add("mcp_traffic", rendered)
        self.scanner.add("mcp_tool_results", rendered)
        assert response is not None
        return response

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        response = self.rpc("tools/call", {"name": name, "arguments": arguments})
        result = response.get("result")
        assert result is not None, response
        payload: dict[str, Any] = result["structuredContent"]
        return payload

    # -- HTTP --------------------------------------------------------------

    def _connect(self) -> http.client.HTTPConnection:
        assert self.ui.base_url
        parsed = urllib.parse.urlsplit(self.ui.base_url)
        assert parsed.hostname and parsed.port
        return http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)

    def get(self, path: str) -> HttpResponse:
        self.scanner.add("http_urls", path)
        connection = self._connect()
        try:
            connection.request("GET", path, headers={"Host": "127.0.0.1"})
            raw = connection.getresponse()
            body = raw.read().decode("utf-8", "replace")
            response = HttpResponse(raw.status, dict(raw.getheaders()), body)
        finally:
            connection.close()
        self.scanner.add("ui_html", response.body)
        return response

    def post(self, path: str, fields: dict[str, str]) -> HttpResponse:
        self.scanner.add("http_urls", path)
        body = urllib.parse.urlencode(fields)
        connection = self._connect()
        try:
            connection.request(
                "POST",
                path,
                body=body.encode("utf-8"),
                headers={
                    "Host": "127.0.0.1",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": str(len(body.encode("utf-8"))),
                },
            )
            raw = connection.getresponse()
            payload = raw.read().decode("utf-8", "replace")
            response = HttpResponse(raw.status, dict(raw.getheaders()), payload)
        finally:
            connection.close()
        if response.status != 303:
            self.scanner.add("ui_html", response.body)
        return response

    # -- flows -------------------------------------------------------------

    def path_for(self, payload: dict[str, Any]) -> str:
        url = payload["authorization_url"]
        return urllib.parse.urlsplit(url).path

    def submit_secret(self, payload: dict[str, Any], value: str) -> HttpResponse:
        return self.post(f"{self.path_for(payload)}/submit", {"secret": value})

    def confirm(self, payload: dict[str, Any]) -> HttpResponse:
        path = self.path_for(payload)
        page = self.get(path)
        token = _hidden_field(page.body, "confirm_token")
        assert token, "stage B page did not render a confirmation token"
        return self.post(f"{path}/confirm", {"confirm_token": token})

    def cancel(self, payload: dict[str, Any]) -> HttpResponse:
        return self.post(f"{self.path_for(payload)}/cancel", {})

    def status(self, request_id: str) -> dict[str, Any]:
        return self.call_tool("secret.status", {"request_id": request_id})

    def finish_flow(self, payload: dict[str, Any], value: str) -> dict[str, Any]:
        """Stage A (+ Stage B when required) through to a terminal state."""

        self.get(self.path_for(payload))
        self.submit_secret(payload, value)
        status = self.status(payload["request_id"])
        if status["state"] == "AWAITING_EXECUTION_CONFIRMATION":
            self.confirm(payload)
            status = self.status(payload["request_id"])
        return status

    def collect_logs(self) -> None:
        self.scanner.add("application_logs", self.log_stream.getvalue())
        self.scanner.add("audit_records", json.dumps(self.log_records))


def build_harness(
    config: VeilConfig,
    registry: AdapterRegistry,
    *,
    start_ui: bool = True,
) -> Harness:
    log_stream = io.StringIO()
    records: list[dict[str, Any]] = []
    logger = AuditLogger(stream=log_stream, sink=records.append)
    broker = SecretBroker(config, registry, logger=logger)
    ui = SecureInputUI(broker, config, logger=logger)
    server = MCPServer(broker, registry, logger=logger)
    if start_ui:
        ui.start()
    return Harness(
        config=config,
        registry=registry,
        broker=broker,
        server=server,
        ui=ui,
        log_stream=log_stream,
        log_records=records,
    )


def _hidden_field(html: str, name: str) -> str | None:
    marker = f'name="{name}" value="'
    index = html.find(marker)
    if index < 0:
        return None
    start = index + len(marker)
    end = html.find('"', start)
    return html[start:end] if end > start else None
