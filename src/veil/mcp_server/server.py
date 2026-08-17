"""JSON-RPC / MCP stdio server (SPEC.md §13, §18.3, §24 SEC-002).

Implemented in-tree, with no framework between the protocol and the broker, for
two reasons: the trusted computing base stays small (SPEC.md §42), and every
outbound frame passes through a single choke point where the tripwire runs.

``handle_message`` is pure and synchronous, which makes the complete MCP
conversation trivially recordable in tests.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, BinaryIO

from veil import __version__
from veil.adapters.registry import AdapterRegistry
from veil.broker import SecretBroker
from veil.logging_ import AuditLogger, get_logger
from veil.mcp_server.tools import ToolRouter
from veil.redaction import safe_display

PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
MAX_FRAME_BYTES = 1 << 20

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

INSTRUCTIONS = (
    "Veil stores credentials without ever revealing them to you.\n"
    "\n"
    "You describe WHERE a credential should go; the human types the value into Veil's own "
    "window and authorizes the destination there. No Veil tool accepts or returns a "
    "credential value — if you find yourself holding one, something has gone wrong and you "
    "should not paste it anywhere.\n"
    "\n"
    "Flow: call secret.store, show the returned authorization_url to the user, then poll "
    "secret.status. An authorized operation cannot be edited: to change the destination, "
    "call secret.revise, which invalidates the old authorization and asks the human again."
)


class MCPServer:
    def __init__(
        self,
        broker: SecretBroker,
        registry: AdapterRegistry,
        *,
        logger: AuditLogger | None = None,
    ) -> None:
        self.broker = broker
        self.registry = registry
        self.log = logger or get_logger()
        self.tools = ToolRouter(broker, registry, self.log)
        self._initialized = False

    # -- message handling --------------------------------------------------

    def handle_message(self, message: object) -> dict[str, Any] | None:
        if not isinstance(message, Mapping):
            return _error_response(None, INVALID_REQUEST, "Invalid request.")
        message_id = message.get("id")
        method = message.get("method")
        if not isinstance(method, str):
            return _error_response(message_id, INVALID_REQUEST, "Invalid request.")

        params = message.get("params")
        params = params if isinstance(params, Mapping) else {}

        if method.startswith("notifications/"):
            if method == "notifications/initialized":
                self._initialized = True
            return None

        if method == "initialize":
            return _result(message_id, self._initialize(params))
        if method == "ping":
            return _result(message_id, {})
        if method == "tools/list":
            return _result(message_id, {"tools": self.tools.list_tools()})
        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments")
            self.log.event("tool_called", tool=safe_display(str(name), max_length=40))
            result = self.tools.call(name, arguments)
            return _result(message_id, result.to_mcp())
        if method in {"resources/list", "prompts/list"}:
            key = "resources" if method.startswith("resources") else "prompts"
            return _result(message_id, {key: []})
        if message_id is None:
            return None
        return _error_response(message_id, METHOD_NOT_FOUND, "Unknown method.")

    def _initialize(self, params: Mapping[str, Any]) -> dict[str, Any]:
        requested = params.get("protocolVersion")
        version = (
            requested
            if isinstance(requested, str) and requested in SUPPORTED_PROTOCOL_VERSIONS
            else PROTOCOL_VERSION
        )
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "veil", "version": __version__},
            "instructions": INSTRUCTIONS,
        }

    # -- transport ---------------------------------------------------------

    def serve(self, stdin: BinaryIO, stdout: BinaryIO) -> None:
        """Newline-delimited JSON-RPC over stdio, the MCP stdio transport."""

        while True:
            line = stdin.readline()
            if not line:
                return
            if len(line) > MAX_FRAME_BYTES:
                self._write(stdout, _error_response(None, INVALID_REQUEST, "Frame too large."))
                continue
            stripped = line.strip()
            if not stripped:
                continue
            try:
                message = json.loads(stripped)
            except (ValueError, UnicodeDecodeError):
                self._write(stdout, _error_response(None, PARSE_ERROR, "Malformed message."))
                continue

            if isinstance(message, list):
                for item in message:
                    response = self._safe_handle(item)
                    if response is not None:
                        self._write(stdout, response)
                continue

            response = self._safe_handle(message)
            if response is not None:
                self._write(stdout, response)

    def _safe_handle(self, message: object) -> dict[str, Any] | None:
        try:
            return self.handle_message(message)
        except Exception:
            message_id = message.get("id") if isinstance(message, Mapping) else None
            self.log.error("mcp_handler_failed", component="mcp")
            return _error_response(message_id, INTERNAL_ERROR, "Internal error.")

    def _write(self, stdout: BinaryIO, response: dict[str, Any]) -> None:
        """Single outbound choke point: nothing reaches the client unchecked."""

        payload = json.dumps(response, ensure_ascii=False, separators=(",", ":"))
        if self.broker.contains_live_secret(payload):
            self.log.security("mcp_frame_blocked", component="mcp")
            payload = json.dumps(
                _error_response(
                    response.get("id"),
                    INTERNAL_ERROR,
                    "The response was suppressed because it contained sensitive data.",
                ),
                ensure_ascii=False,
                separators=(",", ":"),
            )
        stdout.write(payload.encode("utf-8") + b"\n")
        stdout.flush()


def _result(message_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "result": result}


def _error_response(message_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "error": {"code": code, "message": message}}
