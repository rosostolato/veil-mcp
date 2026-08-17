"""MCP tool contract (SPEC.md §6, §13, §18.3).

The schemas here are the structural security guarantee: there is no property
capable of carrying credential content, every object is closed
(``additionalProperties: false``), and arguments are screened for both
secret-shaped field names and credential-shaped values before they reach the
broker.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from veil.adapters.registry import AdapterRegistry
from veil.broker import SecretBroker, parse_store_params
from veil.errors import ErrorCode, PublicError, VeilError, veil_error
from veil.logging_ import AuditLogger
from veil.model import Environment, WriteMode
from veil.redaction import looks_like_credential, safe_display

STORE_TOOL = "secret.store"
STATUS_TOOL = "secret.status"
CANCEL_TOOL = "secret.cancel"
REVISE_TOOL = "secret.revise"
DESTINATIONS_TOOL = "secret.destinations"

#: Field names that would betray an attempt to smuggle credential material
#: through an unmodelled property (SPEC.md §6, §26.5).
SECRET_SHAPED_FIELD = re.compile(
    r"(?:^|[_.\-])?(secret[_-]?value|secretvalue|raw[_-]?secret|rawsecret|password|passwd|pwd|"
    r"passphrase|credential|credentials|api[_-]?key[_-]?value|token[_-]?value|private[_-]?key|"
    r"client[_-]?secret|access[_-]?key|content|payload|value|data|blob|bytes|material)"
    r"(?:$|[_.\-])?",
    re.IGNORECASE,
)

MAX_ARGUMENT_DEPTH = 6
#: A blocking status call occupies the single-threaded stdio loop, so it is kept
#: short: the human's window runs on its own thread and is never blocked by it.
MAX_STATUS_WAIT_SECONDS = 60


class ToolResult:
    __slots__ = ("is_error", "payload")

    def __init__(self, payload: dict[str, Any], *, is_error: bool = False) -> None:
        self.payload = payload
        self.is_error = is_error

    def to_mcp(self) -> dict[str, Any]:
        text = json.dumps(self.payload, indent=2, sort_keys=True, ensure_ascii=False)
        return {
            "content": [{"type": "text", "text": text}],
            "structuredContent": self.payload,
            "isError": self.is_error,
        }


class ToolRouter:
    def __init__(
        self,
        broker: SecretBroker,
        registry: AdapterRegistry,
        logger: AuditLogger,
    ) -> None:
        self.broker = broker
        self.registry = registry
        self.log = logger

    # -- schema ------------------------------------------------------------

    def list_tools(self) -> list[dict[str, Any]]:
        return [
            {
                "name": STORE_TOOL,
                "title": "Request that the user store a credential",
                "description": (
                    "Ask the human to provide a credential and have Veil write it to the "
                    "destination described here. The credential value is never passed through "
                    "this tool, never returned by it, and never becomes visible to the model: "
                    "the user enters it in Veil's own trusted window. Share the returned "
                    "authorization_url with the user, then poll secret.status."
                ),
                "inputSchema": self._store_schema(),
                "annotations": {"destructiveHint": True, "openWorldHint": True},
            },
            {
                "name": STATUS_TOOL,
                "title": "Check a credential request",
                "description": (
                    "Return the non-sensitive status of a credential request. Never returns "
                    "credential material."
                ),
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["request_id"],
                    "properties": {
                        "request_id": {"type": "string", "maxLength": 64},
                        "wait_seconds": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 60,
                            "description": "Optionally block until the request reaches a "
                            "terminal state or this many seconds elapse.",
                        },
                    },
                },
                "annotations": {"readOnlyHint": True},
            },
            {
                "name": CANCEL_TOOL,
                "title": "Cancel a credential request",
                "description": "Cancel a pending request. Any credential already entered is "
                "destroyed.",
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["request_id"],
                    "properties": {
                        "request_id": {"type": "string", "maxLength": 64},
                        "reason": {"type": "string", "maxLength": 200},
                    },
                },
            },
            {
                "name": REVISE_TOOL,
                "title": "Replace a credential request with a corrected one",
                "description": (
                    "Cancel a pending request and create a new one. The original authorization "
                    "is invalidated and the human must authorize the new operation from "
                    "scratch; an authorized operation can never be edited in place."
                ),
                "inputSchema": self._revise_schema(),
            },
            {
                "name": DESTINATIONS_TOOL,
                "title": "List available destinations",
                "description": "List the destinations this Veil instance can write to, with "
                "the target fields each one expects.",
                "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
                "annotations": {"readOnlyHint": True},
            },
        ]

    def _store_schema(self) -> dict[str, Any]:
        target_properties: dict[str, Any] = {}
        for adapter in self.registry:
            schema = adapter.target_schema()
            for key, definition in schema.get("properties", {}).items():
                target_properties.setdefault(key, definition)
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["destination", "name", "target"],
            "properties": {
                "destination": {
                    "type": "string",
                    "enum": list(self.registry.ids()),
                    "description": "Which destination adapter should receive the credential.",
                },
                "name": {
                    "type": "string",
                    "maxLength": 128,
                    "description": (
                        "Logical name of the credential, e.g. STRIPE_SECRET_KEY. This is a "
                        "label, never the credential value."
                    ),
                },
                "target": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": target_properties,
                    "description": "Where the credential goes. Fields depend on the "
                    "destination; call secret.destinations for the exact contract.",
                },
                "write_mode": {
                    "type": "string",
                    "enum": [str(mode) for mode in WriteMode],
                    "default": str(WriteMode.CREATE),
                },
                "environment": {
                    "type": "string",
                    "enum": [str(env) for env in Environment],
                    "description": (
                        "Environment you believe this destination belongs to. Advisory only: "
                        "Veil classifies the destination itself and uses the stricter of the "
                        "two."
                    ),
                },
                "description": {
                    "type": "string",
                    "maxLength": 512,
                    "description": "Short human-readable purpose, shown to the user.",
                },
            },
        }

    def _revise_schema(self) -> dict[str, Any]:
        schema = self._store_schema()
        schema["properties"] = {
            "request_id": {"type": "string", "maxLength": 64},
            **schema["properties"],
        }
        schema["required"] = ["request_id", *schema["required"]]
        return schema

    # -- dispatch ----------------------------------------------------------

    def call(self, name: object, arguments: object) -> ToolResult:
        args: Mapping[str, Any]
        if arguments is None:
            args = {}
        elif isinstance(arguments, Mapping):
            args = arguments
        else:
            return _error(veil_error(ErrorCode.INVALID_ARGUMENTS, "Arguments must be an object."))

        try:
            self._screen_arguments(name, args)
            if name == STORE_TOOL:
                return self._store(args)
            if name == STATUS_TOOL:
                return self._status(args)
            if name == CANCEL_TOOL:
                return self._cancel(args)
            if name == REVISE_TOOL:
                return self._revise(args)
            if name == DESTINATIONS_TOOL:
                return self._destinations()
            raise veil_error(ErrorCode.INVALID_ARGUMENTS, "Unknown tool.")
        except VeilError as exc:
            return _error(exc)
        except Exception:
            self.log.error("tool_call_failed", tool=safe_display(str(name), max_length=40))
            return ToolResult(
                PublicError(
                    ErrorCode.INTERNAL_ERROR,
                    "The request could not be processed.",
                ).to_dict(),
                is_error=True,
            )

    # -- screening ---------------------------------------------------------

    def _screen_arguments(self, tool: object, args: Mapping[str, Any]) -> None:
        """Reject covert secret transport before anything else looks at the args."""

        allowed_keys = {
            "destination",
            "name",
            "target",
            "write_mode",
            "environment",
            "description",
            "request_id",
            "reason",
            "wait_seconds",
        } | {"project", "secret", "collection", "document", "field", "path", "key"}

        findings: list[str] = []

        def walk(node: Any, depth: int) -> None:
            if depth > MAX_ARGUMENT_DEPTH:
                findings.append("nesting")
                return
            if isinstance(node, Mapping):
                for key, value in node.items():
                    key_text = str(key)
                    if key_text not in allowed_keys and SECRET_SHAPED_FIELD.search(key_text):
                        findings.append(f"field:{safe_display(key_text, max_length=40)}")
                    walk(value, depth + 1)
            elif isinstance(node, list | tuple):
                for item in node:
                    walk(item, depth + 1)
            elif isinstance(node, str) and looks_like_credential(node):
                findings.append("credential-shaped-value")

        walk(args, 0)
        if findings:
            self.log.security(
                "secret_shaped_argument_rejected",
                tool=safe_display(str(tool), max_length=40),
                detail={"findings": sorted(set(findings))[:5]},
            )
            raise veil_error(
                ErrorCode.FORBIDDEN_FIELD,
                "This tool never accepts credential material. Remove the offending field and "
                "let the user enter the value in Veil.",
            )

    # -- handlers ----------------------------------------------------------

    def _store(self, args: Mapping[str, Any]) -> ToolResult:
        params = parse_store_params(args, self.registry)
        request = self.broker.create_request(params)
        return ToolResult(self._pending_payload(request.request_id))

    def _revise(self, args: Mapping[str, Any]) -> ToolResult:
        request_id = args.get("request_id")
        if not isinstance(request_id, str):
            raise veil_error(ErrorCode.INVALID_ARGUMENTS, "A request_id is required.")
        rest = {k: v for k, v in args.items() if k != "request_id"}
        params = parse_store_params(rest, self.registry)
        request = self.broker.revise(request_id, params)
        payload = self._pending_payload(request.request_id)
        payload["previous_request_id"] = safe_display(request_id, max_length=64)
        payload["notice"] = (
            "The previous authorization was invalidated. The user must authorize this "
            "operation again."
        )
        return ToolResult(payload)

    def _status(self, args: Mapping[str, Any]) -> ToolResult:
        request_id = args.get("request_id")
        wait = args.get("wait_seconds", 0)
        if isinstance(wait, bool) or not isinstance(wait, int) or wait < 0:
            wait = 0
        wait = min(wait, MAX_STATUS_WAIT_SECONDS)
        if wait:
            return ToolResult(self.broker.wait_for_terminal(request_id, float(wait)))
        return ToolResult(self.broker.public_status(request_id))

    def _cancel(self, args: Mapping[str, Any]) -> ToolResult:
        request_id = args.get("request_id")
        reason = args.get("reason")
        self.broker.cancel(
            request_id,
            reason=safe_display(str(reason), max_length=80) if reason else "agent_cancelled",
        )
        return ToolResult(self.broker.public_status(request_id))

    def _destinations(self) -> ToolResult:
        return ToolResult(
            {
                "destinations": [
                    {
                        "id": adapter.id,
                        "title": adapter.display_name,
                        "destination_class": str(adapter.destination_class),
                        "write_modes": [str(m) for m in adapter.supported_write_modes()],
                        "target_schema": adapter.target_schema(),
                    }
                    for adapter in self.registry
                ],
                "note": (
                    "No destination accepts a credential value through this API. Veil collects "
                    "the value from the user directly."
                ),
            }
        )

    def _pending_payload(self, request_id: str) -> dict[str, Any]:
        status = self.broker.public_status(request_id)
        status["next_step"] = (
            "Show the authorization_url to the user. They will review the destination and "
            "enter the credential in Veil's own window; you will not see the value."
        )
        return status


def _error(exc: VeilError) -> ToolResult:
    return ToolResult(exc.public.to_dict(), is_error=True)
