"""SEC-001 … SEC-010: the canary must not reach any observable channel."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.support.canary import Canary
from tests.support.fakes import RecordingAdapter
from tests.support.harness import Harness, build_harness
from veil.adapters.env_file import EnvFileAdapter
from veil.adapters.registry import AdapterRegistry
from veil.config import VeilConfig
from veil.mcp_server.tools import SECRET_SHAPED_FIELD

pytestmark = pytest.mark.security


def _schema_property_names(node: Any, out: list[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "properties" and isinstance(value, dict):
                out.extend(value)
            _schema_property_names(value, out)
    elif isinstance(node, list):
        for item in node:
            _schema_property_names(item, out)


def test_secret_never_enters_mcp_arguments(harness: Harness) -> None:
    """SEC-001 — no valid tool schema permits credential content."""

    tools = harness.rpc("tools/list")["result"]["tools"]
    names: list[str] = []
    for tool in tools:
        _schema_property_names(tool["inputSchema"], names)
        assert tool["inputSchema"]["additionalProperties"] is False

    offenders = [
        name
        for name in names
        # `secret` (a GCP secret id) and `key` (an env var name) are labels, not
        # values; every other secret-shaped name must be absent entirely.
        if name not in {"secret", "key"} and SECRET_SHAPED_FIELD.search(name)
    ]
    assert offenders == [], f"secret-shaped fields in the public schema: {offenders}"


def test_secret_never_appears_in_any_observable_channel(
    harness: Harness,
    adapter: RecordingAdapter,
    store_args: dict[str, Any],
    canary: Canary,
    capfd: pytest.CaptureFixture[str],
    argv_recorder: list[list[str]],
    tmp_path: Path,
) -> None:
    """SEC-002 … SEC-008, SEC-010 in one pass over a complete flow."""

    payload = harness.call_tool("secret.store", store_args)
    status = harness.finish_flow(payload, canary.value)
    assert status["state"] == "STORED"

    harness.collect_logs()
    captured = capfd.readouterr()
    harness.scanner.add("stdout", captured.out)
    harness.scanner.add("stderr", captured.err)
    harness.scanner.add("process_argv", json.dumps(argv_recorder))
    harness.scanner.add("provider_urls", json.dumps(adapter.urls))
    harness.scanner.add_tree("temp_files", tmp_path)
    harness.scanner.add("mcp_status_result", json.dumps(status))

    harness.scanner.assert_clean(canary)
    # …and the credential really did reach the destination.
    assert adapter.writes == [("STRIPE_SECRET_KEY", canary.value)]


def test_secret_reaches_only_the_approved_env_file(
    tmp_path: Path, canary: Canary, capfd: pytest.CaptureFixture[str]
) -> None:
    """SEC-010 — the only artefact holding the canary is the destination file."""

    config = VeilConfig(
        env_allowed_roots=(tmp_path.resolve(),),
        ui_port=0,
        request_ttl_seconds=60.0,
        disclose_authorization_url=True,
        open_browser=False,
    )
    registry = AdapterRegistry([EnvFileAdapter(config)])
    harness = build_harness(config, registry)
    env_path = tmp_path / ".env"
    try:
        payload = harness.call_tool(
            "secret.store",
            {
                "destination": "env-file",
                "name": "API_TOKEN",
                "target": {"path": ".env"},
                "write_mode": "create",
                "environment": "development",
            },
        )
        status = harness.finish_flow(payload, canary.value)
        assert status["state"] == "STORED", status

        harness.collect_logs()
        captured = capfd.readouterr()
        harness.scanner.add("stdout", captured.out)
        harness.scanner.add("stderr", captured.err)
        harness.scanner.add_tree("temp_files", tmp_path, exclude={env_path})
        harness.scanner.assert_clean(harness_canary := canary)

        harness.scanner.add("approved_destination", env_path.read_bytes())
        harness.scanner.assert_present(harness_canary, "approved_destination")
        # No temp copy of the atomic write survives.
        assert [p.name for p in tmp_path.iterdir()] == [".env"]
    finally:
        harness.broker.shutdown()
        harness.ui.stop()


def test_secret_is_absent_from_logs_at_every_level(
    harness: Harness, adapter: RecordingAdapter, store_args: dict[str, Any], canary: Canary
) -> None:
    """SEC-006 — three independent defences, exercised at DEBUG and INFO."""

    adapter.exists = True
    payload = harness.call_tool(
        "secret.store",
        {**store_args, "write_mode": "replace", "environment": "production"},
    )
    harness.submit_secret(payload, canary.value)
    assert harness.status(payload["request_id"])["state"] == "AWAITING_EXECUTION_CONFIRMATION"

    # 1. Forbidden field name: dropped by the allowlist.
    harness.broker.log.event("careless", value=canary.value)
    # 2. Allowlisted free-text fields, while the secret is live: the tripwire
    #    replaces the whole record.
    harness.broker.log.debug("careless", reason=canary.value, detail={"v": canary.value})

    harness.confirm(payload)
    assert harness.status(payload["request_id"])["state"] == "STORED"

    # 3. After the secret is destroyed the tripwire has nothing to match, so the
    #    credential-shape screen is what stops it.
    harness.broker.log.event("careless_after", reason=canary.value)

    harness.collect_logs()
    harness.scanner.assert_clean(canary)
    assert "[redacted]" in harness.log_stream.getvalue()


def test_live_secret_in_a_log_record_is_suppressed_by_the_tripwire(
    harness: Harness, adapter: RecordingAdapter, store_args: dict[str, Any]
) -> None:
    """SEC-006 — a secret with no recognisable shape is still caught while live."""

    unremarkable = "correct horse battery staple 7413"
    adapter.exists = True
    payload = harness.call_tool(
        "secret.store",
        {**store_args, "write_mode": "replace", "environment": "production"},
    )
    harness.submit_secret(payload, unremarkable)

    harness.broker.log.event("careless", reason=unremarkable)

    rendered = harness.log_stream.getvalue()
    assert "audit_record_suppressed" in rendered
    assert unremarkable not in rendered


def test_canary_derivations_cover_required_encodings(canary: Canary) -> None:
    """SPEC.md §23 — encodings are searched, not just the raw value."""

    import base64

    variants = {v.decode("utf-8", "replace") for v in canary.variants}
    assert canary.value in variants
    assert base64.b64encode(canary.raw).decode() in variants
    assert base64.urlsafe_b64encode(canary.raw).decode() in variants
    assert canary.raw.hex() in variants
    assert canary.raw.hex().upper() in variants
    assert canary.value[:8] in variants
    assert canary.value[-8:] in variants
