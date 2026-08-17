"""End-to-end happy paths and the request state machine (SPEC.md §14, §44)."""

from __future__ import annotations

from typing import Any

from tests.support.canary import Canary
from tests.support.fakes import RecordingAdapter
from tests.support.harness import Harness
from veil.model import RequestState


def test_low_risk_flow_stores_without_stage_b(
    harness: Harness, adapter: RecordingAdapter, store_args: dict[str, Any], canary: Canary
) -> None:
    payload = harness.call_tool("secret.store", store_args)

    assert payload["state"] == str(RequestState.AWAITING_SECRET_AUTHORIZATION)
    assert payload["risk"]["level"] == "low"
    assert payload["requires_confirmation"] is False
    assert payload["authorization_url"].startswith("http://127.0.0.1:")

    status = harness.finish_flow(payload, canary.value)

    assert status["state"] == str(RequestState.STORED)
    assert adapter.writes == [("STRIPE_SECRET_KEY", canary.value)]


def test_high_risk_flow_requires_stage_b(
    harness: Harness, adapter: RecordingAdapter, store_args: dict[str, Any], canary: Canary
) -> None:
    adapter.exists = True
    args = {
        **store_args,
        "target": {"project": "acme-production", "secret": "STRIPE_SECRET_KEY"},
        "write_mode": "replace",
        "environment": "production",
    }
    payload = harness.call_tool("secret.store", args)
    assert payload["risk"]["level"] == "high"
    assert payload["requires_confirmation"] is True

    harness.submit_secret(payload, canary.value)
    mid = harness.status(payload["request_id"])
    assert mid["state"] == str(RequestState.AWAITING_EXECUTION_CONFIRMATION)
    assert adapter.writes == []

    harness.confirm(payload)
    final = harness.status(payload["request_id"])
    assert final["state"] == str(RequestState.STORED)
    assert len(adapter.writes) == 1


def test_tools_list_advertises_no_secret_field(harness: Harness) -> None:
    response = harness.rpc("tools/list")
    tools = {tool["name"]: tool for tool in response["result"]["tools"]}
    assert set(tools) == {
        "secret.store",
        "secret.status",
        "secret.cancel",
        "secret.revise",
        "secret.destinations",
    }
    store_properties = tools["secret.store"]["inputSchema"]["properties"]
    assert set(store_properties) == {
        "destination",
        "name",
        "target",
        "write_mode",
        "environment",
        "description",
    }


def test_initialize_and_ping(harness: Harness) -> None:
    response = harness.rpc("initialize", {"protocolVersion": "2025-06-18"})
    assert response["result"]["serverInfo"]["name"] == "veil"
    assert response["result"]["capabilities"]["tools"] == {"listChanged": False}
    assert harness.rpc("ping")["result"] == {}


def test_cancel_at_stage_a_writes_nothing(
    harness: Harness, adapter: RecordingAdapter, store_args: dict[str, Any]
) -> None:
    payload = harness.call_tool("secret.store", store_args)
    harness.cancel(payload)
    status = harness.status(payload["request_id"])
    assert status["state"] == str(RequestState.CANCELLED)
    assert adapter.writes == []
