"""AUTH-001 … AUTH-008: the human authorizes exactly what executes."""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from tests.support.canary import Canary
from tests.support.fakes import RecordingAdapter
from tests.support.harness import Harness
from veil.model import RequestState

pytestmark = pytest.mark.security


def test_displayed_destination_is_the_executed_destination(
    harness: Harness, adapter: RecordingAdapter, store_args: dict[str, Any], canary: Canary
) -> None:
    """AUTH-001 — one object drives the page and the write, not two."""

    payload = harness.call_tool("secret.store", store_args)
    page = harness.get(harness.path_for(payload)).body

    request = harness.broker.get(payload["request_id"])
    assert request.snapshot.target.account_label in page
    assert request.snapshot.target.resource_label in page
    assert request.snapshot.target.provider_label in page

    harness.finish_flow(payload, canary.value)

    # Identity, not equality: the executor consumed the very object rendered.
    assert adapter.targets[0] is request.snapshot.target


def test_destination_mutation_invalidates_authorization(
    harness: Harness, adapter: RecordingAdapter, store_args: dict[str, Any], canary: Canary
) -> None:
    """AUTH-002 — approving project A then switching to project B needs new approval."""

    first = harness.call_tool("secret.store", store_args)
    harness.get(harness.path_for(first))

    revised = harness.call_tool(
        "secret.revise",
        {
            "request_id": first["request_id"],
            **{**store_args, "target": {"project": "acme-other", "secret": "STRIPE_SECRET_KEY"}},
        },
    )

    assert revised["request_id"] != first["request_id"]
    assert harness.status(first["request_id"])["state"] == str(RequestState.CANCELLED)
    assert harness.status(first["request_id"])["superseded_by"] == revised["request_id"]

    # The old authorization link is dead: no secret can be submitted against it.
    response = harness.submit_secret(first, canary.value)
    assert response.status == 410
    assert adapter.writes == []

    # The new one requires the human to authorize the *new* destination.
    harness.finish_flow(revised, canary.value)
    assert adapter.targets[0].account_label == "acme-other"


def test_snapshot_is_frozen_and_tampering_aborts_execution(
    harness: Harness, adapter: RecordingAdapter, store_args: dict[str, Any], canary: Canary
) -> None:
    """AUTH-002/§11 — even in-process tampering cannot redirect an approved write."""

    payload = harness.call_tool("secret.store", store_args)
    request = harness.broker.get(payload["request_id"])

    with pytest.raises(dataclasses.FrozenInstanceError):
        request.snapshot.target.account_label = "attacker-project"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        request.snapshot.operation = "replace"  # type: ignore[misc]

    # Simulate a compromised process forcing the mutation anyway.
    object.__setattr__(
        request,
        "snapshot",
        dataclasses.replace(
            request.snapshot,
            target=dataclasses.replace(request.snapshot.target, account_label="attacker-project"),
        ),
    )

    harness.submit_secret(payload, canary.value)
    status = harness.status(payload["request_id"])
    assert status["state"] == str(RequestState.FAILED)
    assert status["error"]["code"] == "SNAPSHOT_MISMATCH"
    assert adapter.writes == []


def test_operation_mutation_requires_new_confirmation(
    harness: Harness, adapter: RecordingAdapter, store_args: dict[str, Any]
) -> None:
    """AUTH-003 — new-version approved, replace attempted."""

    adapter.exists = True
    approved = harness.call_tool("secret.store", {**store_args, "write_mode": "create"})
    assert approved["operation"] == "create"

    revised = harness.call_tool(
        "secret.revise",
        {"request_id": approved["request_id"], **{**store_args, "write_mode": "replace"}},
    )
    assert revised["operation"] == "replace"
    assert revised["requires_confirmation"] is True
    assert harness.status(approved["request_id"])["state"] == str(RequestState.CANCELLED)


def test_secret_name_mutation_after_authorization_fails(
    harness: Harness, store_args: dict[str, Any], canary: Canary
) -> None:
    """AUTH-004 — STRIPE_TEST_KEY must not silently become STRIPE_PRODUCTION_KEY."""

    payload = harness.call_tool(
        "secret.store",
        {**store_args, "name": "STRIPE_TEST_KEY", "target": {"project": "acme-dev-project"}},
    )
    request = harness.broker.get(payload["request_id"])
    object.__setattr__(
        request,
        "snapshot",
        dataclasses.replace(request.snapshot, logical_name="STRIPE_PRODUCTION_KEY"),
    )

    harness.submit_secret(payload, canary.value)
    status = harness.status(payload["request_id"])
    assert status["state"] == str(RequestState.FAILED)
    assert status["error"]["code"] == "SNAPSHOT_MISMATCH"


def test_adapter_mutation_after_authorization_fails(
    harness: Harness, config: Any, store_args: dict[str, Any], canary: Canary
) -> None:
    """AUTH-005 — swapping the adapter behind an approved request is refused."""

    payload = harness.call_tool("secret.store", store_args)
    request = harness.broker.get(payload["request_id"])

    impostor = RecordingAdapter(config)
    request.adapter = impostor

    harness.submit_secret(payload, canary.value)
    status = harness.status(payload["request_id"])
    assert status["state"] == str(RequestState.FAILED)
    assert status["error"]["code"] == "SNAPSHOT_MISMATCH"
    assert impostor.writes == []


def test_high_risk_operation_cannot_skip_stage_b(
    harness: Harness, adapter: RecordingAdapter, store_args: dict[str, Any], canary: Canary
) -> None:
    """AUTH-006 — a production overwrite does not execute before confirmation."""

    adapter.exists = True
    payload = harness.call_tool(
        "secret.store",
        {
            **store_args,
            "target": {"project": "acme-production", "secret": "STRIPE_SECRET_KEY"},
            "write_mode": "replace",
            "environment": "production",
        },
    )
    assert payload["risk"]["level"] == "high"

    harness.submit_secret(payload, canary.value)
    assert adapter.writes == []

    request = harness.broker.get(payload["request_id"])
    # A compromised caller tries to jump straight to execution.
    request.confirmation = "implicit"
    harness.broker._execute(request)

    status = harness.status(payload["request_id"])
    assert status["state"] == str(RequestState.FAILED)
    assert status["error"]["code"] == "CONFIRMATION_REQUIRED"
    assert adapter.writes == []


def test_cancellation_at_stage_a_accepts_no_secret(
    harness: Harness, adapter: RecordingAdapter, store_args: dict[str, Any], canary: Canary
) -> None:
    """AUTH-007 — after cancelling, the link cannot accept a value."""

    payload = harness.call_tool("secret.store", store_args)
    harness.cancel(payload)

    response = harness.submit_secret(payload, canary.value)
    assert response.status == 410
    assert adapter.writes == []
    assert harness.status(payload["request_id"])["state"] == str(RequestState.CANCELLED)


def test_cancellation_at_stage_b_discards_the_secret(
    harness: Harness, adapter: RecordingAdapter, store_args: dict[str, Any], canary: Canary
) -> None:
    """AUTH-008 — an entered value is destroyed, and nothing is written."""

    adapter.exists = True
    payload = harness.call_tool(
        "secret.store",
        {**store_args, "write_mode": "replace", "environment": "production"},
    )
    harness.submit_secret(payload, canary.value)
    request = harness.broker.get(payload["request_id"])
    assert request.secret is not None

    harness.cancel(payload)

    assert request.secret is None
    assert adapter.writes == []
    assert harness.status(payload["request_id"])["state"] == str(RequestState.CANCELLED)
    harness.collect_logs()
    harness.scanner.assert_clean(canary)


def test_agent_cannot_downgrade_risk_by_claiming_development(
    harness: Harness, adapter: RecordingAdapter, store_args: dict[str, Any]
) -> None:
    """SPEC.md §10 — claimed environment may raise risk, never lower it."""

    adapter.exists = True
    payload = harness.call_tool(
        "secret.store",
        {
            **store_args,
            "target": {"project": "my-production-project", "secret": "STRIPE_SECRET_KEY"},
            "write_mode": "replace",
            "environment": "development",
        },
    )
    assert payload["destination"]["environment"] == "production"
    assert payload["risk"]["level"] == "high"
    assert payload["requires_confirmation"] is True
    assert any("contradicts" in reason for reason in payload["risk"]["reasons"])
