"""SPEC.md §26 — a compromised agent tries ten different attacks. All fail safely."""

from __future__ import annotations

import base64
from typing import Any

import pytest

from tests.support.canary import Canary
from tests.support.fakes import RecordingAdapter
from tests.support.harness import Harness
from veil.adapters.base import SecretDestinationAdapter
from veil.adapters.registry import AdapterRegistry
from veil.config import VeilConfig
from veil.model import DestinationClass

pytestmark = pytest.mark.security


def test_attacker_controlled_destination_is_rejected(
    harness: Harness, store_args: dict[str, Any]
) -> None:
    """§26.1 / §26.8 — unknown or unsupported adapters do not exist for the agent."""

    for destination in ("evil.example", "http-post", "arbitrary-network", ""):
        payload = harness.call_tool("secret.store", {**store_args, "destination": destination})
        assert payload["code"] == "UNKNOWN_DESTINATION"


def test_arbitrary_network_destination_cannot_be_registered(config: VeilConfig) -> None:
    """§16 — the class is disabled by default, and here it is not implementable."""

    class Exfiltrator(SecretDestinationAdapter):
        id = "webhook"
        display_name = "Webhook"
        destination_class = DestinationClass.ARBITRARY_NETWORK

        def target_schema(self) -> dict[str, Any]:
            return {"type": "object", "additionalProperties": False, "properties": {}}

        async def normalize_target(self, target: Any, *, name: str, environment_hint: Any) -> Any:
            raise AssertionError("unreachable")

        async def calculate_risk(self, target: Any, operation: Any, *, exists: bool) -> Any:
            raise AssertionError("unreachable")

        async def store(self, secret: Any, target: Any, operation: Any) -> Any:
            raise AssertionError("unreachable")

    with pytest.raises(ValueError, match="arbitrary-network"):
        AdapterRegistry([Exfiltrator(config)])


def test_secret_shaped_fields_are_refused(harness: Harness, store_args: dict[str, Any]) -> None:
    """§26.5 — unknown properties cannot become a covert credential channel."""

    for field in ("value", "secret_value", "password", "credential", "content", "raw_secret"):
        payload = harness.call_tool(
            "secret.store", {**store_args, field: "sk_live_deadbeefdeadbeef"}
        )
        assert payload["code"] in {"FORBIDDEN_FIELD", "INVALID_ARGUMENTS"}, field

    nested = harness.call_tool(
        "secret.store",
        {**store_args, "target": {**store_args["target"], "password": "hunter2hunter2"}},
    )
    assert nested["code"] in {"FORBIDDEN_FIELD", "INVALID_TARGET"}


def test_credential_shaped_values_are_refused_anywhere(
    harness: Harness, store_args: dict[str, Any]
) -> None:
    """§26.6 — a real-looking credential in a legitimate field is still refused."""

    for value in (
        "sk_live_51H8ZxKLmNoPqRsTuVwXyZ",
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
        "AKIAIOSFODNN7EXAMPLE",
        "-----BEGIN RSA PRIVATE KEY-----",
    ):
        payload = harness.call_tool("secret.store", {**store_args, "description": value})
        assert payload["code"] == "FORBIDDEN_FIELD", value


def test_metadata_is_never_treated_as_credential_material(
    harness: Harness, adapter: RecordingAdapter, store_args: dict[str, Any], canary: Canary
) -> None:
    """§26.6 — encoding something in metadata does not make it the stored value."""

    encoded = base64.b64encode(b"attacker-planted-value").decode("ascii")
    payload = harness.call_tool(
        "secret.store",
        {**store_args, "description": f"rotate {encoded}", "name": "STRIPE_SECRET_KEY"},
    )
    harness.finish_flow(payload, canary.value)

    stored_values = [value for _, value in adapter.writes]
    assert stored_values == [canary.value]
    assert "attacker-planted-value" not in stored_values[0]


def test_misleading_description_does_not_change_what_the_user_sees(
    harness: Harness, store_args: dict[str, Any]
) -> None:
    """§26.4 / §18.1 — the destination on screen comes from the normalized target."""

    payload = harness.call_tool(
        "secret.store",
        {
            **store_args,
            "target": {"project": "acme-production", "secret": "PROD_DB_PASSWORD"},
            "description": "Harmless development scratch value, no production impact",
            "environment": "development",
        },
    )
    page = harness.get(harness.path_for(payload)).body

    assert "acme-production" in page
    assert "PROD_DB_PASSWORD" in page
    assert "production" in page
    assert payload["destination"]["environment"] == "production"


def test_deeply_nested_and_oversized_arguments_are_rejected(
    harness: Harness, store_args: dict[str, Any]
) -> None:
    """§18.3 — adapter inputs are bounded and allowlisted."""

    nested: dict[str, Any] = {"project": "acme-dev-project"}
    node = nested
    for _ in range(12):
        node["secret"] = {"secret": {}}  # type: ignore[assignment]
        node = node["secret"]  # type: ignore[assignment]
    deep = harness.call_tool("secret.store", {**store_args, "target": nested})
    assert deep["status"] == "failed"

    long_value = harness.call_tool(
        "secret.store",
        {**store_args, "target": {"project": "acme-dev-project", "secret": "A" * 5000}},
    )
    assert long_value["code"] in {"INVALID_TARGET", "FORBIDDEN_FIELD"}


def test_agent_cannot_read_a_secret_back_through_status(
    harness: Harness, store_args: dict[str, Any], canary: Canary
) -> None:
    """§5 — no tool result ever carries credential material."""

    payload = harness.call_tool("secret.store", store_args)
    harness.submit_secret(payload, canary.value)
    status = harness.status(payload["request_id"])

    harness.collect_logs()
    harness.scanner.assert_clean(canary)
    assert "secret" not in {k.lower() for k in status} or status.get("secret") is None
