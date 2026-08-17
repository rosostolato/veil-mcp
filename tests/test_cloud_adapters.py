"""Google Secret Manager and Firestore adapters (SPEC.md §16, §17)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from tests.support.canary import Canary
from tests.support.fakes import FakeFirestoreClient, FakeSecretManagerClient
from tests.support.harness import Harness, build_harness
from veil.adapters.firestore import FirestoreAdapter
from veil.adapters.gcp_secret_manager import GcpSecretManagerAdapter
from veil.adapters.registry import AdapterRegistry
from veil.config import VeilConfig

SECRET_NAME = "projects/acme-dev-project/secrets/API_TOKEN"


@pytest.fixture
def gcp_client() -> FakeSecretManagerClient:
    return FakeSecretManagerClient()


@pytest.fixture
def gcp(config: VeilConfig, gcp_client: FakeSecretManagerClient) -> Iterator[Harness]:
    adapter = GcpSecretManagerAdapter(config, client_factory=lambda: gcp_client)
    harness = build_harness(config, AdapterRegistry([adapter]))
    yield harness
    harness.broker.shutdown()
    harness.ui.stop()


@pytest.fixture
def firestore_client() -> FakeFirestoreClient:
    return FakeFirestoreClient()


@pytest.fixture
def firestore(config: VeilConfig, firestore_client: FakeFirestoreClient) -> Iterator[Harness]:
    adapter = FirestoreAdapter(config, client_factory=lambda: firestore_client)
    harness = build_harness(config, AdapterRegistry([adapter]))
    yield harness
    harness.broker.shutdown()
    harness.ui.stop()


def _gcp_args(**overrides: Any) -> dict[str, Any]:
    args: dict[str, Any] = {
        "destination": "gcp-secret-manager",
        "name": "API_TOKEN",
        "target": {"project": "acme-dev-project", "secret": "API_TOKEN"},
        "write_mode": "create",
        "environment": "development",
    }
    args.update(overrides)
    return args


def test_gcp_create_writes_payload_and_reports_version(
    gcp: Harness, gcp_client: FakeSecretManagerClient, canary: Canary
) -> None:
    payload = gcp.call_tool("secret.store", _gcp_args())
    status = gcp.finish_flow(payload, canary.value)

    assert status["state"] == "STORED"
    assert status["result"]["destination_ref"].endswith("/versions/1")
    assert gcp_client.payloads == [(SECRET_NAME, canary.raw)]
    # The credential is in the request body only: nothing else mentions it.
    assert canary.hits_in(str(gcp_client.requests)) == []


def test_gcp_replace_disables_previous_versions_and_needs_confirmation(
    gcp: Harness, gcp_client: FakeSecretManagerClient, canary: Canary
) -> None:
    gcp_client.existing.add(SECRET_NAME)
    gcp_client.versions[SECRET_NAME] = []

    first = gcp.call_tool("secret.store", _gcp_args(write_mode="new-version"))
    gcp.finish_flow(first, "first-value")

    second = gcp.call_tool("secret.store", _gcp_args(write_mode="replace"))
    assert second["requires_confirmation"] is True
    status = gcp.finish_flow(second, canary.value)

    assert status["state"] == "STORED"
    assert gcp_client.disabled == [f"{SECRET_NAME}/versions/1"]


def test_gcp_production_project_forces_high_risk(gcp: Harness) -> None:
    payload = gcp.call_tool(
        "secret.store",
        _gcp_args(
            target={"project": "acme-production", "secret": "API_TOKEN"},
            write_mode="replace",
            environment="development",
        ),
    )
    assert payload["destination"]["environment"] == "production"
    assert payload["risk"]["level"] == "high"
    assert payload["requires_confirmation"] is True


def test_gcp_rejects_invalid_identifiers(gcp: Harness) -> None:
    for target in (
        {"project": "Bad Project", "secret": "API_TOKEN"},
        {"project": "acme-dev-project", "secret": "bad/secret"},
        {"project": "x", "secret": "API_TOKEN"},
        {"project": "acme-dev-project", "secret": "API_TOKEN", "extra": "1"},
    ):
        payload = gcp.call_tool("secret.store", _gcp_args(target=target))
        assert payload["status"] == "failed", target


def test_firestore_always_warns_and_always_confirms(
    firestore: Harness, firestore_client: FakeFirestoreClient, canary: Canary
) -> None:
    payload = firestore.call_tool(
        "secret.store",
        {
            "destination": "firestore",
            "name": "API_TOKEN",
            "target": {
                "project": "acme-dev-project",
                "collection": "config",
                "document": "runtime",
            },
            "write_mode": "create",
            "environment": "development",
        },
    )

    assert payload["requires_confirmation"] is True
    warnings = payload["destination"]["warnings"]
    assert any("not be designed to store secrets" in w for w in warnings)

    page = firestore.get(firestore.path_for(payload)).body
    assert "may not be designed to store secrets" in page

    status = firestore.finish_flow(payload, canary.value)
    assert status["state"] == "STORED"
    assert firestore_client.documents == {"config/runtime": {"API_TOKEN": canary.value}}


def test_firestore_create_refuses_to_overwrite_an_existing_field(
    firestore: Harness, firestore_client: FakeFirestoreClient, canary: Canary
) -> None:
    firestore_client.documents["config/runtime"] = {"API_TOKEN": "existing"}
    args = {
        "destination": "firestore",
        "name": "API_TOKEN",
        "target": {"project": "acme-dev-project", "collection": "config", "document": "runtime"},
        "write_mode": "create",
    }
    payload = firestore.call_tool("secret.store", args)
    status = firestore.finish_flow(payload, canary.value)

    assert status["state"] == "FAILED"
    assert status["error"]["code"] == "DESTINATION_CONFLICT"
    assert firestore_client.documents == {"config/runtime": {"API_TOKEN": "existing"}}


def test_unavailable_provider_is_reported_without_detail(config: VeilConfig) -> None:
    def explode() -> Any:
        raise RuntimeError("Could not automatically determine credentials for user@example.com")

    adapter = GcpSecretManagerAdapter(config, client_factory=explode)
    harness = build_harness(config, AdapterRegistry([adapter]))
    try:
        payload = harness.call_tool("secret.store", _gcp_args())
        assert payload["status"] == "failed"
        assert payload["code"] == "ADAPTER_UNAVAILABLE"
        assert "user@example.com" not in payload["message"]
    finally:
        harness.broker.shutdown()
        harness.ui.stop()
