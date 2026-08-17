"""SPEC.md §20, §32 — no raw provider output ever crosses the MCP boundary."""

from __future__ import annotations

from typing import Any

import pytest

from tests.support.canary import Canary
from tests.support.fakes import (
    EchoingErrorAdapter,
    EchoingSanitizerAdapter,
    LeakyResultAdapter,
    RaisingSanitizerAdapter,
    RecordingAdapter,
    SlowAdapter,
    StatusError,
)
from tests.support.harness import Harness, build_harness
from veil.adapters.gcp_secret_manager import GcpSecretManagerAdapter
from veil.adapters.registry import AdapterRegistry
from veil.config import VeilConfig

pytestmark = pytest.mark.security


def _harness(config: VeilConfig, adapter: Any) -> Harness:
    return build_harness(config, AdapterRegistry([adapter]))


def _args(destination: str) -> dict[str, Any]:
    return {
        "destination": destination,
        "name": "API_TOKEN",
        "target": {"project": "acme-dev-project", "secret": "API_TOKEN"},
        "write_mode": "create",
    }


@pytest.mark.parametrize(
    ("adapter_factory", "expected_code"),
    [
        (EchoingErrorAdapter, "DESTINATION_WRITE_FAILED"),
        (EchoingSanitizerAdapter, "INTERNAL_ERROR"),
        (RaisingSanitizerAdapter, "INTERNAL_ERROR"),
        (LeakyResultAdapter, "INTERNAL_ERROR"),
    ],
)
def test_provider_error_is_sanitized(
    config: VeilConfig,
    canary: Canary,
    capfd: pytest.CaptureFixture[str],
    adapter_factory: Any,
    expected_code: str,
) -> None:
    adapter = adapter_factory(config)
    harness = _harness(config, adapter)
    try:
        payload = harness.call_tool("secret.store", _args(adapter.id))
        status = harness.finish_flow(payload, canary.value)

        assert status["state"] == "FAILED"
        assert status["error"]["code"] == expected_code
        assert canary.value not in status["error"]["message"]

        harness.collect_logs()
        captured = capfd.readouterr()
        harness.scanner.add("stdout", captured.out)
        harness.scanner.add("stderr", captured.err)
        harness.scanner.assert_clean(canary)
    finally:
        harness.broker.shutdown()
        harness.ui.stop()


def test_adapter_timeout_is_reported_without_detail(config: VeilConfig, canary: Canary) -> None:
    harness = _harness(config.with_(adapter_timeout_seconds=1.0), SlowAdapter(config))
    try:
        payload = harness.call_tool("secret.store", _args("slow-store"))
        status = harness.finish_flow(payload, canary.value)
        assert status["state"] == "FAILED"
        assert status["error"]["code"] == "DESTINATION_TIMEOUT"
    finally:
        harness.broker.shutdown()
        harness.ui.stop()


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [
        (401, "DESTINATION_DENIED"),
        (403, "DESTINATION_DENIED"),
        (404, "DESTINATION_NOT_FOUND"),
        (409, "DESTINATION_CONFLICT"),
        (429, "DESTINATION_RATE_LIMITED"),
        (500, "DESTINATION_WRITE_FAILED"),
        (503, "DESTINATION_UNAVAILABLE"),
    ],
)
def test_provider_status_codes_map_to_public_errors(
    config: VeilConfig, canary: Canary, status_code: int, expected: str
) -> None:
    from tests.support.fakes import FakeSecretManagerClient

    client = FakeSecretManagerClient(
        existing={"projects/acme-dev-project/secrets/API_TOKEN"},
        fail=StatusError(status_code, f'provider said: "{canary.value}" is invalid'),
    )
    adapter = GcpSecretManagerAdapter(config, client_factory=lambda: client)
    harness = _harness(config, adapter)
    try:
        payload = harness.call_tool(
            "secret.store",
            {**_args("gcp-secret-manager"), "write_mode": "new-version"},
        )
        status = harness.finish_flow(payload, canary.value)
        assert status["state"] == "FAILED"
        assert status["error"]["code"] == expected
        harness.collect_logs()
        harness.scanner.assert_clean(canary)
    finally:
        harness.broker.shutdown()
        harness.ui.stop()


def test_malformed_adapter_result_is_refused(config: VeilConfig, canary: Canary) -> None:
    class MalformedAdapter(RecordingAdapter):
        id = "malformed"

        async def store(self, secret: Any, target: Any, operation: Any) -> Any:
            return {"stored": True, "secret": secret.as_text()}

    harness = _harness(config, MalformedAdapter(config))
    try:
        payload = harness.call_tool("secret.store", _args("malformed"))
        status = harness.finish_flow(payload, canary.value)
        assert status["state"] == "FAILED"
        assert status["error"]["code"] in {"INTERNAL_ERROR", "DESTINATION_WRITE_FAILED"}
        harness.collect_logs()
        harness.scanner.assert_clean(canary)
    finally:
        harness.broker.shutdown()
        harness.ui.stop()
