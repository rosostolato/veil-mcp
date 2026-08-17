"""SPEC.md §30, §18.6 — terminal requests are permanently non-reusable."""

from __future__ import annotations

from typing import Any

import pytest

from tests.support.canary import Canary
from tests.support.fakes import RecordingAdapter
from tests.support.harness import Harness
from veil.adapters.registry import AdapterRegistry
from veil.broker import SecretBroker, parse_store_params
from veil.config import VeilConfig
from veil.errors import VeilError
from veil.logging_ import AuditLogger
from veil.model import RequestState

pytestmark = pytest.mark.security


def test_completed_request_cannot_be_replayed(
    harness: Harness, adapter: RecordingAdapter, store_args: dict[str, Any], canary: Canary
) -> None:
    payload = harness.call_tool("secret.store", store_args)
    assert harness.finish_flow(payload, canary.value)["state"] == str(RequestState.STORED)

    replay = harness.submit_secret(payload, canary.value)
    assert replay.status == 410
    confirm = harness.post(f"{harness.path_for(payload)}/confirm", {"confirm_token": "x"})
    assert confirm.status == 410
    assert len(adapter.writes) == 1


def test_cancelled_request_cannot_be_reused(
    harness: Harness, adapter: RecordingAdapter, store_args: dict[str, Any], canary: Canary
) -> None:
    payload = harness.call_tool("secret.store", store_args)
    harness.cancel(payload)

    assert harness.submit_secret(payload, canary.value).status == 410
    assert harness.cancel(payload).status == 410
    assert adapter.writes == []


def test_expired_request_cannot_be_reused(
    config: VeilConfig,
    registry: AdapterRegistry,
    adapter: RecordingAdapter,
    store_args: dict[str, Any],
    canary: Canary,
) -> None:
    clock = _FakeClock()
    broker = SecretBroker(config, registry, logger=AuditLogger(stream=_Discard()), clock=clock)
    request = broker.create_request(parse_store_params(store_args, registry))

    clock.advance(config.request_ttl_seconds + 1)

    with pytest.raises(VeilError) as excinfo:
        broker.submit_secret(request.request_id, request.submit_token, canary.raw)
    assert excinfo.value.public.code == "REQUEST_EXPIRED"
    assert broker.get(request.request_id).state is RequestState.EXPIRED
    assert adapter.writes == []


def test_request_ids_are_unpredictable(harness: Harness, store_args: dict[str, Any]) -> None:
    """§18.6 — unique, single-use, cryptographically unpredictable."""

    ids = {harness.call_tool("secret.store", store_args)["request_id"] for _ in range(20)}
    assert len(ids) == 20
    assert all(len(rid) >= 20 for rid in ids)


def test_authorization_token_is_required_and_checked(
    harness: Harness, store_args: dict[str, Any], canary: Canary
) -> None:
    payload = harness.call_tool("secret.store", store_args)
    request_id = payload["request_id"]

    response = harness.post(f"/r/{request_id}/not-the-token/submit", {"secret": canary.value})
    assert response.status == 403
    assert harness.status(request_id)["state"] == str(RequestState.AWAITING_SECRET_AUTHORIZATION)


class _FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _Discard:
    def write(self, _text: str) -> int:
        return 0

    def flush(self) -> None:
        return None
