"""SPEC.md §29 — races have deterministic, fail-safe outcomes."""

from __future__ import annotations

import concurrent.futures
import threading
from typing import Any

import pytest

from tests.support.canary import Canary
from tests.support.fakes import RecordingAdapter, SlowAdapter
from tests.support.harness import Harness
from veil.adapters.registry import AdapterRegistry
from veil.broker import SecretBroker, parse_store_params
from veil.config import VeilConfig
from veil.errors import VeilError
from veil.logging_ import AuditLogger
from veil.model import RequestState

pytestmark = pytest.mark.security


def _broker(config: VeilConfig, registry: AdapterRegistry) -> SecretBroker:
    return SecretBroker(config, registry, logger=AuditLogger(stream=_Discard()))


def test_double_submit_writes_exactly_once(
    config: VeilConfig, registry: AdapterRegistry, adapter: RecordingAdapter, canary: Canary
) -> None:
    broker = _broker(config, registry)
    request = broker.create_request(parse_store_params(_args(), registry))
    barrier = threading.Barrier(2)

    def submit() -> str:
        barrier.wait()
        try:
            broker.submit_secret(request.request_id, request.submit_token, canary.raw)
            return "ok"
        except VeilError as exc:
            return exc.public.code

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(f.result() for f in [pool.submit(submit), pool.submit(submit)])

    assert outcomes.count("ok") == 1
    assert len(adapter.writes) == 1
    assert broker.get(request.request_id).state is RequestState.STORED


def test_submit_racing_cancel_has_one_winner(
    config: VeilConfig, registry: AdapterRegistry, adapter: RecordingAdapter, canary: Canary
) -> None:
    for _ in range(25):
        broker = _broker(config, registry)
        request = broker.create_request(parse_store_params(_args(), registry))
        results = _race_submit_against_cancel(broker, request, canary)

        state = broker.get(request.request_id).state
        assert state in {RequestState.STORED, RequestState.CANCELLED}
        if state is RequestState.CANCELLED:
            assert results["submit"] != "ok"
        assert broker.get(request.request_id).secret is None

    # Every write that happened corresponds to a request that reached STORED.
    assert all(value == canary.value for _label, value in adapter.writes)


def test_expiration_racing_submission_fails_closed(
    config: VeilConfig, registry: AdapterRegistry, adapter: RecordingAdapter, canary: Canary
) -> None:
    clock = _Clock()
    broker = SecretBroker(config, registry, logger=AuditLogger(stream=_Discard()), clock=clock)
    request = broker.create_request(parse_store_params(_args(), registry))

    clock.advance(config.request_ttl_seconds)  # exactly at the deadline

    with pytest.raises(VeilError) as excinfo:
        broker.submit_secret(request.request_id, request.submit_token, canary.raw)
    assert excinfo.value.public.code == "REQUEST_EXPIRED"
    assert adapter.writes == []


def test_cancel_during_execution_is_refused_not_silently_dropped(
    config: VeilConfig, canary: Canary
) -> None:
    slow = SlowAdapter(config)
    registry = AdapterRegistry([slow])
    broker = SecretBroker(
        config.with_(adapter_timeout_seconds=1.0),
        registry,
        logger=AuditLogger(stream=_Discard()),
    )
    request = broker.create_request(parse_store_params(_args("slow-store"), registry))

    thread = threading.Thread(
        target=lambda: broker.submit_secret(request.request_id, request.submit_token, canary.raw)
    )
    thread.start()
    try:
        _wait_for(lambda: broker.get(request.request_id).state is RequestState.EXECUTING)
        with pytest.raises(VeilError) as excinfo:
            broker.cancel(request.request_id, reason="race")
        assert excinfo.value.public.code == "INVALID_STATE"
    finally:
        thread.join(timeout=15)

    status = broker.public_status(request.request_id)
    assert status["state"] == str(RequestState.FAILED)
    assert status["error"]["code"] == "DESTINATION_TIMEOUT"


def test_two_browser_tabs_cannot_both_submit(
    harness: Harness, adapter: RecordingAdapter, canary: Canary
) -> None:
    payload = harness.call_tool("secret.store", _args())
    first = harness.submit_secret(payload, canary.value)
    second = harness.submit_secret(payload, "second-tab-value")

    assert first.status == 303
    assert second.status in {409, 410}
    assert adapter.writes == [("CANARY_KEY", canary.value)]


def test_revise_racing_confirm_never_writes_the_stale_operation(
    harness: Harness, adapter: RecordingAdapter, canary: Canary
) -> None:
    adapter.exists = True
    payload = harness.call_tool(
        "secret.store", {**_args(), "write_mode": "replace", "environment": "production"}
    )
    harness.submit_secret(payload, canary.value)

    revised = harness.call_tool(
        "secret.revise",
        {
            "request_id": payload["request_id"],
            **{
                **_args(),
                "target": {"project": "acme-dev-project", "secret": "OTHER_KEY"},
                "write_mode": "replace",
            },
        },
    )

    late_confirm = harness.post(
        f"{harness.path_for(payload)}/confirm", {"confirm_token": "whatever"}
    )
    assert late_confirm.status == 410
    assert adapter.writes == []
    assert harness.status(revised["request_id"])["state"] == "AWAITING_SECRET_AUTHORIZATION"


def _race_submit_against_cancel(
    broker: SecretBroker, request: Any, canary: Canary
) -> dict[str, str]:
    """Fire a submit and a cancel at the same instant; report what each got."""

    barrier = threading.Barrier(2)
    results: dict[str, str] = {}

    def submit() -> None:
        barrier.wait()
        try:
            broker.submit_secret(request.request_id, request.submit_token, canary.raw)
            results["submit"] = "ok"
        except VeilError as exc:
            results["submit"] = exc.public.code

    def cancel() -> None:
        barrier.wait()
        try:
            broker.cancel(request.request_id, reason="race")
            results["cancel"] = "ok"
        except VeilError as exc:
            results["cancel"] = exc.public.code

    threads = [threading.Thread(target=submit), threading.Thread(target=cancel)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    return results


def _args(destination: str = "fake-store") -> dict[str, Any]:
    return {
        "destination": destination,
        "name": "CANARY_KEY",
        "target": {"project": "acme-dev-project", "secret": "CANARY_KEY"},
        "write_mode": "create",
    }


def _wait_for(predicate: Any, timeout: float = 5.0) -> None:
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition not reached in time")


class _Clock:
    def __init__(self) -> None:
        self.now = 500.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _Discard:
    def write(self, _text: str) -> int:
        return 0

    def flush(self) -> None:
        return None
