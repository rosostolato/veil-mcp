"""SPEC.md §28, §18.7 — 100 concurrent requests, zero cross-wiring."""

from __future__ import annotations

import concurrent.futures
from typing import Any

import pytest

from tests.support.canary import Canary, LeakScanner
from tests.support.fakes import RecordingAdapter
from tests.support.harness import Harness
from veil.adapters.registry import AdapterRegistry
from veil.broker import SecretBroker, parse_store_params
from veil.config import VeilConfig
from veil.logging_ import AuditLogger

pytestmark = pytest.mark.security

REQUEST_COUNT = 100


def test_concurrent_requests_do_not_cross_secrets(
    config: VeilConfig, registry: AdapterRegistry, adapter: RecordingAdapter
) -> None:
    log_records: list[dict[str, Any]] = []
    broker = SecretBroker(
        config.with_(max_active_requests=REQUEST_COUNT * 2),
        registry,
        logger=AuditLogger(stream=_Discard(), sink=log_records.append),
    )

    expected: dict[str, str] = {}
    requests = []
    for index in range(REQUEST_COUNT):
        canary = Canary.new(f"{index:03d}")
        secret_name = f"CANARY_{index:03d}"
        params = parse_store_params(
            {
                "destination": "fake-store",
                "name": secret_name,
                "target": {"project": "acme-dev-project", "secret": secret_name},
                "write_mode": "create",
            },
            registry,
        )
        request = broker.create_request(params)
        expected[secret_name] = canary.value
        requests.append((request, canary))

    def submit(item: tuple[Any, Canary]) -> None:
        request, canary = item
        broker.submit_secret(request.request_id, request.submit_token, canary.raw)

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(submit, requests))

    assert len(adapter.writes) == REQUEST_COUNT, "every request must write exactly once"
    written = dict(adapter.writes)
    assert len(written) == REQUEST_COUNT, "no duplicate writes"
    assert written == expected, "a secret reached the wrong destination"

    for request, _canary in requests:
        assert broker.get(request.request_id).state == "STORED"
        assert broker.get(request.request_id).secret is None

    scanner = LeakScanner()
    scanner.add("audit_records", str(log_records))
    for _request, canary in requests:
        scanner.assert_clean(canary)


def test_concurrent_requests_through_the_ui_stay_bound(
    harness: Harness, adapter: RecordingAdapter
) -> None:
    """The same isolation, exercised through the real HTTP surface."""

    payloads = []
    for index in range(20):
        name = f"UI_CANARY_{index:03d}"
        payloads.append(
            (
                harness.call_tool(
                    "secret.store",
                    {
                        "destination": "fake-store",
                        "name": name,
                        "target": {"project": "acme-dev-project", "secret": name},
                        "write_mode": "create",
                    },
                ),
                Canary.new(f"ui{index:03d}"),
                name,
            )
        )

    def run(item: tuple[dict[str, Any], Canary, str]) -> None:
        payload, canary, _name = item
        harness.submit_secret(payload, canary.value)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(run, payloads))

    written = dict(adapter.writes)
    assert written == {name: canary.value for _payload, canary, name in payloads}


class _Discard:
    def write(self, _text: str) -> int:
        return 0

    def flush(self) -> None:
        return None
