"""SPEC.md §34 — the trusted window's own security properties."""

from __future__ import annotations

import http.client
import urllib.parse
from typing import Any

import pytest

from tests.support.canary import Canary
from tests.support.fakes import RecordingAdapter
from tests.support.harness import Harness

pytestmark = pytest.mark.security


def test_stage_a_shows_destination_environment_and_operation(
    harness: Harness, store_args: dict[str, Any]
) -> None:
    payload = harness.call_tool(
        "secret.store", {**store_args, "target": {"project": "acme-production"}}
    )
    body = harness.get(harness.path_for(payload)).body

    assert "Destination type" in body
    assert "Project / account" in body
    assert "acme-production" in body
    assert "Environment" in body
    assert "production" in body
    assert "Operation" in body


def test_high_risk_is_visually_distinguishable(
    harness: Harness, adapter: RecordingAdapter, store_args: dict[str, Any]
) -> None:
    adapter.exists = True
    payload = harness.call_tool(
        "secret.store",
        {
            **store_args,
            "target": {"project": "acme-production"},
            "write_mode": "replace",
            "environment": "production",
        },
    )
    body = harness.get(harness.path_for(payload)).body
    assert 'class="risk risk-high"' in body
    assert "high risk" in body


def test_secret_field_is_masked_and_not_autocompleted(
    harness: Harness, store_args: dict[str, Any]
) -> None:
    payload = harness.call_tool("secret.store", store_args)
    body = harness.get(harness.path_for(payload)).body

    assert 'type="password"' in body
    assert 'autocomplete="off"' in body
    assert 'spellcheck="false"' in body
    assert 'type="text"' not in body


def test_pages_are_not_cached_framed_or_referred(
    harness: Harness, store_args: dict[str, Any]
) -> None:
    payload = harness.call_tool("secret.store", store_args)
    response = harness.get(harness.path_for(payload))

    headers = {k.lower(): v for k, v in response.headers.items()}
    assert "no-store" in headers["cache-control"]
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    csp = headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "form-action 'self'" in csp


def test_url_never_contains_credential_material_and_post_redirects(
    harness: Harness, store_args: dict[str, Any], canary: Canary
) -> None:
    payload = harness.call_tool("secret.store", store_args)
    response = harness.submit_secret(payload, canary.value)

    assert response.status == 303, "POST/redirect/GET protects the back button"
    location = response.headers.get("Location", "")
    assert canary.value not in location
    assert canary.value not in harness.path_for(payload)

    # Re-visiting the redirect target must not resubmit anything.
    follow_up = harness.get(location)
    assert canary.value not in follow_up.body
    harness.collect_logs()
    harness.scanner.assert_clean(canary)


def test_stage_b_never_redisplays_the_credential(
    harness: Harness, adapter: RecordingAdapter, store_args: dict[str, Any], canary: Canary
) -> None:
    adapter.exists = True
    payload = harness.call_tool(
        "secret.store", {**store_args, "write_mode": "replace", "environment": "production"}
    )
    harness.submit_secret(payload, canary.value)
    body = harness.get(harness.path_for(payload)).body

    assert canary.value not in body
    assert "been written yet" in body
    assert 'type="password"' not in body


def test_non_loopback_host_header_is_rejected(harness: Harness, store_args: dict[str, Any]) -> None:
    """DNS-rebinding defence: only loopback Host values are served."""

    payload = harness.call_tool("secret.store", store_args)
    parsed = urllib.parse.urlsplit(harness.ui.base_url or "")
    connection = http.client.HTTPConnection(parsed.hostname or "", parsed.port or 0, timeout=5)
    try:
        connection.request(
            "GET", harness.path_for(payload), headers={"Host": "veil.attacker.example"}
        )
        response = connection.getresponse()
        body = response.read().decode()
    finally:
        connection.close()

    assert response.status == 400
    assert "acme" not in body


def test_unknown_paths_do_not_enumerate_requests(
    harness: Harness, store_args: dict[str, Any]
) -> None:
    harness.call_tool("secret.store", store_args)
    for path in ("/", "/r", "/requests", "/r/req_unknown/token"):
        response = harness.get(path)
        assert response.status in {404, 403}
        assert "STRIPE_SECRET_KEY" not in response.body


def test_expired_request_page_reports_expiry(harness: Harness, store_args: dict[str, Any]) -> None:
    payload = harness.call_tool("secret.store", store_args)
    request = harness.broker.get(payload["request_id"])
    request.expires_at = harness.broker._clock() - 1

    response = harness.get(harness.path_for(payload))
    assert response.status == 200
    assert "expired" in response.body.lower()
    assert 'type="password"' not in response.body


def test_oversized_body_is_refused(harness: Harness, store_args: dict[str, Any]) -> None:
    payload = harness.call_tool("secret.store", store_args)
    response = harness.post(f"{harness.path_for(payload)}/submit", {"secret": "x" * 200_000})
    assert response.status == 413
    assert harness.status(payload["request_id"])["state"] == "AWAITING_SECRET_AUTHORIZATION"
