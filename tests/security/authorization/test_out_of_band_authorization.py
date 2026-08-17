"""The authorization channel must stay out of the agent's reach (SPEC.md §4.2, §7).

The Stage A link is a capability: whoever holds it can complete the human's half
of the flow. A compromised agent with a shell or an HTTP tool is exactly the
threat model of SPEC.md §18.1, so by default Veil hands that link to the user's
browser and gives the agent only a request id.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from tests.support.canary import Canary
from tests.support.fakes import RecordingAdapter
from tests.support.harness import build_harness
from veil.adapters.registry import AdapterRegistry
from veil.config import VeilConfig

pytestmark = pytest.mark.security


def _harness(config: VeilConfig, adapter: RecordingAdapter) -> Any:
    return build_harness(config, AdapterRegistry([adapter]))


def test_authorization_url_is_not_disclosed_to_the_agent(
    config: VeilConfig, adapter: RecordingAdapter, store_args: dict[str, Any], canary: Canary
) -> None:
    production_config = config.with_(disclose_authorization_url=False, open_browser=False)
    harness = _harness(production_config, adapter)
    try:
        payload = harness.call_tool("secret.store", store_args)
        status = harness.status(payload["request_id"])

        assert "authorization_url" not in payload
        assert "authorization_url" not in status
        assert "deliberately not shared with you" in payload["authorization"]

        request = harness.broker.get(payload["request_id"])
        rendered = json.dumps([payload, status])
        assert request.submit_token not in rendered
        assert request.confirm_token not in rendered
        assert canary.hits_in(rendered) == []
    finally:
        harness.broker.shutdown()
        harness.ui.stop()


def test_the_human_is_notified_through_the_ui_not_through_mcp(
    config: VeilConfig, adapter: RecordingAdapter, store_args: dict[str, Any]
) -> None:
    presented: list[tuple[str, str]] = []
    harness = _harness(config.with_(disclose_authorization_url=False, open_browser=False), adapter)
    try:
        harness.broker.set_authorization_notifier(lambda rid, url: presented.append((rid, url)))
        payload = harness.call_tool("secret.store", store_args)

        assert len(presented) == 1
        request_id, url = presented[0]
        assert request_id == payload["request_id"]
        assert harness.broker.get(request_id).submit_token in url
    finally:
        harness.broker.shutdown()
        harness.ui.stop()
