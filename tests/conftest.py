from __future__ import annotations

import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.support.canary import Canary
from tests.support.fakes import RecordingAdapter
from tests.support.harness import Harness, build_harness
from veil.adapters.registry import AdapterRegistry
from veil.config import VeilConfig


@pytest.fixture
def config(tmp_path: Path) -> VeilConfig:
    return VeilConfig(
        request_ttl_seconds=60.0,
        adapter_timeout_seconds=5.0,
        env_allowed_roots=(tmp_path.resolve(),),
        ui_host="127.0.0.1",
        ui_port=0,
        # The harness plays the human: it needs the link the browser would get.
        # `test_authorization_url_is_not_disclosed_to_the_agent` covers the
        # production default, where the agent never sees it.
        disclose_authorization_url=True,
        open_browser=False,
    )


@pytest.fixture
def adapter(config: VeilConfig) -> RecordingAdapter:
    return RecordingAdapter(config)


@pytest.fixture
def registry(adapter: RecordingAdapter) -> AdapterRegistry:
    return AdapterRegistry([adapter])


@pytest.fixture
def harness(config: VeilConfig, registry: AdapterRegistry) -> Iterator[Harness]:
    built = build_harness(config, registry)
    try:
        yield built
    finally:
        built.broker.shutdown()
        built.ui.stop()


@pytest.fixture
def canary() -> Canary:
    return Canary.new()


@pytest.fixture
def store_args() -> dict[str, Any]:
    return {
        "destination": "fake-store",
        "name": "STRIPE_SECRET_KEY",
        "target": {"project": "acme-dev-project", "secret": "STRIPE_SECRET_KEY"},
        "write_mode": "create",
        "environment": "development",
    }


@pytest.fixture
def argv_recorder(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Record every spawned process argv (SEC-008, SEC-009)."""

    recorded: list[list[str]] = []
    real_run = subprocess.run
    real_popen = subprocess.Popen

    def spy_run(args: Any, *rest: Any, **kwargs: Any) -> Any:
        recorded.append([str(a) for a in args] if isinstance(args, list | tuple) else [str(args)])
        assert kwargs.get("shell", False) is False, "Veil must never spawn a shell"
        return real_run(args, *rest, **kwargs)

    class SpyPopen(real_popen):  # type: ignore[misc,valid-type]
        def __init__(self, args: Any, *rest: Any, **kwargs: Any) -> None:
            recorded.append(
                [str(a) for a in args] if isinstance(args, list | tuple) else [str(args)]
            )
            assert kwargs.get("shell", False) is False, "Veil must never spawn a shell"
            super().__init__(args, *rest, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy_run)
    monkeypatch.setattr(subprocess, "Popen", SpyPopen)
    return recorded
