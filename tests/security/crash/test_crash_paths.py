"""SPEC.md §18.9, §31 — crashes must not dump credential material."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.support.canary import Canary, LeakScanner
from tests.support.crash_child import STAGES
from tests.support.fakes import RecordingAdapter
from tests.support.harness import Harness
from veil.model import RequestState

pytestmark = pytest.mark.security

REPO_ROOT = Path(__file__).resolve().parents[3]
CHILD = REPO_ROOT / "tests" / "support" / "crash_child.py"


@pytest.mark.parametrize("stage", STAGES)
def test_crash_does_not_leak_the_secret(stage: str, tmp_path: Path) -> None:
    canary = Canary.new(stage.replace("_", ""))
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    result = subprocess.run(
        [sys.executable, str(CHILD), stage, str(tmp_path)],
        input=canary.raw + b"\n",
        capture_output=True,
        cwd=REPO_ROOT,
        env=env,
        timeout=60,
        check=False,
    )

    assert result.returncode != 0, "the child was supposed to die"

    scanner = LeakScanner()
    scanner.add("child_stdout", result.stdout)
    scanner.add("child_stderr", result.stderr)
    scanner.add("process_argv", " ".join([str(CHILD), stage, str(tmp_path)]))
    scanner.add_tree("crash_artifacts", tmp_path)
    scanner.assert_clean(canary)

    if stage != "during_destination_call":
        # SIGKILL cannot run handlers; every other stage must have run ours.
        assert b"unhandled_exception" in result.stderr


def test_shutdown_destroys_live_secrets_at_every_stage(
    harness: Harness, adapter: RecordingAdapter, canary: Canary
) -> None:
    adapter.exists = True
    payload = harness.call_tool(
        "secret.store",
        {
            "destination": "fake-store",
            "name": "SHUTDOWN_KEY",
            "target": {"project": "acme-production", "secret": "SHUTDOWN_KEY"},
            "write_mode": "replace",
            "environment": "production",
        },
    )
    harness.submit_secret(payload, canary.value)
    request = harness.broker.get(payload["request_id"])
    assert request.secret is not None

    harness.broker.shutdown()

    assert request.secret is None
    assert request.state is RequestState.CANCELLED
    assert adapter.writes == []
    harness.collect_logs()
    harness.scanner.assert_clean(canary)


def test_request_cannot_be_replayed_after_a_restart(
    harness: Harness, adapter: RecordingAdapter
) -> None:
    """§31 — nothing about a request survives the process, so nothing is replayable."""

    payload = harness.call_tool(
        "secret.store",
        {
            "destination": "fake-store",
            "name": "RESTART_KEY",
            "target": {"project": "acme-dev-project", "secret": "RESTART_KEY"},
            "write_mode": "create",
        },
    )
    harness.broker.shutdown()

    response = harness.submit_secret(payload, "value-after-restart")
    assert response.status in {403, 404, 410}
    assert adapter.writes == []
