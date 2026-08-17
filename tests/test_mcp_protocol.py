"""MCP transport and contract behaviour (SPEC.md §13, §24 SEC-002/003/004)."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.support.canary import Canary
from tests.support.harness import Harness

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_unknown_methods_and_malformed_frames_are_rejected_cleanly(harness: Harness) -> None:
    assert harness.rpc("does/not/exist")["error"]["code"] == -32601
    assert harness.server.handle_message("not an object")["error"]["code"] == -32600
    assert harness.server.handle_message({"jsonrpc": "2.0", "id": 1})["error"]["code"] == -32600
    assert harness.server.handle_message({"method": "notifications/initialized"}) is None


def test_transport_round_trip_over_stdio(harness: Harness, store_args: dict[str, Any]) -> None:
    lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        "",
        "{ not json",
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "secret.store", "arguments": store_args},
            }
        ),
    ]
    stdin = io.BytesIO(("\n".join(lines) + "\n").encode("utf-8"))
    stdout = io.BytesIO()

    harness.server.serve(stdin, stdout)

    responses = [json.loads(line) for line in stdout.getvalue().splitlines() if line]
    assert [r.get("id") for r in responses] == [1, None, 2, 3]
    assert responses[1]["error"]["code"] == -32700
    assert responses[3]["result"]["isError"] is False


def test_outbound_frames_carrying_a_live_secret_are_blocked(
    harness: Harness, store_args: dict[str, Any], canary: Canary
) -> None:
    """The transport is the last line of defence, and it is armed."""

    payload = harness.call_tool(
        "secret.store", {**store_args, "write_mode": "replace", "environment": "production"}
    )
    harness.submit_secret(payload, canary.value)

    stdout = io.BytesIO()
    harness.server._write(
        stdout,
        {"jsonrpc": "2.0", "id": 9, "result": {"leak": canary.value}},
    )

    written = stdout.getvalue().decode()
    assert canary.hits_in(written) == []
    assert "suppressed" in written


def test_tool_results_are_structured_and_text_consistent(
    harness: Harness, store_args: dict[str, Any]
) -> None:
    response = harness.rpc("tools/call", {"name": "secret.store", "arguments": store_args})
    result = response["result"]
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]


def test_destinations_tool_describes_closed_target_schemas(harness: Harness) -> None:
    payload = harness.call_tool("secret.destinations", {})
    for destination in payload["destinations"]:
        assert destination["target_schema"]["additionalProperties"] is False
    assert payload["note"].startswith("No destination accepts a credential value")


@pytest.mark.security
def test_server_process_keeps_stdout_for_protocol_only(tmp_path: Path) -> None:
    """SEC-004 — a stray print cannot pollute or contaminate the protocol stream."""

    script = (
        "import json,sys;print('this should never reach stdout');sys.stderr.write('log line\\n')"
    )
    env = {
        **os.environ,
        "PYTHONPATH": str(REPO_ROOT / "src"),
        "VEIL_ENV_ALLOWED_ROOTS": str(tmp_path),
        "VEIL_UI_PORT": "0",
    }
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n"
    process = subprocess.run(
        [sys.executable, "-c", f"{script}\nimport veil.__main__ as m; m.main(['serve'])"],
        input=request.encode(),
        capture_output=True,
        cwd=REPO_ROOT,
        env=env,
        timeout=60,
        check=False,
    )

    stdout_lines = [line for line in process.stdout.decode().splitlines() if line.strip()]
    assert all(line.startswith("{") for line in stdout_lines), process.stdout
    assert json.loads(stdout_lines[0])["result"]["serverInfo"]["name"] == "veil"
    assert b"this should never reach stdout" in process.stderr
