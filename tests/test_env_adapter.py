"""`.env` adapter security (SPEC.md §33)."""

from __future__ import annotations

import asyncio
import os
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests.support.canary import Canary
from tests.support.harness import Harness, build_harness
from veil.adapters.env_file import EnvFileAdapter
from veil.adapters.registry import AdapterRegistry
from veil.config import VeilConfig
from veil.errors import ErrorCode
from veil.model import Environment, WriteMode


@pytest.fixture
def env_config(tmp_path: Path) -> VeilConfig:
    return VeilConfig(
        env_allowed_roots=(tmp_path.resolve(),),
        ui_port=0,
        request_ttl_seconds=60.0,
        disclose_authorization_url=True,
        open_browser=False,
    )


@pytest.fixture
def env_harness(env_config: VeilConfig) -> Any:
    harness = build_harness(env_config, AdapterRegistry([EnvFileAdapter(env_config)]))
    yield harness
    harness.broker.shutdown()
    harness.ui.stop()


def _args(path: str = ".env", **overrides: Any) -> dict[str, Any]:
    args: dict[str, Any] = {
        "destination": "env-file",
        "name": "API_TOKEN",
        "target": {"path": path},
        "write_mode": "create",
        "environment": "development",
    }
    args.update(overrides)
    return args


def _git(tmp_path: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=tmp_path,
        capture_output=True,
        check=True,
    )


def test_writes_are_atomic_restrictive_and_preserve_other_variables(
    env_harness: Harness, tmp_path: Path, canary: Canary
) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("EXISTING=keep-me\n# a comment\nOTHER=1\n", encoding="utf-8")

    payload = env_harness.call_tool("secret.store", _args())
    status = env_harness.finish_flow(payload, canary.value)
    assert status["state"] == "STORED", status

    content = env_path.read_text(encoding="utf-8")
    assert "EXISTING=keep-me" in content
    assert "# a comment" in content
    assert f'API_TOKEN="{canary.value}"' in content
    assert stat.S_IMODE(env_path.stat().st_mode) == 0o600
    assert [p.name for p in tmp_path.iterdir()] == [".env"], "no temp copy survives"


def test_value_is_quoted_so_it_cannot_inject_further_variables(
    env_harness: Harness, tmp_path: Path
) -> None:
    payload = env_harness.call_tool("secret.store", _args())
    hostile = 'v"\nEXTRA=injected\n$(whoami)`id`'
    env_harness.finish_flow(payload, hostile)

    content = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "\nEXTRA=injected" not in content
    assert content.count("\n") == 1
    assert "\\$" in content and "\\`" in content


def test_git_tracked_env_file_is_blocked(env_harness: Harness, tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    (tmp_path / ".env").write_text("PLACEHOLDER=1\n", encoding="utf-8")
    _git(tmp_path, "add", ".env")
    _git(tmp_path, "commit", "-q", "-m", "add env")

    payload = env_harness.call_tool("secret.store", _args())
    assert payload["status"] == "failed"
    assert payload["code"] == ErrorCode.DESTINATION_NOT_PERMITTED


def test_gitignored_env_file_is_allowed(
    env_harness: Harness, tmp_path: Path, canary: Canary
) -> None:
    _git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")

    payload = env_harness.call_tool("secret.store", _args())
    assert env_harness.finish_flow(payload, canary.value)["state"] == "STORED"


def test_symlinked_destination_is_refused(env_harness: Harness, tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.env"
    outside.write_text("SHOULD_NOT_BE_TOUCHED=1\n", encoding="utf-8")
    link = tmp_path / ".env"
    link.symlink_to(outside)

    payload = env_harness.call_tool("secret.store", _args())
    assert payload["status"] == "failed"
    assert payload["code"] == ErrorCode.DESTINATION_NOT_PERMITTED
    assert outside.read_text(encoding="utf-8") == "SHOULD_NOT_BE_TOUCHED=1\n"


def test_symlink_planted_after_authorization_is_not_written_through(
    env_harness: Harness, tmp_path: Path, canary: Canary
) -> None:
    """TOCTOU: the rename-based write replaces the link, never its target."""

    outside = tmp_path.parent / "late-outside.env"
    outside.write_text("UNTOUCHED=1\n", encoding="utf-8")

    payload = env_harness.call_tool("secret.store", _args())
    (tmp_path / ".env").symlink_to(outside)  # planted between approval and write

    status = env_harness.finish_flow(payload, canary.value)
    assert outside.read_text(encoding="utf-8") == "UNTOUCHED=1\n"
    assert status["state"] in {"STORED", "FAILED"}
    if status["state"] == "STORED":
        assert not (tmp_path / ".env").is_symlink()


def test_create_mode_refuses_to_overwrite_an_existing_variable(
    env_harness: Harness, tmp_path: Path, canary: Canary
) -> None:
    (tmp_path / ".env").write_text("API_TOKEN=old-value\n", encoding="utf-8")

    payload = env_harness.call_tool("secret.store", _args())
    assert payload["requires_confirmation"] is True, "overwriting is not a one-click operation"
    status = env_harness.finish_flow(payload, canary.value)

    assert status["state"] == "FAILED"
    assert status["error"]["code"] == ErrorCode.DESTINATION_CONFLICT
    assert (tmp_path / ".env").read_text(encoding="utf-8") == "API_TOKEN=old-value\n"


def test_replace_mode_overwrites_after_confirmation(
    env_harness: Harness, tmp_path: Path, canary: Canary
) -> None:
    (tmp_path / ".env").write_text("API_TOKEN=old-value\nKEEP=1\n", encoding="utf-8")

    payload = env_harness.call_tool("secret.store", _args(write_mode="replace"))
    status = env_harness.finish_flow(payload, canary.value)

    assert status["state"] == "STORED"
    content = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "old-value" not in content
    assert "KEEP=1" in content


def test_interrupted_write_leaves_the_original_intact(
    env_config: VeilConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, canary: Canary
) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("EXISTING=keep-me\n", encoding="utf-8")
    adapter = EnvFileAdapter(env_config)

    target = asyncio.run(
        adapter.normalize_target(
            {"path": ".env"}, name="API_TOKEN", environment_hint=Environment.DEVELOPMENT
        )
    )

    def boom(_src: Any, _dst: Any) -> None:
        raise OSError("interrupted")

    monkeypatch.setattr(os, "replace", boom)

    from veil.secret_buffer import SecretBuffer

    with SecretBuffer(canary.raw) as buffer, pytest.raises(OSError, match="interrupted"):
        asyncio.run(adapter.store(buffer, target, WriteMode.CREATE))

    assert env_path.read_text(encoding="utf-8") == "EXISTING=keep-me\n"
    assert [p.name for p in tmp_path.iterdir()] == [".env"], "the temp file was cleaned up"


def test_no_credential_ever_reaches_a_subprocess_argv(
    env_harness: Harness, tmp_path: Path, canary: Canary, argv_recorder: list[list[str]]
) -> None:
    """SEC-008 / SEC-009 — git is the only subprocess, and it sees paths only."""

    _git(tmp_path, "init", "-q")
    payload = env_harness.call_tool("secret.store", _args())
    env_harness.finish_flow(payload, canary.value)

    flattened = " ".join(" ".join(argv) for argv in argv_recorder)
    assert canary.hits_in(flattened) == []
    assert all(argv[0].endswith("git") for argv in argv_recorder if argv)


def test_path_outside_allowed_roots_is_refused(env_harness: Harness, tmp_path: Path) -> None:
    payload = env_harness.call_tool("secret.store", _args(target={"path": "/tmp/veil-escape.env"}))
    assert payload["status"] == "failed"
    assert payload["code"] == ErrorCode.DESTINATION_NOT_PERMITTED
    assert not Path("/tmp/veil-escape.env").exists()


def test_invalid_variable_names_are_refused(env_harness: Harness) -> None:
    for key in ("1BAD", "with-dash", "with space", "WITH=EQUALS", "x" * 200):
        payload = env_harness.call_tool("secret.store", _args(target={"path": ".env", "key": key}))
        assert payload["status"] == "failed", key
        assert payload["code"] == ErrorCode.INVALID_TARGET, key


def test_omitted_variable_name_falls_back_to_the_credential_name(
    env_harness: Harness, tmp_path: Path, canary: Canary
) -> None:
    payload = env_harness.call_tool("secret.store", _args())
    assert payload["destination"]["resource"] == ".env \u2192 API_TOKEN"
    env_harness.finish_flow(payload, canary.value)
    assert "API_TOKEN=" in (tmp_path / ".env").read_text(encoding="utf-8")
