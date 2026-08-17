"""`.env` adapter — local plaintext destination (SPEC.md §16, §33).

Security properties implemented here:

* the resolved path must stay inside an operator-configured root, and explicit
  ``..`` traversal is rejected outright;
* the target must not be a symlink, and the write is performed with
  ``os.replace`` — which replaces a link rather than writing through it — so a
  symlink planted between check and write still cannot redirect the credential;
* a git-tracked ``.env`` is refused by default;
* the write is atomic (temp file in the same directory, ``0600``, ``fsync``,
  rename), so an interrupted write cannot corrupt unrelated variables;
* the credential never appears in an argv: the only subprocess invoked is
  ``git``, and it only ever receives paths.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from veil.adapters.base import SecretDestinationAdapter, adapter_error
from veil.errors import ErrorCode, PublicError
from veil.model import (
    DestinationClass,
    Environment,
    NormalizedTarget,
    PreflightResult,
    RiskAssessment,
    RiskLevel,
    StoreResult,
    ValidationResult,
    WriteMode,
)
from veil.secret_buffer import SecretBuffer

ENV_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
DEFAULT_FILENAME = ".env"
GIT_TIMEOUT_SECONDS = 5.0


class EnvFileAdapter(SecretDestinationAdapter):
    id = "env-file"
    display_name = "Local .env file"
    destination_class = DestinationClass.LOCAL_PLAINTEXT
    risk_class = RiskLevel.MEDIUM

    def target_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "path": {
                    "type": "string",
                    "maxLength": 512,
                    "description": (
                        "Path to the env file, relative to an allowed root. Defaults to '.env'."
                    ),
                },
                "key": {
                    "type": "string",
                    "maxLength": 128,
                    "description": "Variable name to set. Defaults to the credential name.",
                },
            },
        }

    def supported_write_modes(self) -> tuple[WriteMode, ...]:
        return (WriteMode.CREATE, WriteMode.REPLACE)

    # -- normalization -----------------------------------------------------

    async def normalize_target(
        self,
        target: Mapping[str, Any],
        *,
        name: str,
        environment_hint: Environment,
    ) -> NormalizedTarget:
        unknown = sorted(set(target) - {"path", "key"})
        if unknown:
            raise adapter_error(
                ErrorCode.INVALID_TARGET,
                "The destination target contained unsupported fields.",
            )

        key = str(target.get("key") or name)
        if not ENV_KEY_PATTERN.match(key):
            raise adapter_error(
                ErrorCode.INVALID_TARGET,
                "The environment variable name is not a valid identifier.",
            )

        raw_path = str(target.get("path") or DEFAULT_FILENAME)
        resolved = self._resolve_path(raw_path)

        environment = self.classify_environment(str(resolved), key).escalate(environment_hint)
        return NormalizedTarget(
            adapter_id=self.id,
            destination_class=self.destination_class,
            provider_label="Local file (plaintext)",
            account_label=str(resolved.parent),
            resource_label=f"{resolved.name} → {key}",
            environment=environment,
            fields=(("path", str(resolved)), ("key", key)),
            warnings=("This destination stores the credential as plaintext on this machine.",),
        )

    def _resolve_path(self, raw_path: str) -> Path:
        if "\x00" in raw_path:
            raise adapter_error(ErrorCode.INVALID_TARGET, "The destination path is not valid.")
        candidate = Path(raw_path)
        if ".." in candidate.parts:
            raise adapter_error(
                ErrorCode.INVALID_TARGET,
                "Relative path traversal is not permitted in a destination path.",
            )
        roots = self.config.env_allowed_roots
        if not roots:
            raise adapter_error(
                ErrorCode.DESTINATION_NOT_PERMITTED,
                "No local destination directory is permitted by policy.",
            )
        if not candidate.is_absolute():
            candidate = roots[0] / candidate
        if candidate.name in {"", ".", ".."}:
            raise adapter_error(ErrorCode.INVALID_TARGET, "The destination path is not a file.")

        # Resolve the *parent* so symlinked directories cannot escape a root,
        # while leaving the final component unresolved for the symlink check.
        parent = candidate.parent.resolve()
        resolved = parent / candidate.name
        if not any(_is_within(parent, root) for root in roots):
            raise adapter_error(
                ErrorCode.DESTINATION_NOT_PERMITTED,
                "The destination path is outside the directories permitted by policy.",
            )
        return resolved

    # -- validation and preflight -----------------------------------------

    async def validate_target(self, target: NormalizedTarget) -> ValidationResult:
        path = Path(target.field("path") or "")
        if path.is_symlink():
            return ValidationResult(
                ok=False,
                code=ErrorCode.DESTINATION_NOT_PERMITTED,
                message="The destination path is a symbolic link and will not be written through.",
            )
        if path.exists() and not path.is_file():
            return ValidationResult(
                ok=False,
                code=ErrorCode.INVALID_TARGET,
                message="The destination path is not a regular file.",
            )
        if not path.parent.is_dir():
            return ValidationResult(
                ok=False,
                code=ErrorCode.INVALID_TARGET,
                message="The destination directory does not exist.",
            )
        return ValidationResult(ok=True)

    async def preflight(self, target: NormalizedTarget) -> PreflightResult:
        path = Path(target.field("path") or "")
        key = target.field("key") or ""
        notes: list[str] = []

        if _git_tracks(path) and not self.config.allow_git_tracked_env:
            return PreflightResult(
                ok=False,
                code=ErrorCode.DESTINATION_NOT_PERMITTED,
                message="This file is tracked by git; writing a credential into it is blocked.",
            )
        if path.exists() and not _git_ignores(path):
            notes.append("This file does not appear to be git-ignored.")

        exists = False
        if path.exists():
            try:
                existing = _read_without_following_symlinks(path)
            except OSError:
                return PreflightResult(
                    ok=False,
                    code=ErrorCode.DESTINATION_NOT_PERMITTED,
                    message="The destination file could not be read safely.",
                )
            exists = _find_key_line(existing.splitlines(), key) is not None
            if exists:
                notes.append("This variable already has a value in the file and will be replaced.")
        return PreflightResult(ok=True, exists=exists, notes=tuple(notes))

    async def calculate_risk(
        self,
        target: NormalizedTarget,
        operation: WriteMode,
        *,
        exists: bool,
    ) -> RiskAssessment:
        return RiskAssessment(
            level=RiskLevel.MEDIUM,
            reasons=("The credential will be written to a plaintext file on this machine.",),
        )

    # -- write -------------------------------------------------------------

    async def store(
        self,
        secret: SecretBuffer,
        target: NormalizedTarget,
        operation: WriteMode,
    ) -> StoreResult:
        path = Path(target.field("path") or "")
        key = target.field("key") or ""

        if path.is_symlink():
            raise adapter_error(
                ErrorCode.DESTINATION_NOT_PERMITTED,
                "The destination path is a symbolic link and will not be written through.",
            )

        existing_lines: list[str] = []
        if path.exists():
            existing_lines = _read_without_following_symlinks(path).splitlines()

        index = _find_key_line(existing_lines, key)
        if index is not None and operation is WriteMode.CREATE:
            raise adapter_error(
                ErrorCode.DESTINATION_CONFLICT,
                "The variable already exists; a replace operation is required to overwrite it.",
            )

        line = f"{key}={_quote(secret.as_text())}"
        if index is None:
            lines = [*existing_lines, line]
        else:
            lines = [*existing_lines[:index], line, *existing_lines[index + 1 :]]
        content = "\n".join(lines) + "\n"

        _atomic_write(path, content)
        return StoreResult(
            stored=True,
            destination_ref=f"{path}:{key}",
            detail=(("file_mode", "0600"), ("variable", key)),
        )

    async def sanitize_error(self, error: Exception) -> PublicError:
        if isinstance(error, PermissionError):
            return PublicError(
                ErrorCode.DESTINATION_DENIED,
                "The destination file could not be written due to filesystem permissions.",
            )
        if isinstance(error, FileNotFoundError):
            return PublicError(
                ErrorCode.DESTINATION_NOT_FOUND,
                "The destination directory no longer exists.",
            )
        if isinstance(error, IsADirectoryError | NotADirectoryError):
            return PublicError(
                ErrorCode.INVALID_TARGET,
                "The destination path is not a regular file.",
            )
        return await super().sanitize_error(error)


# -- helpers --------------------------------------------------------------


def _is_within(path: Path, root: Path) -> bool:
    try:
        return path == root or path.is_relative_to(root)
    except ValueError:  # pragma: no cover - different drives on Windows
        return False


def _read_without_following_symlinks(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        handle = os.fdopen(fd, "r", encoding="utf-8", errors="replace")
    except BaseException:
        os.close(fd)
        raise
    with handle:
        return handle.read()


def _find_key_line(lines: list[str], key: str) -> int | None:
    prefix_export = f"export {key}="
    prefix = f"{key}="
    for index, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith(prefix) or stripped.startswith(prefix_export):
            return index
    return None


def _quote(value: str) -> str:
    """Serialize a value so it round-trips and cannot inject further variables."""

    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("$", "\\$")
        .replace("`", "\\`")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )
    return f'"{escaped}"'


def _atomic_write(path: Path, content: str) -> None:
    """Write via a 0600 temp file in the same directory, then rename.

    SEC-010: this is the one place Veil creates a temporary copy of credential
    material. It is unavoidable for atomicity (SPEC.md §33). The file is created
    with mode 0600 by ``mkstemp``, is never world-readable, and is deleted
    deterministically on any failure path.
    """

    directory = path.parent
    fd, temp_name = tempfile.mkstemp(prefix=".veil-", dir=directory)
    temp_path = Path(temp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except BaseException:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise
    else:
        try:
            os.chmod(path, 0o600)
        except OSError:  # pragma: no cover - platform dependent
            pass
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def _git_output(path: Path, *args: str) -> subprocess.CompletedProcess[bytes] | None:
    git = shutil.which("git")
    if git is None or not path.parent.is_dir():
        return None
    try:
        return subprocess.run(  # noqa: S603 - fixed argv, no shell, paths only
            [git, "-C", str(path.parent), *args, "--", str(path)],
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _git_tracks(path: Path) -> bool:
    result = _git_output(path, "ls-files", "--error-unmatch")
    return result is not None and result.returncode == 0


def _git_ignores(path: Path) -> bool:
    result = _git_output(path, "check-ignore", "-q")
    return result is not None and result.returncode == 0
