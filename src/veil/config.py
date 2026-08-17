"""Operator-controlled configuration.

Configuration is read from the environment of the Veil process, which the agent
does not control. Nothing here can be influenced by MCP tool arguments — an
agent must not be able to relax a policy (SPEC.md §10).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path

DEFAULT_PRODUCTION_MARKERS = (
    "prod",
    "production",
    "live",
    "prd",
)

DEFAULT_STAGING_MARKERS = (
    "staging",
    "stage",
    "stg",
    "preprod",
    "pre-prod",
    "uat",
)

DEFAULT_DEVELOPMENT_MARKERS = (
    "dev",
    "development",
    "local",
    "sandbox",
    "test",
    "testing",
)


@dataclass(frozen=True, slots=True)
class VeilConfig:
    # Request lifetime -----------------------------------------------------
    request_ttl_seconds: float = 300.0
    max_active_requests: int = 64
    #: Upper bound on a single adapter write, so a hung provider cannot pin a
    #: request in EXECUTING (and therefore pin its secret in memory) forever.
    adapter_timeout_seconds: float = 30.0

    # Confirmation policy (SPEC.md §10). Operators may only make this stricter.
    stage_b_for_medium: bool = True
    stage_b_for_low: bool = False

    # Secure UI ------------------------------------------------------------
    ui_host: str = "127.0.0.1"
    ui_port: int = 0
    #: Open the authorization window on the user's machine. Keeping the URL out
    #: of the agent's reach is what makes the window an out-of-band channel.
    open_browser: bool = True
    #: Return the authorization URL to the agent. OFF by default: the URL is a
    #: capability, and an agent with network access could otherwise authorize
    #: its own request without the human (SPEC.md §4.2, §7).
    disclose_authorization_url: bool = False

    # `.env` adapter -------------------------------------------------------
    env_allowed_roots: tuple[Path, ...] = field(default_factory=lambda: (Path.cwd().resolve(),))
    allow_git_tracked_env: bool = False

    # Destination gating (SPEC.md §16: arbitrary-network is off by default and
    # is not implemented at all in this version).
    allow_arbitrary_network: bool = False
    enabled_adapters: tuple[str, ...] | None = None

    # Environment classification ------------------------------------------
    production_markers: tuple[str, ...] = DEFAULT_PRODUCTION_MARKERS
    staging_markers: tuple[str, ...] = DEFAULT_STAGING_MARKERS
    development_markers: tuple[str, ...] = DEFAULT_DEVELOPMENT_MARKERS

    def with_(self, **changes: object) -> VeilConfig:
        return replace(self, **changes)  # type: ignore[arg-type]

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> VeilConfig:
        source = os.environ if env is None else env
        cfg = cls()
        ttl = _float(source.get("VEIL_REQUEST_TTL_SECONDS"), cfg.request_ttl_seconds)
        roots = source.get("VEIL_ENV_ALLOWED_ROOTS")
        return cls(
            request_ttl_seconds=max(15.0, min(ttl, 3600.0)),
            max_active_requests=int(_float(source.get("VEIL_MAX_ACTIVE_REQUESTS"), 64)),
            adapter_timeout_seconds=max(
                1.0, min(_float(source.get("VEIL_ADAPTER_TIMEOUT_SECONDS"), 30.0), 300.0)
            ),
            stage_b_for_medium=_bool(source.get("VEIL_STAGE_B_FOR_MEDIUM"), True),
            stage_b_for_low=_bool(source.get("VEIL_STAGE_B_FOR_LOW"), False),
            ui_host=source.get("VEIL_UI_HOST", "127.0.0.1"),
            ui_port=int(_float(source.get("VEIL_UI_PORT"), 0)),
            open_browser=_bool(source.get("VEIL_OPEN_BROWSER"), True),
            disclose_authorization_url=_bool(source.get("VEIL_DISCLOSE_AUTHORIZATION_URL"), False),
            env_allowed_roots=(
                tuple(Path(p).expanduser().resolve() for p in roots.split(os.pathsep) if p)
                if roots
                else (Path.cwd().resolve(),)
            ),
            allow_git_tracked_env=_bool(source.get("VEIL_ALLOW_GIT_TRACKED_ENV"), False),
            enabled_adapters=(
                tuple(a.strip() for a in source["VEIL_ENABLED_ADAPTERS"].split(",") if a.strip())
                if source.get("VEIL_ENABLED_ADAPTERS")
                else None
            ),
        )


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _float(value: str | None, default: float) -> float:
    if value is None or value == "":
        return default
    try:
        return float(value)
    except ValueError:
        return default
