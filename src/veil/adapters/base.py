"""Destination adapter interface (SPEC.md §15, §16).

An adapter is the only component besides the broker that touches credential
bytes. It therefore has three obligations:

* it must return a :class:`~veil.model.NormalizedTarget` that fully describes
  the destination, because that object — and nothing else — is what the human
  authorizes and what the executor consumes;
* it must never place secret material in a URL, an argv, a log or an error;
* it must translate its provider's exceptions into a
  :class:`~veil.errors.PublicError` that contains no provider text.
"""

from __future__ import annotations

import abc
from collections.abc import Mapping
from typing import Any

from veil.config import VeilConfig
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


class AdapterError(Exception):
    """Raised by adapters for conditions they can describe safely themselves."""

    def __init__(self, public: PublicError) -> None:
        super().__init__(public.code)
        self.public = public


def adapter_error(code: str, message: str) -> AdapterError:
    return AdapterError(PublicError(code, message))


class SecretDestinationAdapter(abc.ABC):
    id: str
    display_name: str
    destination_class: DestinationClass
    #: Floor for risk assessment; policy may escalate above it, never below.
    risk_class: RiskLevel = RiskLevel.LOW

    def __init__(self, config: VeilConfig) -> None:
        self.config = config

    # -- schema ------------------------------------------------------------

    @abc.abstractmethod
    def target_schema(self) -> dict[str, Any]:
        """JSON Schema for this adapter's ``target`` object.

        Must be closed (``additionalProperties: false``) and must not contain
        any field capable of carrying credential content (SPEC.md §6).
        """

    def supported_write_modes(self) -> tuple[WriteMode, ...]:
        return (WriteMode.CREATE, WriteMode.NEW_VERSION, WriteMode.REPLACE)

    # -- lifecycle ---------------------------------------------------------

    @abc.abstractmethod
    async def normalize_target(
        self,
        target: Mapping[str, Any],
        *,
        name: str,
        environment_hint: Environment,
    ) -> NormalizedTarget:
        """Turn untrusted agent input into a canonical destination object."""

    async def validate_target(self, target: NormalizedTarget) -> ValidationResult:
        return ValidationResult(ok=True)

    async def preflight(self, target: NormalizedTarget) -> PreflightResult:
        return PreflightResult(ok=True)

    @abc.abstractmethod
    async def calculate_risk(
        self,
        target: NormalizedTarget,
        operation: WriteMode,
        *,
        exists: bool,
    ) -> RiskAssessment:
        """Adapter-specific baseline risk. Policy escalates; it never lowers."""

    @abc.abstractmethod
    async def store(
        self,
        secret: SecretBuffer,
        target: NormalizedTarget,
        operation: WriteMode,
    ) -> StoreResult:
        """Write the secret. MUST NOT return, log or echo the secret."""

    async def sanitize_error(self, error: Exception) -> PublicError:
        """Default translation: reveal nothing beyond a generic failure."""

        if isinstance(error, AdapterError):
            return error.public
        return PublicError(
            ErrorCode.DESTINATION_WRITE_FAILED,
            "The destination rejected the credential write.",
        )

    # -- helpers -----------------------------------------------------------

    def classify_environment(self, *parts: str | None) -> Environment:
        """Derive the environment from destination naming.

        This is server-side evidence. The agent's claimed ``environment`` may
        raise the result but never lower it (SPEC.md §10, §26.2).
        """

        haystack = " ".join(p.lower() for p in parts if p)
        tokens = {t for t in _tokenize(haystack) if t}
        for marker in self.config.production_markers:
            if marker in tokens:
                return Environment.PRODUCTION
        for marker in self.config.staging_markers:
            if marker in tokens:
                return Environment.STAGING
        for marker in self.config.development_markers:
            if marker in tokens:
                return Environment.DEVELOPMENT
        return Environment.UNKNOWN


def _tokenize(text: str) -> list[str]:
    out: list[str] = []
    current: list[str] = []
    for ch in text:
        if ch.isalnum():
            current.append(ch)
        else:
            if current:
                out.append("".join(current))
            current = []
    if current:
        out.append("".join(current))
    return out
