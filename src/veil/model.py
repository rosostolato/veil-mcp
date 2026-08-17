"""Immutable domain objects (SPEC.md §11, §12, §14, §15).

Everything the human authorizes and everything the executor performs is derived
from a single frozen :class:`AuthorizationSnapshot`. There is no second
"display" representation, by construction: the UI renders this object and the
executor consumes this object.
"""

from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from veil.redaction import safe_display


class RequestState(enum.StrEnum):
    """The state machine of SPEC.md §14."""

    CREATED = "CREATED"
    PREFLIGHT = "PREFLIGHT"
    AWAITING_SECRET_AUTHORIZATION = "AWAITING_SECRET_AUTHORIZATION"
    SECRET_RECEIVED = "SECRET_RECEIVED"
    AWAITING_EXECUTION_CONFIRMATION = "AWAITING_EXECUTION_CONFIRMATION"
    EXECUTING = "EXECUTING"
    STORED = "STORED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"

    @property
    def is_terminal(self) -> bool:
        return self in TERMINAL_STATES


TERMINAL_STATES = frozenset(
    {
        RequestState.STORED,
        RequestState.FAILED,
        RequestState.CANCELLED,
        RequestState.EXPIRED,
    }
)

#: The only transitions the broker will perform (SPEC.md §14).
ALLOWED_TRANSITIONS: dict[RequestState, frozenset[RequestState]] = {
    RequestState.CREATED: frozenset({RequestState.PREFLIGHT, RequestState.FAILED}),
    RequestState.PREFLIGHT: frozenset(
        {RequestState.AWAITING_SECRET_AUTHORIZATION, RequestState.FAILED}
    ),
    RequestState.AWAITING_SECRET_AUTHORIZATION: frozenset(
        {
            RequestState.SECRET_RECEIVED,
            RequestState.CANCELLED,
            RequestState.EXPIRED,
        }
    ),
    RequestState.SECRET_RECEIVED: frozenset(
        {
            RequestState.AWAITING_EXECUTION_CONFIRMATION,
            RequestState.EXECUTING,
            RequestState.CANCELLED,
            RequestState.EXPIRED,
        }
    ),
    RequestState.AWAITING_EXECUTION_CONFIRMATION: frozenset(
        {
            RequestState.EXECUTING,
            RequestState.CANCELLED,
            RequestState.EXPIRED,
        }
    ),
    RequestState.EXECUTING: frozenset({RequestState.STORED, RequestState.FAILED}),
    RequestState.STORED: frozenset(),
    RequestState.FAILED: frozenset(),
    RequestState.CANCELLED: frozenset(),
    RequestState.EXPIRED: frozenset(),
}


class RiskLevel(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def severity(self) -> int:
        return _RISK_ORDER[self]

    def escalate(self, other: RiskLevel) -> RiskLevel:
        """Risk only ever moves up (SPEC.md §10: agents cannot downgrade)."""

        return self if self.severity >= other.severity else other


_RISK_ORDER = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2}


class Environment(enum.StrEnum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    UNKNOWN = "unknown"

    @property
    def severity(self) -> int:
        return _ENVIRONMENT_ORDER[self]

    def escalate(self, other: Environment) -> Environment:
        return self if self.severity >= other.severity else other


# UNKNOWN ranks above STAGING: an environment we could not classify is treated
# conservatively, but a destination we positively identified as production still
# wins over an agent's vague claim.
_ENVIRONMENT_ORDER = {
    Environment.DEVELOPMENT: 0,
    Environment.STAGING: 1,
    Environment.UNKNOWN: 2,
    Environment.PRODUCTION: 3,
}


class WriteMode(enum.StrEnum):
    CREATE = "create"
    NEW_VERSION = "new-version"
    REPLACE = "replace"


class DestinationClass(enum.StrEnum):
    SECRET_STORE = "secret-store"
    LOCAL_PLAINTEXT = "local-plaintext"
    REMOTE_APPLICATION_STORAGE = "remote-application-storage"
    ARBITRARY_NETWORK = "arbitrary-network"


#: Wording the UI is required to show for the riskier destination classes
#: (SPEC.md §16).
DESTINATION_CLASS_NOTICE: dict[DestinationClass, str] = {
    DestinationClass.LOCAL_PLAINTEXT: (
        "This destination stores the credential as plaintext on this machine."
    ),
    DestinationClass.REMOTE_APPLICATION_STORAGE: (
        "This destination may not be designed to store secrets."
    ),
    DestinationClass.ARBITRARY_NETWORK: (
        "This destination sends the credential to an arbitrary network endpoint."
    ),
}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass(frozen=True, slots=True)
class NormalizedTarget:
    """An adapter's canonical, validated description of *where* a secret goes.

    Adapters produce this from untrusted agent input. Once built it never
    changes, and both the confirmation UI and the executor read it.
    """

    adapter_id: str
    destination_class: DestinationClass
    provider_label: str
    resource_label: str
    environment: Environment
    account_label: str | None = None
    #: Canonical adapter-specific fields, e.g. the resolved absolute path.
    fields: tuple[tuple[str, str], ...] = ()
    #: Adapter-authored, non-sensitive warnings shown to the human.
    warnings: tuple[str, ...] = ()

    def as_public_dict(self) -> dict[str, Any]:
        """Display-safe projection. Used for the UI, audit records and MCP results."""

        data: dict[str, Any] = {
            "adapter": self.adapter_id,
            "destination_class": str(self.destination_class),
            "provider": safe_display(self.provider_label),
            "resource": safe_display(self.resource_label),
            "environment": str(self.environment),
        }
        if self.account_label is not None:
            data["account"] = safe_display(self.account_label)
        if self.fields:
            data["fields"] = {k: safe_display(v) for k, v in self.fields}
        if self.warnings:
            data["warnings"] = [safe_display(w, max_length=200) for w in self.warnings]
        return data

    def digest_payload(self) -> dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "destination_class": str(self.destination_class),
            "provider_label": self.provider_label,
            "resource_label": self.resource_label,
            "environment": str(self.environment),
            "account_label": self.account_label,
            "fields": [list(pair) for pair in self.fields],
        }

    def field(self, name: str) -> str | None:
        for key, value in self.fields:
            if key == name:
                return value
        return None


@dataclass(frozen=True, slots=True)
class ValidationResult:
    ok: bool
    code: str | None = None
    message: str | None = None


@dataclass(frozen=True, slots=True)
class PreflightResult:
    """What the adapter learned about the destination *before* asking for a secret."""

    ok: bool
    exists: bool = False
    notes: tuple[str, ...] = ()
    code: str | None = None
    message: str | None = None


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    level: RiskLevel
    reasons: tuple[str, ...] = ()
    requires_stage_b: bool = False

    def as_public_dict(self) -> dict[str, Any]:
        return {
            "level": str(self.level),
            "reasons": [safe_display(r, max_length=200) for r in self.reasons],
            "requires_confirmation": self.requires_stage_b,
        }


@dataclass(frozen=True, slots=True)
class AuthorizationSnapshot:
    """The immutable operation the human authorizes (SPEC.md §11).

    ``digest`` is recomputed immediately before execution and compared with the
    value recorded at authorization time; any divergence aborts the write.
    """

    request_id: str
    logical_name: str
    target: NormalizedTarget
    operation: WriteMode
    risk: RiskAssessment
    created_at: float
    expires_at: float
    description: str | None = None
    exists_at_preflight: bool = False

    @property
    def digest(self) -> str:
        payload = {
            "request_id": self.request_id,
            "logical_name": self.logical_name,
            "operation": str(self.operation),
            "risk": str(self.risk.level),
            "requires_stage_b": self.risk.requires_stage_b,
            "target": self.target.digest_payload(),
        }
        return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()

    def as_public_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "request_id": self.request_id,
            "credential": safe_display(self.logical_name),
            "operation": str(self.operation),
            "destination": self.target.as_public_dict(),
            "risk": self.risk.as_public_dict(),
            "authorization_digest": self.digest,
        }
        if self.description:
            data["description"] = safe_display(self.description, max_length=300)
        return data


@dataclass(frozen=True, slots=True)
class StoreResult:
    """Non-sensitive outcome metadata handed back to the model (SPEC.md §1)."""

    stored: bool
    #: Provider-side identifier of what was written, e.g. a secret version name.
    destination_ref: str | None = None
    detail: tuple[tuple[str, str], ...] = field(default=())

    def as_public_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"status": "stored" if self.stored else "not-stored"}
        if self.destination_ref:
            data["destination_ref"] = safe_display(self.destination_ref)
        if self.detail:
            data["detail"] = {k: safe_display(v) for k, v in self.detail}
        return data
