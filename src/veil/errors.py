"""Public, secret-free error surface (SPEC.md §20).

Nothing in this module may carry provider detail. Adapters translate their own
exceptions into a :class:`PublicError` through ``sanitize_error``; if that
translation fails for any reason, callers degrade to :data:`INTERNAL_ERROR`
rather than leaking the original exception.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final


class ErrorCode:
    """Stable, machine-readable codes returned across the MCP boundary."""

    UNKNOWN_DESTINATION: Final = "UNKNOWN_DESTINATION"
    INVALID_TARGET: Final = "INVALID_TARGET"
    INVALID_ARGUMENTS: Final = "INVALID_ARGUMENTS"
    FORBIDDEN_FIELD: Final = "FORBIDDEN_FIELD"
    DESTINATION_NOT_PERMITTED: Final = "DESTINATION_NOT_PERMITTED"
    REQUEST_NOT_FOUND: Final = "REQUEST_NOT_FOUND"
    REQUEST_NOT_ACTIVE: Final = "REQUEST_NOT_ACTIVE"
    REQUEST_EXPIRED: Final = "REQUEST_EXPIRED"
    REQUEST_CANCELLED: Final = "REQUEST_CANCELLED"
    INVALID_STATE: Final = "INVALID_STATE"
    UNAUTHORIZED: Final = "UNAUTHORIZED"
    AUTHORIZATION_INVALIDATED: Final = "AUTHORIZATION_INVALIDATED"
    CONFIRMATION_REQUIRED: Final = "CONFIRMATION_REQUIRED"
    SNAPSHOT_MISMATCH: Final = "SNAPSHOT_MISMATCH"
    TOO_MANY_REQUESTS: Final = "TOO_MANY_REQUESTS"
    SECRET_TOO_LARGE: Final = "SECRET_TOO_LARGE"
    EMPTY_SECRET: Final = "EMPTY_SECRET"
    PREFLIGHT_FAILED: Final = "PREFLIGHT_FAILED"
    DESTINATION_WRITE_FAILED: Final = "DESTINATION_WRITE_FAILED"
    DESTINATION_UNAVAILABLE: Final = "DESTINATION_UNAVAILABLE"
    DESTINATION_DENIED: Final = "DESTINATION_DENIED"
    DESTINATION_NOT_FOUND: Final = "DESTINATION_NOT_FOUND"
    DESTINATION_CONFLICT: Final = "DESTINATION_CONFLICT"
    DESTINATION_RATE_LIMITED: Final = "DESTINATION_RATE_LIMITED"
    DESTINATION_TIMEOUT: Final = "DESTINATION_TIMEOUT"
    ADAPTER_UNAVAILABLE: Final = "ADAPTER_UNAVAILABLE"
    INTERNAL_ERROR: Final = "INTERNAL_ERROR"


@dataclass(frozen=True, slots=True)
class PublicError:
    """An error that is safe to hand to the model.

    ``message`` is written by Veil, never by a provider. ``detail`` may only
    contain short, adapter-authored, non-sensitive strings.
    """

    code: str
    message: str
    detail: tuple[tuple[str, str], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"status": "failed", "code": self.code, "message": self.message}
        if self.detail:
            out["detail"] = dict(self.detail)
        return out


INTERNAL_ERROR: Final = PublicError(
    ErrorCode.INTERNAL_ERROR,
    "The operation failed. Details were withheld to avoid disclosing sensitive data.",
)


class VeilError(Exception):
    """Base class for errors that already know their public representation."""

    def __init__(self, public: PublicError) -> None:
        super().__init__(public.code)
        self.public = public


def veil_error(code: str, message: str, **detail: str) -> VeilError:
    return VeilError(PublicError(code, message, tuple(sorted(detail.items()))))
