"""Unpredictable identifiers and capability tokens (SPEC.md §18.6)."""

from __future__ import annotations

import hmac
import secrets

REQUEST_ID_PREFIX = "req_"


def new_request_id() -> str:
    """A single-use, cryptographically unpredictable request identifier."""

    return REQUEST_ID_PREFIX + secrets.token_urlsafe(18)


def new_token() -> str:
    """A capability token binding a browser interaction to one request.

    This is not secret material: it never travels with the credential and it
    grants nothing beyond the right to act on one already-created request.
    """

    return secrets.token_urlsafe(32)


def token_equals(expected: str, provided: str) -> bool:
    return hmac.compare_digest(expected.encode("utf-8"), provided.encode("utf-8"))
