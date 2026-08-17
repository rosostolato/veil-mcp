"""Unit tests for the security-critical domain primitives."""

from __future__ import annotations

import copy
import json
import pickle

import pytest

from veil.model import (
    ALLOWED_TRANSITIONS,
    TERMINAL_STATES,
    Environment,
    RequestState,
    RiskLevel,
)
from veil.redaction import contains_secret, derivations, looks_like_credential, safe_display
from veil.secret_buffer import SecretBuffer, SecretDestroyed


def test_secret_buffer_refuses_to_be_shown_copied_or_serialized() -> None:
    buffer = SecretBuffer(b"super-secret-value")

    assert "super-secret" not in repr(buffer)
    assert "super-secret" not in str(buffer)
    assert "super-secret" not in f"{buffer}"
    assert "super-secret" not in format(buffer, ">40")

    for action in (
        lambda: pickle.dumps(buffer),
        lambda: copy.copy(buffer),
        lambda: copy.deepcopy(buffer),
        lambda: bytes(buffer),
        lambda: list(buffer),
    ):
        with pytest.raises(TypeError):
            action()

    with pytest.raises(TypeError):
        json.dumps({"secret": buffer})


def test_secret_buffer_zeroizes_and_refuses_use_afterwards() -> None:
    buffer = SecretBuffer(bytearray(b"value-to-wipe"))
    assert buffer.as_text() == "value-to-wipe"

    buffer.zeroize()

    assert buffer.destroyed
    for action in (buffer.as_bytes, buffer.as_text, buffer.view, lambda: len(buffer)):
        with pytest.raises(SecretDestroyed):
            action()
    assert buffer.contains_in("value-to-wipe") is False


def test_secret_buffer_wipes_the_callers_mutable_input() -> None:
    source = bytearray(b"transient-copy")
    SecretBuffer(source)
    assert bytes(source) == b""


def test_secret_buffer_rejects_oversized_values() -> None:
    with pytest.raises(ValueError, match="maximum size"):
        SecretBuffer(b"x" * (64 * 1024 + 1))


def test_derivations_detect_encoded_leaks() -> None:
    secret = b"a-very-recognisable-secret-value"
    for encoded in derivations(secret):
        assert contains_secret(b"prefix " + encoded + b" suffix", secret)
    assert not contains_secret(b"unrelated content", secret)


def test_safe_display_neutralises_control_and_bidi_characters() -> None:
    rendered = safe_display("A\x1b[31m‮B​C\x00")
    assert "\x1b" not in rendered
    assert "‮" not in rendered
    assert "​" not in rendered
    assert "\\u001b" in rendered
    assert rendered.startswith("A")


def test_looks_like_credential_matches_known_shapes() -> None:
    assert looks_like_credential("sk_live_abcdefgh12345678")
    assert looks_like_credential("-----BEGIN RSA PRIVATE KEY-----")
    assert not looks_like_credential("STRIPE_SECRET_KEY")
    assert not looks_like_credential("acme-production")


def test_risk_and_environment_only_escalate() -> None:
    assert RiskLevel.LOW.escalate(RiskLevel.HIGH) is RiskLevel.HIGH
    assert RiskLevel.HIGH.escalate(RiskLevel.LOW) is RiskLevel.HIGH
    assert Environment.DEVELOPMENT.escalate(Environment.PRODUCTION) is Environment.PRODUCTION
    assert Environment.PRODUCTION.escalate(Environment.DEVELOPMENT) is Environment.PRODUCTION
    assert Environment.UNKNOWN.severity > Environment.STAGING.severity


def test_terminal_states_have_no_outgoing_transitions() -> None:
    for state in TERMINAL_STATES:
        assert ALLOWED_TRANSITIONS[state] == frozenset()
        assert state.is_terminal
    assert set(ALLOWED_TRANSITIONS) == set(RequestState)


def test_state_machine_matches_the_specified_graph() -> None:
    assert ALLOWED_TRANSITIONS[RequestState.AWAITING_SECRET_AUTHORIZATION] == frozenset(
        {RequestState.SECRET_RECEIVED, RequestState.CANCELLED, RequestState.EXPIRED}
    )
    assert ALLOWED_TRANSITIONS[RequestState.EXECUTING] == frozenset(
        {RequestState.STORED, RequestState.FAILED}
    )
    assert RequestState.SECRET_RECEIVED not in ALLOWED_TRANSITIONS[RequestState.EXECUTING]
