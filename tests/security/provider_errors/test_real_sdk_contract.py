"""The adapters must match the SDKs they actually call, not just our fakes.

These tests import the optional provider SDKs and check the two things a fake
can never prove: that the methods and keyword arguments Veil calls exist, and
that the exceptions those SDKs really raise are mapped to secret-free public
errors. They are skipped when the extras are not installed; CI installs them.

No network is used — only introspection and locally constructed exceptions.
"""

from __future__ import annotations

import asyncio
import inspect

import pytest

from veil.config import VeilConfig

pytestmark = pytest.mark.security


def test_secret_manager_calls_exist_and_accept_a_timeout() -> None:
    secretmanager = pytest.importorskip("google.cloud.secretmanager")

    client = secretmanager.SecretManagerServiceClient
    for method in (
        "get_secret",
        "create_secret",
        "add_secret_version",
        "list_secret_versions",
        "disable_secret_version",
    ):
        function = getattr(client, method, None)
        assert function is not None, f"adapter calls {method}, which the SDK does not have"
        parameters = inspect.signature(function).parameters
        assert "request" in parameters
        # The broker cannot cancel a blocking gRPC call, so the provider-level
        # timeout is what actually bounds a hung destination.
        assert "timeout" in parameters, f"{method} must accept the timeout Veil passes"


def test_firestore_calls_exist_and_accept_a_timeout() -> None:
    pytest.importorskip("google.cloud.firestore")
    from google.cloud.firestore_v1.document import DocumentReference

    for method, required in (("get", {"timeout"}), ("set", {"merge", "timeout"})):
        parameters = set(inspect.signature(getattr(DocumentReference, method)).parameters)
        assert required <= parameters, f"DocumentReference.{method} lost {required - parameters}"


@pytest.mark.parametrize(
    ("exception_name", "expected_code"),
    [
        ("Unauthenticated", "DESTINATION_DENIED"),
        ("PermissionDenied", "DESTINATION_DENIED"),
        ("NotFound", "DESTINATION_NOT_FOUND"),
        ("AlreadyExists", "DESTINATION_CONFLICT"),
        ("TooManyRequests", "DESTINATION_RATE_LIMITED"),
        ("ServiceUnavailable", "DESTINATION_UNAVAILABLE"),
        ("InternalServerError", "DESTINATION_WRITE_FAILED"),
    ],
)
def test_real_google_exceptions_map_to_public_errors(
    exception_name: str, expected_code: str
) -> None:
    exceptions = pytest.importorskip("google.api_core.exceptions")
    from veil.adapters.gcp_secret_manager import GcpSecretManagerAdapter

    adapter = GcpSecretManagerAdapter(VeilConfig())
    secret_text = "sk_live_the_actual_credential_value"
    error = getattr(exceptions, exception_name)(f'rejected "{secret_text}"')

    public = asyncio.run(adapter.sanitize_error(error))

    assert public.code == expected_code
    assert secret_text not in public.message
    assert secret_text not in str(public.detail)
