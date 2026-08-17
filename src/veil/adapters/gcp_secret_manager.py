"""Google Secret Manager adapter (SPEC.md §16 `secret-store`, §17).

The credential travels in the body of an authenticated gRPC call made by the
official SDK: never in a URL, never in an argv, never in a shell string
(SEC-007, SEC-008, SEC-009). The SDK is imported lazily so that installations
that only use the `.env` adapter do not carry it in their trusted computing
base, and so tests can inject a fake client.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any

from veil.adapters.base import SecretDestinationAdapter, adapter_error
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

PROJECT_PATTERN = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$|^[0-9]{6,20}$")
SECRET_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,255}$")

ClientFactory = Callable[[], Any]


class GcpSecretManagerAdapter(SecretDestinationAdapter):
    id = "gcp-secret-manager"
    display_name = "Google Secret Manager"
    destination_class = DestinationClass.SECRET_STORE
    risk_class = RiskLevel.LOW

    def __init__(self, config: VeilConfig, client_factory: ClientFactory | None = None) -> None:
        super().__init__(config)
        self._client_factory = client_factory
        self._client: Any | None = None

    # -- schema ------------------------------------------------------------

    def target_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["project", "secret"],
            "properties": {
                "project": {
                    "type": "string",
                    "maxLength": 64,
                    "description": "Google Cloud project id or number that owns the secret.",
                },
                "secret": {
                    "type": "string",
                    "maxLength": 255,
                    "description": "Secret id within the project.",
                },
            },
        }

    def supported_write_modes(self) -> tuple[WriteMode, ...]:
        return (WriteMode.CREATE, WriteMode.NEW_VERSION, WriteMode.REPLACE)

    # -- normalization -----------------------------------------------------

    async def normalize_target(
        self,
        target: Mapping[str, Any],
        *,
        name: str,
        environment_hint: Environment,
    ) -> NormalizedTarget:
        unknown = sorted(set(target) - {"project", "secret"})
        if unknown:
            raise adapter_error(
                ErrorCode.INVALID_TARGET,
                "The destination target contained unsupported fields.",
            )
        project = str(target.get("project", "")).strip()
        secret_id = str(target.get("secret") or name).strip()

        if not PROJECT_PATTERN.match(project):
            raise adapter_error(
                ErrorCode.INVALID_TARGET,
                "The Google Cloud project identifier is not valid.",
            )
        if not SECRET_PATTERN.match(secret_id):
            raise adapter_error(ErrorCode.INVALID_TARGET, "The secret id is not valid.")

        environment = self.classify_environment(project, secret_id, name).escalate(environment_hint)
        return NormalizedTarget(
            adapter_id=self.id,
            destination_class=self.destination_class,
            provider_label="Google Secret Manager",
            account_label=project,
            resource_label=secret_id,
            environment=environment,
            fields=(
                ("project", project),
                ("secret", secret_id),
                ("resource_name", f"projects/{project}/secrets/{secret_id}"),
            ),
        )

    async def validate_target(self, target: NormalizedTarget) -> ValidationResult:
        if not target.field("project") or not target.field("secret"):
            return ValidationResult(
                ok=False,
                code=ErrorCode.INVALID_TARGET,
                message="The destination target is incomplete.",
            )
        return ValidationResult(ok=True)

    async def preflight(self, target: NormalizedTarget) -> PreflightResult:
        try:
            client = self._get_client()
        except Exception:
            return PreflightResult(
                ok=False,
                code=ErrorCode.ADAPTER_UNAVAILABLE,
                message="Google Secret Manager is not configured on this machine.",
            )
        name = target.field("resource_name") or ""
        try:
            client.get_secret(request={"name": name})
        except Exception:
            return PreflightResult(ok=True, exists=False, notes=("The secret does not exist yet.",))
        return PreflightResult(
            ok=True,
            exists=True,
            notes=("The secret already exists; a new version will be added.",),
        )

    async def calculate_risk(
        self,
        target: NormalizedTarget,
        operation: WriteMode,
        *,
        exists: bool,
    ) -> RiskAssessment:
        reasons: list[str] = []
        level = RiskLevel.LOW
        if operation is WriteMode.REPLACE:
            level = RiskLevel.MEDIUM
            reasons.append("Previous versions of this secret will be disabled.")
        return RiskAssessment(level=level, reasons=tuple(reasons))

    # -- write -------------------------------------------------------------

    async def store(
        self,
        secret: SecretBuffer,
        target: NormalizedTarget,
        operation: WriteMode,
    ) -> StoreResult:
        client = self._get_client()
        project = target.field("project") or ""
        secret_id = target.field("secret") or ""
        parent = f"projects/{project}"
        resource_name = target.field("resource_name") or f"{parent}/secrets/{secret_id}"

        if operation is WriteMode.CREATE:
            client.create_secret(
                request={
                    "parent": parent,
                    "secret_id": secret_id,
                    "secret": {"replication": {"automatic": {}}},
                }
            )

        previous_versions: list[str] = []
        if operation is WriteMode.REPLACE:
            previous_versions = _enabled_version_names(client, resource_name)

        version = client.add_secret_version(
            request={
                "parent": resource_name,
                "payload": {"data": secret.as_bytes()},
            }
        )
        version_name = getattr(version, "name", None) or f"{resource_name}/versions/latest"

        disabled = 0
        failed_disables = 0
        for previous in previous_versions:
            if previous == version_name:
                continue
            try:
                client.disable_secret_version(request={"name": previous})
                disabled += 1
            except Exception:
                # Surfaced as a count in the result; the provider's own message
                # is never propagated (SPEC.md §20).
                failed_disables += 1

        detail = [("operation", str(operation))]
        if disabled:
            detail.append(("disabled_previous_versions", str(disabled)))
        if failed_disables:
            detail.append(("previous_versions_still_enabled", str(failed_disables)))
        return StoreResult(stored=True, destination_ref=version_name, detail=tuple(detail))

    async def sanitize_error(self, error: Exception) -> PublicError:
        """Map provider failures by status code only — never by message."""

        code = getattr(error, "code", None)
        status = code() if callable(code) else code
        status_value = getattr(status, "value", status)
        if isinstance(status_value, tuple):  # grpc StatusCode.value is (int, str)
            status_value = status_value[0]

        mapping = {
            400: (ErrorCode.INVALID_TARGET, "The destination rejected the request as invalid."),
            401: (ErrorCode.DESTINATION_DENIED, "Veil is not authenticated to the destination."),
            403: (ErrorCode.DESTINATION_DENIED, "The destination denied access."),
            404: (ErrorCode.DESTINATION_NOT_FOUND, "The destination resource was not found."),
            409: (ErrorCode.DESTINATION_CONFLICT, "The destination resource already exists."),
            429: (ErrorCode.DESTINATION_RATE_LIMITED, "The destination rate limited the write."),
            500: (ErrorCode.DESTINATION_WRITE_FAILED, "The destination reported an error."),
            503: (ErrorCode.DESTINATION_UNAVAILABLE, "The destination is unavailable."),
            504: (ErrorCode.DESTINATION_TIMEOUT, "The destination did not respond in time."),
        }
        if isinstance(status_value, int) and status_value in mapping:
            mapped = mapping[status_value]
            return PublicError(mapped[0], mapped[1])
        if isinstance(error, TimeoutError):
            return PublicError(
                ErrorCode.DESTINATION_TIMEOUT, "The destination did not respond in time."
            )
        return await super().sanitize_error(error)

    # -- client ------------------------------------------------------------

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        if self._client_factory is not None:
            self._client = self._client_factory()
            return self._client
        try:
            from google.cloud import secretmanager
        except ImportError as exc:  # pragma: no cover - depends on install extras
            raise adapter_error(
                ErrorCode.ADAPTER_UNAVAILABLE,
                "Google Secret Manager support is not installed.",
            ) from exc
        self._client = secretmanager.SecretManagerServiceClient()
        return self._client


def _enabled_version_names(client: Any, resource_name: str) -> list[str]:
    try:
        versions = client.list_secret_versions(request={"parent": resource_name})
    except Exception:
        return []
    names: list[str] = []
    for version in versions:
        state = getattr(version, "state", None)
        state_name = getattr(state, "name", str(state))
        if state_name == "ENABLED":
            name = getattr(version, "name", None)
            if isinstance(name, str):
                names.append(name)
    return names
