"""Firestore adapter — remote application storage (SPEC.md §16, §17).

Firestore is not a secret store. This adapter exists because agents ask for it,
and Veil would rather show the human a loud, accurate warning than pretend the
destination is safe. It is classified ``remote-application-storage``, which
forces elevated confirmation in :mod:`veil.policy`.
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
PATH_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
FIELD_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")

ClientFactory = Callable[[], Any]


class FirestoreAdapter(SecretDestinationAdapter):
    id = "firestore"
    display_name = "Firestore document field"
    destination_class = DestinationClass.REMOTE_APPLICATION_STORAGE
    risk_class = RiskLevel.MEDIUM

    def __init__(self, config: VeilConfig, client_factory: ClientFactory | None = None) -> None:
        super().__init__(config)
        self._client_factory = client_factory
        self._client: Any | None = None

    def target_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["project", "collection", "document"],
            "properties": {
                "project": {"type": "string", "maxLength": 64},
                "collection": {"type": "string", "maxLength": 128},
                "document": {"type": "string", "maxLength": 128},
                "field": {
                    "type": "string",
                    "maxLength": 128,
                    "description": "Document field to set. Defaults to the credential name.",
                },
            },
        }

    def supported_write_modes(self) -> tuple[WriteMode, ...]:
        return (WriteMode.CREATE, WriteMode.REPLACE)

    async def normalize_target(
        self,
        target: Mapping[str, Any],
        *,
        name: str,
        environment_hint: Environment,
    ) -> NormalizedTarget:
        unknown = sorted(set(target) - {"project", "collection", "document", "field"})
        if unknown:
            raise adapter_error(
                ErrorCode.INVALID_TARGET,
                "The destination target contained unsupported fields.",
            )
        project = str(target.get("project", "")).strip()
        collection = str(target.get("collection", "")).strip()
        document = str(target.get("document", "")).strip()
        field_name = str(target.get("field") or name).strip()

        if not PROJECT_PATTERN.match(project):
            raise adapter_error(
                ErrorCode.INVALID_TARGET, "The Google Cloud project identifier is not valid."
            )
        for segment in (collection, document):
            if not PATH_SEGMENT_PATTERN.match(segment):
                raise adapter_error(
                    ErrorCode.INVALID_TARGET,
                    "The Firestore collection or document path is not valid.",
                )
        if not FIELD_PATTERN.match(field_name):
            raise adapter_error(ErrorCode.INVALID_TARGET, "The document field name is not valid.")

        environment = self.classify_environment(project, collection, document, name).escalate(
            environment_hint
        )
        return NormalizedTarget(
            adapter_id=self.id,
            destination_class=self.destination_class,
            provider_label="Firestore (application database)",
            account_label=project,
            resource_label=f"{collection}/{document}.{field_name}",
            environment=environment,
            fields=(
                ("project", project),
                ("collection", collection),
                ("document", document),
                ("field", field_name),
            ),
            warnings=(
                "This destination may not be designed to store secrets.",
                "Anyone with read access to this database can read the credential.",
            ),
        )

    async def validate_target(self, target: NormalizedTarget) -> ValidationResult:
        for key in ("project", "collection", "document", "field"):
            if not target.field(key):
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
                message="Firestore is not configured on this machine.",
            )
        try:
            document = self._document(client, target).get(timeout=self._timeout)
            exists = bool(getattr(document, "exists", False))
            data = document.to_dict() if exists and hasattr(document, "to_dict") else None
            field_present = bool(data and (target.field("field") or "") in data)
        except Exception:
            return PreflightResult(ok=True, exists=False)
        notes = ("The document already exists.",) if exists else ()
        return PreflightResult(ok=True, exists=field_present, notes=notes)

    async def calculate_risk(
        self,
        target: NormalizedTarget,
        operation: WriteMode,
        *,
        exists: bool,
    ) -> RiskAssessment:
        return RiskAssessment(
            level=RiskLevel.MEDIUM,
            reasons=("The credential will be stored in an application database.",),
            requires_stage_b=True,
        )

    async def store(
        self,
        secret: SecretBuffer,
        target: NormalizedTarget,
        operation: WriteMode,
    ) -> StoreResult:
        client = self._get_client()
        reference = self._document(client, target)
        field_name = target.field("field") or ""

        if operation is WriteMode.CREATE:
            snapshot = reference.get(timeout=self._timeout)
            data = snapshot.to_dict() if getattr(snapshot, "exists", False) else None
            if data and field_name in data:
                raise adapter_error(
                    ErrorCode.DESTINATION_CONFLICT,
                    "The document field already exists; a replace operation is required.",
                )

        reference.set({field_name: secret.as_text()}, merge=True, timeout=self._timeout)
        return StoreResult(
            stored=True,
            destination_ref=(
                f"projects/{target.field('project')}/databases/(default)/documents/"
                f"{target.field('collection')}/{target.field('document')}"
            ),
            detail=(("field", field_name),),
        )

    async def sanitize_error(self, error: Exception) -> PublicError:
        code = getattr(error, "code", None)
        status = code() if callable(code) else code
        status_value = getattr(status, "value", status)
        if isinstance(status_value, tuple):
            status_value = status_value[0]
        mapping = {
            401: (ErrorCode.DESTINATION_DENIED, "Veil is not authenticated to the destination."),
            403: (ErrorCode.DESTINATION_DENIED, "The destination denied access."),
            404: (ErrorCode.DESTINATION_NOT_FOUND, "The destination document was not found."),
            409: (ErrorCode.DESTINATION_CONFLICT, "The destination reported a conflict."),
            429: (ErrorCode.DESTINATION_RATE_LIMITED, "The destination rate limited the write."),
            503: (ErrorCode.DESTINATION_UNAVAILABLE, "The destination is unavailable."),
        }
        if isinstance(status_value, int) and status_value in mapping:
            mapped = mapping[status_value]
            return PublicError(mapped[0], mapped[1])
        return await super().sanitize_error(error)

    @property
    def _timeout(self) -> float:
        return self.config.adapter_timeout_seconds

    def _document(self, client: Any, target: NormalizedTarget) -> Any:
        return client.collection(target.field("collection")).document(target.field("document"))

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        if self._client_factory is not None:
            self._client = self._client_factory()
            return self._client
        try:
            from google.cloud import firestore
        except ImportError as exc:  # pragma: no cover - depends on install extras
            raise adapter_error(
                ErrorCode.ADAPTER_UNAVAILABLE,
                "Firestore support is not installed.",
            ) from exc
        self._client = firestore.Client()
        return self._client
