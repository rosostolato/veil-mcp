"""Test doubles: adapters and provider clients that behave badly on purpose."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
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
    WriteMode,
)
from veil.secret_buffer import SecretBuffer


class RecordingAdapter(SecretDestinationAdapter):
    """A well-behaved secret store that records what it was asked to write."""

    id = "fake-store"
    display_name = "Fake Secret Store"
    destination_class = DestinationClass.SECRET_STORE
    risk_class = RiskLevel.LOW

    def __init__(self, config: VeilConfig, *, exists: bool = False) -> None:
        super().__init__(config)
        self.exists = exists
        #: (resource_label, secret_text) pairs, in write order.
        self.writes: list[tuple[str, str]] = []
        #: The exact NormalizedTarget objects handed to ``store``.
        self.targets: list[NormalizedTarget] = []
        self.urls: list[str] = []

    def target_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["project", "secret"],
            "properties": {
                "project": {"type": "string", "maxLength": 64},
                "secret": {"type": "string", "maxLength": 128},
            },
        }

    async def normalize_target(
        self,
        target: Mapping[str, Any],
        *,
        name: str,
        environment_hint: Environment,
    ) -> NormalizedTarget:
        unknown = sorted(set(target) - {"project", "secret"})
        if unknown:
            raise adapter_error(ErrorCode.INVALID_TARGET, "Unsupported target fields.")
        project = str(target.get("project", "")).strip()
        secret_id = str(target.get("secret") or name).strip()
        if not project or not secret_id:
            raise adapter_error(ErrorCode.INVALID_TARGET, "The target is incomplete.")
        environment = self.classify_environment(project, secret_id, name).escalate(environment_hint)
        return NormalizedTarget(
            adapter_id=self.id,
            destination_class=self.destination_class,
            provider_label="Fake Secret Store",
            account_label=project,
            resource_label=secret_id,
            environment=environment,
            fields=(("project", project), ("secret", secret_id)),
        )

    async def preflight(self, target: NormalizedTarget) -> PreflightResult:
        return PreflightResult(ok=True, exists=self.exists)

    async def calculate_risk(
        self,
        target: NormalizedTarget,
        operation: WriteMode,
        *,
        exists: bool,
    ) -> RiskAssessment:
        return RiskAssessment(level=RiskLevel.LOW)

    async def store(
        self,
        secret: SecretBuffer,
        target: NormalizedTarget,
        operation: WriteMode,
    ) -> StoreResult:
        self.urls.append(
            f"https://fake.invalid/v1/projects/{target.field('project')}"
            f"/secrets/{target.field('secret')}:addVersion"
        )
        self.targets.append(target)
        self.writes.append((target.resource_label, secret.as_text()))
        return StoreResult(
            stored=True,
            destination_ref=f"{target.field('project')}/{target.field('secret')}/versions/1",
        )


class EchoingErrorAdapter(RecordingAdapter):
    """A provider whose exception text contains the credential (SPEC.md §32)."""

    id = "echoing-store"
    display_name = "Echoing Store"

    async def store(
        self,
        secret: SecretBuffer,
        target: NormalizedTarget,
        operation: WriteMode,
    ) -> StoreResult:
        raise RuntimeError(f'Failed storing "{secret.as_text()}" at {target.resource_label}')


class EchoingSanitizerAdapter(RecordingAdapter):
    """An adapter whose own ``sanitize_error`` leaks. The broker must catch it."""

    id = "echoing-sanitizer"
    display_name = "Echoing Sanitizer"

    async def store(
        self,
        secret: SecretBuffer,
        target: NormalizedTarget,
        operation: WriteMode,
    ) -> StoreResult:
        raise RuntimeError(secret.as_text())

    async def sanitize_error(self, error: Exception) -> PublicError:
        return PublicError(ErrorCode.DESTINATION_WRITE_FAILED, str(error))


class LeakyResultAdapter(RecordingAdapter):
    """An adapter that returns the credential inside its 'non-sensitive' result."""

    id = "leaky-result"
    display_name = "Leaky Result Store"

    async def store(
        self,
        secret: SecretBuffer,
        target: NormalizedTarget,
        operation: WriteMode,
    ) -> StoreResult:
        return StoreResult(stored=True, destination_ref=f"stored:{secret.as_text()}")


class RaisingSanitizerAdapter(RecordingAdapter):
    """Sanitization itself fails; the broker must suppress rather than expose."""

    id = "broken-sanitizer"
    display_name = "Broken Sanitizer Store"

    async def store(
        self,
        secret: SecretBuffer,
        target: NormalizedTarget,
        operation: WriteMode,
    ) -> StoreResult:
        raise RuntimeError("provider exploded")

    async def sanitize_error(self, error: Exception) -> PublicError:
        raise ValueError("sanitizer exploded")


class SlowAdapter(RecordingAdapter):
    """Never finishes in time; exercises the adapter timeout."""

    id = "slow-store"
    display_name = "Slow Store"

    async def store(
        self,
        secret: SecretBuffer,
        target: NormalizedTarget,
        operation: WriteMode,
    ) -> StoreResult:
        await asyncio.sleep(30)
        raise AssertionError("unreachable")


class StatusError(Exception):
    """Provider-style exception carrying an HTTP-ish status code."""

    def __init__(self, status: int, message: str = "provider failure") -> None:
        super().__init__(message)
        self.code = status


# -- provider client doubles ----------------------------------------------


class FakeSecretVersion:
    def __init__(self, name: str, state: str = "ENABLED") -> None:
        self.name = name
        self.state = type("State", (), {"name": state})()


class FakeSecretManagerClient:
    """Mimics the surface of ``SecretManagerServiceClient`` used by the adapter."""

    def __init__(self, *, existing: set[str] | None = None, fail: Exception | None = None) -> None:
        self.existing = existing or set()
        self.fail = fail
        self.versions: dict[str, list[FakeSecretVersion]] = {}
        self.payloads: list[tuple[str, bytes]] = []
        self.disabled: list[str] = []
        self.requests: list[dict[str, Any]] = []

    def get_secret(self, request: dict[str, Any], timeout: float | None = None) -> Any:
        name = request["name"]
        if name not in self.existing:
            raise StatusError(404, "not found")
        return type("Secret", (), {"name": name})()

    def create_secret(self, request: dict[str, Any], timeout: float | None = None) -> Any:
        self.requests.append({"method": "create_secret", "parent": request["parent"]})
        name = f"{request['parent']}/secrets/{request['secret_id']}"
        if name in self.existing:
            raise StatusError(409, "already exists")
        self.existing.add(name)
        return type("Secret", (), {"name": name})()

    def add_secret_version(self, request: dict[str, Any], timeout: float | None = None) -> Any:
        if self.fail is not None:
            raise self.fail
        parent = request["parent"]
        data = request["payload"]["data"]
        self.payloads.append((parent, bytes(data)))
        versions = self.versions.setdefault(parent, [])
        version = FakeSecretVersion(f"{parent}/versions/{len(versions) + 1}")
        versions.append(version)
        self.requests.append({"method": "add_secret_version", "parent": parent})
        return version

    def list_secret_versions(
        self, request: dict[str, Any], timeout: float | None = None
    ) -> list[FakeSecretVersion]:
        return list(self.versions.get(request["parent"], []))

    def disable_secret_version(self, request: dict[str, Any], timeout: float | None = None) -> Any:
        self.disabled.append(request["name"])
        return None


class FakeDocumentSnapshot:
    def __init__(self, data: dict[str, Any] | None) -> None:
        self._data = data
        self.exists = data is not None

    def to_dict(self) -> dict[str, Any] | None:
        return dict(self._data) if self._data is not None else None


class FakeDocumentReference:
    def __init__(self, store: dict[str, dict[str, Any]], path: str) -> None:
        self._store = store
        self._path = path

    def get(self, timeout: float | None = None) -> FakeDocumentSnapshot:
        return FakeDocumentSnapshot(self._store.get(self._path))

    def set(self, data: dict[str, Any], merge: bool = False, timeout: float | None = None) -> None:
        current = self._store.setdefault(self._path, {})
        if not merge:
            current.clear()
        current.update(data)


class FakeCollection:
    def __init__(self, store: dict[str, dict[str, Any]], name: str) -> None:
        self._store = store
        self._name = name

    def document(self, document_id: str) -> FakeDocumentReference:
        return FakeDocumentReference(self._store, f"{self._name}/{document_id}")


class FakeFirestoreClient:
    def __init__(self) -> None:
        self.documents: dict[str, dict[str, Any]] = {}

    def collection(self, name: str) -> FakeCollection:
        return FakeCollection(self.documents, name)
