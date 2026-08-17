"""Adapter registry (SPEC.md §16, §17).

Only adapters registered here can ever be selected. The ``arbitrary-network``
destination class is rejected at registration time: it is disabled by default
per SPEC.md §16 and is not implemented in this version, so there is no code path
that could enable it by accident.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from veil.adapters.base import SecretDestinationAdapter
from veil.config import VeilConfig
from veil.errors import ErrorCode, veil_error
from veil.model import DestinationClass


class AdapterRegistry:
    def __init__(self, adapters: Iterable[SecretDestinationAdapter] = ()) -> None:
        self._adapters: dict[str, SecretDestinationAdapter] = {}
        for adapter in adapters:
            self.register(adapter)

    def register(self, adapter: SecretDestinationAdapter) -> None:
        if adapter.destination_class is DestinationClass.ARBITRARY_NETWORK:
            raise ValueError("arbitrary-network destinations are not permitted")
        if adapter.id in self._adapters:
            raise ValueError(f"duplicate adapter id: {adapter.id}")
        self._adapters[adapter.id] = adapter

    def get(self, adapter_id: object) -> SecretDestinationAdapter:
        if not isinstance(adapter_id, str) or adapter_id not in self._adapters:
            raise veil_error(
                ErrorCode.UNKNOWN_DESTINATION,
                "The requested destination is not available.",
            )
        return self._adapters[adapter_id]

    def __contains__(self, adapter_id: object) -> bool:
        return isinstance(adapter_id, str) and adapter_id in self._adapters

    def __iter__(self) -> Iterator[SecretDestinationAdapter]:
        return iter(self._adapters.values())

    def ids(self) -> tuple[str, ...]:
        return tuple(self._adapters)


def default_registry(config: VeilConfig) -> AdapterRegistry:
    """Build the adapters enabled for this process."""

    from veil.adapters.env_file import EnvFileAdapter
    from veil.adapters.firestore import FirestoreAdapter
    from veil.adapters.gcp_secret_manager import GcpSecretManagerAdapter

    candidates: list[SecretDestinationAdapter] = [
        GcpSecretManagerAdapter(config),
        EnvFileAdapter(config),
        FirestoreAdapter(config),
    ]
    allowed = config.enabled_adapters
    if allowed is not None:
        candidates = [a for a in candidates if a.id in allowed]
    return AdapterRegistry(candidates)
