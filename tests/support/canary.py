"""Canary secret harness (SPEC.md §22, §23).

A canary is a unique, high-entropy value used as the credential in a test. After
the flow runs, every channel the harness can observe is searched for the canary
*and every encoding of it* that :mod:`veil.redaction` knows about. Any hit in a
channel that was not explicitly declared as an approved secret boundary fails
the test.

The product and the harness deliberately share :func:`veil.redaction.derivations`
so a leak cannot hide behind an encoding the tests forgot about.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from veil.redaction import derivations


@dataclass(frozen=True)
class Canary:
    value: str

    @classmethod
    def new(cls, label: str = "") -> Canary:
        # The recognisable marker sits in the middle, and both ends are random,
        # so the 8-byte prefix/suffix fragment searches of SPEC.md §23 cannot
        # collide with the marker itself or with an unrelated canary.
        middle = f"VEIL_CANARY_{label}_" if label else "VEIL_CANARY_"
        return cls(f"{secrets.token_hex(6)}{middle}{secrets.token_hex(8)}")

    @property
    def raw(self) -> bytes:
        return self.value.encode("utf-8")

    @property
    def variants(self) -> tuple[bytes, ...]:
        return derivations(self.raw)

    def hits_in(self, data: bytes | str) -> list[str]:
        blob = data.encode("utf-8", "surrogatepass") if isinstance(data, str) else bytes(data)
        lowered = blob.lower()
        found: list[str] = []
        for variant in self.variants:
            if variant in blob or variant.lower() in lowered:
                found.append(variant.decode("utf-8", "replace")[:24])
        return found


@dataclass
class LeakScanner:
    """Collects observable channels and asserts the canary is absent from them."""

    channels: dict[str, bytearray] = field(default_factory=dict)

    def add(self, name: str, data: bytes | str) -> None:
        blob = data.encode("utf-8", "surrogatepass") if isinstance(data, str) else bytes(data)
        self.channels.setdefault(name, bytearray()).extend(blob)

    def add_tree(self, name: str, root: Path, *, exclude: set[Path] | None = None) -> None:
        """Add every file under *root*, except explicitly approved destinations."""

        excluded = {p.resolve() for p in (exclude or set())}
        for dirpath, _dirnames, filenames in os.walk(root):
            for filename in filenames:
                path = Path(dirpath) / filename
                try:
                    resolved = path.resolve()
                    if resolved in excluded:
                        continue
                    self.add(f"{name}:{path.name}", path.read_bytes())
                except OSError:
                    continue

    def assert_clean(self, canary: Canary, *, allow: set[str] | None = None) -> None:
        allowed = allow or set()
        leaks: list[str] = []
        for name, blob in self.channels.items():
            if name in allowed:
                continue
            hits = canary.hits_in(blob)
            if hits:
                leaks.append(f"{name}: {hits[0]!r}")
        assert not leaks, "canary leaked into observable channels: " + "; ".join(sorted(leaks))

    def assert_present(self, canary: Canary, name: str) -> None:
        blob = self.channels.get(name, bytearray())
        assert canary.hits_in(blob), f"expected the canary to reach the approved channel {name!r}"
