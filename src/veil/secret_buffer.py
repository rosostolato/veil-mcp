"""Custody of raw credential bytes (SPEC.md §5, §18.9).

A ``SecretBuffer`` is deliberately hostile to the ways secrets normally escape:
it has no useful ``repr``, refuses to be pickled, copied or formatted, and can
be wiped. It is owned by exactly one request and is never placed in module or
process-global state.

Known limitation, stated plainly rather than papered over: CPython cannot
guarantee erasure of secret material. Bytes handed to a provider SDK as an
immutable ``bytes`` object, or copied by the interpreter (e.g. by the garbage
collector compacting nothing but the allocator reusing pages), cannot be
zeroized by us. :meth:`zeroize` wipes the buffer we control, which removes the
long-lived copy; it does not promise that no transient copy ever existed.
"""

from __future__ import annotations

from types import TracebackType
from typing import Any, NoReturn, Self

from veil.redaction import contains_secret

MAX_SECRET_BYTES = 64 * 1024


class SecretDestroyed(RuntimeError):
    """Raised when a wiped buffer is used again."""


class SecretBuffer:
    __slots__ = ("_data", "_destroyed")

    def __init__(self, data: bytes | bytearray | memoryview) -> None:
        raw = bytearray(data)
        if len(raw) > MAX_SECRET_BYTES:
            wipe(raw)
            raise ValueError("secret exceeds maximum size")
        self._data = raw
        self._destroyed = False
        if isinstance(data, bytearray):
            # The caller's mutable copy is no longer needed; remove it.
            wipe(data)

    # -- lifecycle ---------------------------------------------------------

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.zeroize()

    def zeroize(self) -> None:
        if not self._destroyed:
            wipe(self._data)
            self._destroyed = True

    @property
    def destroyed(self) -> bool:
        return self._destroyed

    def __len__(self) -> int:
        self._check()
        return len(self._data)

    # -- controlled access -------------------------------------------------

    def view(self) -> memoryview:
        """Read-only view for consumers that accept the buffer protocol."""

        self._check()
        return memoryview(self._data).toreadonly()

    def as_bytes(self) -> bytes:
        """An immutable copy, for provider SDKs that require ``bytes``.

        The returned object cannot be wiped; keep it alive for as short a time
        as possible and never store it.
        """

        self._check()
        return bytes(self._data)

    def as_text(self, encoding: str = "utf-8") -> str:
        """An immutable ``str`` copy, with the same caveat as :meth:`as_bytes`."""

        self._check()
        return self._data.decode(encoding)

    def contains_in(self, haystack: bytes | str) -> bool:
        """Tripwire hook: does *haystack* carry this secret in any encoding?"""

        if self._destroyed:
            return False
        return contains_secret(haystack, bytes(self._data))

    def _check(self) -> None:
        if self._destroyed:
            raise SecretDestroyed("secret buffer has been zeroized")

    # -- escape hatches, closed --------------------------------------------

    def __repr__(self) -> str:
        return "<SecretBuffer redacted>"

    __str__ = __repr__

    def __format__(self, format_spec: str) -> str:
        return "<SecretBuffer redacted>"

    def _refuse(self, *args: Any, **kwargs: Any) -> NoReturn:
        raise TypeError("SecretBuffer must not be copied or serialized")

    __reduce__ = _refuse
    __reduce_ex__ = _refuse
    __copy__ = _refuse
    __deepcopy__ = _refuse
    __getstate__ = _refuse
    __iter__ = _refuse
    __bytes__ = _refuse


def wipe(buffer: bytearray) -> None:
    """Best-effort in-place erasure of a mutable byte buffer."""

    length = len(buffer)
    if length:
        buffer[:] = b"\x00" * length
    del buffer[:]
