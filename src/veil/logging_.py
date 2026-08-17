"""Structured, allowlisted audit logging (SPEC.md §19, §18.8, §18.9).

Two rules make this module boring on purpose:

1. A log record is built from an explicit allowlist of safe field names. There
   is no ``log(msg % args)`` path, no exception formatting, and no way to pass a
   request body, provider payload or buffer through it.
2. Every rendered line passes a tripwire before it is written. If any live
   secret (in any encoding :mod:`veil.redaction` knows) appears in the line, the
   record is replaced by a suppression marker.

Logs go to stderr — never stdout, which carries the MCP protocol.
"""

from __future__ import annotations

import json
import sys
import threading
from collections.abc import Callable
from typing import Any, TextIO

from veil.redaction import looks_like_credential, safe_field

#: The complete set of keys an audit record may carry (SPEC.md §19).
ALLOWED_AUDIT_FIELDS = frozenset(
    {
        "request_id",
        "operation",
        "destination",
        "destination_class",
        "adapter",
        "logical_name",
        "environment",
        "resource",
        "account",
        "risk",
        "confirmation",
        "result",
        "state",
        "from_state",
        "to_state",
        "stage",
        "reason",
        "code",
        "error_code",
        "authorization_digest",
        "duration_ms",
        "count",
        "tool",
        "method",
        "path",
        "status_code",
        "component",
        "detail",
    }
)

#: Keys that must never be logged even if a caller passes them (SPEC.md §19).
FORBIDDEN_AUDIT_FIELDS = frozenset(
    {
        "secret",
        "secret_value",
        "value",
        "password",
        "token",
        "credential",
        "content",
        "body",
        "payload",
        "stdin",
        "clipboard",
        "hash",
        "prefix",
        "suffix",
        "length",
        "secret_length",
    }
)

Tripwire = Callable[[str], bool]
"""Returns True when the given rendered text carries live secret material."""


class AuditLogger:
    def __init__(
        self,
        stream: TextIO | None = None,
        *,
        tripwire: Tripwire | None = None,
        sink: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self._stream = stream if stream is not None else sys.stderr
        self._tripwire = tripwire
        self._sink = sink
        self._lock = threading.Lock()

    def set_tripwire(self, tripwire: Tripwire | None) -> None:
        self._tripwire = tripwire

    def event(self, event: str, **fields: Any) -> None:
        self._emit("info", event, fields)

    def security(self, event: str, **fields: Any) -> None:
        self._emit("security", event, fields)

    def error(self, event: str, **fields: Any) -> None:
        self._emit("error", event, fields)

    def debug(self, event: str, **fields: Any) -> None:
        # Debug records go through exactly the same allowlist and tripwire as
        # every other level: SEC-006 does not exempt DEBUG or TRACE.
        self._emit("debug", event, fields)

    def _emit(self, level: str, event: str, fields: dict[str, Any]) -> None:
        record: dict[str, Any] = {"level": level, "event": safe_field(event, max_length=80)}
        dropped: list[str] = []
        for key, value in fields.items():
            if key in FORBIDDEN_AUDIT_FIELDS or key not in ALLOWED_AUDIT_FIELDS:
                dropped.append(key)
                continue
            record[key] = _safe_value(value)
        if dropped:
            record["dropped_fields"] = sorted(safe_field(k, max_length=40) for k in dropped)

        line = json.dumps(record, sort_keys=True, ensure_ascii=True)
        if self._tripwire is not None and self._tripwire(line):
            record = {
                "level": "security",
                "event": "audit_record_suppressed",
                "reason": "tripwire_detected_secret_material",
                "original_event": record["event"],
            }
            line = json.dumps(record, sort_keys=True, ensure_ascii=True)

        with self._lock:
            if self._sink is not None:
                self._sink(record)
            try:
                self._stream.write(line + "\n")
                self._stream.flush()
            except (ValueError, OSError):  # stream closed during shutdown
                pass


REDACTED = "[redacted]"


def _safe_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {safe_field(k, max_length=40): _safe_value(v) for k, v in list(value.items())[:20]}
    if isinstance(value, list | tuple):
        return [_safe_value(v) for v in list(value)[:20]]
    if isinstance(value, bool | int | float) or value is None:
        return value
    text = safe_field(value)
    # Even an allowlisted field must not carry credential-shaped text.
    return REDACTED if looks_like_credential(text) else text


_default_logger = AuditLogger()


def get_logger() -> AuditLogger:
    return _default_logger


def install_crash_handler(on_crash: Callable[[], None], logger: AuditLogger | None = None) -> None:
    """Wipe live secrets on an unhandled exception (SPEC.md §18.9).

    The handler prints only the exception type — never its message, never a
    frame dump, never an in-flight request body.
    """

    log = logger or get_logger()
    previous = sys.excepthook

    def hook(
        exc_type: type[BaseException],
        exc: BaseException,
        tb: Any,
    ) -> None:
        try:
            on_crash()
        finally:
            log.error("unhandled_exception", code=exc_type.__name__, component="process")
        if exc_type is KeyboardInterrupt:
            previous(exc_type, exc, tb)

    sys.excepthook = hook
