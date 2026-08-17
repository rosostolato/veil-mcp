"""Leak detection and display sanitization (SPEC.md §22, §23, §36).

Two independent jobs live here:

* :func:`derivations` enumerates the encodings a secret could accidentally be
  re-emitted in. The runtime tripwire and the canary test harness share this
  function so that the product and its tests cannot drift apart.
* :func:`safe_display` / :func:`safe_field` make untrusted, agent-supplied
  metadata safe to render in a terminal or a browser.
"""

from __future__ import annotations

import base64
import json
import re
import unicodedata
import urllib.parse

# Below this length, prefix/suffix matching produces false positives rather than
# signal, so the tripwire only looks for whole encodings of short secrets.
_FRAGMENT_MIN_LENGTH = 16
_FRAGMENT_SIZE = 8


def derivations(secret: bytes) -> tuple[bytes, ...]:
    """Every byte-string whose presence in an output channel indicates a leak.

    Covers the transformations SPEC.md §23 requires: raw, Base64 (standard and
    URL-safe, padded and unpadded), hex in both cases, URL encoding, the JSON
    string escaping of the value, and the leading/trailing fragments.
    """

    if not secret:
        return ()

    forms: list[bytes] = [secret]

    for encoder in (base64.b64encode, base64.urlsafe_b64encode):
        encoded = encoder(secret)
        forms.append(encoded)
        forms.append(encoded.rstrip(b"="))

    forms.append(secret.hex().encode("ascii"))
    forms.append(secret.hex().upper().encode("ascii"))

    try:
        text = secret.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is not None:
        forms.append(urllib.parse.quote(text, safe="").encode("ascii"))
        forms.append(urllib.parse.quote_plus(text).encode("ascii"))
        # json.dumps wraps in quotes; the escaped body is what would appear
        # inside a JSON-RPC frame.
        forms.append(json.dumps(text)[1:-1].encode("utf-8"))

    if len(secret) >= _FRAGMENT_MIN_LENGTH:
        forms.append(secret[:_FRAGMENT_SIZE])
        forms.append(secret[-_FRAGMENT_SIZE:])

    seen: dict[bytes, None] = {}
    for form in forms:
        if form:
            seen.setdefault(form, None)
    return tuple(seen)


def contains_secret(haystack: bytes | str, secret: bytes) -> bool:
    """True if *haystack* contains *secret* in any form :func:`derivations` knows."""

    if isinstance(haystack, str):
        data = haystack.encode("utf-8", "surrogatepass")
    else:
        data = haystack
    lowered = data.lower()
    for form in derivations(secret):
        if form in data or form.lower() in lowered:
            return True
    return False


# Characters that let untrusted metadata rewrite what a human sees: bidi
# overrides and isolates, zero-width joiners, and other invisible formatting.
_BIDI_AND_INVISIBLE = frozenset(
    chr(code)
    for code in (
        0x00AD,  # soft hyphen
        0x061C,  # arabic letter mark
        *range(0x200B, 0x2010),  # zero-width space .. RLM and friends
        *range(0x202A, 0x202F),  # embeddings, overrides, pop
        *range(0x2066, 0x206A),  # isolates
        0xFEFF,  # zero-width no-break space / BOM
    )
)


def safe_display(value: str, *, max_length: int = 256) -> str:
    """Render untrusted text so it cannot forge UI or drive a terminal.

    Control characters, ANSI escape introducers, bidi overrides and invisible
    formatting characters are replaced by a visible ``\\uXXXX`` escape. The
    result is NFC-normalized and length-bounded.
    """

    normalized = unicodedata.normalize("NFC", value)
    out: list[str] = []
    for ch in normalized:
        category = unicodedata.category(ch)
        if ch in _BIDI_AND_INVISIBLE or category in {"Cc", "Cf", "Co", "Cs", "Cn"}:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    text = "".join(out)
    if len(text) > max_length:
        text = text[: max_length - 1] + "…"
    return text


#: Values that look like live credential material regardless of where they
#: appear. Used to reject inbound tool arguments (SPEC.md §6, §26.5) and to
#: screen outbound log fields (SPEC.md §19) — a defence in depth behind the
#: field allowlist and the live-secret tripwire, not a replacement for either.
CREDENTIAL_SHAPED_VALUE: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk_(live|test)_[A-Za-z0-9]{8,}"),
    re.compile(r"rk_(live|test)_[A-Za-z0-9]{8,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    # The canary marker used by the security suite: treated as credential
    # material by the product itself so a test can never "pass" by leaking it.
    re.compile(r"VEIL_CANARY_[A-Za-z0-9]{8,}"),
    re.compile(r"SECURE_INPUT_CANARY_[A-Za-z0-9]{8,}"),
)


def looks_like_credential(value: str) -> bool:
    return any(pattern.search(value) for pattern in CREDENTIAL_SHAPED_VALUE)


def safe_field(value: object, *, max_length: int = 256) -> str:
    """Coerce an arbitrary value into a bounded, display-safe string."""

    if isinstance(value, str):
        return safe_display(value, max_length=max_length)
    if isinstance(value, bool | int | float) or value is None:
        return safe_display(str(value), max_length=max_length)
    return safe_display(type(value).__name__, max_length=max_length)
