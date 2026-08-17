"""Trusted UI rendering (SPEC.md §7, §8, §9, §34, §36).

Every value on these pages is derived from the request's immutable
:class:`~veil.model.AuthorizationSnapshot`. There is no separate "display
destination": what the human reads here is what the executor writes to.

Untrusted metadata (names, projects, paths, descriptions chosen by the agent) is
passed through :func:`veil.redaction.safe_display` — which neutralises control
characters, ANSI introducers and bidi overrides — and then HTML-escaped.
"""

from __future__ import annotations

import html
import secrets
from typing import Any

from veil.broker import SecretRequest
from veil.model import DESTINATION_CLASS_NOTICE, DestinationClass, RequestState, RiskLevel
from veil.redaction import safe_display

IDENTITY_WORDS = (
    "amber",
    "anchor",
    "basalt",
    "beacon",
    "cedar",
    "cobalt",
    "copper",
    "delta",
    "ember",
    "falcon",
    "flint",
    "garnet",
    "harbor",
    "indigo",
    "ivory",
    "juniper",
    "kestrel",
    "lantern",
    "marble",
    "meadow",
    "nickel",
    "onyx",
    "opal",
    "pewter",
    "quartz",
    "raven",
    "saffron",
    "slate",
    "tundra",
    "umber",
    "verdant",
    "willow",
)


def new_identity_phrase() -> str:
    """A per-process phrase the operator can check against the console.

    Anti-spoofing aid only (SPEC.md §18.4): a page that cannot show the phrase
    printed by *your* Veil process is not your Veil process.
    """

    return " ".join(secrets.choice(IDENTITY_WORDS) for _ in range(3))


_STYLE = """
:root { color-scheme: light dark; }
body { font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
       margin: 0; padding: 2rem 1rem; background: #10131a; color: #e7ecf3; }
main { max-width: 40rem; margin: 0 auto; background: #171b24; border: 1px solid #262d3b;
       border-radius: 12px; padding: 1.5rem 1.75rem; }
h1 { font-size: 1.15rem; margin: 0 0 .25rem; }
.identity { font-size: .8rem; color: #93a1b5; margin: 0 0 1.25rem; }
.identity code { color: #cfe1ff; }
dl { display: grid; grid-template-columns: 11rem 1fr; gap: .4rem 1rem; margin: 1rem 0; }
dt { color: #93a1b5; font-size: .82rem; text-transform: uppercase; letter-spacing: .04em; }
dd { margin: 0; word-break: break-word; font-weight: 600; }
.risk { display: inline-block; padding: .1rem .5rem; border-radius: 999px; font-size: .78rem;
        font-weight: 700; letter-spacing: .04em; text-transform: uppercase; }
.risk-low { background: #14361f; color: #7ee2a8; }
.risk-medium { background: #3a2f10; color: #f0cf7a; }
.risk-high { background: #45161a; color: #ff9d9d; }
.notice { border-left: 3px solid #f0cf7a; background: #201c10; padding: .6rem .9rem;
          margin: .75rem 0; font-size: .9rem; }
.notice-danger { border-color: #ff7676; background: #241516; }
label { display: block; margin: 1.25rem 0 .35rem; font-size: .82rem; color: #93a1b5;
        text-transform: uppercase; letter-spacing: .04em; }
input[type=password] { width: 100%; box-sizing: border-box; padding: .7rem .8rem;
        border-radius: 8px; border: 1px solid #39435a; background: #0d1017; color: #e7ecf3;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 1rem; }
.actions { display: flex; gap: .75rem; margin-top: 1.5rem; }
button { flex: 1; padding: .7rem 1rem; border-radius: 8px; border: 1px solid #39435a;
         background: #222a38; color: #e7ecf3; font-size: .95rem; font-weight: 600;
         cursor: pointer; }
button.primary { background: #2f6df6; border-color: #2f6df6; color: #fff; }
button.danger { background: #b3373f; border-color: #b3373f; color: #fff; }
.state { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
footer { color: #6f7c91; font-size: .78rem; margin-top: 1.25rem; }
"""


def _e(value: object) -> str:
    return html.escape(safe_display(str(value)), quote=True)


def page(title: str, body: str, *, nonce: str, identity: str) -> str:
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        '<meta name="robots" content="noindex, nofollow">'
        f"<title>{_e(title)}</title>"
        f'<style nonce="{html.escape(nonce)}">{_STYLE}</style>'
        "</head><body><main>"
        f"<h1>{_e(title)}</h1>"
        f'<p class="identity">Veil secure input · session <code>{_e(identity)}</code></p>'
        f"{body}"
        "<footer>Veil never shows a credential back to you, and never sends it to the "
        "agent or the model.</footer>"
        "</main></body></html>"
    )


def _risk_badge(level: RiskLevel) -> str:
    return f'<span class="risk risk-{level}">{_e(str(level))} risk</span>'


def _destination_rows(request: SecretRequest) -> str:
    snapshot = request.snapshot
    target = snapshot.target
    rows = [
        ("Credential", _e(snapshot.logical_name)),
        ("Destination type", _e(target.provider_label)),
    ]
    if target.account_label:
        rows.append(("Project / account", _e(target.account_label)))
    rows.extend(
        [
            ("Destination", _e(target.resource_label)),
            ("Environment", _e(str(target.environment))),
            ("Operation", _e(_operation_label(request))),
            ("Risk", _risk_badge(snapshot.risk.level)),
        ]
    )
    if snapshot.description:
        rows.append(("Agent description", _e(snapshot.description)))
    return "<dl>" + "".join(f"<dt>{label}</dt><dd>{value}</dd>" for label, value in rows) + "</dl>"


def _operation_label(request: SecretRequest) -> str:
    operation = str(request.snapshot.operation)
    labels = {
        "create": "Create a new credential",
        "new-version": "Add a new version",
        "replace": "Replace the existing credential",
    }
    label = labels.get(operation, operation)
    if request.snapshot.exists_at_preflight and operation != "new-version":
        label += " (a value already exists and will be overwritten)"
    return label


def _notices(request: SecretRequest) -> str:
    out: list[str] = []
    class_notice = DESTINATION_CLASS_NOTICE.get(
        DestinationClass(request.snapshot.target.destination_class)
    )
    if class_notice:
        out.append(f'<p class="notice notice-danger">{_e(class_notice)}</p>')
    for warning in request.snapshot.target.warnings:
        if warning != class_notice:
            out.append(f'<p class="notice">{_e(warning)}</p>')
    for reason in request.snapshot.risk.reasons:
        out.append(f'<p class="notice">{_e(reason)}</p>')
    return "".join(out)


def stage_a_page(request: SecretRequest, *, nonce: str, identity: str, base_path: str) -> str:
    body = (
        "<p>An agent has requested a credential. Veil will send it only to the "
        "destination shown below.</p>"
        + _destination_rows(request)
        + _notices(request)
        + f'<form method="post" action="{html.escape(base_path)}/submit" '
        'autocomplete="off" novalidate>'
        '<label for="secret">Credential value</label>'
        '<input id="secret" name="secret" type="password" autocomplete="off" '
        'autocapitalize="off" autocorrect="off" spellcheck="false" '
        'inputmode="text" required>'
        '<div class="actions">'
        '<button type="submit" formaction="'
        + html.escape(base_path)
        + '/cancel" formnovalidate class="danger">Cancel</button>'
        '<button type="submit" class="primary">Continue</button>'
        "</div></form>"
    )
    if request.requires_stage_b:
        body += (
            '<p class="notice">This operation needs a second confirmation after you enter '
            "the value. Nothing is written until you confirm.</p>"
        )
    return page("Secure credential request", body, nonce=nonce, identity=identity)


def stage_b_page(
    request: SecretRequest,
    *,
    nonce: str,
    identity: str,
    base_path: str,
    confirm_token: str,
) -> str:
    body = (
        "<p>The credential has been received. It has <strong>not</strong> been written yet, "
        "and it will not be shown again.</p>"
        + _destination_rows(request)
        + _notices(request)
        + f'<form method="post" action="{html.escape(base_path)}/confirm">'
        f'<input type="hidden" name="confirm_token" value="{html.escape(confirm_token)}">'
        '<div class="actions">'
        '<button type="submit" formaction="'
        + html.escape(base_path)
        + '/cancel" class="danger">Cancel</button>'
        '<button type="submit" class="primary">Confirm and store</button>'
        "</div></form>"
    )
    return page("Confirm secret operation", body, nonce=nonce, identity=identity)


def status_page(request: SecretRequest, *, nonce: str, identity: str) -> str:
    state = request.state
    headline = {
        RequestState.STORED: "The credential was stored.",
        RequestState.FAILED: "The operation failed. The credential was discarded.",
        RequestState.CANCELLED: "The request was cancelled. The credential was discarded.",
        RequestState.EXPIRED: "The request expired. The credential was discarded.",
        RequestState.EXECUTING: "Writing the credential to the destination…",
    }.get(state, "This request is no longer awaiting input.")

    body = f"<p>{_e(headline)}</p>" + _destination_rows(request)
    if request.error is not None:
        body += f'<p class="notice notice-danger">{_e(request.error.message)}</p>'
    if request.result is not None and request.result.destination_ref:
        body += f"<dl><dt>Stored as</dt><dd>{_e(request.result.destination_ref)}</dd></dl>"
    body += f'<p class="state">state: {_e(str(state))}</p>'
    return page("Credential request", body, nonce=nonce, identity=identity)


def message_page(title: str, message: str, *, nonce: str, identity: str) -> str:
    return page(title, f"<p>{_e(message)}</p>", nonce=nonce, identity=identity)


def security_headers(nonce: str) -> dict[str, str]:
    """Headers required by SPEC.md §34 (no caching, no leakage, no framing)."""

    return {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Permissions-Policy": "clipboard-read=(), clipboard-write=(), geolocation=()",
        "Content-Security-Policy": (
            "default-src 'none'; "
            f"style-src 'nonce-{nonce}'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'none'"
        ),
    }


def new_nonce() -> str:
    return secrets.token_urlsafe(16)


def as_public(request: SecretRequest) -> dict[str, Any]:
    return request.public_status()
