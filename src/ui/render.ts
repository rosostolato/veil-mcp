/**
 * Trusted UI rendering (SPEC.md §7, §8, §9, §34, §36).
 *
 * Every value on these pages is derived from the request's immutable
 * `AuthorizationSnapshot`. There is no separate "display destination": what the
 * human reads here is what the executor writes to.
 *
 * Untrusted metadata (names, projects, paths, descriptions chosen by the agent)
 * is passed through `safeDisplay` — which neutralises control characters, ANSI
 * introducers and bidi overrides — and then HTML-escaped.
 */

import { randomBytes, randomInt } from 'node:crypto';

import type { SecretRequest } from '../broker.js';
import { DESTINATION_CLASS_NOTICE, RequestState, type RiskLevel } from '../model.js';
import { safeDisplay } from '../redaction.js';

const IDENTITY_WORDS = [
  'amber',
  'anchor',
  'basalt',
  'beacon',
  'cedar',
  'cobalt',
  'copper',
  'delta',
  'ember',
  'falcon',
  'flint',
  'garnet',
  'harbor',
  'indigo',
  'ivory',
  'juniper',
  'kestrel',
  'lantern',
  'marble',
  'meadow',
  'nickel',
  'onyx',
  'opal',
  'pewter',
  'quartz',
  'raven',
  'saffron',
  'slate',
  'tundra',
  'umber',
  'verdant',
  'willow',
] as const;

/**
 * A per-process phrase the operator can check against the console.
 *
 * Anti-spoofing aid only (SPEC.md §18.4): a page that cannot show the phrase
 * printed by *your* Veil process is not your Veil process.
 */
export function newIdentityPhrase(): string {
  return Array.from({ length: 3 }, () => IDENTITY_WORDS[randomInt(IDENTITY_WORDS.length)]).join(
    ' ',
  );
}

export function newNonce(): string {
  return randomBytes(16).toString('base64url');
}

const STYLE = `
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
`;

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Sanitize untrusted text, then escape it for HTML. */
function e(value: unknown): string {
  return escapeHtml(safeDisplay(String(value)));
}

export function page(
  title: string,
  body: string,
  options: { nonce: string; identity: string },
): string {
  return (
    '<!doctype html>\n' +
    '<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<meta name="referrer" content="no-referrer">' +
    '<meta name="robots" content="noindex, nofollow">' +
    `<title>${e(title)}</title>` +
    `<style nonce="${escapeHtml(options.nonce)}">${STYLE}</style>` +
    '</head><body><main>' +
    `<h1>${e(title)}</h1>` +
    `<p class="identity">Veil secure input · session <code>${e(options.identity)}</code></p>` +
    body +
    '<footer>Veil never shows a credential back to you, and never sends it to the ' +
    'agent or the model.</footer>' +
    '</main></body></html>'
  );
}

function riskBadge(level: RiskLevel): string {
  return `<span class="risk risk-${level}">${e(level)} risk</span>`;
}

function operationLabel(request: SecretRequest): string {
  const labels: Record<string, string> = {
    create: 'Create a new credential',
    'new-version': 'Add a new version',
    replace: 'Replace the existing credential',
  };
  const operation = request.snapshot.operation;
  let label = labels[operation] ?? operation;
  if (request.snapshot.existsAtPreflight && operation !== 'new-version') {
    label += ' (a value already exists and will be overwritten)';
  }
  return label;
}

function destinationRows(request: SecretRequest): string {
  const { snapshot } = request;
  const { target } = snapshot;
  const rows: [string, string][] = [
    ['Credential', e(snapshot.logicalName)],
    ['Destination type', e(target.providerLabel)],
  ];
  if (target.accountLabel) rows.push(['Project / account', e(target.accountLabel)]);
  rows.push(
    ['Destination', e(target.resourceLabel)],
    ['Environment', e(target.environment)],
    ['Operation', e(operationLabel(request))],
    ['Risk', riskBadge(snapshot.risk.level)],
  );
  if (snapshot.description) rows.push(['Agent description', e(snapshot.description)]);
  return `<dl>${rows.map(([label, value]) => `<dt>${label}</dt><dd>${value}</dd>`).join('')}</dl>`;
}

function notices(request: SecretRequest): string {
  const out: string[] = [];
  const classNotice = DESTINATION_CLASS_NOTICE[request.snapshot.target.destinationClass];
  if (classNotice) out.push(`<p class="notice notice-danger">${e(classNotice)}</p>`);
  for (const warning of request.snapshot.target.warnings) {
    if (warning !== classNotice) out.push(`<p class="notice">${e(warning)}</p>`);
  }
  for (const reason of request.snapshot.risk.reasons) {
    out.push(`<p class="notice">${e(reason)}</p>`);
  }
  return out.join('');
}

export function stageAPage(
  request: SecretRequest,
  options: { nonce: string; identity: string; basePath: string },
): string {
  const action = escapeHtml(options.basePath);
  let body =
    '<p>An agent has requested a credential. Veil will send it only to the ' +
    'destination shown below.</p>' +
    destinationRows(request) +
    notices(request) +
    `<form method="post" action="${action}/submit" autocomplete="off" novalidate>` +
    '<label for="secret">Credential value</label>' +
    '<input id="secret" name="secret" type="password" autocomplete="off" ' +
    'autocapitalize="off" autocorrect="off" spellcheck="false" inputmode="text" required>' +
    '<div class="actions">' +
    `<button type="submit" formaction="${action}/cancel" formnovalidate class="danger">Cancel</button>` +
    '<button type="submit" class="primary">Continue</button>' +
    '</div></form>';
  if (request.requiresStageB) {
    body +=
      '<p class="notice">This operation needs a second confirmation after you enter ' +
      'the value. Nothing is written until you confirm.</p>';
  }
  return page('Secure credential request', body, options);
}

export function stageBPage(
  request: SecretRequest,
  options: { nonce: string; identity: string; basePath: string; confirmToken: string },
): string {
  const action = escapeHtml(options.basePath);
  const body =
    '<p>The credential has been received. It has <strong>not</strong> been written yet, ' +
    'and it will not be shown again.</p>' +
    destinationRows(request) +
    notices(request) +
    `<form method="post" action="${action}/confirm">` +
    `<input type="hidden" name="confirm_token" value="${escapeHtml(options.confirmToken)}">` +
    '<div class="actions">' +
    `<button type="submit" formaction="${action}/cancel" class="danger">Cancel</button>` +
    '<button type="submit" class="primary">Confirm and store</button>' +
    '</div></form>';
  return page('Confirm secret operation', body, options);
}

export function statusPage(
  request: SecretRequest,
  options: { nonce: string; identity: string },
): string {
  const headlines: Partial<Record<RequestState, string>> = {
    [RequestState.STORED]: 'The credential was stored.',
    [RequestState.FAILED]: 'The operation failed. The credential was discarded.',
    [RequestState.CANCELLED]: 'The request was cancelled. The credential was discarded.',
    [RequestState.EXPIRED]: 'The request expired. The credential was discarded.',
    [RequestState.EXECUTING]: 'Writing the credential to the destination…',
  };
  let body =
    `<p>${e(headlines[request.state] ?? 'This request is no longer awaiting input.')}</p>` +
    destinationRows(request);
  if (request.error) body += `<p class="notice notice-danger">${e(request.error.message)}</p>`;
  if (request.result?.destinationRef) {
    body += `<dl><dt>Stored as</dt><dd>${e(request.result.destinationRef)}</dd></dl>`;
  }
  body += `<p class="state">state: ${e(request.state)}</p>`;
  return page('Credential request', body, options);
}

export function messagePage(
  title: string,
  message: string,
  options: { nonce: string; identity: string },
): string {
  return page(title, `<p>${e(message)}</p>`, options);
}

/** Headers required by SPEC.md §34 (no caching, no leakage, no framing). */
export function securityHeaders(nonce: string): Record<string, string> {
  return {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store, no-cache, must-revalidate, max-age=0',
    pragma: 'no-cache',
    expires: '0',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'permissions-policy': 'clipboard-read=(), clipboard-write=(), geolocation=()',
    'content-security-policy':
      "default-src 'none'; " +
      `style-src 'nonce-${nonce}'; ` +
      "form-action 'self'; " +
      "frame-ancestors 'none'; " +
      "base-uri 'none'",
  };
}
