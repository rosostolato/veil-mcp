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
 *
 * Each page answers two questions at a glance: what to paste, and where it goes.
 * The environment is carried by the colour of the band at the top; everything
 * else the human may want to audit sits behind "Details".
 */

import { randomBytes, randomInt } from 'node:crypto';
import { basename } from 'node:path';

import type { SecretRequest } from '../broker.js';
import {
  DESTINATION_CLASS_NOTICE,
  DestinationClass,
  RequestState,
  type RiskLevel,
} from '../model.js';
import { safeDisplay } from '../redaction.js';

/** Each identity word has a fixed swatch, so the phrase can be matched by colour. */
const IDENTITY_WORDS = {
  amber: '#d99a2b',
  anchor: '#3d5a80',
  basalt: '#4a4e57',
  beacon: '#e4572e',
  cedar: '#a0522d',
  cobalt: '#1f4fbf',
  copper: '#b87333',
  delta: '#2a9d8f',
  ember: '#c4361b',
  falcon: '#8d7b68',
  flint: '#6c757d',
  garnet: '#8e1b3a',
  harbor: '#26667f',
  indigo: '#4b3f9e',
  ivory: '#d8cfb4',
  juniper: '#4f7f5a',
  kestrel: '#b5651d',
  lantern: '#f2b134',
  marble: '#b9bec7',
  meadow: '#7fb24a',
  nickel: '#8a9099',
  onyx: '#25282d',
  opal: '#7fc4b8',
  pewter: '#96a0a8',
  quartz: '#e3a6c1',
  raven: '#33334d',
  saffron: '#f4a300',
  slate: '#5d6d7e',
  tundra: '#9db4c0',
  umber: '#6f4e37',
  verdant: '#2e8b57',
  willow: '#9bbf6a',
} as const;

type IdentityWord = keyof typeof IDENTITY_WORDS;
const WORDS = Object.keys(IDENTITY_WORDS) as IdentityWord[];

/**
 * A per-process phrase the operator can check against the console.
 *
 * Anti-spoofing aid only (SPEC.md §18.4): a page that cannot show the phrase
 * printed by *your* Veil process is not your Veil process.
 */
export function newIdentityPhrase(): string {
  return Array.from({ length: 3 }, () => WORDS[randomInt(WORDS.length)]).join(' ');
}

export function newNonce(): string {
  return randomBytes(16).toString('base64url');
}

const SWATCH_STYLE = WORDS.map((word) => `.sw-${word}{background:${IDENTITY_WORDS[word]}}`).join(
  '',
);

const STYLE = `
:root { color-scheme: light dark;
  --bg: #e9edf1; --surface: #ffffff; --sunk: #dde3e9; --fg: #111820; --muted: #4f5d6c;
  --line: #c9d2db; --accent: #0b6b60; --accent-ink: #ffffff;
  --ok: #17703c; --warn: #7d5200; --danger: #b4231b; --danger-soft: #fbe3e0;
  --prod: #b4231b; --prod-ink: #ffffff; --dev: #2a5f8f; --dev-ink: #ffffff;
  --caution: #c98a12; --caution-ink: #1d1300;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
@media (prefers-color-scheme: dark) { :root {
  --bg: #0c1115; --surface: #171e25; --sunk: #0f151a; --fg: #eef2f6; --muted: #a3b0bd;
  --line: #2c3742; --accent: #52d1bc; --accent-ink: #04211c;
  --ok: #74dca0; --warn: #f4c96c; --danger: #ff8d84; --danger-soft: #3a1714;
  --prod: #ef5a50; --prod-ink: #1e0503; --dev: #6aa8e0; --dev-ink: #04182a;
  --caution: #f4c96c; --caution-ink: #1d1300; } }
* { box-sizing: border-box; }
body { font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; margin: 0;
  padding: 2.5rem 1rem; background: var(--bg); color: var(--fg); }
.card { max-width: 28rem; margin: 0 auto; background: var(--surface); border: 1px solid var(--line);
  border-radius: 18px; overflow: hidden; box-shadow: 0 10px 30px -18px rgba(0,0,0,.35); }
.band { display: flex; justify-content: space-between; align-items: center; gap: .75rem;
  padding: .55rem 1.25rem; font: 600 .74rem var(--mono); letter-spacing: .1em;
  text-transform: uppercase; font-variant-numeric: tabular-nums; }
.band .ttl { letter-spacing: .04em; opacity: .9; }
.env-production { background: var(--prod); color: var(--prod-ink); }
.env-development { background: var(--dev); color: var(--dev-ink); }
.env-staging, .env-unknown { background: var(--caution); color: var(--caution-ink); }
.risk { font: inherit; }
.body { padding: 1.4rem 1.25rem 1.25rem; display: grid; gap: 1.1rem; }
h1 { font-size: 1.5rem; line-height: 1.2; margin: 0; letter-spacing: -.01em; overflow-wrap: anywhere; }
h1 code { font: 600 .82em var(--mono); background: var(--sunk); padding: .05em .3em; border-radius: 6px; }
p { margin: 0; }
.lede { color: var(--muted); font-size: .92rem; }
.dest { display: grid; gap: .25rem; }
.dest small { font: 500 .7rem var(--mono); letter-spacing: .1em; text-transform: uppercase; color: var(--muted); }
.path { font: 600 1rem/1.35 var(--mono); overflow-wrap: anywhere; }
.path .sep { color: var(--muted); font-weight: 400; }
.over { font-size: .86rem; font-weight: 600; color: var(--warn); }
.danger { font-size: .86rem; font-weight: 600; color: var(--danger); background: var(--danger-soft);
  border-radius: 10px; padding: .5rem .7rem; }
label { display: block; font-size: .86rem; font-weight: 600; margin-bottom: .4rem; }
label code { font-family: var(--mono); }
.sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
input[type=password], input[type=text] { width: 100%; padding: .95rem 1rem; border-radius: 12px;
  border: 2px solid var(--line); background: var(--surface); color: var(--fg);
  font: 1.05rem var(--mono); }
input[type=password] { letter-spacing: .08em; }
input:focus { outline: none; border-color: var(--accent); }
.status { font-size: .88rem; font-weight: 600; margin-top: .45rem; min-height: 1.35rem; }
.status.idle { color: var(--muted); font-weight: 400; }
.status.ok { color: var(--ok); } .status.warn { color: var(--warn); }
.actions { display: grid; grid-template-columns: auto 1fr; gap: .6rem; }
.actions form { display: contents; }
.btn { padding: .9rem 1.1rem; border-radius: 12px; border: 1px solid var(--line); background: transparent;
  color: var(--fg); font: 600 .95rem system-ui, -apple-system, "Segoe UI", sans-serif; cursor: pointer;
  overflow-wrap: anywhere; }
.btn.primary { background: var(--accent); border-color: var(--accent); color: var(--accent-ink); font-size: 1rem; }
.btn:disabled { background: var(--sunk); border-color: var(--sunk); color: var(--muted); cursor: not-allowed; }
button:focus-visible, summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.foot { display: flex; justify-content: space-between; align-items: flex-start; gap: .75rem; flex-wrap: wrap;
  border-top: 1px solid var(--line); padding: .7rem 1.25rem; font-size: .78rem; color: var(--muted); }
.sigil { display: flex; align-items: center; gap: .45rem; font-family: var(--mono); }
.sigil i { width: 12px; height: 12px; border-radius: 3px; display: inline-block; margin-right: 2px; }
details { font-size: .82rem; min-width: 0; }
summary { cursor: pointer; }
details dl { display: grid; grid-template-columns: auto 1fr; gap: .3rem .8rem; margin: .6rem 0 0; }
details dt { color: var(--muted); } details dd { margin: 0; color: var(--fg); overflow-wrap: anywhere; }
details ul { margin: 0; padding-left: 1rem; }
.check { width: 52px; height: 52px; border-radius: 50%; display: grid; place-items: center;
  font-size: 1.6rem; font-weight: 700; color: var(--ok); border: 2px solid var(--ok); }
.state { font: .75rem var(--mono); color: var(--muted); }
.promise { max-width: 28rem; margin: 1rem auto 0; font-size: .78rem; color: var(--muted); text-align: center; }
@media (max-width: 420px) { .actions { grid-template-columns: 1fr; } .actions .primary { order: -1; } }
${SWATCH_STYLE}
`;

/**
 * The page's only script. Static text, run under the per-response nonce.
 *
 * It reads the field locally to describe the value's shape, keeps the primary
 * button honest, counts down the expiry and maps Escape to Cancel. It never
 * writes the value anywhere: the CSP leaves it no network, and the value only
 * leaves the page through the form the human submits.
 */
const SCRIPT = `
(function () {
  var d = document;
  var primary = d.getElementById('primary');
  var cancel = d.getElementById('cancel');
  var secret = d.getElementById('secret');
  var check = d.getElementById('check');
  var name = d.getElementById('confirm_name');
  var ttl = d.getElementById('ttl');

  function clock(s) { return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0'); }
  if (ttl) {
    var left = Number(ttl.getAttribute('data-seconds')) || 0;
    setInterval(function () {
      left = Math.max(0, left - 1);
      ttl.textContent = left > 0 ? 'expires in ' + clock(left) : 'expired';
    }, 1000);
  }

  function shape(v, env) {
    if (!v) return ['idle', 'Veil checks the format here. The value is never shown.'];
    if (/[\\r\\n]/.test(v)) return ['warn', 'Contains a line break. Check what you pasted.'];
    if (/^\\s|\\s$/.test(v)) return ['warn', 'Starts or ends with a space. Check what you pasted.'];
    var size = v.length + ' characters';
    var m = /^[A-Za-z]{0,12}[_-](live|prod|production|test|sandbox|dev)[_-]/i.exec(v);
    if (!m) return ['idle', size];
    var live = /^(live|prod|production)$/i.test(m[1]);
    var kind = live ? 'live' : 'test';
    if (env === 'production' && !live) return ['warn', 'Looks like a test key, but this goes to production.'];
    if ((env === 'development' || env === 'staging') && live) return ['warn', 'Looks like a live key, but this goes to ' + env + '.'];
    if (env === 'unknown') return ['idle', 'Looks like a ' + kind + ' key · ' + size];
    return ['ok', 'Looks like a ' + kind + ' key · matches ' + env + ' · ' + size];
  }

  if (secret && check && primary) {
    var env = secret.getAttribute('data-env');
    check.hidden = false;
    var update = function () {
      var r = shape(secret.value, env);
      check.className = 'status ' + r[0];
      check.textContent = r[1];
      primary.disabled = secret.value.length === 0;
    };
    secret.addEventListener('input', update);
    update();
  }

  if (name && primary) {
    var expect = name.getAttribute('data-expect');
    var sync = function () { primary.disabled = name.value.trim() !== expect; };
    name.addEventListener('input', sync);
    sync();
  }

  d.addEventListener('keydown', function (event) {
    if (event.key !== 'Escape' || !cancel) return;
    event.preventDefault();
    if (secret) secret.value = '';
    cancel.click();
  });
})();
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

interface PageOptions {
  nonce: string;
  /**
   * Identity phrase. Only pages reached through a request's own link or
   * session carry it; anything else would hand it to any local client.
   */
  identity?: string;
  /** Environment band shown above the card body. */
  band?: string;
  /** Collapsed audit detail shown in the footer, next to the identity phrase. */
  details?: string;
}

function sigil(identity: string): string {
  const swatches = identity
    .split(' ')
    .filter((word): word is IdentityWord => Object.hasOwn(IDENTITY_WORDS, word))
    .map((word) => `<i class="sw-${word}"></i>`)
    .join('');
  return (
    '<span class="sigil" title="Must match the words in your Veil terminal">' +
    `<span aria-hidden="true">${swatches}</span><code>${e(identity)}</code></span>`
  );
}

export function page(title: string, body: string, options: PageOptions): string {
  return (
    '<!doctype html>\n' +
    '<html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<meta name="referrer" content="no-referrer">' +
    '<meta name="robots" content="noindex, nofollow">' +
    `<title>${e(title)} · Veil</title>` +
    `<style nonce="${escapeHtml(options.nonce)}">${STYLE}</style>` +
    '</head><body><main class="card">' +
    (options.band ?? '') +
    `<div class="body">${body}</div>` +
    (options.identity
      ? `<footer class="foot">${sigil(options.identity)}${options.details ?? ''}</footer>`
      : '') +
    '</main>' +
    '<p class="promise">Veil never shows a credential back to you, and never sends it to the ' +
    'agent or the model.</p>' +
    `<script nonce="${escapeHtml(options.nonce)}">${SCRIPT}</script>` +
    '</body></html>'
  );
}

function clock(seconds: number): string {
  const whole = Math.max(0, Math.floor(seconds));
  return `${Math.floor(whole / 60)}:${String(whole % 60).padStart(2, '0')}`;
}

function band(request: SecretRequest, secondsLeft: number): string {
  const { environment } = request.snapshot.target;
  const level: RiskLevel = request.snapshot.risk.level;
  return (
    `<div class="band env-${e(environment)}">` +
    `<span>● ${e(environment)} · <span class="risk risk-${level}">${e(level)} risk</span></span>` +
    `<span class="ttl" id="ttl" data-seconds="${Math.floor(secondsLeft)}">expires in ${clock(secondsLeft)}</span>` +
    '</div>'
  );
}

const OPERATION_LABELS: Record<string, string> = {
  create: 'Create a new credential',
  'new-version': 'Add a new version',
  replace: 'Replace the existing credential',
};

function operationLabel(request: SecretRequest): string {
  const operation = request.snapshot.operation;
  let label = OPERATION_LABELS[operation] ?? operation;
  if (request.snapshot.existsAtPreflight && operation !== 'new-version') {
    label += ' (a value already exists and will be overwritten)';
  }
  return label;
}

/** The one line a human needs when the write is not a plain create. */
function overwriteLine(request: SecretRequest): string {
  const { operation, existsAtPreflight } = request.snapshot;
  if (operation === 'new-version') {
    return '<p class="over">Adds a new version. Apps reading the latest version get this one.</p>';
  }
  if (existsAtPreflight) {
    return '<p class="over">A value already exists here and will be overwritten.</p>';
  }
  return '';
}

function destinationPath(request: SecretRequest): string {
  const { target } = request.snapshot;
  const parts = [target.providerLabel, target.accountLabel, target.resourceLabel].filter(
    (part): part is string => Boolean(part),
  );
  return `<div class="path">${parts.map(e).join(' <span class="sep">›</span> ')}</div>`;
}

function destination(request: SecretRequest): string {
  const classNotice = DESTINATION_CLASS_NOTICE[request.snapshot.target.destinationClass];
  return (
    '<div class="dest"><small>Goes to</small>' +
    destinationPath(request) +
    overwriteLine(request) +
    (classNotice ? `<p class="danger">${e(classNotice)}</p>` : '') +
    '</div>'
  );
}

/**
 * A local file is named by the file and the key inside it, not by its
 * directory: a whole absolute path is neither a short label nor something a
 * human should have to type.
 */
function localFile(request: SecretRequest): { file: string; key: string; phrase: string } | null {
  const { target } = request.snapshot;
  const { path, key, relative } = target.fields;
  if (target.destinationClass !== DestinationClass.LOCAL_PLAINTEXT || !path || !key) return null;
  // The path is part of what is confirmed: the same key in another file is a
  // different destination.
  return { file: basename(path), key, phrase: `${relative ?? basename(path)}:${key}` };
}

/** Short name of where the write lands, used on the primary button. */
function shortDestination(request: SecretRequest): string {
  const { target } = request.snapshot;
  return localFile(request)?.file ?? target.accountLabel ?? target.providerLabel;
}

/** What the human types to confirm a stage B write. */
export function confirmationPhrase(request: SecretRequest): string {
  const { target } = request.snapshot;
  return safeDisplay(localFile(request)?.phrase ?? target.accountLabel ?? target.resourceLabel);
}

function details(request: SecretRequest): string {
  const { snapshot } = request;
  const { target } = snapshot;
  const classNotice = DESTINATION_CLASS_NOTICE[target.destinationClass];
  const warnings = [
    ...target.warnings.filter((warning) => warning !== classNotice),
    ...snapshot.risk.reasons,
  ];
  const rows: [string, string][] = [
    ['Credential', e(snapshot.logicalName)],
    ['Destination type', e(target.providerLabel)],
  ];
  if (target.accountLabel) rows.push(['Project / account', e(target.accountLabel)]);
  rows.push(
    ['Destination', e(target.resourceLabel)],
    ['Environment', e(target.environment)],
    ['Operation', e(operationLabel(request))],
    ['Risk', `${e(snapshot.risk.level)} risk`],
  );
  if (warnings.length > 0) {
    rows.push(['Warnings', `<ul>${warnings.map((w) => `<li>${e(w)}</li>`).join('')}</ul>`]);
  }
  if (snapshot.description) rows.push(['Agent description', e(snapshot.description)]);
  rows.push(['The agent receives', 'Only whether it was stored, never the value']);
  const count =
    warnings.length > 0 ? ` · ${warnings.length} warning${warnings.length > 1 ? 's' : ''}` : '';
  return (
    `<details><summary>Details${count}</summary><dl>` +
    rows.map(([label, value]) => `<dt>${label}</dt><dd>${value}</dd>`).join('') +
    '</dl></details>'
  );
}

function cancelForm(action: string): string {
  return (
    `<form method="post" action="${action}/cancel">` +
    '<button type="submit" class="btn" id="cancel">Cancel</button></form>'
  );
}

interface RequestPageOptions {
  nonce: string;
  identity: string;
  basePath: string;
  secondsLeft: number;
}

export function stageAPage(request: SecretRequest, options: RequestPageOptions): string {
  const action = escapeHtml(options.basePath);
  const primary = request.requiresStageB ? 'Continue' : `Save to ${e(shortDestination(request))}`;
  const body =
    `<h1>Paste <code>${e(request.snapshot.logicalName)}</code></h1>` +
    destination(request) +
    `<form id="entry" method="post" action="${action}/submit" autocomplete="off" novalidate>` +
    '<label class="sr" for="secret">Credential value</label>' +
    // Browsers ignore autocomplete="off" on password fields; these keep the
    // built-in and the common third-party password managers from saving it.
    '<input id="secret" name="secret" type="password" autocomplete="one-time-code" ' +
    'data-1p-ignore data-lpignore="true" data-bwignore data-form-type="other" ' +
    'autocapitalize="off" autocorrect="off" spellcheck="false" inputmode="text" required ' +
    `autofocus placeholder="Paste here" data-env="${e(request.snapshot.target.environment)}">` +
    '<p id="check" class="status idle" aria-live="polite" hidden></p>' +
    '</form>' +
    '<div class="actions">' +
    cancelForm(action) +
    `<button type="submit" form="entry" class="btn primary" id="primary">${primary}</button>` +
    '</div>' +
    (request.requiresStageB
      ? '<p class="lede">You confirm the destination on the next step. Nothing is written before that.</p>'
      : '');
  return page('Paste a credential', body, {
    ...options,
    band: band(request, options.secondsLeft),
    details: details(request),
  });
}

export function stageBPage(
  request: SecretRequest,
  options: RequestPageOptions & { confirmToken: string; mismatch?: boolean },
): string {
  const action = escapeHtml(options.basePath);
  const phrase = confirmationPhrase(request);
  const environment = request.snapshot.target.environment;
  const title = environment === 'production' ? 'Save to production?' : 'Confirm where this goes';
  const body =
    `<h1>${title}</h1>` +
    '<p class="lede">The credential was received. Nothing has been written yet, and it will ' +
    'not be shown again.</p>' +
    destination(request) +
    `<form id="entry" method="post" action="${action}/confirm" autocomplete="off">` +
    `<input type="hidden" name="confirm_token" value="${escapeHtml(options.confirmToken)}">` +
    `<label for="confirm_name">Type <code>${escapeHtml(phrase)}</code> to confirm</label>` +
    '<input id="confirm_name" name="confirm_name" type="text" autocomplete="off" ' +
    `autocapitalize="off" autocorrect="off" spellcheck="false" required autofocus ` +
    `data-expect="${escapeHtml(phrase)}">` +
    (options.mismatch
      ? '<p class="status warn">That did not match. Type the name exactly as shown.</p>'
      : '') +
    '</form>' +
    '<div class="actions">' +
    cancelForm(action) +
    `<button type="submit" form="entry" class="btn primary" id="primary">Save to ${e(shortDestination(request))}</button>` +
    '</div>';
  return page('Confirm the destination', body, {
    ...options,
    band: band(request, options.secondsLeft),
    details: details(request),
  });
}

export function statusPage(
  request: SecretRequest,
  options: { nonce: string; identity: string },
): string {
  const headlines: Partial<Record<RequestState, string>> = {
    [RequestState.STORED]: 'Saved',
    [RequestState.FAILED]: 'The operation failed',
    [RequestState.CANCELLED]: 'Cancelled',
    [RequestState.EXPIRED]: 'This request expired',
    [RequestState.EXECUTING]: 'Saving…',
  };
  const notes: Partial<Record<RequestState, string>> = {
    [RequestState.STORED]:
      'Veil wiped the value. The agent only learns that it was stored. You can close this window.',
    [RequestState.FAILED]: 'The credential was discarded.',
    [RequestState.CANCELLED]: 'The credential was discarded. You can close this window.',
    [RequestState.EXPIRED]: 'The credential was discarded. Ask the agent to start a new request.',
    [RequestState.EXECUTING]: 'Writing the credential to the destination. Reload in a moment.',
  };
  const stored = request.state === RequestState.STORED;
  let body =
    (stored ? '<span class="check" aria-hidden="true">✓</span>' : '') +
    `<h1>${e(headlines[request.state] ?? 'This request is no longer awaiting input')}</h1>` +
    `<div class="dest"><small>${stored ? 'Stored in' : 'Destination'}</small>${destinationPath(request)}</div>`;
  if (request.result?.destinationRef) {
    body += `<div class="dest"><small>Reference</small><div class="path">${e(request.result.destinationRef)}</div></div>`;
  }
  if (request.error) body += `<p class="danger">${e(request.error.message)}</p>`;
  const note = notes[request.state];
  if (note) body += `<p class="lede">${e(note)}</p>`;
  body += `<p class="state">state: ${e(request.state)}</p>`;
  return page(headlines[request.state] ?? 'Credential request', body, options);
}

/** Unauthenticated pages: no identity phrase, no request detail. */
export function messagePage(title: string, message: string, options: { nonce: string }): string {
  return page(title, `<h1>${e(title)}</h1><p class="lede">${e(message)}</p>`, {
    nonce: options.nonce,
  });
}

/** Shown when a single-use link is opened a second time. */
export function linkReusedPage(options: { nonce: string; cancelPath: string }): string {
  const body =
    '<h1>This link was already opened</h1>' +
    '<p class="danger">Someone opened this request before this window did. If that was ' +
    'not you, another program on this computer may have the link.</p>' +
    '<p class="lede">Cancel it here, then ask the agent for a new request. If you opened it ' +
    'yourself in another window, finish there instead.</p>' +
    `<form method="post" action="${escapeHtml(options.cancelPath)}">` +
    '<div class="actions"><button type="submit" class="btn primary" id="cancel">' +
    'Cancel this request</button></div></form>';
  return page('Link already opened', body, { nonce: options.nonce });
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
    'cross-origin-opener-policy': 'same-origin',
    'cross-origin-resource-policy': 'same-origin',
    'permissions-policy': 'clipboard-read=(), clipboard-write=(), geolocation=()',
    'content-security-policy':
      "default-src 'none'; " +
      `style-src 'nonce-${nonce}'; ` +
      `script-src 'nonce-${nonce}'; ` +
      "form-action 'self'; " +
      "frame-ancestors 'none'; " +
      "base-uri 'none'",
  };
}
