/**
 * Leak detection and display sanitization (SPEC.md §22, §23, §36).
 *
 * Two independent jobs live here:
 *
 * - `derivations` enumerates the encodings a secret could accidentally be
 *   re-emitted in. The runtime tripwire and the canary test harness share this
 *   function so that the product and its tests cannot drift apart.
 * - `safeDisplay` makes untrusted, agent-supplied metadata safe to render in a
 *   terminal or a browser.
 */

/**
 * Below this length, prefix/suffix matching produces false positives rather
 * than signal, so the tripwire only looks for whole encodings of short secrets.
 */
const FRAGMENT_MIN_LENGTH = 16;
const FRAGMENT_SIZE = 8;

/**
 * Every byte string whose presence in an output channel indicates a leak.
 *
 * Covers the transformations SPEC.md §23 requires: raw, Base64 (standard and
 * URL-safe, padded and unpadded), hex in both cases, URL encoding, the JSON
 * string escaping of the value, and the leading/trailing fragments.
 */
export function derivations(secret: Buffer): Buffer[] {
  if (secret.length === 0) return [];

  const forms: Buffer[] = [secret];

  const base64 = secret.toString('base64');
  const base64Url = secret.toString('base64url');
  forms.push(Buffer.from(base64, 'utf8'));
  forms.push(Buffer.from(base64.replace(/=+$/, ''), 'utf8'));
  forms.push(Buffer.from(base64Url, 'utf8'));
  forms.push(Buffer.from(base64Url.replace(/=+$/, ''), 'utf8'));

  const hex = secret.toString('hex');
  forms.push(Buffer.from(hex, 'utf8'));
  forms.push(Buffer.from(hex.toUpperCase(), 'utf8'));

  const text = secret.toString('utf8');
  if (Buffer.from(text, 'utf8').equals(secret)) {
    forms.push(Buffer.from(encodeURIComponent(text), 'utf8'));
    forms.push(Buffer.from(encodeURIComponent(text).replace(/%20/g, '+'), 'utf8'));
    // JSON.stringify wraps in quotes; the escaped body is what would appear
    // inside a JSON-RPC frame.
    const escaped = JSON.stringify(text);
    forms.push(Buffer.from(escaped.slice(1, -1), 'utf8'));
  }

  if (secret.length >= FRAGMENT_MIN_LENGTH) {
    forms.push(secret.subarray(0, FRAGMENT_SIZE));
    forms.push(secret.subarray(secret.length - FRAGMENT_SIZE));
  }

  const seen = new Set<string>();
  const unique: Buffer[] = [];
  for (const form of forms) {
    if (form.length === 0) continue;
    const key = form.toString('latin1');
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(form);
    }
  }
  return unique;
}

/** True if `haystack` contains `secret` in any form `derivations` knows. */
export function containsSecret(haystack: Buffer | string, secret: Buffer): boolean {
  const data = typeof haystack === 'string' ? Buffer.from(haystack, 'utf8') : haystack;
  if (data.length === 0) return false;
  const lowered = Buffer.from(data.toString('latin1').toLowerCase(), 'latin1');
  for (const form of derivations(secret)) {
    if (data.includes(form)) return true;
    const loweredForm = Buffer.from(form.toString('latin1').toLowerCase(), 'latin1');
    if (lowered.includes(loweredForm)) return true;
  }
  return false;
}

/**
 * Characters that let untrusted metadata rewrite what a human sees: bidi
 * overrides and isolates, zero-width joiners, and other invisible formatting.
 */
function isBidiOrInvisible(code: number): boolean {
  return (
    code === 0x00ad ||
    code === 0x061c ||
    (code >= 0x200b && code <= 0x200f) ||
    (code >= 0x202a && code <= 0x202e) ||
    (code >= 0x2066 && code <= 0x2069) ||
    code === 0xfeff
  );
}

function isControl(code: number): boolean {
  return code < 0x20 || (code >= 0x7f && code <= 0x9f);
}

/**
 * Render untrusted text so it cannot forge UI or drive a terminal.
 *
 * Control characters, ANSI escape introducers, bidi overrides and invisible
 * formatting characters are replaced by a visible `\uXXXX` escape. The result is
 * NFC-normalized and length-bounded.
 */
export function safeDisplay(value: string, maxLength = 256): string {
  const normalized = value.normalize('NFC');
  let out = '';
  // Iterating by code point, and stopping before the budget is exceeded, keeps
  // truncation off the middle of a surrogate pair: a lone surrogate is not
  // valid UTF-8 and would be mangled by anything that re-encodes the output.
  for (const character of normalized) {
    const code = character.codePointAt(0) ?? 0;
    const rendered =
      isControl(code) || isBidiOrInvisible(code)
        ? `\\u${code.toString(16).padStart(4, '0')}`
        : character;
    if (out.length + rendered.length > maxLength - 1) {
      return `${out}…`;
    }
    out += rendered;
  }
  return out;
}

/** Coerce an arbitrary value into a bounded, display-safe string. */
export function safeField(value: unknown, maxLength = 256): string {
  if (typeof value === 'string') return safeDisplay(value, maxLength);
  if (typeof value === 'number' || typeof value === 'boolean' || value === null) {
    return safeDisplay(String(value), maxLength);
  }
  if (value === undefined) return safeDisplay('undefined', maxLength);
  return safeDisplay(value.constructor?.name ?? 'object', maxLength);
}

/**
 * Values that look like live credential material regardless of where they
 * appear. Used to reject inbound tool arguments (SPEC.md §6, §26.5) and to
 * screen outbound log fields (SPEC.md §19) — a defence in depth behind the field
 * allowlist and the live-secret tripwire, not a replacement for either.
 */
export const CREDENTIAL_SHAPED_VALUE: readonly RegExp[] = [
  /sk_(live|test)_[A-Za-z0-9]{8,}/,
  /rk_(live|test)_[A-Za-z0-9]{8,}/,
  /gh[pousr]_[A-Za-z0-9]{16,}/,
  /github_pat_[A-Za-z0-9_]{20,}/,
  /xox[baprs]-[A-Za-z0-9-]{10,}/,
  /AKIA[0-9A-Z]{16}/,
  /ASIA[0-9A-Z]{16}/,
  /AIza[0-9A-Za-z_-]{30,}/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
  // The canary marker used by the security suite: treated as credential
  // material by the product itself so a test can never "pass" by leaking it.
  /VEIL_CANARY_[A-Za-z0-9]{8,}/,
  /SECURE_INPUT_CANARY_[A-Za-z0-9]{8,}/,
];

export function looksLikeCredential(value: string): boolean {
  return CREDENTIAL_SHAPED_VALUE.some((pattern) => pattern.test(value));
}
