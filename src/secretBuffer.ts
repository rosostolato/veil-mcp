/**
 * Custody of raw credential bytes (SPEC.md §5, §18.9).
 *
 * A `SecretBuffer` is deliberately hostile to the ways secrets normally escape:
 * it has no useful string form, refuses to be serialized or inspected, and can
 * be wiped. It is owned by exactly one request and is never placed in module or
 * process-global state.
 *
 * Node lets us do better here than CPython did: the credential lives in a
 * `Buffer` we allocate, and `zeroize` overwrites those exact bytes. The honest
 * limitation is that any conversion to a JavaScript string — which some provider
 * SDKs require — creates an immutable copy the engine may keep until GC, and
 * that copy cannot be wiped.
 */

import { containsSecret } from './redaction.js';

export const MAX_SECRET_BYTES = 64 * 1024;

export class SecretDestroyedError extends Error {
  constructor() {
    super('secret buffer has been zeroized');
    this.name = 'SecretDestroyedError';
  }
}

export class SecretBuffer {
  #data: Buffer;
  #destroyed = false;

  /**
   * Takes ownership of `data`. A caller-supplied Buffer is copied and then
   * wiped, so the transient parse buffer stops holding the credential.
   */
  constructor(data: Buffer) {
    if (data.length > MAX_SECRET_BYTES) {
      wipe(data);
      throw new RangeError('secret exceeds maximum size');
    }
    this.#data = Buffer.allocUnsafe(data.length);
    data.copy(this.#data);
    wipe(data);
  }

  get destroyed(): boolean {
    return this.#destroyed;
  }

  get byteLength(): number {
    this.#check();
    return this.#data.length;
  }

  zeroize(): void {
    if (!this.#destroyed) {
      wipe(this.#data);
      this.#destroyed = true;
    }
  }

  /** A read-only view, for consumers that accept bytes without copying. */
  view(): Buffer {
    this.#check();
    return this.#data;
  }

  /**
   * An immutable copy, for provider APIs that require one. The returned value
   * cannot be wiped: keep it alive as briefly as possible and never store it.
   */
  toBytes(): Buffer {
    this.#check();
    return Buffer.from(this.#data);
  }

  /** An immutable string copy, with the same caveat as `toBytes`. */
  toText(encoding: BufferEncoding = 'utf8'): string {
    this.#check();
    return this.#data.toString(encoding);
  }

  /** Tripwire hook: does `haystack` carry this secret in any encoding? */
  containsIn(haystack: Buffer | string): boolean {
    if (this.#destroyed) return false;
    return containsSecret(haystack, this.#data);
  }

  #check(): void {
    if (this.#destroyed) throw new SecretDestroyedError();
  }

  // -- escape hatches, closed ------------------------------------------------

  toString(): string {
    return '<SecretBuffer redacted>';
  }

  toJSON(): never {
    throw new TypeError('SecretBuffer must not be serialized');
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return '<SecretBuffer redacted>';
  }

  get [Symbol.toStringTag](): string {
    return 'SecretBuffer';
  }
}

/** Best-effort in-place erasure of a mutable byte buffer. */
export function wipe(buffer: Buffer): void {
  if (buffer.length > 0) buffer.fill(0);
}
