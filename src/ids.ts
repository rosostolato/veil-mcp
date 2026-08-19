/** Unpredictable identifiers and capability tokens (SPEC.md §18.6). */

import { randomBytes, timingSafeEqual } from 'node:crypto';

export const REQUEST_ID_PREFIX = 'req_';

/** A single-use, cryptographically unpredictable request identifier. */
export function newRequestId(): string {
  return REQUEST_ID_PREFIX + randomBytes(18).toString('base64url');
}

/**
 * A capability token binding a browser interaction to one request.
 *
 * This is not secret material: it never travels with the credential and it
 * grants nothing beyond the right to act on one already-created request.
 */
export function newToken(): string {
  return randomBytes(32).toString('base64url');
}

export function tokenEquals(expected: string, provided: string): boolean {
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(provided, 'utf8');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
