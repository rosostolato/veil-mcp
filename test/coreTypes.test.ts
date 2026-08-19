/** Unit tests for the security-critical domain primitives. */

import { describe, expect, it } from 'vitest';

import {
  ALLOWED_TRANSITIONS,
  Environment,
  RequestState,
  RiskLevel,
  TERMINAL_STATES,
  deepFreeze,
  environmentSeverity,
  escalateEnvironment,
  escalateRisk,
  isTerminal,
} from '../src/model.js';
import { containsSecret, derivations, looksLikeCredential, safeDisplay } from '../src/redaction.js';
import { SecretBuffer, SecretDestroyedError } from '../src/secretBuffer.js';

describe('SecretBuffer', () => {
  it('refuses to be shown or serialized', () => {
    const buffer = new SecretBuffer(Buffer.from('super-secret-value', 'utf8'));

    expect(String(buffer)).toBe('<SecretBuffer redacted>');
    expect(String(buffer)).not.toContain('super-secret');
    expect(() => JSON.stringify({ secret: buffer })).toThrow(TypeError);
    expect(() => JSON.stringify(buffer)).toThrow(TypeError);
  });

  it('zeroizes and refuses use afterwards', () => {
    const buffer = new SecretBuffer(Buffer.from('value-to-wipe', 'utf8'));
    expect(buffer.toText()).toBe('value-to-wipe');

    buffer.zeroize();

    expect(buffer.destroyed).toBe(true);
    expect(() => buffer.toBytes()).toThrow(SecretDestroyedError);
    expect(() => buffer.toText()).toThrow(SecretDestroyedError);
    expect(() => buffer.view()).toThrow(SecretDestroyedError);
    expect(() => buffer.byteLength).toThrow(SecretDestroyedError);
    expect(buffer.containsIn('value-to-wipe')).toBe(false);
  });

  it("wipes the caller's buffer so no second copy survives", () => {
    const source = Buffer.from('transient-copy', 'utf8');
    const buffer = new SecretBuffer(source);
    expect(source.every((byte) => byte === 0)).toBe(true);
    expect(buffer.toText()).toBe('transient-copy');
  });

  it('rejects oversized values', () => {
    expect(() => new SecretBuffer(Buffer.alloc(64 * 1024 + 1, 0x41))).toThrow(RangeError);
  });
});

describe('redaction', () => {
  it('detects every encoding of a secret', () => {
    const secret = Buffer.from('a-very-recognisable-secret-value', 'utf8');
    for (const encoded of derivations(secret)) {
      expect(containsSecret(Buffer.concat([Buffer.from('prefix '), encoded]), secret)).toBe(true);
    }
    expect(containsSecret('unrelated content', secret)).toBe(false);
  });

  it('neutralises control and bidi characters', () => {
    const rendered = safeDisplay('A\x1b[31m\u202eB\u200bC\x00');
    expect(rendered).not.toContain('\x1b');
    expect(rendered).not.toContain('\u202e');
    expect(rendered).not.toContain('\u200b');
    expect(rendered).toContain('\\u001b');
    expect(rendered.startsWith('A')).toBe(true);
  });

  it('recognises credential-shaped values without flagging labels', () => {
    expect(looksLikeCredential('sk_live_abcdefgh12345678')).toBe(true);
    expect(looksLikeCredential('-----BEGIN RSA PRIVATE KEY-----')).toBe(true);
    expect(looksLikeCredential('STRIPE_SECRET_KEY')).toBe(false);
    expect(looksLikeCredential('acme-production')).toBe(false);
  });
});

describe('domain model', () => {
  it('only escalates risk and environment', () => {
    expect(escalateRisk(RiskLevel.LOW, RiskLevel.HIGH)).toBe(RiskLevel.HIGH);
    expect(escalateRisk(RiskLevel.HIGH, RiskLevel.LOW)).toBe(RiskLevel.HIGH);
    expect(escalateEnvironment(Environment.DEVELOPMENT, Environment.PRODUCTION)).toBe(
      Environment.PRODUCTION,
    );
    expect(escalateEnvironment(Environment.PRODUCTION, Environment.DEVELOPMENT)).toBe(
      Environment.PRODUCTION,
    );
    expect(environmentSeverity(Environment.UNKNOWN)).toBeGreaterThan(
      environmentSeverity(Environment.STAGING),
    );
  });

  it('gives terminal states no outgoing transitions', () => {
    for (const state of TERMINAL_STATES) {
      expect([...ALLOWED_TRANSITIONS[state]]).toEqual([]);
      expect(isTerminal(state)).toBe(true);
    }
    expect(Object.keys(ALLOWED_TRANSITIONS).sort()).toEqual(Object.values(RequestState).sort());
  });

  it('matches the specified state graph', () => {
    expect([...ALLOWED_TRANSITIONS[RequestState.AWAITING_SECRET_AUTHORIZATION]].sort()).toEqual(
      [RequestState.CANCELLED, RequestState.EXPIRED, RequestState.SECRET_RECEIVED].sort(),
    );
    expect([...ALLOWED_TRANSITIONS[RequestState.EXECUTING]].sort()).toEqual(
      [RequestState.FAILED, RequestState.STORED].sort(),
    );
    expect(ALLOWED_TRANSITIONS[RequestState.EXECUTING].has(RequestState.SECRET_RECEIVED)).toBe(
      false,
    );
  });

  it('deep-freezes nested authorization data', () => {
    const frozen = deepFreeze({ target: { fields: { project: 'a' } }, warnings: ['w'] });
    expect(Object.isFrozen(frozen)).toBe(true);
    expect(Object.isFrozen(frozen.target)).toBe(true);
    expect(Object.isFrozen(frozen.target.fields)).toBe(true);
    expect(Object.isFrozen(frozen.warnings)).toBe(true);
    expect(() => {
      frozen.target.fields.project = 'attacker';
    }).toThrow(TypeError);
  });
});
