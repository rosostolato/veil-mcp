/** SEC-001 … SEC-010: the canary must not reach any observable channel. */

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { EnvFileAdapter } from '../../../src/adapters/envFile.js';
import { AdapterRegistry } from '../../../src/adapters/registry.js';
import { SECRET_SHAPED_FIELD } from '../../../src/mcp/tools.js';
import { Canary } from '../../support/canary.js';
import { RecordingAdapter } from '../../support/fakes.js';
import { Harness, storeArgs, testConfig } from '../../support/harness.js';
import { makeTempDir, removeTempDir } from '../../support/tmp.js';

function schemaPropertyNames(node: unknown, out: string[] = []): string[] {
  if (Array.isArray(node)) {
    for (const item of node) schemaPropertyNames(item, out);
  } else if (node !== null && typeof node === 'object') {
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      if (key === 'properties' && value !== null && typeof value === 'object') {
        out.push(...Object.keys(value));
      }
      schemaPropertyNames(value, out);
    }
  }
  return out;
}

describe('canary leakage', () => {
  let harness: Harness;
  let adapter: RecordingAdapter;
  let canary: Canary;

  beforeEach(async () => {
    const config = testConfig();
    adapter = new RecordingAdapter(config);
    harness = await Harness.start(config, new AdapterRegistry([adapter]));
    canary = Canary.create();
  });

  afterEach(async () => {
    await harness.stop();
  });

  it('SEC-001: no tool schema permits credential content', async () => {
    const response = await harness.rpc('tools/list');
    const tools = (response.result?.tools ?? []) as { inputSchema: Record<string, unknown> }[];

    const names: string[] = [];
    for (const tool of tools) {
      schemaPropertyNames(tool.inputSchema, names);
      expect(tool.inputSchema.additionalProperties).toBe(false);
    }

    // `secret` (a Secret Manager id) and `key` (an env var name) are labels, not
    // values; every other secret-shaped name must be absent entirely.
    const offenders = names.filter(
      (name) => !['secret', 'key'].includes(name) && SECRET_SHAPED_FIELD.test(name),
    );
    expect(offenders).toEqual([]);
  });

  it('SEC-002…SEC-008: the secret reaches no observable channel', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    const status = await harness.finishFlow(payload, canary.value);
    expect(status.state).toBe('STORED');

    harness.collectLogs();
    harness.scanner.add('provider_urls', JSON.stringify(adapter.urls));
    harness.scanner.add('mcp_status_result', JSON.stringify(status));
    harness.scanner.add('process_argv', process.argv.join(' '));
    harness.scanner.add('process_env', JSON.stringify(process.env));

    harness.scanner.assertClean(canary);
    // …and the credential really did reach the destination.
    expect(adapter.writes).toEqual([['STRIPE_SECRET_KEY', canary.value]]);
  });

  it('SEC-006: logs stay clean at every level', async () => {
    adapter.exists = true;
    const payload = await harness.callTool(
      'secret_store',
      storeArgs({ write_mode: 'replace', environment: 'production' }),
    );
    await harness.submitSecret(payload, canary.value);
    expect((await harness.status(payload.request_id as string)).state).toBe(
      'AWAITING_EXECUTION_CONFIRMATION',
    );

    // 1. Forbidden field name: dropped by the allowlist.
    harness.broker.log.event('careless', { value: canary.value });
    // 2. Allowlisted free-text fields while the secret is live: the tripwire
    //    replaces the whole record.
    harness.broker.log.debug('careless', { reason: canary.value, detail: { v: canary.value } });

    await harness.confirm(payload);
    expect((await harness.status(payload.request_id as string)).state).toBe('STORED');

    // 3. After the secret is destroyed the tripwire has nothing to match, so
    //    the credential-shape screen is what stops it.
    harness.broker.log.event('careless_after', { reason: canary.value });

    harness.collectLogs();
    harness.scanner.assertClean(canary);
    expect(harness.logText).toContain('[redacted]');
  });

  it('SEC-006: a shapeless live secret is still caught by the tripwire', async () => {
    const unremarkable = 'correct horse battery staple 7413';
    adapter.exists = true;
    const payload = await harness.callTool(
      'secret_store',
      storeArgs({ write_mode: 'replace', environment: 'production' }),
    );
    await harness.submitSecret(payload, unremarkable);

    harness.broker.log.event('careless', { reason: unremarkable });

    expect(harness.logText).toContain('audit_record_suppressed');
    expect(harness.logText).not.toContain(unremarkable);
  });

  it('SPEC.md §23: derivations cover the required encodings', () => {
    const variants = new Set(canary.variants.map((variant) => variant.toString('utf8')));
    expect(variants.has(canary.value)).toBe(true);
    expect(variants.has(canary.raw.toString('base64'))).toBe(true);
    expect(variants.has(canary.raw.toString('base64url'))).toBe(true);
    expect(variants.has(canary.raw.toString('hex'))).toBe(true);
    expect(variants.has(canary.raw.toString('hex').toUpperCase())).toBe(true);
    expect(variants.has(canary.value.slice(0, 8))).toBe(true);
    expect(variants.has(canary.value.slice(-8))).toBe(true);
  });
});

describe('SEC-010: temporary copies', () => {
  it('leaves the canary only in the approved destination file', async () => {
    const root = makeTempDir();
    const canary = Canary.create();
    const config = testConfig({ envAllowedRoots: [root] });
    const harness = await Harness.start(config, new AdapterRegistry([new EnvFileAdapter(config)]));
    const envPath = join(root, '.env');

    try {
      const payload = await harness.callTool('secret_store', {
        destination: 'env-file',
        name: 'API_TOKEN',
        target: { path: '.env' },
        write_mode: 'create',
        environment: 'development',
      });
      const status = await harness.finishFlow(payload, canary.value);
      expect(status.state).toBe('STORED');

      harness.collectLogs();
      harness.scanner.addTree('temp_files', root, [envPath]);
      harness.scanner.assertClean(canary);

      harness.scanner.add('approved_destination', readFileSync(envPath));
      harness.scanner.assertPresent(canary, 'approved_destination');
      expect(readdirSync(root)).toEqual(['.env']);
    } finally {
      await harness.stop();
      removeTempDir(root);
    }
  });
});
