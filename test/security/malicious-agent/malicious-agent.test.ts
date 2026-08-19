/** SPEC.md §26 — a compromised agent tries every attack. All fail safely. */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { SecretDestinationAdapter, type JsonSchema } from '../../../src/adapters/base.js';
import { AdapterRegistry } from '../../../src/adapters/registry.js';
import {
  DestinationClass,
  type NormalizedTarget,
  type RiskAssessment,
  type StoreResult,
} from '../../../src/model.js';
import { Canary } from '../../support/canary.js';
import { RecordingAdapter } from '../../support/fakes.js';
import { Harness, storeArgs, testConfig } from '../../support/harness.js';

describe('malicious agent', () => {
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

  it('§26.1/§26.8: rejects attacker-controlled destinations', async () => {
    for (const destination of ['evil.example', 'http-post', 'arbitrary-network', '']) {
      const payload = await harness.callTool('secret_store', storeArgs({ destination }));
      expect(payload.code, destination).toBe('UNKNOWN_DESTINATION');
    }
  });

  it('§16: an arbitrary-network adapter cannot even be registered', () => {
    class Exfiltrator extends SecretDestinationAdapter {
      readonly id = 'webhook';
      readonly displayName = 'Webhook';
      readonly destinationClass = DestinationClass.ARBITRARY_NETWORK;
      targetSchema(): JsonSchema {
        return { type: 'object', additionalProperties: false, properties: {} };
      }
      normalizeTarget(): Promise<NormalizedTarget> {
        throw new Error('unreachable');
      }
      calculateRisk(): Promise<RiskAssessment> {
        throw new Error('unreachable');
      }
      store(): Promise<StoreResult> {
        throw new Error('unreachable');
      }
    }

    expect(() => new AdapterRegistry([new Exfiltrator(harness.config)])).toThrow(
      /arbitrary-network/,
    );
  });

  it('§26.5: refuses secret-shaped fields', async () => {
    for (const field of [
      'value',
      'secret_value',
      'password',
      'credential',
      'content',
      'raw_secret',
    ]) {
      const payload = await harness.callTool(
        'secret_store',
        storeArgs({ [field]: 'sk_live_deadbeefdeadbeef' }),
      );
      expect(['FORBIDDEN_FIELD', 'INVALID_ARGUMENTS'], field).toContain(payload.code);
    }

    const nested = await harness.callTool(
      'secret_store',
      storeArgs({ target: { project: 'acme-dev-project', password: 'hunter2hunter2' } }),
    );
    expect(['FORBIDDEN_FIELD', 'INVALID_TARGET']).toContain(nested.code);
  });

  it('§26.6: refuses credential-shaped values in legitimate fields', async () => {
    for (const value of [
      'sk_live_51H8ZxKLmNoPqRsTuVwXyZ',
      'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345',
      'AKIAIOSFODNN7EXAMPLE',
      '-----BEGIN RSA PRIVATE KEY-----',
    ]) {
      const payload = await harness.callTool('secret_store', storeArgs({ description: value }));
      expect(payload.code, value).toBe('FORBIDDEN_FIELD');
    }
  });

  it('§26.6: metadata is never treated as credential material', async () => {
    const encoded = Buffer.from('attacker-planted-value', 'utf8').toString('base64');
    const payload = await harness.callTool(
      'secret_store',
      storeArgs({ description: `rotate ${encoded}` }),
    );
    await harness.finishFlow(payload, canary.value);

    expect(adapter.writes.map(([, value]) => value)).toEqual([canary.value]);
  });

  it('§26.4/§18.1: a misleading description cannot change what the user sees', async () => {
    const payload = await harness.callTool(
      'secret_store',
      storeArgs({
        target: { project: 'acme-production', secret: 'PROD_DB_PASSWORD' },
        description: 'Harmless development scratch value, no production impact',
        environment: 'development',
      }),
    );
    const page = await harness.get(harness.pathFor(payload));

    expect(page.body).toContain('acme-production');
    expect(page.body).toContain('PROD_DB_PASSWORD');
    expect(page.body).toContain('production');
    expect((payload.destination as { environment: string }).environment).toBe('production');
  });

  it('§18.3: bounds nesting and oversized arguments', async () => {
    const nested: Record<string, unknown> = { project: 'acme-dev-project' };
    let node = nested;
    for (let depth = 0; depth < 12; depth += 1) {
      node.secret = { secret: {} };
      node = node.secret as Record<string, unknown>;
    }
    const deep = await harness.callTool('secret_store', storeArgs({ target: nested }));
    expect(deep.status).toBe('failed');

    const long = await harness.callTool(
      'secret_store',
      storeArgs({ target: { project: 'acme-dev-project', secret: 'A'.repeat(5000) } }),
    );
    expect(['INVALID_TARGET', 'FORBIDDEN_FIELD']).toContain(long.code);
  });

  it('§5: the agent cannot read a secret back through status', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    await harness.submitSecret(payload, canary.value);
    const status = await harness.status(payload.request_id as string);

    harness.collectLogs();
    harness.scanner.add('status_payload', JSON.stringify(status));
    harness.scanner.assertClean(canary);
  });
});
