/** End-to-end happy paths and the request state machine (SPEC.md §14, §44). */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { AdapterRegistry } from '../src/adapters/registry.js';
import { RequestState } from '../src/model.js';
import { Canary } from './support/canary.js';
import { RecordingAdapter } from './support/fakes.js';
import { Harness, storeArgs, testConfig } from './support/harness.js';

describe('credential request flow', () => {
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

  it('stores a low-risk credential without a second confirmation', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());

    expect(payload.state).toBe(RequestState.AWAITING_SECRET_AUTHORIZATION);
    expect((payload.risk as { level: string }).level).toBe('low');
    expect(payload.requires_confirmation).toBe(false);
    expect(payload.authorization_url).toMatch(/^http:\/\/127\.0\.0\.1:\d+/);

    const status = await harness.finishFlow(payload, canary.value);

    expect(status.state).toBe(RequestState.STORED);
    expect(adapter.writes).toEqual([['STRIPE_SECRET_KEY', canary.value]]);
  });

  it('requires stage B before a high-risk write', async () => {
    adapter.exists = true;
    const payload = await harness.callTool(
      'secret_store',
      storeArgs({
        target: { project: 'acme-production', secret: 'STRIPE_SECRET_KEY' },
        write_mode: 'replace',
        environment: 'production',
      }),
    );
    expect((payload.risk as { level: string }).level).toBe('high');
    expect(payload.requires_confirmation).toBe(true);

    await harness.submitSecret(payload, canary.value);
    const mid = await harness.status(payload.request_id as string);
    expect(mid.state).toBe(RequestState.AWAITING_EXECUTION_CONFIRMATION);
    expect(adapter.writes).toEqual([]);

    await harness.confirm(payload);
    const final = await harness.status(payload.request_id as string);
    expect(final.state).toBe(RequestState.STORED);
    expect(adapter.writes).toHaveLength(1);
  });

  it('advertises exactly the five tools, none carrying a secret field', async () => {
    const response = await harness.rpc('tools/list');
    const tools = (response.result?.tools ?? []) as {
      name: string;
      inputSchema: { properties: Record<string, unknown> };
    }[];
    expect(tools.map((tool) => tool.name).sort()).toEqual([
      'secret_cancel',
      'secret_destinations',
      'secret_revise',
      'secret_status',
      'secret_store',
    ]);
    const store = tools.find((tool) => tool.name === 'secret_store');
    expect(Object.keys(store?.inputSchema.properties ?? {}).sort()).toEqual([
      'description',
      'destination',
      'environment',
      'name',
      'target',
      'write_mode',
    ]);
  });

  it('answers initialize and ping', async () => {
    const response = await harness.rpc('initialize', { protocolVersion: '2025-06-18' });
    expect(response.result?.serverInfo).toEqual({ name: 'veil', version: '0.1.0' });
    expect(response.result?.capabilities).toEqual({ tools: { listChanged: false } });
    const ping = await harness.rpc('ping');
    expect(ping.result).toEqual({});
  });

  it('writes nothing when the user cancels at stage A', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    await harness.cancel(payload);
    const status = await harness.status(payload.request_id as string);
    expect(status.state).toBe(RequestState.CANCELLED);
    expect(adapter.writes).toEqual([]);
  });
});
