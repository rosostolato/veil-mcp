/** SPEC.md §29 — races have deterministic, fail-safe outcomes. */

import { beforeEach, describe, expect, it } from 'vitest';

import { AdapterRegistry } from '../../../src/adapters/registry.js';
import { SecretBroker, parseStoreParams } from '../../../src/broker.js';
import { AuditLogger } from '../../../src/logging.js';
import { RequestState } from '../../../src/model.js';
import { Canary } from '../../support/canary.js';
import { DiscardStream, RecordingAdapter, SlowAdapter } from '../../support/fakes.js';
import { Harness, testConfig } from '../../support/harness.js';

function args(destination = 'fake-store'): Record<string, unknown> {
  return {
    destination,
    name: 'CANARY_KEY',
    target: { project: 'acme-dev-project', secret: 'CANARY_KEY' },
    write_mode: 'create',
  };
}

function makeBroker(
  config = testConfig(),
  adapter = new RecordingAdapter(config),
): { broker: SecretBroker; adapter: RecordingAdapter; registry: AdapterRegistry } {
  const registry = new AdapterRegistry([adapter]);
  const broker = new SecretBroker(config, registry, {
    logger: new AuditLogger({ stream: new DiscardStream() }),
  });
  return { broker, adapter, registry };
}

describe('race conditions', () => {
  let canary: Canary;

  beforeEach(() => {
    canary = Canary.create();
  });

  it('a double submit writes exactly once', async () => {
    const { broker, adapter, registry } = makeBroker();
    const request = await broker.createRequest(parseStoreParams(args(), registry));

    const outcomes = await Promise.allSettled([
      broker.submitSecret(request.requestId, request.submitToken, canary.raw),
      broker.submitSecret(request.requestId, request.submitToken, canary.raw),
    ]);

    expect(outcomes.filter((outcome) => outcome.status === 'fulfilled')).toHaveLength(1);
    expect(adapter.writes).toHaveLength(1);
    expect(broker.get(request.requestId).state).toBe(RequestState.STORED);
  });

  it('submit racing cancel has exactly one winner', async () => {
    for (let attempt = 0; attempt < 25; attempt += 1) {
      const { broker, registry } = makeBroker();
      const request = await broker.createRequest(parseStoreParams(args(), registry));

      const [submit, cancel] = await Promise.allSettled([
        broker.submitSecret(request.requestId, request.submitToken, canary.raw),
        Promise.resolve().then(() => broker.cancel(request.requestId, { reason: 'race' })),
      ]);

      const state = broker.get(request.requestId).state;
      expect([RequestState.STORED, RequestState.CANCELLED]).toContain(state);
      if (state === RequestState.CANCELLED) expect(submit?.status).toBe('rejected');
      else expect(cancel?.status).toBe('rejected');
      expect(broker.get(request.requestId).secret).toBeNull();
    }
  });

  it('expiration racing submission fails closed', async () => {
    const config = testConfig();
    const adapter = new RecordingAdapter(config);
    const registry = new AdapterRegistry([adapter]);
    let now = 500;
    const broker = new SecretBroker(config, registry, {
      logger: new AuditLogger({ stream: new DiscardStream() }),
      clock: () => now,
    });
    const request = await broker.createRequest(parseStoreParams(args(), registry));

    now += config.requestTtlSeconds; // exactly at the deadline

    await expect(
      broker.submitSecret(request.requestId, request.submitToken, canary.raw),
    ).rejects.toMatchObject({ public: { code: 'REQUEST_EXPIRED' } });
    expect(adapter.writes).toEqual([]);
  });

  it('cancelling during execution is refused, not silently dropped', async () => {
    const config = testConfig({ adapterTimeoutSeconds: 1 });
    const slow = new SlowAdapter(config);
    const registry = new AdapterRegistry([slow]);
    const broker = new SecretBroker(config, registry, {
      logger: new AuditLogger({ stream: new DiscardStream() }),
    });
    const request = await broker.createRequest(parseStoreParams(args('slow-store'), registry));

    const submitted = broker.submitSecret(request.requestId, request.submitToken, canary.raw);
    await Promise.resolve();
    expect(broker.get(request.requestId).state).toBe(RequestState.EXECUTING);
    expect(() => broker.cancel(request.requestId, { reason: 'race' })).toThrowError(
      expect.objectContaining({ public: expect.objectContaining({ code: 'INVALID_STATE' }) }),
    );

    await submitted;
    const status = broker.publicStatus(request.requestId);
    expect(status.state).toBe(RequestState.FAILED);
    expect((status.error as { code: string }).code).toBe('DESTINATION_TIMEOUT');
  });

  it('two browser tabs cannot both submit', async () => {
    const config = testConfig();
    const adapter = new RecordingAdapter(config);
    const harness = await Harness.start(config, new AdapterRegistry([adapter]));
    try {
      const payload = await harness.callTool('secret_store', args());
      const first = await harness.submitSecret(payload, canary.value);
      const second = await harness.submitSecret(payload, 'second-tab-value');

      expect(first.status).toBe(303);
      expect([409, 410]).toContain(second.status);
      expect(adapter.writes).toEqual([['CANARY_KEY', canary.value]]);
    } finally {
      await harness.stop();
    }
  });

  it('a revision never lets the stale operation execute', async () => {
    const config = testConfig();
    const adapter = new RecordingAdapter(config, { exists: true });
    const harness = await Harness.start(config, new AdapterRegistry([adapter]));
    try {
      const payload = await harness.callTool('secret_store', {
        ...args(),
        write_mode: 'replace',
        environment: 'production',
      });
      await harness.submitSecret(payload, canary.value);

      const revised = await harness.callTool('secret_revise', {
        request_id: payload.request_id,
        ...args(),
        target: { project: 'acme-dev-project', secret: 'OTHER_KEY' },
        write_mode: 'replace',
      });

      const lateConfirm = await harness.post(`${harness.pathFor(payload)}/confirm`, {
        confirm_token: 'whatever',
      });
      expect(lateConfirm.status).toBe(410);
      expect(adapter.writes).toEqual([]);
      expect((await harness.status(revised.request_id as string)).state).toBe(
        'AWAITING_SECRET_AUTHORIZATION',
      );
    } finally {
      await harness.stop();
    }
  });
});
