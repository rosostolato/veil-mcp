/** SPEC.md §30, §18.6 — terminal requests are permanently non-reusable. */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { AdapterRegistry } from '../../../src/adapters/registry.js';
import { SecretBroker, parseStoreParams } from '../../../src/broker.js';
import { AuditLogger } from '../../../src/logging.js';
import { RequestState } from '../../../src/model.js';
import { Canary } from '../../support/canary.js';
import { DiscardStream, RecordingAdapter } from '../../support/fakes.js';
import { Harness, storeArgs, testConfig } from '../../support/harness.js';

describe('replay protection', () => {
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

  it('a completed request cannot be replayed', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    expect((await harness.finishFlow(payload, canary.value)).state).toBe(RequestState.STORED);

    const replay = await harness.submitSecret(payload, canary.value);
    expect(replay.status).toBe(410);
    const confirm = await harness.post(`${harness.pathFor(payload)}/confirm`, {
      confirm_token: 'x',
    });
    expect(confirm.status).toBe(410);
    expect(adapter.writes).toHaveLength(1);
  });

  it('a cancelled request cannot be reused', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    await harness.cancel(payload);

    expect((await harness.submitSecret(payload, canary.value)).status).toBe(410);
    expect((await harness.cancel(payload)).status).toBe(410);
    expect(adapter.writes).toEqual([]);
  });

  it('request ids are unpredictable and unique', async () => {
    const ids = new Set<string>();
    for (let index = 0; index < 20; index += 1) {
      const payload = await harness.callTool('secret_store', storeArgs());
      ids.add(payload.request_id as string);
    }
    expect(ids.size).toBe(20);
    expect([...ids].every((id) => id.length >= 20)).toBe(true);
  });

  it('the authorization token is required and checked', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    const requestId = payload.request_id as string;

    const response = await harness.post(`/r/${requestId}/not-the-token/submit`, {
      secret: canary.value,
    });
    expect(response.status).toBe(403);
    expect((await harness.status(requestId)).state).toBe(
      RequestState.AWAITING_SECRET_AUTHORIZATION,
    );
  });
});

describe('expiry', () => {
  it('an expired request cannot be reused', async () => {
    const config = testConfig();
    const adapter = new RecordingAdapter(config);
    const registry = new AdapterRegistry([adapter]);
    let now = 1000;
    const broker = new SecretBroker(config, registry, {
      logger: new AuditLogger({ stream: new DiscardStream() }),
      clock: () => now,
    });
    const canary = Canary.create();

    const request = await broker.createRequest(parseStoreParams(storeArgs(), registry));
    now += config.requestTtlSeconds + 1;

    await expect(
      broker.submitSecret(request.requestId, request.submitToken, canary.raw),
    ).rejects.toMatchObject({ public: { code: 'REQUEST_EXPIRED' } });
    expect(broker.get(request.requestId).state).toBe(RequestState.EXPIRED);
    expect(adapter.writes).toEqual([]);
  });
});
