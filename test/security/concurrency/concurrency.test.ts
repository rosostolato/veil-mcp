/** SPEC.md §28, §18.7 — 100 concurrent requests, zero cross-wiring. */

import { describe, expect, it } from 'vitest';

import { AdapterRegistry } from '../../../src/adapters/registry.js';
import { SecretBroker, parseStoreParams } from '../../../src/broker.js';
import { AuditLogger } from '../../../src/logging.js';
import { Canary, LeakScanner } from '../../support/canary.js';
import { DiscardStream, RecordingAdapter } from '../../support/fakes.js';
import { Harness, testConfig } from '../../support/harness.js';

const REQUEST_COUNT = 100;

describe('concurrency isolation', () => {
  it('never crosses a secret between concurrent requests', async () => {
    const config = testConfig({ maxActiveRequests: REQUEST_COUNT * 2 });
    const adapter = new RecordingAdapter(config);
    const registry = new AdapterRegistry([adapter]);
    const records: Record<string, unknown>[] = [];
    const broker = new SecretBroker(config, registry, {
      logger: new AuditLogger({ stream: new DiscardStream(), sink: (r) => records.push(r) }),
    });

    const expected = new Map<string, string>();
    const prepared: {
      request: Awaited<ReturnType<SecretBroker['createRequest']>>;
      canary: Canary;
    }[] = [];

    for (let index = 0; index < REQUEST_COUNT; index += 1) {
      const canary = Canary.create(String(index).padStart(3, '0'));
      const secretName = `CANARY_${String(index).padStart(3, '0')}`;
      const request = await broker.createRequest(
        parseStoreParams(
          {
            destination: 'fake-store',
            name: secretName,
            target: { project: 'acme-dev-project', secret: secretName },
            write_mode: 'create',
          },
          registry,
        ),
      );
      expected.set(secretName, canary.value);
      prepared.push({ request, canary });
    }

    await Promise.all(
      prepared.map(({ request, canary }) =>
        broker.submitSecret(request.requestId, request.submitToken, canary.raw),
      ),
    );

    expect(adapter.writes).toHaveLength(REQUEST_COUNT);
    const written = new Map(adapter.writes);
    expect(written.size).toBe(REQUEST_COUNT);
    expect([...written.entries()].sort()).toEqual([...expected.entries()].sort());

    for (const { request } of prepared) {
      expect(broker.get(request.requestId).state).toBe('STORED');
      expect(broker.get(request.requestId).secret).toBeNull();
    }

    const scanner = new LeakScanner();
    scanner.add('audit_records', JSON.stringify(records));
    for (const { canary } of prepared) scanner.assertClean(canary);
  });

  it('keeps requests bound when driven through the real HTTP surface', async () => {
    const config = testConfig();
    const adapter = new RecordingAdapter(config);
    const harness = await Harness.start(config, new AdapterRegistry([adapter]));
    try {
      const prepared: { payload: Record<string, unknown>; canary: Canary; name: string }[] = [];
      for (let index = 0; index < 20; index += 1) {
        const name = `UI_CANARY_${String(index).padStart(3, '0')}`;
        prepared.push({
          payload: await harness.callTool('secret_store', {
            destination: 'fake-store',
            name,
            target: { project: 'acme-dev-project', secret: name },
            write_mode: 'create',
          }),
          canary: Canary.create(`ui${String(index).padStart(3, '0')}`),
          name,
        });
      }

      await Promise.all(
        prepared.map(({ payload, canary }) => harness.submitSecret(payload, canary.value)),
      );

      const written = new Map(adapter.writes);
      expect([...written.entries()].sort()).toEqual(
        prepared.map(({ name, canary }) => [name, canary.value] as [string, string]).sort(),
      );
    } finally {
      await harness.stop();
    }
  });
});
