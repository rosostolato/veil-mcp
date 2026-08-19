/** SPEC.md §20, §32 — no raw provider output crosses the MCP boundary. */

import { describe, expect, it } from 'vitest';

import { GcpSecretManagerAdapter } from '../../../src/adapters/gcpSecretManager.js';
import { AdapterRegistry } from '../../../src/adapters/registry.js';
import type { SecretDestinationAdapter } from '../../../src/adapters/base.js';
import { Canary } from '../../support/canary.js';
import {
  EchoingErrorAdapter,
  EchoingSanitizerAdapter,
  FakeSecretManager,
  LeakyResultAdapter,
  MalformedResultAdapter,
  RaisingSanitizerAdapter,
  SlowAdapter,
} from '../../support/fakes.js';
import { Harness, testConfig } from '../../support/harness.js';

function args(destination: string): Record<string, unknown> {
  return {
    destination,
    name: 'API_TOKEN',
    target: { project: 'acme-dev-project', secret: 'API_TOKEN' },
    write_mode: 'create',
  };
}

async function withHarness<T>(
  build: (config: ReturnType<typeof testConfig>) => SecretDestinationAdapter,
  run: (harness: Harness, canary: Canary) => Promise<T>,
  overrides: Partial<ReturnType<typeof testConfig>> = {},
): Promise<T> {
  const config = testConfig(overrides);
  const harness = await Harness.start(config, new AdapterRegistry([build(config)]));
  try {
    return await run(harness, Canary.create());
  } finally {
    await harness.stop();
  }
}

describe('provider error sanitization', () => {
  const cases: [
    string,
    (config: ReturnType<typeof testConfig>) => SecretDestinationAdapter,
    string,
  ][] = [
    [
      'echoes the secret in its error',
      (c) => new EchoingErrorAdapter(c),
      'DESTINATION_WRITE_FAILED',
    ],
    ['leaks through its own sanitizer', (c) => new EchoingSanitizerAdapter(c), 'INTERNAL_ERROR'],
    ['throws inside its sanitizer', (c) => new RaisingSanitizerAdapter(c), 'INTERNAL_ERROR'],
    ['returns the secret in its result', (c) => new LeakyResultAdapter(c), 'INTERNAL_ERROR'],
    ['returns an unusable result', (c) => new MalformedResultAdapter(c), 'INTERNAL_ERROR'],
  ];

  for (const [name, build, expectedCode] of cases) {
    it(`sanitizes an adapter that ${name}`, async () => {
      await withHarness(build, async (harness, canary) => {
        const adapterId = harness.registry.ids()[0] ?? '';
        const payload = await harness.callTool('secret_store', args(adapterId));
        const status = await harness.finishFlow(payload, canary.value);

        expect(status.state).toBe('FAILED');
        expect((status.error as { code: string }).code).toBe(expectedCode);
        expect(String((status.error as { message: string }).message)).not.toContain(canary.value);

        harness.collectLogs();
        harness.scanner.assertClean(canary);
      });
    });
  }

  it('reports an adapter timeout without detail', async () => {
    await withHarness(
      (config) => new SlowAdapter(config),
      async (harness, canary) => {
        const payload = await harness.callTool('secret_store', args('slow-store'));
        const status = await harness.finishFlow(payload, canary.value);
        expect(status.state).toBe('FAILED');
        expect((status.error as { code: string }).code).toBe('DESTINATION_TIMEOUT');
      },
      { adapterTimeoutSeconds: 1 },
    );
  });

  const statuses: [number, string][] = [
    [401, 'DESTINATION_DENIED'],
    [403, 'DESTINATION_DENIED'],
    [404, 'DESTINATION_NOT_FOUND'],
    [409, 'DESTINATION_CONFLICT'],
    [429, 'DESTINATION_RATE_LIMITED'],
    [500, 'DESTINATION_WRITE_FAILED'],
    [503, 'DESTINATION_UNAVAILABLE'],
  ];

  for (const [status, expectedCode] of statuses) {
    it(`maps provider status ${status} to ${expectedCode}`, async () => {
      const provider = new FakeSecretManager();
      provider.existing.add('projects/acme-dev-project/secrets/API_TOKEN');
      provider.failStatus = status;

      await withHarness(
        (config) => new GcpSecretManagerAdapter(config, provider.transport()),
        async (harness, canary) => {
          const payload = await harness.callTool('secret_store', {
            ...args('gcp-secret-manager'),
            write_mode: 'new-version',
          });
          const result = await harness.finishFlow(payload, canary.value);
          expect(result.state).toBe('FAILED');
          expect((result.error as { code: string }).code).toBe(expectedCode);
          harness.collectLogs();
          harness.scanner.assertClean(canary);
        },
      );
    });
  }
});
