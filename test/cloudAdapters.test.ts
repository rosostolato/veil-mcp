/** Google Secret Manager and Firestore adapters (SPEC.md §16, §17). */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { FirestoreAdapter } from '../src/adapters/firestore.js';
import { GcpSecretManagerAdapter } from '../src/adapters/gcpSecretManager.js';
import { AdapterRegistry } from '../src/adapters/registry.js';
import { Canary } from './support/canary.js';
import { FakeFirestore, FakeSecretManager } from './support/fakes.js';
import { Harness, testConfig } from './support/harness.js';

const SECRET_NAME = 'projects/acme-dev-project/secrets/API_TOKEN';

function gcpArgs(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    destination: 'gcp-secret-manager',
    name: 'API_TOKEN',
    target: { project: 'acme-dev-project', secret: 'API_TOKEN' },
    write_mode: 'create',
    environment: 'development',
    ...overrides,
  };
}

describe('Google Secret Manager adapter', () => {
  let provider: FakeSecretManager;
  let harness: Harness;
  let canary: Canary;

  beforeEach(async () => {
    provider = new FakeSecretManager();
    const config = testConfig();
    harness = await Harness.start(
      config,
      new AdapterRegistry([new GcpSecretManagerAdapter(config, provider.transport())]),
    );
    canary = Canary.create();
  });

  afterEach(async () => {
    await harness.stop();
  });

  it('creates a secret, writes the payload and reports the version', async () => {
    const payload = await harness.callTool('secret_store', gcpArgs());
    const status = await harness.finishFlow(payload, canary.value);

    expect(status.state).toBe('STORED');
    expect((status.result as { destination_ref: string }).destination_ref).toMatch(
      /\/versions\/1$/,
    );
    expect(provider.payloads).toEqual([[SECRET_NAME, canary.value]]);

    // The credential appears in exactly one place: the request body.
    const urls = provider.requests.map((request) => request.url).join(' ');
    expect(canary.hitsIn(urls)).toEqual([]);
  });

  it('disables previous versions on replace, after confirmation', async () => {
    provider.existing.add(SECRET_NAME);

    const first = await harness.callTool('secret_store', gcpArgs({ write_mode: 'new-version' }));
    await harness.finishFlow(first, 'first-value');

    const second = await harness.callTool('secret_store', gcpArgs({ write_mode: 'replace' }));
    expect(second.requires_confirmation).toBe(true);
    const status = await harness.finishFlow(second, canary.value);

    expect(status.state).toBe('STORED');
    expect(provider.disabled).toEqual([`${SECRET_NAME}/versions/1`]);
  });

  it('forces high risk for a production project', async () => {
    const payload = await harness.callTool(
      'secret_store',
      gcpArgs({
        target: { project: 'acme-production', secret: 'API_TOKEN' },
        write_mode: 'replace',
        environment: 'development',
      }),
    );
    expect((payload.destination as { environment: string }).environment).toBe('production');
    expect((payload.risk as { level: string }).level).toBe('high');
    expect(payload.requires_confirmation).toBe(true);
  });

  it('rejects invalid identifiers', async () => {
    const targets = [
      { project: 'Bad Project', secret: 'API_TOKEN' },
      { project: 'acme-dev-project', secret: 'bad/secret' },
      { project: 'x', secret: 'API_TOKEN' },
      { project: 'acme-dev-project', secret: 'API_TOKEN', extra: '1' },
    ];
    for (const target of targets) {
      const payload = await harness.callTool('secret_store', gcpArgs({ target }));
      expect(payload.status, JSON.stringify(target)).toBe('failed');
    }
  });

  it('reports an unconfigured provider without detail', async () => {
    const config = testConfig();
    const failing = new GcpSecretManagerAdapter(config, () => {
      throw new Error('Could not load the default credentials for user@example.com');
    });
    const other = await Harness.start(config, new AdapterRegistry([failing]));
    try {
      const payload = await other.callTool('secret_store', gcpArgs());
      expect(payload.status).toBe('failed');
      expect(String(payload.message)).not.toContain('user@example.com');
    } finally {
      await other.stop();
    }
  });
});

describe('Firestore adapter', () => {
  let provider: FakeFirestore;
  let harness: Harness;
  let canary: Canary;

  beforeEach(async () => {
    provider = new FakeFirestore();
    const config = testConfig();
    harness = await Harness.start(
      config,
      new AdapterRegistry([new FirestoreAdapter(config, provider.transport())]),
    );
    canary = Canary.create();
  });

  afterEach(async () => {
    await harness.stop();
  });

  const firestoreArgs = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
    destination: 'firestore',
    name: 'API_TOKEN',
    target: { project: 'acme-dev-project', collection: 'config', document: 'runtime' },
    write_mode: 'create',
    environment: 'development',
    ...overrides,
  });

  it('always warns and always confirms', async () => {
    const payload = await harness.callTool('secret_store', firestoreArgs());

    expect(payload.requires_confirmation).toBe(true);
    const warnings = (payload.destination as { warnings: string[] }).warnings;
    expect(warnings.some((warning) => warning.includes('not be designed to store secrets'))).toBe(
      true,
    );

    const page = await harness.get(harness.pathFor(payload));
    expect(page.body).toContain('may not be designed to store secrets');

    const status = await harness.finishFlow(payload, canary.value);
    expect(status.state).toBe('STORED');
    expect(provider.values('config/runtime')).toEqual({ API_TOKEN: canary.value });
  });

  it('refuses to overwrite an existing field in create mode', async () => {
    provider.documents.set('config/runtime', { API_TOKEN: { stringValue: 'existing' } });

    const payload = await harness.callTool('secret_store', firestoreArgs());
    const status = await harness.finishFlow(payload, canary.value);

    expect(status.state).toBe('FAILED');
    expect((status.error as { code: string }).code).toBe('DESTINATION_CONFLICT');
    expect(provider.values('config/runtime')).toEqual({ API_TOKEN: 'existing' });
  });
});
