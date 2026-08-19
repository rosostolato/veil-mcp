/**
 * The Google adapters speak REST directly, so these tests pin the wire contract
 * the way the Python port pinned the SDK's method signatures: the credential
 * must appear only in a request body, every call must carry a timeout, and the
 * URLs must be the documented ones.
 */

import { describe, expect, it } from 'vitest';

import { FirestoreAdapter } from '../../../src/adapters/firestore.js';
import { GcpSecretManagerAdapter } from '../../../src/adapters/gcpSecretManager.js';
import type { GoogleRequest, GoogleResponse } from '../../../src/adapters/googleTransport.js';
import { AdapterRegistry } from '../../../src/adapters/registry.js';
import { Canary } from '../../support/canary.js';
import { FakeFirestore, FakeSecretManager } from '../../support/fakes.js';
import { Harness, testConfig } from '../../support/harness.js';

describe('Google REST contract', () => {
  it('puts the credential in the body, never in the URL, and always times out', async () => {
    const provider = new FakeSecretManager();
    const recorded: GoogleRequest[] = [];
    const config = testConfig({ adapterTimeoutSeconds: 7 });
    const inner = provider.transport();
    const transport = (request: GoogleRequest): Promise<GoogleResponse> => {
      recorded.push(request);
      return inner(request);
    };
    const harness = await Harness.start(
      config,
      new AdapterRegistry([new GcpSecretManagerAdapter(config, transport)]),
    );
    const canary = Canary.create();

    try {
      const payload = await harness.callTool('secret_store', {
        destination: 'gcp-secret-manager',
        name: 'API_TOKEN',
        target: { project: 'acme-dev-project', secret: 'API_TOKEN' },
        write_mode: 'create',
      });
      const status = await harness.finishFlow(payload, canary.value);
      expect(status.state).toBe('STORED');

      expect(recorded.every((request) => request.timeoutMs === 7000)).toBe(true);
      expect(canary.hitsIn(recorded.map((request) => request.url).join(' '))).toEqual([]);

      const addVersion = recorded.find((request) => request.url.endsWith(':addVersion'));
      expect(addVersion?.method).toBe('POST');
      expect(addVersion?.url).toBe(
        'https://secretmanager.googleapis.com/v1/projects/acme-dev-project/secrets/API_TOKEN:addVersion',
      );
      // The payload is base64 of the credential — the one approved carrier.
      const body = addVersion?.body as { payload: { data: string } };
      expect(Buffer.from(body.payload.data, 'base64').toString('utf8')).toBe(canary.value);

      const create = recorded.find((request) => request.url.includes('secretId='));
      expect(create?.url).toBe(
        'https://secretmanager.googleapis.com/v1/projects/acme-dev-project/secrets?secretId=API_TOKEN',
      );
    } finally {
      await harness.stop();
    }
  });

  it('writes a Firestore field with an updateMask and no credential in the URL', async () => {
    const provider = new FakeFirestore();
    const recorded: GoogleRequest[] = [];
    const config = testConfig();
    const inner = provider.transport();
    const transport = (request: GoogleRequest): Promise<GoogleResponse> => {
      recorded.push(request);
      return inner(request);
    };
    const harness = await Harness.start(
      config,
      new AdapterRegistry([new FirestoreAdapter(config, transport)]),
    );
    const canary = Canary.create();

    try {
      const payload = await harness.callTool('secret_store', {
        destination: 'firestore',
        name: 'API_TOKEN',
        target: { project: 'acme-dev-project', collection: 'config', document: 'runtime' },
        write_mode: 'create',
      });
      await harness.finishFlow(payload, canary.value);

      const patch = recorded.find((request) => request.method === 'PATCH');
      expect(patch?.url).toBe(
        'https://firestore.googleapis.com/v1/projects/acme-dev-project/databases/(default)' +
          '/documents/config/runtime?updateMask.fieldPaths=API_TOKEN',
      );
      expect(canary.hitsIn(recorded.map((request) => request.url).join(' '))).toEqual([]);
      expect(JSON.stringify(patch?.body)).toContain(canary.value);
    } finally {
      await harness.stop();
    }
  });
});
