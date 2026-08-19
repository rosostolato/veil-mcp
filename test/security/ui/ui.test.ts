/** SPEC.md §34 — the trusted window's own security properties. */

import { request as httpRequest } from 'node:http';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { AdapterRegistry } from '../../../src/adapters/registry.js';
import { isLoopbackHost } from '../../../src/ui/server.js';
import { Canary } from '../../support/canary.js';
import { RecordingAdapter } from '../../support/fakes.js';
import { Harness, storeArgs, testConfig } from '../../support/harness.js';

describe('secure UI', () => {
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

  it('shows destination, environment and operation before entry', async () => {
    const payload = await harness.callTool(
      'secret_store',
      storeArgs({ target: { project: 'acme-production' } }),
    );
    const body = (await harness.get(harness.pathFor(payload))).body;

    expect(body).toContain('Destination type');
    expect(body).toContain('Project / account');
    expect(body).toContain('acme-production');
    expect(body).toContain('Environment');
    expect(body).toContain('production');
    expect(body).toContain('Operation');
  });

  it('makes high risk visually distinguishable', async () => {
    adapter.exists = true;
    const payload = await harness.callTool(
      'secret_store',
      storeArgs({
        target: { project: 'acme-production' },
        write_mode: 'replace',
        environment: 'production',
      }),
    );
    const body = (await harness.get(harness.pathFor(payload))).body;
    expect(body).toContain('class="risk risk-high"');
    expect(body).toContain('high risk');
  });

  it('masks the credential field and disables autocomplete', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    const body = (await harness.get(harness.pathFor(payload))).body;

    expect(body).toContain('type="password"');
    expect(body).toContain('autocomplete="off"');
    expect(body).toContain('spellcheck="false"');
    expect(body).not.toContain('type="text"');
  });

  it('is not cached, framed or referred', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    const response = await harness.get(harness.pathFor(payload));

    expect(response.headers.get('cache-control')).toContain('no-store');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    expect(response.headers.get('x-frame-options')).toBe('DENY');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    const csp = response.headers.get('content-security-policy') ?? '';
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("form-action 'self'");
  });

  it('keeps the credential out of the URL and redirects after POST', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    const response = await harness.submitSecret(payload, canary.value);

    expect(response.status).toBe(303);
    const location = response.headers.get('location') ?? '';
    expect(location).not.toContain(canary.value);
    expect(harness.pathFor(payload)).not.toContain(canary.value);

    const followUp = await harness.get(location);
    expect(followUp.body).not.toContain(canary.value);
    harness.collectLogs();
    harness.scanner.assertClean(canary);
  });

  it('never redisplays the credential at stage B', async () => {
    adapter.exists = true;
    const payload = await harness.callTool(
      'secret_store',
      storeArgs({ write_mode: 'replace', environment: 'production' }),
    );
    await harness.submitSecret(payload, canary.value);
    const body = (await harness.get(harness.pathFor(payload))).body;

    expect(body).not.toContain(canary.value);
    expect(body).toContain('been written yet');
    expect(body).not.toContain('type="password"');
  });

  it('rejects non-loopback Host headers', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    // undici refuses to send a forged Host header, so this goes over node:http.
    const { status, body } = await rawRequest(
      harness.ui.baseUrl ?? '',
      harness.pathFor(payload),
      'veil.attacker.example',
    );

    expect(status).toBe(400);
    expect(body).not.toContain('acme');
  });

  it('parses Host headers without a permissive shortcut', () => {
    expect(isLoopbackHost('127.0.0.1')).toBe(true);
    expect(isLoopbackHost('127.0.0.1:8080')).toBe(true);
    expect(isLoopbackHost('localhost:3000')).toBe(true);
    expect(isLoopbackHost('[::1]:9000')).toBe(true);
    expect(isLoopbackHost('veil.attacker.example')).toBe(false);
    expect(isLoopbackHost('127.0.0.1.attacker.example')).toBe(false);
    expect(isLoopbackHost('127.0.0.1:notaport')).toBe(false);
    expect(isLoopbackHost('')).toBe(false);
  });

  it('does not enumerate requests from unknown paths', async () => {
    await harness.callTool('secret_store', storeArgs());
    for (const path of ['/', '/r', '/requests', '/r/req_unknown/token']) {
      const response = await harness.get(path);
      expect([403, 404]).toContain(response.status);
      expect(response.body).not.toContain('STRIPE_SECRET_KEY');
    }
  });

  it('reports expiry on the request page', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    harness.broker.get(payload.request_id).expiresAt = performance.now() / 1000 - 1;

    const response = await harness.get(harness.pathFor(payload));
    expect(response.status).toBe(200);
    expect(response.body.toLowerCase()).toContain('expired');
    expect(response.body).not.toContain('type="password"');
  });

  it('refuses an oversized body', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    const response = await harness.post(`${harness.pathFor(payload)}/submit`, {
      secret: 'x'.repeat(200_000),
    });
    expect(response.status).toBe(413);
    expect((await harness.status(payload.request_id as string)).state).toBe(
      'AWAITING_SECRET_AUTHORIZATION',
    );
  });
});

/** A request with a forged Host header, which fetch will not send. */
function rawRequest(
  baseUrl: string,
  path: string,
  host: string,
): Promise<{ status: number; body: string }> {
  const url = new URL(baseUrl);
  return new Promise((resolve, reject) => {
    const client = httpRequest(
      { hostname: url.hostname, port: url.port, path, method: 'GET', headers: { host } },
      (response) => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', (chunk: string) => (body += chunk));
        response.on('end', () => resolve({ status: response.statusCode ?? 0, body }));
      },
    );
    client.on('error', reject);
    client.end();
  });
}
