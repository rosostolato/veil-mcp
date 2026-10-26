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

  it('trades the link for an HttpOnly session cookie and a token-free address', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    const opened = await harness.get(harness.pathFor(payload), { browser: false });

    expect(opened.status).toBe(303);
    expect(opened.headers.get('location')).toBe(`/r/${payload.request_id as string}`);
    const cookie = opened.headers.get('set-cookie') ?? '';
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('SameSite=Lax');
    expect(cookie).toContain(`Path=/r/${payload.request_id as string}`);
  });

  it('burns the link on first use and raises an alarm on the second', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    const path = harness.pathFor(payload);
    await harness.get(path, { browser: false });

    const second = await harness.get(path, { browser: false });
    expect(second.status).toBe(409);
    expect(second.body).toContain('already opened');
    expect(second.body).not.toContain('STRIPE_SECRET_KEY');
    expect(second.body).not.toContain(harness.ui.identity);

    // The page without the first opener's cookie is refused, too.
    const page = await harness.get(`/r/${payload.request_id as string}`, { browser: false });
    expect(page.status).toBe(403);

    // The alarm's Cancel works with the link alone.
    await harness.post(`${path}/cancel`, {}, { browser: false });
    expect((await harness.status(payload.request_id as string)).state).toBe('CANCELLED');
  });

  it('shows the identity phrase only on pages reached through the request', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    const words = harness.ui.identity;

    for (const path of ['/', '/r', `/r/${payload.request_id as string}`]) {
      expect((await harness.get(path, { browser: false })).body).not.toContain(words);
    }
    expect((await harness.get(harness.pathFor(payload))).body).toContain(words);
  });

  it('refuses a cross-site POST even with the session cookie', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    const opened = await harness.get(harness.pathFor(payload), { browser: false });
    const cookie = (opened.headers.get('set-cookie') ?? '').split(';')[0] ?? '';
    expect(cookie).toMatch(/^veil_session=/);
    const cancel = (headers: Record<string, string>): Promise<Response> =>
      fetch(`${harness.ui.baseUrl ?? ''}/r/${payload.request_id as string}/cancel`, {
        method: 'POST',
        redirect: 'manual',
        headers: { cookie, ...headers },
      });

    for (const headers of [
      { origin: 'https://evil.example' },
      { 'sec-fetch-site': 'cross-site' },
      { 'sec-fetch-site': 'same-site', origin: 'http://localhost:1' },
      { origin: 'null' },
    ]) {
      expect((await cancel(headers)).status).toBe(403);
    }
    expect((await harness.status(payload.request_id as string)).state).toBe(
      'AWAITING_SECRET_AUTHORIZATION',
    );

    // The same cookie from Veil's own page goes through: the refusals above
    // were the origin check, not a missing session. This is the exact shape a
    // browser sends under `Referrer-Policy: no-referrer`: `Origin: null`.
    expect((await cancel({ origin: 'null', 'sec-fetch-site': 'same-origin' })).status).toBe(303);
    expect((await harness.status(payload.request_id as string)).state).toBe('CANCELLED');
  });

  it('isolates the window and keeps password managers away from the field', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    const response = await harness.get(harness.pathFor(payload));

    expect(response.headers.get('cross-origin-opener-policy')).toBe('same-origin');
    expect(response.headers.get('cross-origin-resource-policy')).toBe('same-origin');
    expect(response.body).toContain('autocomplete="one-time-code"');
    expect(response.body).toContain('data-1p-ignore');
    expect(response.body).toContain('data-lpignore="true"');
  });

  it('answers 400 to a malformed address', async () => {
    expect((await harness.get('/r/%E0%A4%A/x', { browser: false })).status).toBe(400);
  });

  it('keeps the identity phrase and the link fingerprint-only in the audit log', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    const link = harness.pathFor(payload);
    const token = link.slice(link.lastIndexOf('/') + 1);

    expect(harness.logText).not.toContain(harness.ui.identity);
    const requested = harness.logRecords.find(
      (record) => record.event === 'authorization_requested',
    );
    expect(JSON.stringify(requested)).not.toContain(token);
    expect(JSON.stringify(requested)).toContain('link_fingerprint');
    // With no browser to open, the operator still needs a way in.
    expect(
      harness.logRecords.some((record) => record.event === 'authorization_link_for_operator'),
    ).toBe(true);
  });

  it('refuses to bind anywhere but loopback', async () => {
    const config = testConfig({ uiHost: '0.0.0.0' });
    await expect(
      Harness.start(config, new AdapterRegistry([new RecordingAdapter(config)])),
    ).rejects.toThrow('loopback');
  });

  it('runs only its own script, under the response nonce', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    const response = await harness.get(harness.pathFor(payload));
    const csp = response.headers.get('content-security-policy') ?? '';
    const nonce = /script-src 'nonce-([^']+)'/.exec(csp)?.[1];

    expect(nonce).toBeTruthy();
    expect(csp).not.toContain('unsafe-inline');
    const scripts = response.body.match(/<script[^>]*>/g) ?? [];
    expect(scripts).toEqual([`<script nonce="${nonce}">`]);
  });

  it('keeps Cancel out of the form that carries the credential', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    const body = (await harness.get(harness.pathFor(payload))).body;
    const entry = /<form id="entry"[\s\S]*?<\/form>/.exec(body)?.[0] ?? '';

    expect(entry).toContain('name="secret"');
    expect(entry).not.toContain('/cancel');
  });

  it('writes nothing until the destination name is typed at stage B', async () => {
    adapter.exists = true;
    const payload = await harness.callTool(
      'secret_store',
      storeArgs({
        target: { project: 'acme-production' },
        write_mode: 'replace',
        environment: 'production',
      }),
    );
    await harness.submitSecret(payload, canary.value);
    const path = harness.pathFor(payload);
    const page = await harness.get(path);
    expect(page.body).toContain('data-expect="acme-production"');
    const token = /name="confirm_token" value="([^"]+)"/.exec(page.body)?.[1] ?? '';

    const wrong = await harness.post(`${path}/confirm`, {
      confirm_token: token,
      confirm_name: 'acme-staging',
    });
    expect(wrong.status).toBe(303);
    expect(wrong.headers.get('location')).toContain('?mismatch=1');
    expect((await harness.status(payload.request_id as string)).state).toBe(
      'AWAITING_EXECUTION_CONFIRMATION',
    );
    expect(adapter.writes).toHaveLength(0);
    const retry = await harness.get(wrong.headers.get('location') ?? '');
    expect(retry.body).toContain('did not match');

    await harness.post(`${path}/confirm`, {
      confirm_token: token,
      confirm_name: 'acme-production',
    });
    expect((await harness.status(payload.request_id as string)).state).toBe('STORED');
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
