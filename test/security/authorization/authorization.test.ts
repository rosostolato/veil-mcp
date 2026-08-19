/** AUTH-001 … AUTH-008: the human authorizes exactly what executes. */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { AdapterRegistry } from '../../../src/adapters/registry.js';
import { RequestState } from '../../../src/model.js';
import { Canary } from '../../support/canary.js';
import { RecordingAdapter } from '../../support/fakes.js';
import { Harness, storeArgs, testConfig } from '../../support/harness.js';

describe('authorization integrity', () => {
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

  it('AUTH-001: the displayed destination is the executed destination', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    const page = await harness.get(harness.pathFor(payload));

    const request = harness.broker.get(payload.request_id);
    expect(page.body).toContain(request.snapshot.target.accountLabel ?? '');
    expect(page.body).toContain(request.snapshot.target.resourceLabel);
    expect(page.body).toContain(request.snapshot.target.providerLabel);

    await harness.finishFlow(payload, canary.value);

    // Identity, not equality: the executor consumed the very object rendered.
    expect(adapter.targets[0]).toBe(request.snapshot.target);
  });

  it('AUTH-002: changing the destination invalidates the authorization', async () => {
    const first = await harness.callTool('secret_store', storeArgs());
    await harness.get(harness.pathFor(first));

    const revised = await harness.callTool('secret_revise', {
      request_id: first.request_id,
      ...storeArgs({ target: { project: 'acme-other', secret: 'STRIPE_SECRET_KEY' } }),
    });

    expect(revised.request_id).not.toBe(first.request_id);
    const oldStatus = await harness.status(first.request_id as string);
    expect(oldStatus.state).toBe(RequestState.CANCELLED);
    expect(oldStatus.superseded_by).toBe(revised.request_id);

    // The old authorization link is dead: no secret can be submitted against it.
    const response = await harness.submitSecret(first, canary.value);
    expect(response.status).toBe(410);
    expect(adapter.writes).toEqual([]);

    await harness.finishFlow(revised, canary.value);
    expect(adapter.targets[0]?.accountLabel).toBe('acme-other');
  });

  it('AUTH-002: tampering with a frozen snapshot aborts execution', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    const request = harness.broker.get(payload.request_id);

    // deepFreeze makes the in-place edit throw rather than silently succeed.
    expect(() => {
      (request.snapshot.target as { accountLabel: string }).accountLabel = 'attacker-project';
    }).toThrow(TypeError);

    // Simulate a compromised process replacing the whole snapshot anyway.
    request.snapshot = {
      ...request.snapshot,
      target: { ...request.snapshot.target, accountLabel: 'attacker-project' },
    };

    await harness.submitSecret(payload, canary.value);
    const status = await harness.status(payload.request_id as string);
    expect(status.state).toBe(RequestState.FAILED);
    expect((status.error as { code: string }).code).toBe('SNAPSHOT_MISMATCH');
    expect(adapter.writes).toEqual([]);
  });

  it('AUTH-003: changing the operation requires a new confirmation', async () => {
    adapter.exists = true;
    const approved = await harness.callTool('secret_store', storeArgs({ write_mode: 'create' }));
    expect(approved.operation).toBe('create');

    const revised = await harness.callTool('secret_revise', {
      request_id: approved.request_id,
      ...storeArgs({ write_mode: 'replace' }),
    });
    expect(revised.operation).toBe('replace');
    expect(revised.requires_confirmation).toBe(true);
    expect((await harness.status(approved.request_id as string)).state).toBe(
      RequestState.CANCELLED,
    );
  });

  it('AUTH-004: changing the credential name after authorization fails', async () => {
    const payload = await harness.callTool(
      'secret_store',
      storeArgs({ name: 'STRIPE_TEST_KEY', target: { project: 'acme-dev-project' } }),
    );
    const request = harness.broker.get(payload.request_id);
    request.snapshot = { ...request.snapshot, logicalName: 'STRIPE_PRODUCTION_KEY' };

    await harness.submitSecret(payload, canary.value);
    const status = await harness.status(payload.request_id as string);
    expect(status.state).toBe(RequestState.FAILED);
    expect((status.error as { code: string }).code).toBe('SNAPSHOT_MISMATCH');
  });

  it('AUTH-005: swapping the adapter after authorization fails', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    const request = harness.broker.get(payload.request_id);

    const impostor = new RecordingAdapter(harness.config);
    request.adapter = impostor;

    await harness.submitSecret(payload, canary.value);
    const status = await harness.status(payload.request_id as string);
    expect(status.state).toBe(RequestState.FAILED);
    expect((status.error as { code: string }).code).toBe('SNAPSHOT_MISMATCH');
    expect(impostor.writes).toEqual([]);
  });

  it('AUTH-006: a high-risk operation cannot skip stage B', async () => {
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

    await harness.submitSecret(payload, canary.value);
    expect(adapter.writes).toEqual([]);

    // A compromised caller tries to jump straight to execution by forging the
    // confirmation flag; the executor re-checks it against the snapshot.
    const request = harness.broker.get(payload.request_id);
    request.confirmation = 'implicit';
    await harness.broker.confirmExecution(request.requestId, 'wrong-token').catch(() => undefined);

    expect(adapter.writes).toEqual([]);
    expect((await harness.status(payload.request_id as string)).state).toBe(
      RequestState.AWAITING_EXECUTION_CONFIRMATION,
    );
  });

  it('AUTH-007: cancelling at stage A accepts no secret', async () => {
    const payload = await harness.callTool('secret_store', storeArgs());
    await harness.cancel(payload);

    const response = await harness.submitSecret(payload, canary.value);
    expect(response.status).toBe(410);
    expect(adapter.writes).toEqual([]);
    expect((await harness.status(payload.request_id as string)).state).toBe(RequestState.CANCELLED);
  });

  it('AUTH-008: cancelling at stage B discards the secret', async () => {
    adapter.exists = true;
    const payload = await harness.callTool(
      'secret_store',
      storeArgs({ write_mode: 'replace', environment: 'production' }),
    );
    await harness.submitSecret(payload, canary.value);
    const request = harness.broker.get(payload.request_id);
    expect(request.secret).not.toBeNull();

    await harness.cancel(payload);

    expect(request.secret).toBeNull();
    expect(adapter.writes).toEqual([]);
    expect((await harness.status(payload.request_id as string)).state).toBe(RequestState.CANCELLED);
    harness.collectLogs();
    harness.scanner.assertClean(canary);
  });

  it('SPEC.md §10: an agent cannot downgrade risk by claiming development', async () => {
    adapter.exists = true;
    const payload = await harness.callTool(
      'secret_store',
      storeArgs({
        target: { project: 'my-production-project', secret: 'STRIPE_SECRET_KEY' },
        write_mode: 'replace',
        environment: 'development',
      }),
    );
    expect((payload.destination as { environment: string }).environment).toBe('production');
    expect((payload.risk as { level: string }).level).toBe('high');
    expect(payload.requires_confirmation).toBe(true);
    expect(
      (payload.risk as { reasons: string[] }).reasons.some((reason) =>
        reason.includes('contradicts'),
      ),
    ).toBe(true);
  });
});
