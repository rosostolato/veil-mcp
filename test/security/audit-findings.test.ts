/**
 * Regression tests for issues found in the post-port audit.
 *
 * Each one reproduces a defect that the ported suite did not cover.
 */

import { mkdirSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { EnvFileAdapter } from '../../src/adapters/envFile.js';
import { AdapterRegistry } from '../../src/adapters/registry.js';
import { SecretBroker, parseStoreParams } from '../../src/broker.js';
import { ErrorCode } from '../../src/errors.js';
import { AuditLogger } from '../../src/logging.js';
import { Environment, RequestState, isTerminal } from '../../src/model.js';
import { safeDisplay } from '../../src/redaction.js';
import { Canary } from '../support/canary.js';
import { DeferredAdapter, DiscardStream } from '../support/fakes.js';
import { Harness, testConfig } from '../support/harness.js';
import { makeTempDir, removeTempDir } from '../support/tmp.js';

describe('a symlinked directory cannot escape the allowed roots', () => {
  it('rejects a path whose parent is a symlink pointing outside', async () => {
    const root = makeTempDir();
    const outside = makeTempDir('veil-outside-');
    try {
      symlinkSync(outside, join(root, 'escape'));
      const adapter = new EnvFileAdapter(testConfig({ envAllowedRoots: [root] }));

      await expect(
        adapter.normalizeTarget(
          { path: 'escape/.env' },
          { name: 'TOKEN', environmentHint: Environment.DEVELOPMENT },
        ),
      ).rejects.toMatchObject({ public: { code: ErrorCode.DESTINATION_NOT_PERMITTED } });
    } finally {
      removeTempDir(root);
      removeTempDir(outside);
    }
  });

  it('rejects a deeper symlinked ancestor', async () => {
    const root = makeTempDir();
    const outside = makeTempDir('veil-outside-');
    try {
      mkdirSync(join(root, 'nested'));
      symlinkSync(outside, join(root, 'nested', 'escape'));
      const adapter = new EnvFileAdapter(testConfig({ envAllowedRoots: [root] }));

      await expect(
        adapter.normalizeTarget(
          { path: 'nested/escape/config/.env' },
          { name: 'TOKEN', environmentHint: Environment.DEVELOPMENT },
        ),
      ).rejects.toMatchObject({ public: { code: ErrorCode.DESTINATION_NOT_PERMITTED } });
    } finally {
      removeTempDir(root);
      removeTempDir(outside);
    }
  });

  it('shows the user the resolved path, so display matches execution', async () => {
    const root = makeTempDir();
    try {
      mkdirSync(join(root, 'real'));
      symlinkSync(join(root, 'real'), join(root, 'alias'));
      const adapter = new EnvFileAdapter(testConfig({ envAllowedRoots: [root] }));

      const target = await adapter.normalizeTarget(
        { path: 'alias/.env' },
        { name: 'TOKEN', environmentHint: Environment.DEVELOPMENT },
      );
      // The link stays inside the root, so it is allowed — but the path shown
      // is the one that will actually be written.
      expect(target.fields.path).toBe(join(realpathSync(join(root, 'real')), '.env'));
      expect(target.accountLabel).not.toContain('alias');
    } finally {
      removeTempDir(root);
    }
  });

  it('still writes normally inside an allowed root reached through a symlink', async () => {
    // macOS /tmp is itself a symlink to /private/tmp: a root that is not
    // canonicalised would reject every legitimate write under it.
    const real = makeTempDir();
    const linkedRoot = join(makeTempDir('veil-link-'), 'root');
    try {
      symlinkSync(real, linkedRoot);
      const config = testConfig({ envAllowedRoots: [linkedRoot] });
      const harness = await Harness.start(
        config,
        new AdapterRegistry([new EnvFileAdapter(config)]),
      );
      const canary = Canary.create();
      try {
        const payload = await harness.callTool('secret_store', {
          destination: 'env-file',
          name: 'API_TOKEN',
          target: { path: '.env' },
          write_mode: 'create',
          environment: 'development',
        });
        const status = await harness.finishFlow(payload, canary.value);
        expect(status.state).toBe('STORED');
        expect(readFileSync(join(real, '.env'), 'utf8')).toContain(canary.value);
      } finally {
        await harness.stop();
      }
    } finally {
      removeTempDir(real);
    }
  });

  it('refuses a parent directory swapped for a symlink after authorization', async () => {
    const root = makeTempDir();
    const outside = makeTempDir('veil-outside-');
    try {
      mkdirSync(join(root, 'conf'));
      const config = testConfig({ envAllowedRoots: [root] });
      const adapter = new EnvFileAdapter(config);
      const target = await adapter.normalizeTarget(
        { path: 'conf/.env' },
        { name: 'TOKEN', environmentHint: Environment.DEVELOPMENT },
      );

      // Between authorization and the write, the directory becomes a link out.
      removeTempDir(join(root, 'conf'));
      symlinkSync(outside, join(root, 'conf'));

      const { SecretBuffer } = await import('../../src/secretBuffer.js');
      const buffer = new SecretBuffer(Buffer.from('value', 'utf8'));
      await expect(adapter.store(buffer, target, 'create')).rejects.toMatchObject({
        public: { code: ErrorCode.DESTINATION_NOT_PERMITTED },
      });
      buffer.zeroize();
    } finally {
      removeTempDir(root);
      removeTempDir(outside);
    }
  });
});

describe('a terminal request stays terminal', () => {
  it('does not resurrect a cancelled request when a late write completes', async () => {
    const config = testConfig({ adapterTimeoutSeconds: 30 });
    const adapter = new DeferredAdapter(config);
    const registry = new AdapterRegistry([adapter]);
    const records: Record<string, unknown>[] = [];
    const broker = new SecretBroker(config, registry, {
      logger: new AuditLogger({ stream: new DiscardStream(), sink: (r) => records.push(r) }),
    });

    const request = await broker.createRequest(
      parseStoreParams(
        { destination: 'deferred-store', name: 'K', target: { project: 'p', secret: 'K' } },
        registry,
      ),
    );
    const submitted = broker.submitSecret(
      request.requestId,
      request.submitToken,
      Buffer.from('value', 'utf8'),
    );
    await Promise.resolve();
    expect(broker.get(request.requestId).state).toBe(RequestState.EXECUTING);

    broker.shutdown();
    const afterShutdown = broker.get(request.requestId).state;
    expect(isTerminal(afterShutdown)).toBe(true);

    // The provider answers only now, after the request has already ended.
    adapter.finish();
    await submitted;

    // The request must not move back out of its terminal state, and the audit
    // trail must not claim two different outcomes for one request.
    expect(broker.get(request.requestId).state).toBe(afterShutdown);
    const finished = records.filter((record) => record.event === 'request_finished');
    expect(finished).toHaveLength(1);
  });

  it('only performs transitions the specified state machine allows', async () => {
    const config = testConfig({ adapterTimeoutSeconds: 30 });
    const adapter = new DeferredAdapter(config);
    const registry = new AdapterRegistry([adapter]);
    const broker = new SecretBroker(config, registry, {
      logger: new AuditLogger({ stream: new DiscardStream() }),
    });

    const request = await broker.createRequest(
      parseStoreParams(
        { destination: 'deferred-store', name: 'K', target: { project: 'p', secret: 'K' } },
        registry,
      ),
    );
    const submitted = broker.submitSecret(
      request.requestId,
      request.submitToken,
      Buffer.from('value', 'utf8'),
    );
    await Promise.resolve();

    broker.shutdown();
    // EXECUTING may only become STORED or FAILED (SPEC.md §14).
    expect(broker.get(request.requestId).state).toBe(RequestState.FAILED);
    adapter.finish();
    await submitted;
  });
});

describe('display sanitization', () => {
  it('never truncates in the middle of a surrogate pair', () => {
    const rendered = safeDisplay('\u{1f510}'.repeat(200));
    expect(rendered.length).toBeLessThanOrEqual(256);
    // No lone surrogate anywhere in the output.
    expect(/[\uD800-\uDFFF]/.test(rendered.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g, ''))).toBe(
      false,
    );
    expect(Buffer.from(rendered, 'utf8').toString('utf8')).toBe(rendered);
  });

  it('keeps truncating long plain text', () => {
    expect(safeDisplay('a'.repeat(5000)).length).toBe(256);
  });
});

describe('the browser opener', () => {
  it('refuses to hand anything but a Veil authorization URL to a command line', async () => {
    const config = testConfig({ openBrowser: true });
    const harness = await Harness.start(config, new AdapterRegistry([new EnvFileAdapter(config)]));
    try {
      // Nothing reaches an argv on the strength of where it came from.
      harness.ui.present('req_test', 'http://evil.example/r/a/b');
      harness.ui.present('req_test', 'http://127.0.0.1:8080/r/a/b; rm -rf /');
      harness.ui.present('req_test', 'file:///etc/passwd');

      const refusals = harness.logRecords.filter(
        (record) => record.event === 'browser_open_refused',
      );
      expect(refusals).toHaveLength(3);
      expect(harness.logRecords.some((record) => record.event === 'browser_open_failed')).toBe(
        false,
      );
    } finally {
      await harness.stop();
    }
  });
});

describe('configured roots', () => {
  it('canonicalises roots so a symlinked root still works', () => {
    const real = makeTempDir();
    const linkDirectory = makeTempDir('veil-link-');
    try {
      const link = join(linkDirectory, 'root');
      symlinkSync(real, link);
      const config = testConfig({ envAllowedRoots: [link] });
      expect(config.envAllowedRoots).toEqual([realpathSync(real)]);
    } finally {
      removeTempDir(real);
      removeTempDir(linkDirectory);
    }
  });
});

describe('oversized request bodies', () => {
  it('answers 413 even when the client hides the size with chunked encoding', async () => {
    const config = testConfig();
    const harness = await Harness.start(config, new AdapterRegistry([new EnvFileAdapter(config)]));
    try {
      const root = makeTempDir();
      writeFileSync(join(root, '.env'), '');
      const payload = await harness.callTool('secret_store', {
        destination: 'env-file',
        name: 'API_TOKEN',
        target: { path: '.env' },
        write_mode: 'create',
        environment: 'development',
      });

      const response = await fetch(
        `${harness.ui.baseUrl ?? ''}${harness.pathFor(payload)}/submit`,
        {
          method: 'POST',
          redirect: 'manual',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          // A stream has no content-length, so the declared-size check cannot fire.
          body: new ReadableStream({
            start(controller) {
              controller.enqueue(new TextEncoder().encode(`secret=${'x'.repeat(200_000)}`));
              controller.close();
            },
          }),
          duplex: 'half',
        },
      );

      expect(response.status).toBe(413);
      expect((await harness.status(payload.request_id as string)).state).toBe(
        'AWAITING_SECRET_AUTHORIZATION',
      );
      removeTempDir(root);
    } finally {
      await harness.stop();
    }
  });
});
