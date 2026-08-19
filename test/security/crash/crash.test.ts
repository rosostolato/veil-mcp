/** SPEC.md §18.9, §31 — crashes must not dump credential material. */

import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { AdapterRegistry } from '../../../src/adapters/registry.js';
import { RequestState } from '../../../src/model.js';
import { Canary, LeakScanner } from '../../support/canary.js';
import { RecordingAdapter } from '../../support/fakes.js';
import { Harness, testConfig } from '../../support/harness.js';
import { makeTempDir, removeTempDir } from '../../support/tmp.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(HERE, '../../..');
const CHILD = join(PROJECT_ROOT, 'test/support/crashChild.mjs');
const STAGES = [
  'secret_entry',
  'secret_received',
  'during_destination_call',
  'after_destination_success',
] as const;

describe('crash paths', () => {
  beforeAll(() => {
    // The child runs the built output, which is what ships.
    execFileSync('npm', ['run', '--silent', 'build'], { cwd: PROJECT_ROOT, stdio: 'pipe' });
  }, 120_000);

  for (const stage of STAGES) {
    it(`does not leak the secret when it dies at ${stage}`, () => {
      const canary = Canary.create(stage.replace(/_/g, ''));
      const workdir = makeTempDir();
      try {
        const result = spawnSync(process.execPath, [CHILD, stage, workdir], {
          input: `${canary.value}\n`,
          cwd: PROJECT_ROOT,
          timeout: 60_000,
        });

        expect(result.status === 0 && result.signal === null).toBe(false);

        const scanner = new LeakScanner();
        scanner.add('child_stdout', result.stdout ?? Buffer.alloc(0));
        scanner.add('child_stderr', result.stderr ?? Buffer.alloc(0));
        scanner.add('process_argv', [CHILD, stage, workdir].join(' '));
        scanner.addTree('crash_artifacts', workdir);
        scanner.assertClean(canary);

        if (stage !== 'during_destination_call') {
          // SIGKILL cannot run handlers; every other stage must have run ours.
          expect((result.stderr ?? Buffer.alloc(0)).toString('utf8')).toContain(
            'unhandled_exception',
          );
        }
      } finally {
        removeTempDir(workdir);
      }
    }, 90_000);
  }
});

describe('shutdown', () => {
  let harness: Harness;
  let adapter: RecordingAdapter;

  afterAll(async () => {
    await harness?.stop();
  });

  it('destroys live secrets at every stage', async () => {
    const config = testConfig();
    adapter = new RecordingAdapter(config, { exists: true });
    harness = await Harness.start(config, new AdapterRegistry([adapter]));
    const canary = Canary.create();

    const payload = await harness.callTool('secret_store', {
      destination: 'fake-store',
      name: 'SHUTDOWN_KEY',
      target: { project: 'acme-production', secret: 'SHUTDOWN_KEY' },
      write_mode: 'replace',
      environment: 'production',
    });
    await harness.submitSecret(payload, canary.value);
    const request = harness.broker.get(payload.request_id);
    expect(request.secret).not.toBeNull();

    harness.broker.shutdown();

    expect(request.secret).toBeNull();
    expect(request.state).toBe(RequestState.CANCELLED);
    expect(adapter.writes).toEqual([]);
    harness.collectLogs();
    harness.scanner.assertClean(canary);
  });

  it('leaves nothing replayable after a restart', async () => {
    const payload = await harness.callTool('secret_store', {
      destination: 'fake-store',
      name: 'RESTART_KEY',
      target: { project: 'acme-dev-project', secret: 'RESTART_KEY' },
      write_mode: 'create',
    });
    harness.broker.shutdown();

    const response = await harness.submitSecret(payload, 'value-after-restart');
    expect([403, 404, 410]).toContain(response.status);
  });
});
