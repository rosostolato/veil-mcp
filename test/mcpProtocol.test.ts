/** MCP transport and contract behaviour (SPEC.md §13, §24 SEC-002/003/004). */

import { spawnSync } from 'node:child_process';
import { execFileSync } from 'node:child_process';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { AdapterRegistry } from '../src/adapters/registry.js';
import { Canary } from './support/canary.js';
import { RecordingAdapter } from './support/fakes.js';
import { Harness, storeArgs, testConfig } from './support/harness.js';
import { makeTempDir, removeTempDir } from './support/tmp.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(HERE, '..');

describe('MCP protocol', () => {
  let harness: Harness;
  let adapter: RecordingAdapter;

  beforeEach(async () => {
    const config = testConfig();
    adapter = new RecordingAdapter(config);
    harness = await Harness.start(config, new AdapterRegistry([adapter]));
  });

  afterEach(async () => {
    await harness.stop();
  });

  it('rejects unknown methods and malformed frames cleanly', async () => {
    expect((await harness.rpc('does/not/exist')).error?.code).toBe(-32601);
    expect((await harness.server.handleMessage('not an object'))?.error?.code).toBe(-32600);
    expect((await harness.server.handleMessage({ jsonrpc: '2.0', id: 1 }))?.error?.code).toBe(
      -32600,
    );
    expect(await harness.server.handleMessage({ method: 'notifications/initialized' })).toBeNull();
  });

  it('round-trips over a real stdio stream', async () => {
    const lines = [
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
      JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
      '',
      '{ not json',
      JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }),
      JSON.stringify({
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: { name: 'secret_store', arguments: storeArgs() },
      }),
    ];
    const input = new PassThrough();
    const written: string[] = [];
    const output = {
      write(chunk: string): boolean {
        written.push(chunk);
        return true;
      },
    };

    input.end(`${lines.join('\n')}\n`);
    await harness.server.serve(input, output);

    const responses = written
      .join('')
      .split('\n')
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as { id: unknown; result?: { isError: boolean } });
    expect(responses.map((response) => response.id)).toEqual([1, null, 2, 3]);
    expect(responses[3]?.result?.isError).toBe(false);
  });

  it('blocks an outbound frame carrying a live secret', async () => {
    const canary = Canary.create();
    adapter.exists = true;
    const payload = await harness.callTool(
      'secret_store',
      storeArgs({ write_mode: 'replace', environment: 'production' }),
    );
    await harness.submitSecret(payload, canary.value);

    const written: string[] = [];
    harness.server.writeForTesting(
      {
        write(chunk: string): boolean {
          written.push(chunk);
          return true;
        },
      },
      { jsonrpc: '2.0', id: 9, result: { leak: canary.value } },
    );

    const text = written.join('');
    expect(canary.hitsIn(text)).toEqual([]);
    expect(text).toContain('suppressed');
  });

  it('keeps the text and structured content consistent', async () => {
    const response = await harness.rpc('tools/call', {
      name: 'secret_store',
      arguments: storeArgs(),
    });
    const result = response.result as {
      content: { text: string }[];
      structuredContent: Record<string, unknown>;
    };
    expect(JSON.parse(result.content[0]?.text ?? '{}')).toEqual(result.structuredContent);
  });

  it('describes closed target schemas', async () => {
    const payload = await harness.callTool('secret_destinations', {});
    for (const destination of payload.destinations as {
      target_schema: { additionalProperties: unknown };
    }[]) {
      expect(destination.target_schema.additionalProperties).toBe(false);
    }
    expect(String(payload.note)).toMatch(/^No destination accepts a credential value/);
  });

  it('annotates every tool as the connector review criteria require', async () => {
    const response = await harness.rpc('tools/list');
    const tools = (response.result?.tools ?? []) as {
      name: string;
      title: string;
      description: string;
      annotations: Record<string, unknown>;
    }[];

    for (const tool of tools) {
      expect(tool.name.length).toBeLessThanOrEqual(64);
      expect(tool.name).toMatch(/^[a-zA-Z0-9_-]+$/);
      expect(tool.title.length).toBeGreaterThan(0);
      expect(typeof tool.annotations.readOnlyHint).toBe('boolean');
      expect(typeof tool.annotations.destructiveHint).toBe('boolean');
      // Descriptions describe; they never instruct the model how to behave.
      expect(tool.description).not.toMatch(/\byou must\b|\balways call\b|\bignore\b/i);
    }

    const readOnly = tools.filter((tool) => tool.annotations.readOnlyHint === true);
    expect(readOnly.map((tool) => tool.name).sort()).toEqual([
      'secret_destinations',
      'secret_status',
    ]);
  });
});

describe('the packaged server', () => {
  beforeAll(() => {
    execFileSync('npm', ['run', '--silent', 'build'], { cwd: PROJECT_ROOT, stdio: 'pipe' });
  }, 120_000);

  it('SEC-004: reserves stdout for the protocol alone', () => {
    const workdir = makeTempDir();
    try {
      const request = `${JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: '2025-06-18' },
      })}\n`;

      const result = spawnSync(
        process.execPath,
        [
          '-e',
          `import('${join(PROJECT_ROOT, 'dist/index.js').replace(/\\/g, '/')}')` +
            '.then((module) => {' +
            '  void module.main([]);' +
            // A stray log from anywhere in the process, once the server is live.
            "  setTimeout(() => { console.log('this should never reach stdout'); " +
            "    process.stdout.write('nor this\\n'); }, 150);" +
            '});',
        ],
        {
          input: request,
          cwd: workdir,
          timeout: 60_000,
          env: {
            ...process.env,
            VEIL_UI_PORT: '0',
            VEIL_OPEN_BROWSER: 'false',
            VEIL_ENV_ALLOWED_ROOTS: workdir,
            VEIL_ENABLED_ADAPTERS: 'env-file',
          },
        },
      );

      const stdoutLines = (result.stdout ?? Buffer.alloc(0))
        .toString('utf8')
        .split('\n')
        .filter((line) => line.trim().length > 0);

      expect(stdoutLines.every((line) => line.startsWith('{'))).toBe(true);
      const first = JSON.parse(stdoutLines[0] ?? '{}') as {
        result?: { serverInfo?: { name?: string } };
      };
      expect(first.result?.serverInfo?.name).toBe('veil');
      expect((result.stderr ?? Buffer.alloc(0)).toString('utf8')).toContain(
        'this should never reach stdout',
      );
    } finally {
      removeTempDir(workdir);
    }
  }, 90_000);
});
