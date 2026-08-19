/** `.env` adapter security (SPEC.md §33). */

import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { EnvFileAdapter } from '../src/adapters/envFile.js';
import { AdapterRegistry } from '../src/adapters/registry.js';
import { ErrorCode } from '../src/errors.js';
import { Environment, WriteMode } from '../src/model.js';
import { SecretBuffer } from '../src/secretBuffer.js';
import { Canary } from './support/canary.js';
import { Harness, testConfig } from './support/harness.js';
import { git, makeTempDir, removeTempDir } from './support/tmp.js';

function args(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    destination: 'env-file',
    name: 'API_TOKEN',
    target: { path: '.env' },
    write_mode: 'create',
    environment: 'development',
    ...overrides,
  };
}

describe('env-file adapter', () => {
  let root: string;
  let harness: Harness;
  let canary: Canary;

  beforeEach(async () => {
    root = makeTempDir();
    const config = testConfig({ envAllowedRoots: [root] });
    harness = await Harness.start(config, new AdapterRegistry([new EnvFileAdapter(config)]));
    canary = Canary.create();
  });

  afterEach(async () => {
    await harness.stop();
    removeTempDir(root);
  });

  it('writes atomically with restrictive permissions and preserves other variables', async () => {
    const envPath = join(root, '.env');
    writeFileSync(envPath, 'EXISTING=keep-me\n# a comment\nOTHER=1\n');

    const payload = await harness.callTool('secret_store', args());
    const status = await harness.finishFlow(payload, canary.value);
    expect(status.state).toBe('STORED');

    const content = readFileSync(envPath, 'utf8');
    expect(content).toContain('EXISTING=keep-me');
    expect(content).toContain('# a comment');
    expect(content).toContain(`API_TOKEN="${canary.value}"`);
    expect(statSync(envPath).mode & 0o777).toBe(0o600);
    expect(readdirSync(root)).toEqual(['.env']);
  });

  it('quotes the value so it cannot inject further variables', async () => {
    const payload = await harness.callTool('secret_store', args());
    const hostile = 'v"\nEXTRA=injected\n$(whoami)`id`';
    await harness.finishFlow(payload, hostile);

    const content = readFileSync(join(root, '.env'), 'utf8');
    expect(content).not.toContain('\nEXTRA=injected');
    expect(content.split('\n').filter((line) => line.length > 0)).toHaveLength(1);
    expect(content).toContain('\\$');
    expect(content).toContain('\\`');
  });

  it('blocks a git-tracked env file', async () => {
    git(root, 'init', '-q');
    git(root, 'config', 'user.email', 't@example.com');
    git(root, 'config', 'user.name', 'Test');
    writeFileSync(join(root, '.env'), 'PLACEHOLDER=1\n');
    git(root, 'add', '.env');
    git(root, 'commit', '-q', '-m', 'add env');

    const payload = await harness.callTool('secret_store', args());
    expect(payload.status).toBe('failed');
    expect(payload.code).toBe(ErrorCode.DESTINATION_NOT_PERMITTED);
  });

  it('allows a gitignored env file', async () => {
    git(root, 'init', '-q');
    writeFileSync(join(root, '.gitignore'), '.env\n');

    const payload = await harness.callTool('secret_store', args());
    const status = await harness.finishFlow(payload, canary.value);
    expect(status.state).toBe('STORED');
  });

  it('refuses a symlinked destination', async () => {
    const outside = join(root, 'outside');
    mkdirSync(outside);
    const target = join(outside, 'outside.env');
    writeFileSync(target, 'SHOULD_NOT_BE_TOUCHED=1\n');
    symlinkSync(target, join(root, '.env'));

    const payload = await harness.callTool('secret_store', args());
    expect(payload.status).toBe('failed');
    expect(payload.code).toBe(ErrorCode.DESTINATION_NOT_PERMITTED);
    expect(readFileSync(target, 'utf8')).toBe('SHOULD_NOT_BE_TOUCHED=1\n');
  });

  it('does not write through a symlink planted after authorization', async () => {
    const outside = join(root, 'outside');
    mkdirSync(outside);
    const target = join(outside, 'late.env');
    writeFileSync(target, 'UNTOUCHED=1\n');

    const payload = await harness.callTool('secret_store', args());
    symlinkSync(target, join(root, '.env')); // planted between approval and write

    const status = await harness.finishFlow(payload, canary.value);
    expect(readFileSync(target, 'utf8')).toBe('UNTOUCHED=1\n');
    expect(['STORED', 'FAILED']).toContain(status.state);
  });

  it('refuses to overwrite an existing variable in create mode', async () => {
    writeFileSync(join(root, '.env'), 'API_TOKEN=old-value\n');

    const payload = await harness.callTool('secret_store', args());
    expect(payload.requires_confirmation).toBe(true);
    const status = await harness.finishFlow(payload, canary.value);

    expect(status.state).toBe('FAILED');
    expect((status.error as { code: string }).code).toBe(ErrorCode.DESTINATION_CONFLICT);
    expect(readFileSync(join(root, '.env'), 'utf8')).toBe('API_TOKEN=old-value\n');
  });

  it('overwrites in replace mode after confirmation', async () => {
    writeFileSync(join(root, '.env'), 'API_TOKEN=old-value\nKEEP=1\n');

    const payload = await harness.callTool('secret_store', args({ write_mode: 'replace' }));
    const status = await harness.finishFlow(payload, canary.value);

    expect(status.state).toBe('STORED');
    const content = readFileSync(join(root, '.env'), 'utf8');
    expect(content).not.toContain('old-value');
    expect(content).toContain('KEEP=1');
  });

  it('leaves the original intact when the write is interrupted', async () => {
    const envPath = join(root, '.env');
    writeFileSync(envPath, 'EXISTING=keep-me\n');
    const config = testConfig({ envAllowedRoots: [root] });
    const adapter = new EnvFileAdapter(config);
    const target = await adapter.normalizeTarget(
      { path: '.env' },
      { name: 'API_TOKEN', environmentHint: Environment.DEVELOPMENT },
    );

    const fsPromises = await import('node:fs/promises');
    const spy = vi.spyOn(fsPromises.default, 'rename').mockRejectedValue(new Error('interrupted'));
    try {
      const buffer = new SecretBuffer(canary.raw);
      await expect(adapter.store(buffer, target, WriteMode.CREATE)).rejects.toThrow('interrupted');
      buffer.zeroize();
    } finally {
      spy.mockRestore();
    }

    expect(readFileSync(envPath, 'utf8')).toBe('EXISTING=keep-me\n');
    expect(readdirSync(root)).toEqual(['.env']);
  });

  it('refuses paths outside the allowed roots', async () => {
    const payload = await harness.callTool(
      'secret_store',
      args({ target: { path: '/tmp/veil-escape.env' } }),
    );
    expect(payload.status).toBe('failed');
    expect(payload.code).toBe(ErrorCode.DESTINATION_NOT_PERMITTED);
    expect(existsSync('/tmp/veil-escape.env')).toBe(false);
  });

  it('refuses invalid variable names and falls back to the credential name', async () => {
    for (const key of ['1BAD', 'with-dash', 'with space', 'WITH=EQUALS', 'x'.repeat(200)]) {
      const payload = await harness.callTool(
        'secret_store',
        args({ target: { path: '.env', key } }),
      );
      expect(payload.status, key).toBe('failed');
      expect(payload.code, key).toBe(ErrorCode.INVALID_TARGET);
    }

    const payload = await harness.callTool('secret_store', args());
    expect((payload.destination as { resource: string }).resource).toBe('.env → API_TOKEN');
  });

  it('keeps the credential out of every spawned argv', async () => {
    git(root, 'init', '-q');
    const spawned: string[][] = [];
    const childProcess = await import('node:child_process');
    const original = childProcess.default.execFile;
    const spy = vi.spyOn(childProcess.default, 'execFile').mockImplementation(((
      command: string,
      argv: string[],
      ...rest: unknown[]
    ) => {
      spawned.push([command, ...argv]);
      return (original as unknown as (...a: unknown[]) => unknown)(command, argv, ...rest);
    }) as never);

    try {
      const payload = await harness.callTool('secret_store', args());
      await harness.finishFlow(payload, canary.value);
    } finally {
      spy.mockRestore();
    }

    const flattened = spawned.map((argv) => argv.join(' ')).join(' ');
    expect(canary.hitsIn(flattened)).toEqual([]);
    expect(spawned.every((argv) => argv[0] === 'git')).toBe(true);
    chmodSync(join(root, '.env'), 0o600);
  });
});
