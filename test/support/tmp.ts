/** Temporary-directory helpers for tests that touch the filesystem. */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export function makeTempDir(prefix = 'veil-test-'): string {
  // realpath so macOS's /var -> /private/var symlink cannot make an allowed
  // root look like an escape.
  return realpathSync(mkdtempSync(join(tmpdir(), prefix)));
}

export function removeTempDir(path: string): void {
  rmSync(path, { recursive: true, force: true });
}

export function git(directory: string, ...args: string[]): void {
  execFileSync('git', args, { cwd: directory, stdio: 'pipe' });
}
