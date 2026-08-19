/**
 * `.env` adapter — local plaintext destination (SPEC.md §16, §33).
 *
 * Security properties implemented here:
 *
 * - the resolved path must stay inside an operator-configured root, and explicit
 *   `..` traversal is rejected outright;
 * - the target must not be a symlink, and the write is performed with `rename`,
 *   which replaces a link rather than writing through it, so a symlink planted
 *   between check and write still cannot redirect the credential;
 * - a git-tracked `.env` is refused by default;
 * - the write is atomic (temp file in the same directory, `0600`, `fsync`,
 *   rename), so an interrupted write cannot corrupt unrelated variables;
 * - the credential never appears in an argv: the only subprocess invoked is
 *   `git`, it is spawned without a shell, and it only ever receives paths.
 */

import { execFile } from 'node:child_process';
import { constants as fsConstants, promises as fs, realpathSync } from 'node:fs';
import { isAbsolute, join, parse, relative, resolve, sep } from 'node:path';
import { promisify } from 'node:util';

import { ErrorCode, publicError, type PublicError } from '../errors.js';
import {
  DestinationClass,
  Environment,
  RiskLevel,
  WriteMode,
  normalizedTarget,
  type NormalizedTarget,
  type PreflightResult,
  type RiskAssessment,
  type StoreResult,
  type ValidationResult,
} from '../model.js';
import type { SecretBuffer } from '../secretBuffer.js';
import { SecretDestinationAdapter, adapterError, scalarString, type JsonSchema } from './base.js';

const execFileAsync = promisify(execFile);

export const ENV_KEY_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const DEFAULT_FILENAME = '.env';
const GIT_TIMEOUT_MS = 5_000;

export class EnvFileAdapter extends SecretDestinationAdapter {
  readonly id = 'env-file';
  readonly displayName = 'Local .env file';
  readonly destinationClass = DestinationClass.LOCAL_PLAINTEXT;
  override readonly riskClass = RiskLevel.MEDIUM;

  targetSchema(): JsonSchema {
    return {
      type: 'object',
      additionalProperties: false,
      properties: {
        path: {
          type: 'string',
          maxLength: 512,
          description: "Path to the env file, relative to an allowed root. Defaults to '.env'.",
        },
        key: {
          type: 'string',
          maxLength: 128,
          description: 'Variable name to set. Defaults to the credential name.',
        },
      },
    };
  }

  override supportedWriteModes(): readonly WriteMode[] {
    return [WriteMode.CREATE, WriteMode.REPLACE];
  }

  async normalizeTarget(
    target: Readonly<Record<string, unknown>>,
    context: { name: string; environmentHint: Environment },
  ): Promise<NormalizedTarget> {
    const unknown = Object.keys(target).filter((key) => key !== 'path' && key !== 'key');
    if (unknown.length > 0) {
      throw adapterError(
        ErrorCode.INVALID_TARGET,
        'The destination target contained unsupported fields.',
      );
    }

    const key = scalarString(target.key) || context.name;
    if (!ENV_KEY_PATTERN.test(key)) {
      throw adapterError(
        ErrorCode.INVALID_TARGET,
        'The environment variable name is not a valid identifier.',
      );
    }

    const resolved = this.#resolvePath(scalarString(target.path) || DEFAULT_FILENAME);
    const parsed = parse(resolved);

    return Promise.resolve(
      normalizedTarget({
        adapterId: this.id,
        destinationClass: this.destinationClass,
        providerLabel: 'Local file (plaintext)',
        accountLabel: parsed.dir,
        resourceLabel: `${parsed.base} → ${key}`,
        environment: this.environmentFor(context.environmentHint, resolved, key),
        fields: { path: resolved, key },
        warnings: ['This destination stores the credential as plaintext on this machine.'],
      }),
    );
  }

  #resolvePath(rawPath: string): string {
    if (rawPath.includes('\0')) {
      throw adapterError(ErrorCode.INVALID_TARGET, 'The destination path is not valid.');
    }
    if (rawPath.split(/[\\/]/).includes('..')) {
      throw adapterError(
        ErrorCode.INVALID_TARGET,
        'Relative path traversal is not permitted in a destination path.',
      );
    }
    const roots = this.config.envAllowedRoots;
    if (roots.length === 0) {
      throw adapterError(
        ErrorCode.DESTINATION_NOT_PERMITTED,
        'No local destination directory is permitted by policy.',
      );
    }

    const firstRoot = roots[0] as string;
    const candidate = isAbsolute(rawPath) ? rawPath : join(firstRoot, rawPath);
    const parsed = parse(candidate);
    if (!parsed.base || parsed.base === '.' || parsed.base === '..') {
      throw adapterError(ErrorCode.INVALID_TARGET, 'The destination path is not a file.');
    }

    // Canonicalise the *parent*, following symlinks, so a linked directory
    // cannot point outside a root. `path.resolve` alone is purely lexical and
    // would happily accept `root/link-to-elsewhere/.env`. The final component
    // is deliberately left unresolved: it is checked separately, and the write
    // uses rename, which replaces a link rather than following it.
    const parent = canonicalDirectory(parsed.dir);
    if (!roots.some((root) => isWithin(parent, root))) {
      throw adapterError(
        ErrorCode.DESTINATION_NOT_PERMITTED,
        'The destination path is outside the directories permitted by policy.',
      );
    }
    return join(parent, parsed.base);
  }

  /**
   * Re-check containment immediately before writing.
   *
   * Canonicalising at authorization time cannot bind the filesystem: a parent
   * directory can still be swapped for a symlink afterwards. Repeating the
   * check here shrinks that window to the moment of the write.
   */
  #assertStillInsideRoots(path: string): void {
    const parent = canonicalDirectory(parse(path).dir);
    if (!this.config.envAllowedRoots.some((root) => isWithin(parent, root))) {
      throw adapterError(
        ErrorCode.DESTINATION_NOT_PERMITTED,
        'The destination path is outside the directories permitted by policy.',
      );
    }
  }

  override async validateTarget(target: NormalizedTarget): Promise<ValidationResult> {
    const path = target.fields.path ?? '';
    const stats = await fs.lstat(path).catch(() => null);
    if (stats?.isSymbolicLink()) {
      return {
        ok: false,
        code: ErrorCode.DESTINATION_NOT_PERMITTED,
        message: 'The destination path is a symbolic link and will not be written through.',
      };
    }
    if (stats && !stats.isFile()) {
      return {
        ok: false,
        code: ErrorCode.INVALID_TARGET,
        message: 'The destination path is not a regular file.',
      };
    }
    const parentStats = await fs.stat(parse(path).dir).catch(() => null);
    if (!parentStats?.isDirectory()) {
      return {
        ok: false,
        code: ErrorCode.INVALID_TARGET,
        message: 'The destination directory does not exist.',
      };
    }
    return { ok: true };
  }

  override async preflight(target: NormalizedTarget): Promise<PreflightResult> {
    const path = target.fields.path ?? '';
    const key = target.fields.key ?? '';
    const notes: string[] = [];

    if ((await gitTracks(path)) && !this.config.allowGitTrackedEnv) {
      return {
        ok: false,
        code: ErrorCode.DESTINATION_NOT_PERMITTED,
        message: 'This file is tracked by git; writing a credential into it is blocked.',
      };
    }

    const exists = await fileExists(path);
    if (exists && !(await gitIgnores(path))) {
      notes.push('This file does not appear to be git-ignored.');
    }

    let variableExists = false;
    if (exists) {
      let content: string;
      try {
        content = await readWithoutFollowingSymlinks(path);
      } catch {
        return {
          ok: false,
          code: ErrorCode.DESTINATION_NOT_PERMITTED,
          message: 'The destination file could not be read safely.',
        };
      }
      variableExists = findKeyLine(content.split('\n'), key) !== null;
      if (variableExists) {
        notes.push('This variable already has a value in the file and will be replaced.');
      }
    }
    return { ok: true, exists: variableExists, notes };
  }

  calculateRisk(): Promise<RiskAssessment> {
    return Promise.resolve({
      level: RiskLevel.MEDIUM,
      reasons: ['The credential will be written to a plaintext file on this machine.'],
      requiresStageB: false,
    });
  }

  async store(
    secret: SecretBuffer,
    target: NormalizedTarget,
    operation: WriteMode,
  ): Promise<StoreResult> {
    const path = target.fields.path ?? '';
    const key = target.fields.key ?? '';

    this.#assertStillInsideRoots(path);

    const stats = await fs.lstat(path).catch(() => null);
    if (stats?.isSymbolicLink()) {
      throw adapterError(
        ErrorCode.DESTINATION_NOT_PERMITTED,
        'The destination path is a symbolic link and will not be written through.',
      );
    }

    const existingLines = stats ? (await readWithoutFollowingSymlinks(path)).split('\n') : [];
    if (existingLines.length > 0 && existingLines[existingLines.length - 1] === '') {
      existingLines.pop();
    }

    const index = findKeyLine(existingLines, key);
    if (index !== null && operation === WriteMode.CREATE) {
      throw adapterError(
        ErrorCode.DESTINATION_CONFLICT,
        'The variable already exists; a replace operation is required to overwrite it.',
      );
    }

    const line = `${key}=${quote(secret.toText())}`;
    const lines =
      index === null
        ? [...existingLines, line]
        : [...existingLines.slice(0, index), line, ...existingLines.slice(index + 1)];

    await atomicWrite(path, `${lines.join('\n')}\n`);
    return {
      stored: true,
      destinationRef: `${path}:${key}`,
      detail: { file_mode: '0600', variable: key },
    };
  }

  override async sanitizeError(error: unknown): Promise<PublicError> {
    const code = (error as NodeJS.ErrnoException | null)?.code;
    if (code === 'EACCES' || code === 'EPERM') {
      return publicError(
        ErrorCode.DESTINATION_DENIED,
        'The destination file could not be written due to filesystem permissions.',
      );
    }
    if (code === 'ENOENT') {
      return publicError(
        ErrorCode.DESTINATION_NOT_FOUND,
        'The destination directory no longer exists.',
      );
    }
    if (code === 'EISDIR' || code === 'ENOTDIR') {
      return publicError(ErrorCode.INVALID_TARGET, 'The destination path is not a regular file.');
    }
    return super.sanitizeError(error);
  }
}

// -- helpers ----------------------------------------------------------------

/**
 * The canonical form of a directory, following symlinks.
 *
 * Missing directories are resolved as far as they exist, so a path under a
 * directory that has not been created yet is still checked against the real
 * location of its nearest existing ancestor.
 */
export function canonicalDirectory(directory: string): string {
  const absolute = resolve(directory);
  let head = absolute;
  const tail: string[] = [];

  for (;;) {
    try {
      return join(realpathSync(head), ...tail.reverse());
    } catch {
      const parsed = parse(head);
      if (parsed.dir === head) return absolute; // reached the filesystem root
      tail.push(parsed.base);
      head = parsed.dir;
    }
  }
}

function isWithin(path: string, root: string): boolean {
  if (path === root) return true;
  const rel = relative(root, path);
  return rel.length > 0 && !rel.startsWith('..') && !isAbsolute(rel);
}

async function fileExists(path: string): Promise<boolean> {
  return (await fs.lstat(path).catch(() => null)) !== null;
}

async function readWithoutFollowingSymlinks(path: string): Promise<string> {
  const handle = await fs.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    return await handle.readFile({ encoding: 'utf8' });
  } finally {
    await handle.close();
  }
}

function findKeyLine(lines: readonly string[], key: string): number | null {
  const prefix = `${key}=`;
  const exportPrefix = `export ${key}=`;
  for (const [index, line] of lines.entries()) {
    const stripped = line.replace(/^\s+/, '');
    if (stripped.startsWith(prefix) || stripped.startsWith(exportPrefix)) return index;
  }
  return null;
}

/** Serialize a value so it round-trips and cannot inject further variables. */
export function quote(value: string): string {
  const escaped = value
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\$/g, '\\$')
    .replace(/`/g, '\\`')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r');
  return `"${escaped}"`;
}

/**
 * Write via a 0600 temp file in the same directory, then rename.
 *
 * SEC-010: this is the one place Veil creates a temporary copy of credential
 * material. It is unavoidable for atomicity (SPEC.md §33). The file is created
 * with mode 0600 before any bytes are written, is never world-readable, and is
 * deleted deterministically on any failure path.
 */
async function atomicWrite(path: string, content: string): Promise<void> {
  const directory = parse(path).dir;
  const temporary = join(directory, `.veil-${process.pid}-${Date.now().toString(36)}.tmp`);
  const handle = await fs.open(temporary, 'wx', 0o600);
  try {
    await handle.chmod(0o600);
    await handle.writeFile(content, { encoding: 'utf8' });
    await handle.sync();
  } catch (error) {
    await handle.close().catch(() => undefined);
    await fs.unlink(temporary).catch(() => undefined);
    throw error;
  }
  await handle.close();

  try {
    await fs.rename(temporary, path);
  } catch (error) {
    await fs.unlink(temporary).catch(() => undefined);
    throw error;
  }
  await fs.chmod(path, 0o600).catch(() => undefined);

  const directoryHandle = await fs.open(directory, fsConstants.O_RDONLY).catch(() => null);
  if (directoryHandle) {
    await directoryHandle.sync().catch(() => undefined);
    await directoryHandle.close();
  }
}

async function git(path: string, args: readonly string[]): Promise<number | null> {
  const directory = parse(path).dir;
  try {
    await execFileAsync('git', ['-C', directory, ...args, '--', path], {
      timeout: GIT_TIMEOUT_MS,
      // No shell: the credential is not here, and neither is a shell string.
      shell: false,
    });
    return 0;
  } catch (error) {
    const code = (error as { code?: number | string }).code;
    return typeof code === 'number' ? code : null;
  }
}

async function gitTracks(path: string): Promise<boolean> {
  return (await git(path, ['ls-files', '--error-unmatch'])) === 0;
}

async function gitIgnores(path: string): Promise<boolean> {
  return (await git(path, ['check-ignore', '-q'])) === 0;
}

export const __testing = { isWithin, findKeyLine, quote, sep };
