/**
 * Operator-controlled configuration.
 *
 * Configuration is read from the environment of the Veil process, which the
 * agent does not control. Nothing here can be influenced by MCP tool arguments —
 * an agent must not be able to relax a policy (SPEC.md §10).
 */

import { realpathSync } from 'node:fs';
import { delimiter, resolve } from 'node:path';

export const DEFAULT_PRODUCTION_MARKERS = ['prod', 'production', 'live', 'prd'] as const;
export const DEFAULT_STAGING_MARKERS = [
  'staging',
  'stage',
  'stg',
  'preprod',
  'pre-prod',
  'uat',
] as const;
export const DEFAULT_DEVELOPMENT_MARKERS = [
  'dev',
  'development',
  'local',
  'sandbox',
  'test',
  'testing',
] as const;

export interface VeilConfig {
  // Request lifetime
  readonly requestTtlSeconds: number;
  readonly maxActiveRequests: number;
  /**
   * Upper bound on a single adapter write, so a hung provider cannot pin a
   * request in EXECUTING (and therefore pin its secret in memory) forever.
   */
  readonly adapterTimeoutSeconds: number;

  // Confirmation policy (SPEC.md §10). Operators may only make this stricter.
  readonly stageBForMedium: boolean;
  readonly stageBForLow: boolean;

  // Secure UI
  readonly uiHost: string;
  readonly uiPort: number;
  /**
   * Open the authorization window on the user's machine. Keeping the URL out of
   * the agent's reach is what makes the window an out-of-band channel.
   */
  readonly openBrowser: boolean;
  /**
   * Return the authorization URL to the agent. OFF by default: the URL is a
   * capability, and an agent with network access could otherwise authorize its
   * own request without the human (SPEC.md §4.2, §7).
   */
  readonly discloseAuthorizationUrl: boolean;

  // `.env` adapter
  readonly envAllowedRoots: readonly string[];
  readonly allowGitTrackedEnv: boolean;

  // Destination gating (SPEC.md §16: arbitrary-network is off by default and is
  // not implemented at all in this version).
  readonly enabledAdapters?: readonly string[];

  // Environment classification
  readonly productionMarkers: readonly string[];
  readonly stagingMarkers: readonly string[];
  readonly developmentMarkers: readonly string[];
}

/**
 * Canonicalise a configured root, following symlinks.
 *
 * The `.env` adapter compares canonical paths, so the roots must be canonical
 * too — on macOS `/tmp` is a symlink to `/private/tmp`, and a lexical root
 * would reject every legitimate write beneath it.
 */
export function canonicalRoot(path: string): string {
  const absolute = resolve(path);
  try {
    return realpathSync(absolute);
  } catch {
    return absolute;
  }
}

export function defaultConfig(overrides: Partial<VeilConfig> = {}): VeilConfig {
  return Object.freeze({
    requestTtlSeconds: 300,
    maxActiveRequests: 64,
    adapterTimeoutSeconds: 30,
    stageBForMedium: true,
    stageBForLow: false,
    uiHost: '127.0.0.1',
    uiPort: 0,
    openBrowser: true,
    discloseAuthorizationUrl: false,
    allowGitTrackedEnv: false,
    productionMarkers: [...DEFAULT_PRODUCTION_MARKERS],
    stagingMarkers: [...DEFAULT_STAGING_MARKERS],
    developmentMarkers: [...DEFAULT_DEVELOPMENT_MARKERS],
    ...overrides,
    envAllowedRoots: (overrides.envAllowedRoots ?? [canonicalRoot(process.cwd())]).map(
      canonicalRoot,
    ),
  });
}

export function configFromEnv(env: NodeJS.ProcessEnv = process.env): VeilConfig {
  const roots = env.VEIL_ENV_ALLOWED_ROOTS;
  return defaultConfig({
    requestTtlSeconds: clamp(number(env.VEIL_REQUEST_TTL_SECONDS, 300), 15, 3600),
    maxActiveRequests: Math.trunc(number(env.VEIL_MAX_ACTIVE_REQUESTS, 64)),
    adapterTimeoutSeconds: clamp(number(env.VEIL_ADAPTER_TIMEOUT_SECONDS, 30), 1, 300),
    stageBForMedium: boolean(env.VEIL_STAGE_B_FOR_MEDIUM, true),
    stageBForLow: boolean(env.VEIL_STAGE_B_FOR_LOW, false),
    uiHost: env.VEIL_UI_HOST ?? '127.0.0.1',
    uiPort: Math.trunc(number(env.VEIL_UI_PORT, 0)),
    openBrowser: boolean(env.VEIL_OPEN_BROWSER, true),
    discloseAuthorizationUrl: boolean(env.VEIL_DISCLOSE_AUTHORIZATION_URL, false),
    envAllowedRoots: roots
      ? roots
          .split(delimiter)
          .filter((entry) => entry.length > 0)
          .map((entry) => canonicalRoot(entry))
      : [canonicalRoot(process.cwd())],
    allowGitTrackedEnv: boolean(env.VEIL_ALLOW_GIT_TRACKED_ENV, false),
    ...(env.VEIL_ENABLED_ADAPTERS
      ? {
          enabledAdapters: env.VEIL_ENABLED_ADAPTERS.split(',')
            .map((entry) => entry.trim())
            .filter((entry) => entry.length > 0),
        }
      : {}),
  });
}

function boolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(value.trim().toLowerCase());
}

function number(value: string | undefined, fallback: number): number {
  if (value === undefined || value === '') return fallback;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function clamp(value: number, low: number, high: number): number {
  return Math.min(Math.max(value, low), high);
}
