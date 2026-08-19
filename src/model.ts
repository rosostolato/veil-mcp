/**
 * Immutable domain objects (SPEC.md §11, §12, §14, §15).
 *
 * Everything the human authorizes and everything the executor performs is
 * derived from a single frozen `AuthorizationSnapshot`. There is no second
 * "display" representation, by construction: the UI renders this object and the
 * executor consumes this object.
 *
 * TypeScript's `readonly` disappears at run time, so immutability here is
 * enforced by `deepFreeze` — a tampering attempt throws in strict mode, and the
 * executor re-checks the snapshot digest regardless.
 */

import { createHash } from 'node:crypto';

import { safeDisplay } from './redaction.js';

/** The state machine of SPEC.md §14. */
export const RequestState = {
  CREATED: 'CREATED',
  PREFLIGHT: 'PREFLIGHT',
  AWAITING_SECRET_AUTHORIZATION: 'AWAITING_SECRET_AUTHORIZATION',
  SECRET_RECEIVED: 'SECRET_RECEIVED',
  AWAITING_EXECUTION_CONFIRMATION: 'AWAITING_EXECUTION_CONFIRMATION',
  EXECUTING: 'EXECUTING',
  STORED: 'STORED',
  FAILED: 'FAILED',
  CANCELLED: 'CANCELLED',
  EXPIRED: 'EXPIRED',
} as const;

export type RequestState = (typeof RequestState)[keyof typeof RequestState];

export const TERMINAL_STATES: ReadonlySet<RequestState> = new Set([
  RequestState.STORED,
  RequestState.FAILED,
  RequestState.CANCELLED,
  RequestState.EXPIRED,
]);

export function isTerminal(state: RequestState): boolean {
  return TERMINAL_STATES.has(state);
}

/** The only transitions the broker will perform (SPEC.md §14). */
export const ALLOWED_TRANSITIONS: Readonly<Record<RequestState, ReadonlySet<RequestState>>> =
  Object.freeze({
    [RequestState.CREATED]: new Set([RequestState.PREFLIGHT, RequestState.FAILED]),
    [RequestState.PREFLIGHT]: new Set([
      RequestState.AWAITING_SECRET_AUTHORIZATION,
      RequestState.FAILED,
    ]),
    [RequestState.AWAITING_SECRET_AUTHORIZATION]: new Set([
      RequestState.SECRET_RECEIVED,
      RequestState.CANCELLED,
      RequestState.EXPIRED,
    ]),
    [RequestState.SECRET_RECEIVED]: new Set([
      RequestState.AWAITING_EXECUTION_CONFIRMATION,
      RequestState.EXECUTING,
      RequestState.CANCELLED,
      RequestState.EXPIRED,
    ]),
    [RequestState.AWAITING_EXECUTION_CONFIRMATION]: new Set([
      RequestState.EXECUTING,
      RequestState.CANCELLED,
      RequestState.EXPIRED,
    ]),
    [RequestState.EXECUTING]: new Set([RequestState.STORED, RequestState.FAILED]),
    [RequestState.STORED]: new Set<RequestState>(),
    [RequestState.FAILED]: new Set<RequestState>(),
    [RequestState.CANCELLED]: new Set<RequestState>(),
    [RequestState.EXPIRED]: new Set<RequestState>(),
  });

export const RiskLevel = { LOW: 'low', MEDIUM: 'medium', HIGH: 'high' } as const;
export type RiskLevel = (typeof RiskLevel)[keyof typeof RiskLevel];

const RISK_ORDER: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2 };

/** Risk only ever moves up (SPEC.md §10: agents cannot downgrade). */
export function escalateRisk(current: RiskLevel, other: RiskLevel): RiskLevel {
  return RISK_ORDER[current] >= RISK_ORDER[other] ? current : other;
}

export function riskSeverity(level: RiskLevel): number {
  return RISK_ORDER[level];
}

export const Environment = {
  DEVELOPMENT: 'development',
  STAGING: 'staging',
  PRODUCTION: 'production',
  UNKNOWN: 'unknown',
} as const;
export type Environment = (typeof Environment)[keyof typeof Environment];

/**
 * UNKNOWN ranks above STAGING: an environment we could not classify is treated
 * conservatively, but a destination we positively identified as production still
 * wins over an agent's vague claim.
 */
const ENVIRONMENT_ORDER: Record<Environment, number> = {
  development: 0,
  staging: 1,
  unknown: 2,
  production: 3,
};

export function environmentSeverity(environment: Environment): number {
  return ENVIRONMENT_ORDER[environment];
}

export function escalateEnvironment(current: Environment, other: Environment): Environment {
  return ENVIRONMENT_ORDER[current] >= ENVIRONMENT_ORDER[other] ? current : other;
}

export const WriteMode = {
  CREATE: 'create',
  NEW_VERSION: 'new-version',
  REPLACE: 'replace',
} as const;
export type WriteMode = (typeof WriteMode)[keyof typeof WriteMode];

export const DestinationClass = {
  SECRET_STORE: 'secret-store',
  LOCAL_PLAINTEXT: 'local-plaintext',
  REMOTE_APPLICATION_STORAGE: 'remote-application-storage',
  ARBITRARY_NETWORK: 'arbitrary-network',
} as const;
export type DestinationClass = (typeof DestinationClass)[keyof typeof DestinationClass];

/** Wording the UI is required to show for the riskier classes (SPEC.md §16). */
export const DESTINATION_CLASS_NOTICE: Partial<Record<DestinationClass, string>> = Object.freeze({
  [DestinationClass.LOCAL_PLAINTEXT]:
    'This destination stores the credential as plaintext on this machine.',
  [DestinationClass.REMOTE_APPLICATION_STORAGE]:
    'This destination may not be designed to store secrets.',
  [DestinationClass.ARBITRARY_NETWORK]:
    'This destination sends the credential to an arbitrary network endpoint.',
});

/**
 * Recursively freeze an object graph.
 *
 * `readonly` is a compile-time fiction; this is what actually stops a
 * compromised code path from rewriting an authorized destination in place.
 */
export function deepFreeze<T>(value: T): Readonly<T> {
  if (value === null || typeof value !== 'object') return value;
  if (Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const key of Reflect.ownKeys(value)) {
    const property = (value as Record<PropertyKey, unknown>)[key];
    if (property && typeof property === 'object') deepFreeze(property);
  }
  return value;
}

function canonical(value: unknown): string {
  return JSON.stringify(value, (_key, item: unknown) => {
    if (item && typeof item === 'object' && !Array.isArray(item)) {
      const record = item as Record<string, unknown>;
      return Object.fromEntries(
        Object.keys(record)
          .sort()
          .map((k) => [k, record[k]]),
      );
    }
    return item;
  });
}

/**
 * An adapter's canonical, validated description of *where* a secret goes.
 *
 * Adapters produce this from untrusted agent input. Once built it never
 * changes, and both the confirmation UI and the executor read it.
 */
export interface NormalizedTarget {
  readonly adapterId: string;
  readonly destinationClass: DestinationClass;
  readonly providerLabel: string;
  readonly resourceLabel: string;
  readonly environment: Environment;
  readonly accountLabel?: string;
  /** Canonical adapter-specific fields, e.g. the resolved absolute path. */
  readonly fields: Readonly<Record<string, string>>;
  /** Adapter-authored, non-sensitive warnings shown to the human. */
  readonly warnings: readonly string[];
}

export function normalizedTarget(target: {
  adapterId: string;
  destinationClass: DestinationClass;
  providerLabel: string;
  resourceLabel: string;
  environment: Environment;
  accountLabel?: string;
  fields?: Record<string, string>;
  warnings?: readonly string[];
}): NormalizedTarget {
  return deepFreeze({
    ...target,
    fields: { ...(target.fields ?? {}) },
    warnings: [...(target.warnings ?? [])],
  });
}

/** Display-safe projection, used by the UI, audit records and MCP results. */
export function targetToPublic(target: NormalizedTarget): Record<string, unknown> {
  const data: Record<string, unknown> = {
    adapter: target.adapterId,
    destination_class: target.destinationClass,
    provider: safeDisplay(target.providerLabel),
    resource: safeDisplay(target.resourceLabel),
    environment: target.environment,
  };
  if (target.accountLabel !== undefined) data.account = safeDisplay(target.accountLabel);
  if (Object.keys(target.fields).length > 0) {
    data.fields = Object.fromEntries(
      Object.entries(target.fields).map(([key, value]) => [key, safeDisplay(value)]),
    );
  }
  if (target.warnings.length > 0) {
    data.warnings = target.warnings.map((warning) => safeDisplay(warning, 200));
  }
  return data;
}

function targetDigestPayload(target: NormalizedTarget): Record<string, unknown> {
  return {
    adapterId: target.adapterId,
    destinationClass: target.destinationClass,
    providerLabel: target.providerLabel,
    resourceLabel: target.resourceLabel,
    environment: target.environment,
    accountLabel: target.accountLabel ?? null,
    fields: Object.keys(target.fields)
      .sort()
      .map((key) => [key, target.fields[key]]),
  };
}

export interface ValidationResult {
  readonly ok: boolean;
  readonly code?: string;
  readonly message?: string;
}

/** What the adapter learned about the destination before asking for a secret. */
export interface PreflightResult {
  readonly ok: boolean;
  readonly exists?: boolean;
  readonly notes?: readonly string[];
  readonly code?: string;
  readonly message?: string;
}

export interface RiskAssessment {
  readonly level: RiskLevel;
  readonly reasons: readonly string[];
  readonly requiresStageB: boolean;
}

export function riskToPublic(risk: RiskAssessment): Record<string, unknown> {
  return {
    level: risk.level,
    reasons: risk.reasons.map((reason) => safeDisplay(reason, 200)),
    requires_confirmation: risk.requiresStageB,
  };
}

/**
 * The immutable operation the human authorizes (SPEC.md §11).
 *
 * `digest` is recomputed immediately before execution and compared with the
 * value recorded at authorization time; any divergence aborts the write.
 */
export interface AuthorizationSnapshot {
  readonly requestId: string;
  readonly logicalName: string;
  readonly target: NormalizedTarget;
  readonly operation: WriteMode;
  readonly risk: RiskAssessment;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly description?: string;
  readonly existsAtPreflight: boolean;
}

export function snapshotDigest(snapshot: AuthorizationSnapshot): string {
  const payload = {
    requestId: snapshot.requestId,
    logicalName: snapshot.logicalName,
    operation: snapshot.operation,
    risk: snapshot.risk.level,
    requiresStageB: snapshot.risk.requiresStageB,
    target: targetDigestPayload(snapshot.target),
  };
  return createHash('sha256').update(canonical(payload), 'utf8').digest('hex');
}

export function snapshotToPublic(snapshot: AuthorizationSnapshot): Record<string, unknown> {
  const data: Record<string, unknown> = {
    request_id: snapshot.requestId,
    credential: safeDisplay(snapshot.logicalName),
    operation: snapshot.operation,
    destination: targetToPublic(snapshot.target),
    risk: riskToPublic(snapshot.risk),
    authorization_digest: snapshotDigest(snapshot),
  };
  if (snapshot.description) data.description = safeDisplay(snapshot.description, 300);
  return data;
}

/** Non-sensitive outcome metadata handed back to the model (SPEC.md §1). */
export interface StoreResult {
  readonly stored: boolean;
  /** Provider-side identifier of what was written, e.g. a secret version name. */
  readonly destinationRef?: string;
  readonly detail?: Readonly<Record<string, string>>;
}

export function storeResultToPublic(result: StoreResult): Record<string, unknown> {
  const data: Record<string, unknown> = { status: result.stored ? 'stored' : 'not-stored' };
  if (result.destinationRef) data.destination_ref = safeDisplay(result.destinationRef);
  if (result.detail && Object.keys(result.detail).length > 0) {
    data.detail = Object.fromEntries(
      Object.entries(result.detail).map(([key, value]) => [key, safeDisplay(value)]),
    );
  }
  return data;
}
