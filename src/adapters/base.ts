/**
 * Destination adapter interface (SPEC.md §15, §16).
 *
 * An adapter is the only component besides the broker that touches credential
 * bytes. It therefore has three obligations:
 *
 * - it must return a `NormalizedTarget` that fully describes the destination,
 *   because that object — and nothing else — is what the human authorizes and
 *   what the executor consumes;
 * - it must never place secret material in a URL, an argv, a log or an error;
 * - it must translate its provider's errors into a `PublicError` that contains
 *   no provider text.
 */

import type { VeilConfig } from '../config.js';
import { ErrorCode, publicError, type PublicError } from '../errors.js';
import {
  Environment,
  RiskLevel,
  WriteMode,
  escalateEnvironment,
  type DestinationClass,
  type NormalizedTarget,
  type PreflightResult,
  type RiskAssessment,
  type StoreResult,
  type ValidationResult,
} from '../model.js';
import type { SecretBuffer } from '../secretBuffer.js';

/** Raised by adapters for conditions they can describe safely themselves. */
export class AdapterError extends Error {
  readonly public: PublicError;

  constructor(publicRepresentation: PublicError) {
    super(publicRepresentation.code);
    this.name = 'AdapterError';
    this.public = publicRepresentation;
  }
}

export function adapterError(code: string, message: string): AdapterError {
  return new AdapterError(publicError(code, message));
}

/**
 * Coerce a validated target value to a string.
 *
 * Target values are scalars by schema, but an adapter must never turn an
 * unexpected object into the string "[object Object]" and treat that as a
 * project or path name.
 */
export function scalarString(value: unknown): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return '';
}

export interface JsonSchema {
  readonly type: 'object';
  readonly additionalProperties: false;
  readonly required?: readonly string[];
  readonly properties: Readonly<Record<string, Record<string, unknown>>>;
}

export abstract class SecretDestinationAdapter {
  abstract readonly id: string;
  abstract readonly displayName: string;
  abstract readonly destinationClass: DestinationClass;
  /** Floor for risk assessment; policy may escalate above it, never below. */
  readonly riskClass: RiskLevel = RiskLevel.LOW;

  constructor(readonly config: VeilConfig) {}

  /**
   * JSON Schema for this adapter's `target` object. Must be closed
   * (`additionalProperties: false`) and must not contain any field capable of
   * carrying credential content (SPEC.md §6).
   */
  abstract targetSchema(): JsonSchema;

  supportedWriteModes(): readonly WriteMode[] {
    return [WriteMode.CREATE, WriteMode.NEW_VERSION, WriteMode.REPLACE];
  }

  /** Turn untrusted agent input into a canonical destination object. */
  abstract normalizeTarget(
    target: Readonly<Record<string, unknown>>,
    context: { name: string; environmentHint: Environment },
  ): Promise<NormalizedTarget>;

  validateTarget(target: NormalizedTarget): Promise<ValidationResult> {
    void target;
    return Promise.resolve({ ok: true });
  }

  preflight(target: NormalizedTarget): Promise<PreflightResult> {
    void target;
    return Promise.resolve({ ok: true });
  }

  /** Adapter-specific baseline risk. Policy escalates; it never lowers. */
  abstract calculateRisk(
    target: NormalizedTarget,
    operation: WriteMode,
    context: { exists: boolean },
  ): Promise<RiskAssessment>;

  /** Write the secret. MUST NOT return, log or echo the secret. */
  abstract store(
    secret: SecretBuffer,
    target: NormalizedTarget,
    operation: WriteMode,
  ): Promise<StoreResult>;

  /** Default translation: reveal nothing beyond a generic failure. */
  sanitizeError(error: unknown): Promise<PublicError> {
    if (error instanceof AdapterError) return Promise.resolve(error.public);
    return Promise.resolve(
      publicError(
        ErrorCode.DESTINATION_WRITE_FAILED,
        'The destination rejected the credential write.',
      ),
    );
  }

  /**
   * Derive the environment from destination naming.
   *
   * This is server-side evidence. The agent's claimed `environment` may raise
   * the result but never lower it (SPEC.md §10, §26.2).
   */
  classifyEnvironment(...parts: readonly (string | undefined)[]): Environment {
    const tokens = new Set(
      parts
        .filter((part): part is string => Boolean(part))
        .flatMap((part) => part.toLowerCase().split(/[^a-z0-9]+/))
        .filter((token) => token.length > 0),
    );
    if (this.config.productionMarkers.some((marker) => tokens.has(marker))) {
      return Environment.PRODUCTION;
    }
    if (this.config.stagingMarkers.some((marker) => tokens.has(marker))) return Environment.STAGING;
    if (this.config.developmentMarkers.some((marker) => tokens.has(marker))) {
      return Environment.DEVELOPMENT;
    }
    return Environment.UNKNOWN;
  }

  protected environmentFor(
    hint: Environment,
    ...parts: readonly (string | undefined)[]
  ): Environment {
    return escalateEnvironment(this.classifyEnvironment(...parts), hint);
  }
}
