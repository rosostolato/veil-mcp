/**
 * Public, secret-free error surface (SPEC.md §20).
 *
 * Nothing in this module may carry provider detail. Adapters translate their own
 * exceptions into a `PublicError` through `sanitizeError`; if that translation
 * fails for any reason, callers degrade to `INTERNAL_ERROR` rather than leaking
 * the original error.
 */

/** Stable, machine-readable codes returned across the MCP boundary. */
export const ErrorCode = {
  UNKNOWN_DESTINATION: 'UNKNOWN_DESTINATION',
  INVALID_TARGET: 'INVALID_TARGET',
  INVALID_ARGUMENTS: 'INVALID_ARGUMENTS',
  FORBIDDEN_FIELD: 'FORBIDDEN_FIELD',
  DESTINATION_NOT_PERMITTED: 'DESTINATION_NOT_PERMITTED',
  REQUEST_NOT_FOUND: 'REQUEST_NOT_FOUND',
  REQUEST_NOT_ACTIVE: 'REQUEST_NOT_ACTIVE',
  REQUEST_EXPIRED: 'REQUEST_EXPIRED',
  REQUEST_CANCELLED: 'REQUEST_CANCELLED',
  INVALID_STATE: 'INVALID_STATE',
  UNAUTHORIZED: 'UNAUTHORIZED',
  AUTHORIZATION_INVALIDATED: 'AUTHORIZATION_INVALIDATED',
  CONFIRMATION_REQUIRED: 'CONFIRMATION_REQUIRED',
  SNAPSHOT_MISMATCH: 'SNAPSHOT_MISMATCH',
  TOO_MANY_REQUESTS: 'TOO_MANY_REQUESTS',
  SECRET_TOO_LARGE: 'SECRET_TOO_LARGE',
  EMPTY_SECRET: 'EMPTY_SECRET',
  PREFLIGHT_FAILED: 'PREFLIGHT_FAILED',
  DESTINATION_WRITE_FAILED: 'DESTINATION_WRITE_FAILED',
  DESTINATION_UNAVAILABLE: 'DESTINATION_UNAVAILABLE',
  DESTINATION_DENIED: 'DESTINATION_DENIED',
  DESTINATION_NOT_FOUND: 'DESTINATION_NOT_FOUND',
  DESTINATION_CONFLICT: 'DESTINATION_CONFLICT',
  DESTINATION_RATE_LIMITED: 'DESTINATION_RATE_LIMITED',
  DESTINATION_TIMEOUT: 'DESTINATION_TIMEOUT',
  ADAPTER_UNAVAILABLE: 'ADAPTER_UNAVAILABLE',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
} as const;

export type ErrorCodeValue = (typeof ErrorCode)[keyof typeof ErrorCode];

/**
 * An error that is safe to hand to the model. `message` is written by Veil,
 * never by a provider. `detail` may only contain short, adapter-authored,
 * non-sensitive strings.
 */
export interface PublicError {
  readonly code: string;
  readonly message: string;
  readonly detail?: Readonly<Record<string, string>>;
}

export function publicError(
  code: string,
  message: string,
  detail?: Record<string, string>,
): PublicError {
  return Object.freeze(
    detail ? { code, message, detail: Object.freeze(detail) } : { code, message },
  );
}

export function publicErrorToJSON(error: PublicError): Record<string, unknown> {
  const out: Record<string, unknown> = {
    status: 'failed',
    code: error.code,
    message: error.message,
  };
  if (error.detail && Object.keys(error.detail).length > 0) out.detail = { ...error.detail };
  return out;
}

export const INTERNAL_ERROR: PublicError = publicError(
  ErrorCode.INTERNAL_ERROR,
  'The operation failed. Details were withheld to avoid disclosing sensitive data.',
);

/** Base class for errors that already know their public representation. */
export class VeilError extends Error {
  readonly public: PublicError;

  constructor(publicRepresentation: PublicError) {
    super(publicRepresentation.code);
    this.name = 'VeilError';
    this.public = publicRepresentation;
  }
}

export function veilError(
  code: string,
  message: string,
  detail?: Record<string, string>,
): VeilError {
  return new VeilError(publicError(code, message, detail));
}
