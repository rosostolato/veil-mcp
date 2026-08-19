/**
 * Structured, allowlisted audit logging (SPEC.md §19, §18.8, §18.9).
 *
 * Two rules make this module boring on purpose:
 *
 * 1. A record is built from an explicit allowlist of safe field names. There is
 *    no format-string path, no error serialization, and no way to pass a request
 *    body, provider payload or buffer through it.
 * 2. Every rendered line passes a tripwire before it is written. If any live
 *    secret (in any encoding `redaction` knows) appears in the line, the record
 *    is replaced by a suppression marker.
 *
 * Logs go to stderr — never stdout, which carries the MCP protocol.
 */

import { looksLikeCredential, safeField } from './redaction.js';

/** The complete set of keys an audit record may carry (SPEC.md §19). */
export const ALLOWED_AUDIT_FIELDS: ReadonlySet<string> = new Set([
  'request_id',
  'operation',
  'destination',
  'destination_class',
  'adapter',
  'logical_name',
  'environment',
  'resource',
  'account',
  'risk',
  'confirmation',
  'result',
  'state',
  'from_state',
  'to_state',
  'stage',
  'reason',
  'code',
  'error_code',
  'authorization_digest',
  'duration_ms',
  'count',
  'tool',
  'method',
  'path',
  'status_code',
  'component',
  'detail',
]);

/** Keys that must never be logged even if a caller passes them (SPEC.md §19). */
export const FORBIDDEN_AUDIT_FIELDS: ReadonlySet<string> = new Set([
  'secret',
  'secret_value',
  'value',
  'password',
  'token',
  'credential',
  'content',
  'body',
  'payload',
  'stdin',
  'clipboard',
  'hash',
  'prefix',
  'suffix',
  'length',
  'secret_length',
]);

export const REDACTED = '[redacted]';

/** Returns true when the given rendered text carries live secret material. */
export type Tripwire = (text: string) => boolean;

export type AuditFields = Record<string, unknown>;

export interface AuditLoggerOptions {
  readonly stream?: { write(chunk: string): unknown };
  readonly tripwire?: Tripwire;
  readonly sink?: (record: Record<string, unknown>) => void;
}

export class AuditLogger {
  #stream: { write(chunk: string): unknown };
  #tripwire: Tripwire | undefined;
  #sink: ((record: Record<string, unknown>) => void) | undefined;

  constructor(options: AuditLoggerOptions = {}) {
    this.#stream = options.stream ?? process.stderr;
    this.#tripwire = options.tripwire;
    this.#sink = options.sink;
  }

  setTripwire(tripwire: Tripwire | undefined): void {
    this.#tripwire = tripwire;
  }

  event(event: string, fields: AuditFields = {}): void {
    this.#emit('info', event, fields);
  }

  security(event: string, fields: AuditFields = {}): void {
    this.#emit('security', event, fields);
  }

  error(event: string, fields: AuditFields = {}): void {
    this.#emit('error', event, fields);
  }

  /**
   * Debug records go through exactly the same allowlist and tripwire as every
   * other level: SEC-006 does not exempt DEBUG or TRACE.
   */
  debug(event: string, fields: AuditFields = {}): void {
    this.#emit('debug', event, fields);
  }

  #emit(level: string, event: string, fields: AuditFields): void {
    let record: Record<string, unknown> = { level, event: safeField(event, 80) };
    const dropped: string[] = [];

    for (const [key, value] of Object.entries(fields)) {
      if (FORBIDDEN_AUDIT_FIELDS.has(key) || !ALLOWED_AUDIT_FIELDS.has(key)) {
        dropped.push(key);
        continue;
      }
      record[key] = safeValue(value);
    }
    if (dropped.length > 0) {
      record.dropped_fields = dropped.map((key) => safeField(key, 40)).sort();
    }

    let line = stableStringify(record);
    if (this.#tripwire?.(line)) {
      record = {
        level: 'security',
        event: 'audit_record_suppressed',
        reason: 'tripwire_detected_secret_material',
        original_event: record.event,
      };
      line = stableStringify(record);
    }

    this.#sink?.(record);
    try {
      this.#stream.write(`${line}\n`);
    } catch {
      // The stream closed during shutdown; losing a record is preferable to
      // crashing a process that may still hold a secret.
    }
  }
}

function safeValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.slice(0, 20).map(safeValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .slice(0, 20)
        .map(([key, item]) => [safeField(key, 40), safeValue(item)]),
    );
  }
  if (typeof value === 'number' || typeof value === 'boolean' || value === null) return value;
  const text = safeField(value);
  // Even an allowlisted field must not carry credential-shaped text.
  return looksLikeCredential(text) ? REDACTED : text;
}

function stableStringify(record: Record<string, unknown>): string {
  return JSON.stringify(record, (_key, value: unknown) => {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const entries = value as Record<string, unknown>;
      return Object.fromEntries(
        Object.keys(entries)
          .sort()
          .map((key) => [key, entries[key]]),
      );
    }
    return value;
  });
}

const defaultLogger = new AuditLogger();

export function getLogger(): AuditLogger {
  return defaultLogger;
}

/**
 * Wipe live secrets on an unhandled error (SPEC.md §18.9).
 *
 * The handler reports only the error's constructor name — never its message,
 * never a stack, never an in-flight request body.
 */
export function installCrashHandler(onCrash: () => void, logger: AuditLogger = getLogger()): void {
  const handle = (error: unknown): void => {
    try {
      onCrash();
    } finally {
      logger.error('unhandled_exception', {
        code: error instanceof Error ? error.constructor.name : 'unknown',
        component: 'process',
      });
    }
    process.exit(1);
  };

  process.on('uncaughtException', handle);
  process.on('unhandledRejection', handle);
}
