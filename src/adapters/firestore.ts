/**
 * Firestore adapter — remote application storage (SPEC.md §16, §17).
 *
 * Firestore is not a secret store. This adapter exists because agents ask for
 * it, and Veil would rather show the human a loud, accurate warning than pretend
 * the destination is safe. It is classified `remote-application-storage`, which
 * forces elevated confirmation in `policy`.
 */

import type { VeilConfig } from '../config.js';
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
import {
  FIRESTORE_BASE,
  GoogleStatusError,
  createDefaultTransport,
  type GoogleTransport,
} from './googleTransport.js';

const PROJECT_PATTERN = /^(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{6,20})$/;
const PATH_SEGMENT_PATTERN = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/;
/**
 * One segment of a field path. A dotted `field` (`openrouter.api_key`) names a
 * key inside a map field, which is how application config documents are
 * usually shaped. Segments stay simple identifiers: Firestore's backtick-quoted
 * segments are not accepted, so a path can never smuggle a dot or a quote.
 */
const FIELD_SEGMENT_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const MAX_FIELD_DEPTH = 8;
const SCOPES = ['https://www.googleapis.com/auth/datastore'];

type FirestoreFields = Record<string, unknown>;

/** `a.b.c` → `['a', 'b', 'c']`, or `null` when any segment is not a plain identifier. */
function fieldSegments(path: string): string[] | null {
  const segments = path.split('.');
  if (segments.length > MAX_FIELD_DEPTH) return null;
  return segments.every((segment) => FIELD_SEGMENT_PATTERN.test(segment)) ? segments : null;
}

/** The REST `fields` body that sets `segments` to a string, nested through map values. */
function nestedFields(segments: readonly string[], value: string): FirestoreFields {
  let node: unknown = { stringValue: value };
  for (const segment of [...segments].reverse().slice(0, -1)) {
    node = { mapValue: { fields: { [segment]: node } } };
  }
  return { [segments[0] ?? '']: node };
}

/**
 * What the document holds at `segments`: `absent`, `present`, or `blocked` when
 * an intermediate segment exists but is not a map. Writing through a blocked
 * path would replace that value with a map, which is a silent overwrite.
 */
function fieldState(
  fields: FirestoreFields | undefined,
  segments: readonly string[],
): 'absent' | 'present' | 'blocked' {
  let current: FirestoreFields | undefined = fields;
  for (const [index, segment] of segments.entries()) {
    if (!current || !Object.hasOwn(current, segment)) return 'absent';
    if (index === segments.length - 1) return 'present';
    const map = (current[segment] as { mapValue?: { fields?: FirestoreFields } } | undefined)
      ?.mapValue;
    if (!map) return 'blocked';
    current = map.fields ?? {};
  }
  return 'absent';
}

export class FirestoreAdapter extends SecretDestinationAdapter {
  readonly id = 'firestore';
  readonly displayName = 'Firestore document field';
  readonly destinationClass = DestinationClass.REMOTE_APPLICATION_STORAGE;
  override readonly riskClass = RiskLevel.MEDIUM;

  #transport: GoogleTransport | undefined;

  constructor(config: VeilConfig, transport?: GoogleTransport) {
    super(config);
    this.#transport = transport;
  }

  targetSchema(): JsonSchema {
    return {
      type: 'object',
      additionalProperties: false,
      required: ['project', 'collection', 'document'],
      properties: {
        project: { type: 'string', maxLength: 64, description: 'Google Cloud project id.' },
        collection: { type: 'string', maxLength: 128, description: 'Collection id.' },
        document: { type: 'string', maxLength: 128, description: 'Document id.' },
        field: {
          type: 'string',
          maxLength: 128,
          description:
            'Document field to set. Defaults to the credential name. A dotted path ' +
            '(e.g. "openrouter.api_key") sets a key inside a map field, leaving its siblings untouched.',
        },
      },
    };
  }

  override supportedWriteModes(): readonly WriteMode[] {
    return [WriteMode.CREATE, WriteMode.REPLACE];
  }

  normalizeTarget(
    target: Readonly<Record<string, unknown>>,
    context: { name: string; environmentHint: Environment },
  ): Promise<NormalizedTarget> {
    const allowed = new Set(['project', 'collection', 'document', 'field']);
    if (Object.keys(target).some((key) => !allowed.has(key))) {
      throw adapterError(
        ErrorCode.INVALID_TARGET,
        'The destination target contained unsupported fields.',
      );
    }
    const project = scalarString(target.project).trim();
    const collection = scalarString(target.collection).trim();
    const document = scalarString(target.document).trim();
    const field = (scalarString(target.field) || context.name).trim();

    if (!PROJECT_PATTERN.test(project)) {
      throw adapterError(
        ErrorCode.INVALID_TARGET,
        'The Google Cloud project identifier is not valid.',
      );
    }
    for (const segment of [collection, document]) {
      if (!PATH_SEGMENT_PATTERN.test(segment)) {
        throw adapterError(
          ErrorCode.INVALID_TARGET,
          'The Firestore collection or document path is not valid.',
        );
      }
    }
    if (!fieldSegments(field)) {
      throw adapterError(ErrorCode.INVALID_TARGET, 'The document field name is not valid.');
    }

    return Promise.resolve(
      normalizedTarget({
        adapterId: this.id,
        destinationClass: this.destinationClass,
        providerLabel: 'Firestore (application database)',
        accountLabel: project,
        resourceLabel: `${collection}/${document}.${field}`,
        environment: this.environmentFor(
          context.environmentHint,
          project,
          collection,
          document,
          context.name,
        ),
        fields: { project, collection, document, field },
        warnings: [
          'This destination may not be designed to store secrets.',
          'Anyone with read access to this database can read the credential.',
        ],
      }),
    );
  }

  override validateTarget(target: NormalizedTarget): Promise<ValidationResult> {
    for (const key of ['project', 'collection', 'document', 'field']) {
      if (!target.fields[key]) {
        return Promise.resolve({
          ok: false,
          code: ErrorCode.INVALID_TARGET,
          message: 'The destination target is incomplete.',
        });
      }
    }
    return Promise.resolve({ ok: true });
  }

  override async preflight(target: NormalizedTarget): Promise<PreflightResult> {
    let transport: GoogleTransport;
    try {
      transport = await this.#getTransport();
    } catch {
      return {
        ok: false,
        code: ErrorCode.ADAPTER_UNAVAILABLE,
        message: 'Firestore is not configured on this machine.',
      };
    }
    const response = await transport({
      method: 'GET',
      url: this.#documentUrl(target),
      timeoutMs: this.#timeoutMs,
    }).catch(() => null);

    if (!response || response.status !== 200) return { ok: true, exists: false };
    const fields = (response.body as { fields?: FirestoreFields } | null)?.fields ?? {};
    const segments = fieldSegments(target.fields.field ?? '') ?? [];
    return {
      ok: true,
      exists: fieldState(fields, segments) !== 'absent',
      notes: ['The document already exists.'],
    };
  }

  calculateRisk(): Promise<RiskAssessment> {
    return Promise.resolve({
      level: RiskLevel.MEDIUM,
      reasons: ['The credential will be stored in an application database.'],
      requiresStageB: true,
    });
  }

  async store(
    secret: SecretBuffer,
    target: NormalizedTarget,
    operation: WriteMode,
  ): Promise<StoreResult> {
    const transport = await this.#getTransport();
    const fieldName = target.fields.field ?? '';
    const segments = fieldSegments(fieldName);
    if (!segments) {
      throw adapterError(ErrorCode.INVALID_TARGET, 'The document field name is not valid.');
    }

    // Read before every write, not only on create: a path through a non-map
    // value would turn that value into a map, and replace mode must not do that
    // to a field it was not asked to replace.
    const existing = await transport({
      method: 'GET',
      url: this.#documentUrl(target),
      timeoutMs: this.#timeoutMs,
    }).catch(() => null);
    const fields =
      existing?.status === 200
        ? ((existing.body as { fields?: FirestoreFields } | null)?.fields ?? {})
        : undefined;
    const state = fieldState(fields, segments);
    if (state === 'blocked') {
      throw adapterError(
        ErrorCode.DESTINATION_CONFLICT,
        'A parent of the document field holds a value that is not a map.',
      );
    }
    if (operation === WriteMode.CREATE && state === 'present') {
      throw adapterError(
        ErrorCode.DESTINATION_CONFLICT,
        'The document field already exists; a replace operation is required.',
      );
    }

    // The update mask names the full dotted path, so Firestore sets only that
    // leaf and keeps every sibling inside the parent maps.
    const response = await transport({
      method: 'PATCH',
      url: `${this.#documentUrl(target)}?updateMask.fieldPaths=${encodeURIComponent(fieldName)}`,
      body: { fields: nestedFields(segments, secret.toText()) },
      timeoutMs: this.#timeoutMs,
    });
    if (response.status < 200 || response.status >= 300) {
      throw new GoogleStatusError(response.status);
    }

    return {
      stored: true,
      destinationRef:
        `projects/${target.fields.project ?? ''}/databases/(default)/documents/` +
        `${target.fields.collection ?? ''}/${target.fields.document ?? ''}`,
      detail: { field: fieldName },
    };
  }

  override sanitizeError(error: unknown): Promise<PublicError> {
    const status = error instanceof GoogleStatusError ? error.status : undefined;
    const mapping: Record<number, [string, string]> = {
      401: [ErrorCode.DESTINATION_DENIED, 'Veil is not authenticated to the destination.'],
      403: [ErrorCode.DESTINATION_DENIED, 'The destination denied access.'],
      404: [ErrorCode.DESTINATION_NOT_FOUND, 'The destination document was not found.'],
      409: [ErrorCode.DESTINATION_CONFLICT, 'The destination reported a conflict.'],
      429: [ErrorCode.DESTINATION_RATE_LIMITED, 'The destination rate limited the write.'],
      503: [ErrorCode.DESTINATION_UNAVAILABLE, 'The destination is unavailable.'],
    };
    const mapped = status === undefined ? undefined : mapping[status];
    if (mapped) return Promise.resolve(publicError(mapped[0], mapped[1]));
    return super.sanitizeError(error);
  }

  get #timeoutMs(): number {
    return this.config.adapterTimeoutSeconds * 1000;
  }

  #documentUrl(target: NormalizedTarget): string {
    const project = target.fields.project ?? '';
    const collection = target.fields.collection ?? '';
    const document = target.fields.document ?? '';
    return (
      `${FIRESTORE_BASE}/projects/${project}/databases/(default)/documents/` +
      `${encodeURIComponent(collection)}/${encodeURIComponent(document)}`
    );
  }

  async #getTransport(): Promise<GoogleTransport> {
    this.#transport ??= await createDefaultTransport(SCOPES);
    return this.#transport;
  }
}
