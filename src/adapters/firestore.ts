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
const FIELD_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const SCOPES = ['https://www.googleapis.com/auth/datastore'];

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
          description: 'Document field to set. Defaults to the credential name.',
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
    if (!FIELD_PATTERN.test(field)) {
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
    const fields = (response.body as { fields?: Record<string, unknown> } | null)?.fields ?? {};
    const fieldName = target.fields.field ?? '';
    return {
      ok: true,
      exists: Object.hasOwn(fields, fieldName),
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

    if (operation === WriteMode.CREATE) {
      const existing = await transport({
        method: 'GET',
        url: this.#documentUrl(target),
        timeoutMs: this.#timeoutMs,
      }).catch(() => null);
      const fields =
        (existing?.body as { fields?: Record<string, unknown> } | null)?.fields ?? undefined;
      if (existing?.status === 200 && fields && Object.hasOwn(fields, fieldName)) {
        throw adapterError(
          ErrorCode.DESTINATION_CONFLICT,
          'The document field already exists; a replace operation is required.',
        );
      }
    }

    const response = await transport({
      method: 'PATCH',
      url: `${this.#documentUrl(target)}?updateMask.fieldPaths=${encodeURIComponent(fieldName)}`,
      body: { fields: { [fieldName]: { stringValue: secret.toText() } } },
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
