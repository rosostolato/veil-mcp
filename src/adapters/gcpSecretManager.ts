/**
 * Google Secret Manager adapter (SPEC.md §16 `secret-store`, §17).
 *
 * The credential travels in the body of an authenticated HTTPS request: never in
 * a URL, never in an argv, never in a shell string (SEC-007, SEC-008, SEC-009).
 * Errors are mapped by HTTP status only — a provider message is never repeated.
 */

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
  GoogleStatusError,
  SECRET_MANAGER_BASE,
  createDefaultTransport,
  type GoogleTransport,
} from './googleTransport.js';

export const PROJECT_PATTERN = /^(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{6,20})$/;
export const SECRET_PATTERN = /^[A-Za-z0-9_-]{1,255}$/;
const SCOPES = ['https://www.googleapis.com/auth/cloud-platform'];

export class GcpSecretManagerAdapter extends SecretDestinationAdapter {
  readonly id = 'gcp-secret-manager';
  readonly displayName = 'Google Secret Manager';
  readonly destinationClass = DestinationClass.SECRET_STORE;
  override readonly riskClass = RiskLevel.LOW;

  #transport: GoogleTransport | undefined;

  constructor(
    config: ConstructorParameters<typeof SecretDestinationAdapter>[0],
    transport?: GoogleTransport,
  ) {
    super(config);
    this.#transport = transport;
  }

  targetSchema(): JsonSchema {
    return {
      type: 'object',
      additionalProperties: false,
      required: ['project', 'secret'],
      properties: {
        project: {
          type: 'string',
          maxLength: 64,
          description: 'Google Cloud project id or number that owns the secret.',
        },
        secret: {
          type: 'string',
          maxLength: 255,
          description: 'Secret id within the project.',
        },
      },
    };
  }

  normalizeTarget(
    target: Readonly<Record<string, unknown>>,
    context: { name: string; environmentHint: Environment },
  ): Promise<NormalizedTarget> {
    const unknown = Object.keys(target).filter((key) => key !== 'project' && key !== 'secret');
    if (unknown.length > 0) {
      throw adapterError(
        ErrorCode.INVALID_TARGET,
        'The destination target contained unsupported fields.',
      );
    }
    const project = scalarString(target.project).trim();
    const secretId = (scalarString(target.secret) || context.name).trim();

    if (!PROJECT_PATTERN.test(project)) {
      throw adapterError(
        ErrorCode.INVALID_TARGET,
        'The Google Cloud project identifier is not valid.',
      );
    }
    if (!SECRET_PATTERN.test(secretId)) {
      throw adapterError(ErrorCode.INVALID_TARGET, 'The secret id is not valid.');
    }

    return Promise.resolve(
      normalizedTarget({
        adapterId: this.id,
        destinationClass: this.destinationClass,
        providerLabel: 'Google Secret Manager',
        accountLabel: project,
        resourceLabel: secretId,
        environment: this.environmentFor(context.environmentHint, project, secretId, context.name),
        fields: {
          project,
          secret: secretId,
          resource_name: `projects/${project}/secrets/${secretId}`,
        },
      }),
    );
  }

  override validateTarget(target: NormalizedTarget): Promise<ValidationResult> {
    if (!target.fields.project || !target.fields.secret) {
      return Promise.resolve({
        ok: false,
        code: ErrorCode.INVALID_TARGET,
        message: 'The destination target is incomplete.',
      });
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
        message: 'Google Secret Manager is not configured on this machine.',
      };
    }

    const response = await transport({
      method: 'GET',
      url: `${SECRET_MANAGER_BASE}/${target.fields.resource_name ?? ''}`,
      timeoutMs: this.#timeoutMs,
    }).catch(() => null);

    if (!response || response.status !== 200) {
      return { ok: true, exists: false, notes: ['The secret does not exist yet.'] };
    }
    return {
      ok: true,
      exists: true,
      notes: ['The secret already exists; a new version will be added.'],
    };
  }

  calculateRisk(_target: NormalizedTarget, operation: WriteMode): Promise<RiskAssessment> {
    if (operation === WriteMode.REPLACE) {
      return Promise.resolve({
        level: RiskLevel.MEDIUM,
        reasons: ['Previous versions of this secret will be disabled.'],
        requiresStageB: false,
      });
    }
    return Promise.resolve({ level: RiskLevel.LOW, reasons: [], requiresStageB: false });
  }

  async store(
    secret: SecretBuffer,
    target: NormalizedTarget,
    operation: WriteMode,
  ): Promise<StoreResult> {
    const transport = await this.#getTransport();
    const project = target.fields.project ?? '';
    const secretId = target.fields.secret ?? '';
    const resourceName = target.fields.resource_name ?? `projects/${project}/secrets/${secretId}`;

    if (operation === WriteMode.CREATE) {
      await this.#call(transport, {
        method: 'POST',
        url: `${SECRET_MANAGER_BASE}/projects/${project}/secrets?secretId=${encodeURIComponent(secretId)}`,
        body: { replication: { automatic: {} } },
        timeoutMs: this.#timeoutMs,
      });
    }

    const previousVersions =
      operation === WriteMode.REPLACE ? await this.#enabledVersions(transport, resourceName) : [];

    // The one request that carries credential material, and it carries it in
    // the body over TLS.
    const added = await this.#call(transport, {
      method: 'POST',
      url: `${SECRET_MANAGER_BASE}/${resourceName}:addVersion`,
      body: { payload: { data: secret.toBytes().toString('base64') } },
      timeoutMs: this.#timeoutMs,
    });

    const versionName =
      (added as { name?: string } | null)?.name ?? `${resourceName}/versions/latest`;

    let disabled = 0;
    let failedDisables = 0;
    for (const previous of previousVersions) {
      if (previous === versionName) continue;
      try {
        await this.#call(transport, {
          method: 'POST',
          url: `${SECRET_MANAGER_BASE}/${previous}:disable`,
          body: {},
          timeoutMs: this.#timeoutMs,
        });
        disabled += 1;
      } catch {
        // Surfaced as a count in the result; the provider's own message is
        // never propagated (SPEC.md §20). The credential write already
        // succeeded, so this must not fail the operation.
        failedDisables += 1;
      }
    }

    const detail: Record<string, string> = { operation };
    if (disabled > 0) detail.disabled_previous_versions = String(disabled);
    if (failedDisables > 0) detail.previous_versions_still_enabled = String(failedDisables);
    return { stored: true, destinationRef: versionName, detail };
  }

  /** Map provider failures by status code only — never by message. */
  override sanitizeError(error: unknown): Promise<PublicError> {
    const status = error instanceof GoogleStatusError ? error.status : undefined;
    const mapping: Record<number, [string, string]> = {
      400: [ErrorCode.INVALID_TARGET, 'The destination rejected the request as invalid.'],
      401: [ErrorCode.DESTINATION_DENIED, 'Veil is not authenticated to the destination.'],
      403: [ErrorCode.DESTINATION_DENIED, 'The destination denied access.'],
      404: [ErrorCode.DESTINATION_NOT_FOUND, 'The destination resource was not found.'],
      409: [ErrorCode.DESTINATION_CONFLICT, 'The destination resource already exists.'],
      429: [ErrorCode.DESTINATION_RATE_LIMITED, 'The destination rate limited the write.'],
      500: [ErrorCode.DESTINATION_WRITE_FAILED, 'The destination reported an error.'],
      503: [ErrorCode.DESTINATION_UNAVAILABLE, 'The destination is unavailable.'],
      504: [ErrorCode.DESTINATION_TIMEOUT, 'The destination did not respond in time.'],
    };
    const mapped = status === undefined ? undefined : mapping[status];
    if (mapped) return Promise.resolve(publicError(mapped[0], mapped[1]));

    if (error instanceof Error && (error.name === 'TimeoutError' || error.name === 'AbortError')) {
      return Promise.resolve(
        publicError(ErrorCode.DESTINATION_TIMEOUT, 'The destination did not respond in time.'),
      );
    }
    return super.sanitizeError(error);
  }

  get #timeoutMs(): number {
    return this.config.adapterTimeoutSeconds * 1000;
  }

  async #call(
    transport: GoogleTransport,
    request: Parameters<GoogleTransport>[0],
  ): Promise<unknown> {
    const response = await transport(request);
    if (response.status < 200 || response.status >= 300) {
      throw new GoogleStatusError(response.status);
    }
    return response.body;
  }

  async #enabledVersions(transport: GoogleTransport, resourceName: string): Promise<string[]> {
    try {
      const body = (await this.#call(transport, {
        method: 'GET',
        url: `${SECRET_MANAGER_BASE}/${resourceName}/versions`,
        timeoutMs: this.#timeoutMs,
      })) as { versions?: { name?: string; state?: string }[] } | null;
      return (body?.versions ?? [])
        .filter((version) => version.state === 'ENABLED')
        .map((version) => version.name)
        .filter((name): name is string => typeof name === 'string');
    } catch {
      return [];
    }
  }

  async #getTransport(): Promise<GoogleTransport> {
    this.#transport ??= await createDefaultTransport(SCOPES);
    return this.#transport;
  }
}
