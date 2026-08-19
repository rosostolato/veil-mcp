/** Test doubles: adapters and provider transports that behave badly on purpose. */

import {
  SecretDestinationAdapter,
  adapterError,
  scalarString,
  type JsonSchema,
} from '../../src/adapters/base.js';
import type {
  GoogleRequest,
  GoogleResponse,
  GoogleTransport,
} from '../../src/adapters/googleTransport.js';
import type { VeilConfig } from '../../src/config.js';
import { ErrorCode, publicError, type PublicError } from '../../src/errors.js';
import {
  DestinationClass,
  Environment,
  RiskLevel,
  normalizedTarget,
  type NormalizedTarget,
  type PreflightResult,
  type RiskAssessment,
  type StoreResult,
} from '../../src/model.js';
import type { SecretBuffer } from '../../src/secretBuffer.js';

/** A well-behaved secret store that records what it was asked to write. */
export class RecordingAdapter extends SecretDestinationAdapter {
  readonly id: string = 'fake-store';
  readonly displayName: string = 'Fake Secret Store';
  readonly destinationClass = DestinationClass.SECRET_STORE;
  override readonly riskClass = RiskLevel.LOW;

  exists = false;
  /** [resourceLabel, secretText] pairs, in write order. */
  readonly writes: [string, string][] = [];
  /** The exact NormalizedTarget objects handed to `store`. */
  readonly targets: NormalizedTarget[] = [];
  readonly urls: string[] = [];

  constructor(config: VeilConfig, options: { exists?: boolean } = {}) {
    super(config);
    this.exists = options.exists ?? false;
  }

  targetSchema(): JsonSchema {
    return {
      type: 'object',
      additionalProperties: false,
      required: ['project', 'secret'],
      properties: {
        project: { type: 'string', maxLength: 64 },
        secret: { type: 'string', maxLength: 128 },
      },
    };
  }

  normalizeTarget(
    target: Readonly<Record<string, unknown>>,
    context: { name: string; environmentHint: Environment },
  ): Promise<NormalizedTarget> {
    const unknown = Object.keys(target).filter((key) => key !== 'project' && key !== 'secret');
    if (unknown.length > 0) {
      throw adapterError(ErrorCode.INVALID_TARGET, 'Unsupported target fields.');
    }
    const project = scalarString(target.project).trim();
    const secretId = (scalarString(target.secret) || context.name).trim();
    if (!project || !secretId) {
      throw adapterError(ErrorCode.INVALID_TARGET, 'The target is incomplete.');
    }
    return Promise.resolve(
      normalizedTarget({
        adapterId: this.id,
        destinationClass: this.destinationClass,
        providerLabel: 'Fake Secret Store',
        accountLabel: project,
        resourceLabel: secretId,
        environment: this.environmentFor(context.environmentHint, project, secretId, context.name),
        fields: { project, secret: secretId },
      }),
    );
  }

  override preflight(): Promise<PreflightResult> {
    return Promise.resolve({ ok: true, exists: this.exists });
  }

  calculateRisk(): Promise<RiskAssessment> {
    return Promise.resolve({ level: RiskLevel.LOW, reasons: [], requiresStageB: false });
  }

  store(secret: SecretBuffer, target: NormalizedTarget): Promise<StoreResult> {
    this.urls.push(
      `https://fake.invalid/v1/projects/${target.fields.project ?? ''}` +
        `/secrets/${target.fields.secret ?? ''}:addVersion`,
    );
    this.targets.push(target);
    this.writes.push([target.resourceLabel, secret.toText()]);
    return Promise.resolve({
      stored: true,
      destinationRef: `${target.fields.project ?? ''}/${target.fields.secret ?? ''}/versions/1`,
    });
  }
}

/** A provider whose error text contains the credential (SPEC.md §32). */
export class EchoingErrorAdapter extends RecordingAdapter {
  override readonly id = 'echoing-store';
  override readonly displayName = 'Echoing Store';

  override store(secret: SecretBuffer, target: NormalizedTarget): Promise<StoreResult> {
    throw new Error(`Failed storing "${secret.toText()}" at ${target.resourceLabel}`);
  }
}

/** An adapter whose own `sanitizeError` leaks. The broker must catch it. */
export class EchoingSanitizerAdapter extends RecordingAdapter {
  override readonly id = 'echoing-sanitizer';
  override readonly displayName = 'Echoing Sanitizer';

  override store(secret: SecretBuffer): Promise<StoreResult> {
    throw new Error(secret.toText());
  }

  override sanitizeError(error: unknown): Promise<PublicError> {
    return Promise.resolve(
      publicError(ErrorCode.DESTINATION_WRITE_FAILED, (error as Error).message),
    );
  }
}

/** An adapter that returns the credential inside its "non-sensitive" result. */
export class LeakyResultAdapter extends RecordingAdapter {
  override readonly id = 'leaky-result';
  override readonly displayName = 'Leaky Result Store';

  override store(secret: SecretBuffer): Promise<StoreResult> {
    return Promise.resolve({ stored: true, destinationRef: `stored:${secret.toText()}` });
  }
}

/** Sanitization itself fails; the broker must suppress rather than expose. */
export class RaisingSanitizerAdapter extends RecordingAdapter {
  override readonly id = 'broken-sanitizer';
  override readonly displayName = 'Broken Sanitizer Store';

  override store(): Promise<StoreResult> {
    throw new Error('provider exploded');
  }

  override sanitizeError(): Promise<PublicError> {
    throw new Error('sanitizer exploded');
  }
}

/** Never finishes in time; exercises the adapter timeout. */
export class SlowAdapter extends RecordingAdapter {
  override readonly id = 'slow-store';
  override readonly displayName = 'Slow Store';

  override store(): Promise<StoreResult> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        resolve({ stored: true });
      }, 30_000);
      timer.unref?.();
    });
  }
}

/** A store() the test finishes by hand, to drive late-completion races. */
export class DeferredAdapter extends RecordingAdapter {
  override readonly id = 'deferred-store';
  override readonly displayName = 'Deferred Store';

  #resolve: ((result: StoreResult) => void) | null = null;

  override store(_secret: SecretBuffer, target: NormalizedTarget): Promise<StoreResult> {
    return new Promise<StoreResult>((resolve) => {
      this.#resolve = (result): void => {
        this.targets.push(target);
        resolve(result);
      };
    });
  }

  /** Complete the pending write, as a provider eventually would. */
  finish(result: StoreResult = { stored: true, destinationRef: 'deferred/1' }): void {
    const resolve = this.#resolve;
    this.#resolve = null;
    resolve?.(result);
  }
}

/** An adapter returning a shape the broker must refuse. */
export class MalformedResultAdapter extends RecordingAdapter {
  override readonly id = 'malformed';
  override readonly displayName = 'Malformed Store';

  override store(secret: SecretBuffer): Promise<StoreResult> {
    return Promise.resolve({ secret: secret.toText() } as unknown as StoreResult);
  }
}

// -- provider transport doubles ---------------------------------------------

export interface RecordedRequest {
  readonly method: string;
  readonly url: string;
  readonly body: unknown;
}

export class FakeSecretManager {
  readonly requests: RecordedRequest[] = [];
  readonly payloads: [string, string][] = [];
  readonly disabled: string[] = [];
  existing = new Set<string>();
  versions = new Map<string, string[]>();
  failStatus: number | null = null;

  transport(): GoogleTransport {
    return (request: GoogleRequest): Promise<GoogleResponse> => {
      this.requests.push({ method: request.method, url: request.url, body: request.body });
      const url = request.url;

      if (request.method === 'GET' && url.endsWith('/versions')) {
        const parent = url.slice(url.indexOf('/v1/') + 4, url.length - '/versions'.length);
        const names = this.versions.get(parent) ?? [];
        return Promise.resolve({
          status: 200,
          body: { versions: names.map((name) => ({ name, state: 'ENABLED' })) },
        });
      }
      if (request.method === 'GET') {
        const name = url.slice(url.indexOf('/v1/') + 4);
        return Promise.resolve(
          this.existing.has(name) ? { status: 200, body: { name } } : { status: 404, body: null },
        );
      }
      if (url.includes('/secrets?secretId=')) {
        const project = url.slice(url.indexOf('/projects/') + 1, url.indexOf('/secrets?'));
        const secretId = decodeURIComponent(
          url.slice(url.indexOf('secretId=') + 'secretId='.length),
        );
        const name = `${project}/secrets/${secretId}`;
        if (this.existing.has(name)) return Promise.resolve({ status: 409, body: null });
        this.existing.add(name);
        return Promise.resolve({ status: 200, body: { name } });
      }
      if (url.endsWith(':addVersion')) {
        if (this.failStatus !== null) {
          return Promise.resolve({ status: this.failStatus, body: { error: 'provider failure' } });
        }
        const parent = url.slice(url.indexOf('/v1/') + 4, url.length - ':addVersion'.length);
        const data = (request.body as { payload: { data: string } }).payload.data;
        this.payloads.push([parent, Buffer.from(data, 'base64').toString('utf8')]);
        const names = this.versions.get(parent) ?? [];
        const name = `${parent}/versions/${names.length + 1}`;
        this.versions.set(parent, [...names, name]);
        return Promise.resolve({ status: 200, body: { name } });
      }
      if (url.endsWith(':disable')) {
        this.disabled.push(url.slice(url.indexOf('/v1/') + 4, url.length - ':disable'.length));
        return Promise.resolve({ status: 200, body: {} });
      }
      return Promise.resolve({ status: 404, body: null });
    };
  }
}

export class FakeFirestore {
  readonly documents = new Map<string, Record<string, unknown>>();
  readonly requests: RecordedRequest[] = [];

  transport(): GoogleTransport {
    return (request: GoogleRequest): Promise<GoogleResponse> => {
      this.requests.push({ method: request.method, url: request.url, body: request.body });
      const path = documentPath(request.url);

      if (request.method === 'GET') {
        const document = this.documents.get(path);
        return Promise.resolve(
          document ? { status: 200, body: { fields: document } } : { status: 404, body: null },
        );
      }
      const incoming = (request.body as { fields: Record<string, { stringValue: string }> }).fields;
      const current = this.documents.get(path) ?? {};
      this.documents.set(path, { ...current, ...incoming });
      return Promise.resolve({ status: 200, body: { name: path } });
    };
  }

  /** The stored plain values, for assertions. */
  values(path: string): Record<string, string> {
    const document = this.documents.get(path) ?? {};
    return Object.fromEntries(
      Object.entries(document).map(([key, value]) => [
        key,
        (value as { stringValue?: string }).stringValue ?? '',
      ]),
    );
  }
}

function documentPath(url: string): string {
  const withoutQuery = url.split('?')[0] ?? '';
  const marker = '/documents/';
  const index = withoutQuery.indexOf(marker);
  return index === -1 ? withoutQuery : withoutQuery.slice(index + marker.length);
}

/** A sink that swallows log output. */
export class DiscardStream {
  write(): boolean {
    return true;
  }
}
