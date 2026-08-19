/**
 * The secure input broker: state machine, custody and execution.
 *
 * Implements SPEC.md §11 (immutable authorization snapshot), §12 (destination
 * integrity), §14 (state machine), §18.5–§18.7 (TOCTOU, replay, cross-request
 * confusion), §20 (error sanitization) and §29–§30 (races and replay).
 *
 * Concurrency model
 * -----------------
 * Node runs this on one thread, so there are no locks. That is not a licence to
 * be careless: every check-then-act sequence on request state is written to
 * complete synchronously, with no `await` between the check and the transition.
 * Adapter I/O happens only after a request has been moved to EXECUTING, so a
 * slow provider cannot leave a request in a state another caller could claim.
 *
 * Secret custody
 * --------------
 * A `SecretBuffer` lives in exactly one `SecretRequest` and is reachable only
 * through it. There is no global secret table, no cache and no copy: a secret
 * submitted for request A is structurally incapable of reaching request B.
 */

import { z } from 'zod';

import { AdapterError, type SecretDestinationAdapter } from './adapters/base.js';
import type { AdapterRegistry } from './adapters/registry.js';
import type { VeilConfig } from './config.js';
import {
  ErrorCode,
  INTERNAL_ERROR,
  VeilError,
  publicError,
  publicErrorToJSON,
  veilError,
  type PublicError,
} from './errors.js';
import { newRequestId, newToken, tokenEquals } from './ids.js';
import { AuditLogger, getLogger } from './logging.js';
import {
  ALLOWED_TRANSITIONS,
  Environment,
  RequestState,
  WriteMode,
  deepFreeze,
  isTerminal,
  riskToPublic,
  snapshotDigest,
  storeResultToPublic,
  targetToPublic,
  type AuthorizationSnapshot,
  type StoreResult,
} from './model.js';
import { evaluateRisk } from './policy.js';
import { safeDisplay } from './redaction.js';
import { MAX_SECRET_BYTES, SecretBuffer, wipe } from './secretBuffer.js';

export const MAX_NAME_LENGTH = 128;
export const MAX_DESCRIPTION_LENGTH = 512;
export const MAX_TARGET_FIELDS = 12;
export const MAX_TARGET_VALUE_LENGTH = 1024;
export const TERMINAL_HISTORY_LIMIT = 512;

/** Validated, non-secret parameters of a `secret.store` call (SPEC.md §13). */
export interface StoreRequestParams {
  readonly destination: string;
  readonly name: string;
  readonly target: Readonly<Record<string, string | number | boolean>>;
  readonly writeMode: WriteMode;
  readonly environment: Environment;
  readonly description?: string;
}

/**
 * Server-side state for one credential request.
 *
 * `snapshot` is frozen at creation time; `authorizedDigest` is the digest the
 * human was shown. Execution recomputes the digest and refuses to proceed on any
 * divergence.
 */
export class SecretRequest {
  readonly requestId: string;
  readonly params: StoreRequestParams;
  adapter: SecretDestinationAdapter;
  snapshot: AuthorizationSnapshot;
  readonly authorizedDigest: string;
  readonly createdAt: number;
  expiresAt: number;
  state: RequestState = RequestState.CREATED;
  readonly submitToken = newToken();
  readonly confirmToken = newToken();
  secret: SecretBuffer | null = null;
  result: StoreResult | null = null;
  error: PublicError | null = null;
  confirmation: 'none' | 'implicit' | 'explicit' = 'none';
  supersededBy: string | null = null;
  executionClaimed = false;

  #terminalResolvers: (() => void)[] = [];

  constructor(init: {
    requestId: string;
    params: StoreRequestParams;
    adapter: SecretDestinationAdapter;
    snapshot: AuthorizationSnapshot;
    createdAt: number;
    expiresAt: number;
  }) {
    this.requestId = init.requestId;
    this.params = init.params;
    this.adapter = init.adapter;
    this.snapshot = init.snapshot;
    this.authorizedDigest = snapshotDigest(init.snapshot);
    this.createdAt = init.createdAt;
    this.expiresAt = init.expiresAt;
  }

  get requiresStageB(): boolean {
    return this.snapshot.risk.requiresStageB;
  }

  publicStatus(authorizationUrl?: string): Record<string, unknown> {
    const data: Record<string, unknown> = {
      request_id: this.requestId,
      state: this.state,
      operation: this.snapshot.operation,
      credential: safeDisplay(this.snapshot.logicalName),
      destination: targetToPublic(this.snapshot.target),
      risk: riskToPublic(this.snapshot.risk),
      requires_confirmation: this.requiresStageB,
      authorization_digest: this.authorizedDigest,
      terminal: isTerminal(this.state),
    };
    if (authorizationUrl && !isTerminal(this.state)) data.authorization_url = authorizationUrl;
    if (this.supersededBy) data.superseded_by = this.supersededBy;
    if (this.result) data.result = storeResultToPublic(this.result);
    if (this.error) data.error = publicErrorToJSON(this.error);
    return data;
  }

  whenTerminal(timeoutMs: number): Promise<void> {
    if (isTerminal(this.state)) return Promise.resolve();
    return new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        resolve();
      }, timeoutMs);
      timer.unref?.();
      this.#terminalResolvers.push(() => {
        clearTimeout(timer);
        resolve();
      });
    });
  }

  notifyTerminal(): void {
    const resolvers = this.#terminalResolvers;
    this.#terminalResolvers = [];
    for (const resolve of resolvers) resolve();
  }

  /** Never leak custody details through string conversion. */
  toString(): string {
    return `<SecretRequest ${this.requestId} ${this.state}>`;
  }
}

export type AuthorizationNotifier = (requestId: string, url: string) => void;

export class SecretBroker {
  readonly log: AuditLogger;
  #active = new Map<string, SecretRequest>();
  #history = new Map<string, SecretRequest>();
  #uiBaseUrl: string | null = null;
  #notifier: AuthorizationNotifier | null = null;
  #clock: () => number;

  constructor(
    readonly config: VeilConfig,
    readonly registry: AdapterRegistry,
    options: { logger?: AuditLogger; clock?: () => number } = {},
  ) {
    this.log = options.logger ?? getLogger();
    this.#clock = options.clock ?? ((): number => Date.now() / 1000);
    this.log.setTripwire((text) => this.containsLiveSecret(text));
  }

  // -- UI wiring -------------------------------------------------------------

  setUiBaseUrl(baseUrl: string | null): void {
    this.#uiBaseUrl = baseUrl ? baseUrl.replace(/\/+$/, '') : null;
  }

  /**
   * Register who presents a new request to the human (the UI).
   *
   * It is how the authorization window reaches the *person* without the URL
   * passing through the agent.
   */
  setAuthorizationNotifier(notifier: AuthorizationNotifier | null): void {
    this.#notifier = notifier;
  }

  authorizationUrl(request: SecretRequest): string | null {
    if (!this.#uiBaseUrl || isTerminal(request.state)) return null;
    return `${this.#uiBaseUrl}/r/${request.requestId}/${request.submitToken}`;
  }

  /**
   * The URL as the *agent* may see it — normally not at all.
   *
   * The link is a capability: anything holding it can complete Stage A. An agent
   * with a shell or an HTTP tool could therefore authorize its own request, so by
   * default Veil hands the link to the human's browser and gives the agent only a
   * request id (SPEC.md §4.2, §7).
   */
  disclosableAuthorizationUrl(request: SecretRequest): string | null {
    return this.config.discloseAuthorizationUrl ? this.authorizationUrl(request) : null;
  }

  // -- creation --------------------------------------------------------------

  async createRequest(params: StoreRequestParams): Promise<SecretRequest> {
    const adapter = this.registry.get(params.destination);
    if (!adapter.supportedWriteModes().includes(params.writeMode)) {
      throw veilError(
        ErrorCode.INVALID_ARGUMENTS,
        'The destination does not support the requested write mode.',
      );
    }

    const target = await this.#adapterCall(
      () =>
        adapter.normalizeTarget(params.target, {
          name: params.name,
          environmentHint: params.environment,
        }),
      ErrorCode.INVALID_TARGET,
      'The destination target could not be interpreted.',
    );
    if (target.adapterId !== adapter.id) {
      throw veilError(
        ErrorCode.INVALID_TARGET,
        'The destination adapter produced an inconsistent target.',
      );
    }

    const validation = await this.#adapterCall(
      () => adapter.validateTarget(target),
      ErrorCode.INVALID_TARGET,
      'The destination target could not be validated.',
    );
    if (!validation.ok) {
      throw veilError(
        validation.code ?? ErrorCode.INVALID_TARGET,
        validation.message ?? 'The destination target is not valid.',
      );
    }

    const preflight = await this.#adapterCall(
      () => adapter.preflight(target),
      ErrorCode.PREFLIGHT_FAILED,
      'The destination could not be prepared.',
    );
    if (!preflight.ok) {
      throw veilError(
        preflight.code ?? ErrorCode.PREFLIGHT_FAILED,
        preflight.message ?? 'The destination could not be prepared.',
      );
    }
    const exists = preflight.exists ?? false;

    const adapterRisk = await this.#adapterCall(
      () => adapter.calculateRisk(target, params.writeMode, { exists }),
      ErrorCode.PREFLIGHT_FAILED,
      'The destination could not be classified.',
    );
    const risk = evaluateRisk(this.config, {
      adapterAssessment: adapterRisk,
      adapterFloor: adapter.riskClass,
      target,
      operation: params.writeMode,
      claimedEnvironment: params.environment,
      exists,
    });

    const now = this.#clock();
    const requestId = newRequestId();
    const snapshot = deepFreeze<AuthorizationSnapshot>({
      requestId,
      logicalName: params.name,
      target,
      operation: params.writeMode,
      risk: deepFreeze({ ...risk, reasons: [...risk.reasons] }),
      createdAt: now,
      expiresAt: now + this.config.requestTtlSeconds,
      ...(params.description === undefined ? {} : { description: params.description }),
      existsAtPreflight: exists,
    });

    const request = new SecretRequest({
      requestId,
      params,
      adapter,
      snapshot,
      createdAt: now,
      expiresAt: snapshot.expiresAt,
    });

    this.#sweepExpired();
    if (this.#active.size >= this.config.maxActiveRequests) {
      throw veilError(
        ErrorCode.TOO_MANY_REQUESTS,
        'Too many credential requests are already pending.',
      );
    }
    this.#active.set(requestId, request);
    this.#transition(request, RequestState.PREFLIGHT);
    this.#transition(request, RequestState.AWAITING_SECRET_AUTHORIZATION);

    this.log.event('request_created', {
      request_id: requestId,
      adapter: adapter.id,
      destination: target.destinationClass,
      logical_name: safeDisplay(params.name, 80),
      environment: target.environment,
      operation: params.writeMode,
      risk: risk.level,
      stage: risk.requiresStageB ? 'A+B' : 'A',
      authorization_digest: request.authorizedDigest,
    });

    this.#notify(request);
    return request;
  }

  #notify(request: SecretRequest): void {
    const url = this.authorizationUrl(request);
    if (!this.#notifier || !url) return;
    try {
      this.#notifier(request.requestId, url);
    } catch {
      this.log.error('authorization_notify_failed', { request_id: request.requestId });
    }
  }

  // -- lookup ----------------------------------------------------------------

  get(requestId: unknown): SecretRequest {
    if (typeof requestId !== 'string') {
      throw veilError(ErrorCode.REQUEST_NOT_FOUND, 'Unknown credential request.');
    }
    const request = this.#active.get(requestId) ?? this.#history.get(requestId);
    if (!request) throw veilError(ErrorCode.REQUEST_NOT_FOUND, 'Unknown credential request.');
    this.#checkExpiry(request);
    return request;
  }

  publicStatus(requestId: unknown): Record<string, unknown> {
    const request = this.get(requestId);
    const status = request.publicStatus(this.disclosableAuthorizationUrl(request) ?? undefined);
    if (!('authorization_url' in status) && !isTerminal(request.state)) {
      status.authorization =
        'Veil has opened its own window on the user’s machine. Ask the user to ' +
        'complete it there; the link is deliberately not shared with you.';
    }
    return status;
  }

  activeIds(): readonly string[] {
    return [...this.#active.keys()];
  }

  // -- stage A ---------------------------------------------------------------

  /** Accept credential bytes for exactly one request (SPEC.md §18.7). */
  async submitSecret(requestId: unknown, token: string, raw: Buffer): Promise<void> {
    let buffer: SecretBuffer | null = null;
    try {
      if (raw.length === 0) {
        throw veilError(ErrorCode.EMPTY_SECRET, 'No credential value was provided.');
      }
      if (raw.length > MAX_SECRET_BYTES) {
        throw veilError(ErrorCode.SECRET_TOO_LARGE, 'The credential value is too large.');
      }
      buffer = new SecretBuffer(raw);

      // No `await` from here to the transition: the check and the act are one
      // step, so a concurrent submit cannot land between them.
      const request = this.get(requestId);
      this.#requireState(request, RequestState.AWAITING_SECRET_AUTHORIZATION);
      this.#requireToken(request, request.submitToken, token, 'A');

      request.secret = buffer;
      buffer = null; // ownership transferred to the request
      this.#transition(request, RequestState.SECRET_RECEIVED);
      request.confirmation = 'implicit';
      this.log.event('secret_received', {
        request_id: request.requestId,
        stage: 'A',
        risk: request.snapshot.risk.level,
      });

      if (request.requiresStageB) {
        this.#transition(request, RequestState.AWAITING_EXECUTION_CONFIRMATION);
        this.log.event('stage_b_required', {
          request_id: request.requestId,
          risk: request.snapshot.risk.level,
        });
        return;
      }
      if (this.#claimExecution(request)) await this.#execute(request);
    } finally {
      buffer?.zeroize();
      wipe(raw);
    }
  }

  // -- stage B ---------------------------------------------------------------

  async confirmExecution(requestId: unknown, token: string): Promise<void> {
    const request = this.get(requestId);
    this.#requireState(request, RequestState.AWAITING_EXECUTION_CONFIRMATION);
    this.#requireToken(request, request.confirmToken, token, 'B');
    request.confirmation = 'explicit';
    this.log.event('execution_confirmed', {
      request_id: request.requestId,
      stage: 'B',
      confirmation: 'explicit',
    });
    if (this.#claimExecution(request)) await this.#execute(request);
  }

  // -- cancellation / revision ----------------------------------------------

  cancel(requestId: unknown, options: { token?: string; reason?: string } = {}): void {
    const request = this.get(requestId);
    if (isTerminal(request.state)) {
      throw veilError(ErrorCode.REQUEST_NOT_ACTIVE, 'This credential request is no longer active.');
    }
    if (options.token !== undefined) {
      const valid =
        tokenEquals(request.submitToken, options.token) ||
        tokenEquals(request.confirmToken, options.token);
      if (!valid) {
        this.log.security('token_mismatch', { request_id: request.requestId, stage: 'C' });
        throw veilError(ErrorCode.UNAUTHORIZED, 'Invalid authorization token.');
      }
    }
    if (request.state === RequestState.EXECUTING) {
      throw veilError(
        ErrorCode.INVALID_STATE,
        'The operation is already executing and cannot be cancelled.',
      );
    }
    this.#finish(request, RequestState.CANCELLED, { reason: options.reason ?? 'user' });
  }

  /**
   * Any change to an authorized operation invalidates it (SPEC.md §11).
   *
   * The old request is cancelled and its secret destroyed; a brand-new request
   * with a fresh authorization flow is returned. There is no path that mutates
   * an existing snapshot.
   */
  async revise(requestId: unknown, params: StoreRequestParams): Promise<SecretRequest> {
    const existing = this.get(requestId);
    this.log.security('authorization_invalidated', {
      request_id: existing.requestId,
      reason: 'revision_requested',
      state: existing.state,
    });
    if (!isTerminal(existing.state)) {
      if (existing.state === RequestState.EXECUTING) {
        throw veilError(
          ErrorCode.INVALID_STATE,
          'The operation is already executing and cannot be revised.',
        );
      }
      this.#finish(existing, RequestState.CANCELLED, { reason: 'superseded' });
    }
    const created = await this.createRequest(params);
    existing.supersededBy = created.requestId;
    return created;
  }

  // -- maintenance -----------------------------------------------------------

  sweepExpired(): number {
    return this.#sweepExpired();
  }

  /** Destroy every live secret (used on exit and on crash). */
  shutdown(): void {
    for (const request of [...this.#active.values()]) {
      if (!isTerminal(request.state)) {
        this.#finish(request, RequestState.CANCELLED, { reason: 'shutdown' });
      }
      this.#destroySecret(request);
    }
  }

  /** Tripwire used by the logger, the MCP transport and the UI. */
  containsLiveSecret(text: string): boolean {
    if (!text) return false;
    for (const request of this.#active.values()) {
      const secret = request.secret;
      if (secret && !secret.destroyed && secret.containsIn(text)) return true;
    }
    return false;
  }

  async waitForTerminal(
    requestId: unknown,
    timeoutSeconds: number,
  ): Promise<Record<string, unknown>> {
    const request = this.get(requestId);
    await request.whenTerminal(timeoutSeconds * 1000);
    return this.publicStatus(request.requestId);
  }

  // -- internals -------------------------------------------------------------

  #requireState(request: SecretRequest, expected: RequestState): void {
    if (request.state === expected) return;
    if (isTerminal(request.state)) {
      this.log.security('reuse_attempt', {
        request_id: request.requestId,
        state: request.state,
      });
      const code =
        request.state === RequestState.EXPIRED
          ? ErrorCode.REQUEST_EXPIRED
          : request.state === RequestState.CANCELLED
            ? ErrorCode.REQUEST_CANCELLED
            : ErrorCode.REQUEST_NOT_ACTIVE;
      throw veilError(code, 'This credential request is no longer active.');
    }
    throw veilError(
      ErrorCode.INVALID_STATE,
      'The credential request is not at the expected stage.',
    );
  }

  #requireToken(request: SecretRequest, expected: string, provided: string, stage: string): void {
    if (typeof provided !== 'string' || !tokenEquals(expected, provided)) {
      this.log.security('token_mismatch', { request_id: request.requestId, stage });
      throw veilError(ErrorCode.UNAUTHORIZED, 'Invalid authorization token.');
    }
  }

  /** Single-flight guard against double submit and replay (SPEC.md §29). */
  #claimExecution(request: SecretRequest): boolean {
    if (request.executionClaimed) return false;
    request.executionClaimed = true;
    this.#transition(request, RequestState.EXECUTING);
    return true;
  }

  #transition(request: SecretRequest, toState: RequestState): void {
    if (!ALLOWED_TRANSITIONS[request.state].has(toState)) {
      throw veilError(
        ErrorCode.INVALID_STATE,
        'The credential request is not at the expected stage.',
      );
    }
    request.state = toState;
  }

  #checkExpiry(request: SecretRequest): void {
    if (isTerminal(request.state) || request.state === RequestState.EXECUTING) return;
    if (this.#clock() >= request.expiresAt) {
      this.#finish(request, RequestState.EXPIRED, { reason: 'ttl' });
    }
  }

  #sweepExpired(): number {
    let count = 0;
    for (const request of [...this.#active.values()]) {
      const before = request.state;
      this.#checkExpiry(request);
      if (request.state !== before) count += 1;
    }
    return count;
  }

  #finish(
    request: SecretRequest,
    state: RequestState,
    options: { reason?: string; result?: StoreResult; error?: PublicError } = {},
  ): void {
    request.state = state;
    request.result = options.result ?? null;
    request.error = options.error ?? null;
    this.#destroySecret(request);
    this.#active.delete(request.requestId);
    this.#history.set(request.requestId, request);
    while (this.#history.size > TERMINAL_HISTORY_LIMIT) {
      const oldest = this.#history.keys().next().value;
      if (oldest === undefined) break;
      this.#history.delete(oldest);
    }
    request.notifyTerminal();
    this.log.event('request_finished', {
      request_id: request.requestId,
      state,
      reason: options.reason ?? '',
      result: state === RequestState.STORED ? 'success' : 'failure',
      confirmation: request.confirmation,
      adapter: request.snapshot.target.adapterId,
      operation: request.snapshot.operation,
      logical_name: safeDisplay(request.snapshot.logicalName, 80),
      environment: request.snapshot.target.environment,
      risk: request.snapshot.risk.level,
      error_code: options.error?.code ?? '',
    });
  }

  #destroySecret(request: SecretRequest): void {
    const secret = request.secret;
    request.secret = null;
    secret?.zeroize();
  }

  /** Perform exactly the authorized operation (SPEC.md §4.3, §11, §12). */
  async #execute(request: SecretRequest): Promise<void> {
    const started = Date.now();
    const snapshot = request.snapshot;
    const adapter = request.adapter;
    const secret = request.secret;

    try {
      if (snapshotDigest(snapshot) !== request.authorizedDigest) {
        throw veilError(
          ErrorCode.SNAPSHOT_MISMATCH,
          'The authorized operation changed and can no longer be executed.',
        );
      }
      if (
        adapter.id !== snapshot.target.adapterId ||
        adapter !== this.registry.get(snapshot.target.adapterId)
      ) {
        throw veilError(
          ErrorCode.SNAPSHOT_MISMATCH,
          'The authorized destination adapter changed and cannot be executed.',
        );
      }
      if (!secret || secret.destroyed) {
        throw veilError(ErrorCode.INVALID_STATE, 'No credential value is available.');
      }
      if (snapshot.risk.requiresStageB && request.confirmation !== 'explicit') {
        throw veilError(
          ErrorCode.CONFIRMATION_REQUIRED,
          'This operation requires explicit confirmation before execution.',
        );
      }
    } catch (error) {
      const publicRepresentation = error instanceof VeilError ? error.public : INTERNAL_ERROR;
      this.#finish(request, RequestState.FAILED, {
        reason: 'precondition',
        error: publicRepresentation,
      });
      this.log.security('execution_blocked', {
        request_id: request.requestId,
        code: publicRepresentation.code,
      });
      return;
    }

    this.log.event('execution_started', {
      request_id: request.requestId,
      adapter: adapter.id,
      operation: snapshot.operation,
      authorization_digest: request.authorizedDigest,
    });

    let result: StoreResult | null = null;
    let failure: PublicError | null = null;
    try {
      result = await withTimeout(
        adapter.store(secret, snapshot.target, snapshot.operation),
        this.config.adapterTimeoutSeconds * 1000,
      );
      if (!result || typeof result !== 'object' || typeof result.stored !== 'boolean') {
        throw new AdapterError(
          publicError(
            ErrorCode.INTERNAL_ERROR,
            'The destination adapter returned an unusable result.',
          ),
        );
      }
      failure = this.#scrubResult(request, result);
      if (failure) result = null;
    } catch (error) {
      failure =
        error instanceof VeilError ? error.public : await this.#sanitize(request, adapter, error);
    }

    const durationMs = Date.now() - started;
    if (!failure && result) {
      this.#finish(request, RequestState.STORED, { reason: 'stored', result });
    } else {
      this.#finish(request, RequestState.FAILED, {
        reason: 'adapter',
        error: failure ?? INTERNAL_ERROR,
      });
    }
    this.log.event('execution_finished', {
      request_id: request.requestId,
      adapter: adapter.id,
      duration_ms: durationMs,
      result: failure ? 'failure' : 'success',
      error_code: failure?.code ?? '',
    });
  }

  /** Translate a provider error without ever echoing it (SPEC.md §20). */
  async #sanitize(
    request: SecretRequest,
    adapter: SecretDestinationAdapter,
    error: unknown,
  ): Promise<PublicError> {
    if (error instanceof TimeoutError) {
      return publicError(ErrorCode.DESTINATION_TIMEOUT, 'The destination did not respond in time.');
    }

    let candidate: PublicError;
    try {
      candidate = await adapter.sanitizeError(error);
      if (
        !candidate ||
        typeof candidate.code !== 'string' ||
        typeof candidate.message !== 'string'
      ) {
        return INTERNAL_ERROR;
      }
    } catch {
      this.log.security('sanitization_failed', { request_id: request.requestId });
      return INTERNAL_ERROR;
    }

    const rendered = `${candidate.code} ${candidate.message} ${JSON.stringify(candidate.detail ?? {})}`;
    const secret = request.secret;
    if (secret && !secret.destroyed && secret.containsIn(rendered)) {
      this.log.security('sanitized_error_contained_secret', {
        request_id: request.requestId,
        code: 'TRIPWIRE',
      });
      return INTERNAL_ERROR;
    }
    if (this.containsLiveSecret(rendered)) {
      this.log.security('tripwire_blocked_error', { request_id: request.requestId });
      return INTERNAL_ERROR;
    }
    return publicError(
      safeDisplay(candidate.code, 64),
      safeDisplay(candidate.message, 300),
      candidate.detail
        ? Object.fromEntries(
            Object.entries(candidate.detail).map(([key, value]) => [
              safeDisplay(key, 40),
              safeDisplay(String(value), 200),
            ]),
          )
        : undefined,
    );
  }

  /** Refuse to publish a result that carries credential material. */
  #scrubResult(request: SecretRequest, result: StoreResult): PublicError | null {
    const rendered = JSON.stringify(storeResultToPublic(result));
    const secret = request.secret;
    if (
      (secret && !secret.destroyed && secret.containsIn(rendered)) ||
      this.containsLiveSecret(rendered)
    ) {
      this.log.security('adapter_result_contained_secret', {
        request_id: request.requestId,
        adapter: request.snapshot.target.adapterId,
      });
      return publicError(
        ErrorCode.INTERNAL_ERROR,
        'The destination reported a result that could not be safely returned.',
      );
    }
    return null;
  }

  /**
   * Run a pre-secret adapter step, translating failures safely.
   *
   * An adapter may describe its own refusal through `AdapterError`; anything
   * else it throws is replaced with a generic public error, because an unplanned
   * error's text is not ours to trust (SPEC.md §20).
   */
  async #adapterCall<T>(
    call: () => Promise<T>,
    fallbackCode: string,
    fallbackMessage: string,
  ): Promise<T> {
    try {
      return await call();
    } catch (error) {
      if (error instanceof AdapterError) throw new VeilError(error.public);
      if (error instanceof VeilError) throw error;
      this.log.error('adapter_step_failed', { code: fallbackCode });
      throw veilError(fallbackCode, fallbackMessage);
    }
  }
}

export class TimeoutError extends Error {
  constructor() {
    super('adapter_timeout');
    this.name = 'TimeoutError';
  }
}

/**
 * Bound an adapter call.
 *
 * The underlying work may continue in the background — JavaScript cannot cancel
 * an arbitrary promise — but the request stops waiting, is finalized, and its
 * secret is destroyed. Adapters additionally pass provider-level timeouts so the
 * abandoned work really does stop.
 */
export async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          reject(new TimeoutError());
        }, timeoutMs);
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// -- parameter validation ----------------------------------------------------

const targetValue = z.union([z.string().max(MAX_TARGET_VALUE_LENGTH), z.number(), z.boolean()]);

export const storeParamsSchema = z
  .object({
    destination: z.string(),
    name: z.string().trim().min(1).max(MAX_NAME_LENGTH),
    target: z.record(z.string(), targetValue),
    write_mode: z.enum([WriteMode.CREATE, WriteMode.NEW_VERSION, WriteMode.REPLACE]).optional(),
    environment: z
      .enum([
        Environment.DEVELOPMENT,
        Environment.STAGING,
        Environment.PRODUCTION,
        Environment.UNKNOWN,
      ])
      .optional(),
    description: z.string().max(MAX_DESCRIPTION_LENGTH).optional(),
  })
  .strict();

/**
 * Validate `secret.store` arguments (SPEC.md §6, §13, §18.3).
 *
 * Structural rejection of secret-shaped input happens here and in the MCP schema
 * layer: unknown fields are refused rather than ignored, so a malicious agent
 * cannot smuggle credential material through an unmodelled property.
 */
export function parseStoreParams(payload: unknown, registry: AdapterRegistry): StoreRequestParams {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw veilError(ErrorCode.INVALID_ARGUMENTS, 'Arguments must be an object.');
  }

  const allowed = new Set([
    'destination',
    'name',
    'target',
    'write_mode',
    'description',
    'environment',
  ]);
  const unknown = Object.keys(payload).filter((key) => !allowed.has(key));
  if (unknown.length > 0) {
    throw veilError(
      ErrorCode.FORBIDDEN_FIELD,
      'The request contained fields that are not part of the tool contract.',
      {
        fields: unknown
          .slice(0, 5)
          .map((key) => safeDisplay(key, 40))
          .join(', '),
      },
    );
  }

  const parsed = storeParamsSchema.safeParse(payload);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const path = issue?.path.join('.') ?? '';
    if (path.startsWith('target')) {
      throw veilError(ErrorCode.INVALID_TARGET, 'The destination target is not valid.');
    }
    if (path === 'destination') {
      throw veilError(ErrorCode.UNKNOWN_DESTINATION, 'The requested destination is not available.');
    }
    throw veilError(ErrorCode.INVALID_ARGUMENTS, 'The request arguments are not valid.');
  }

  const value = parsed.data;
  if (!registry.has(value.destination)) {
    throw veilError(ErrorCode.UNKNOWN_DESTINATION, 'The requested destination is not available.');
  }
  if (Object.keys(value.target).length > MAX_TARGET_FIELDS) {
    throw veilError(ErrorCode.INVALID_TARGET, 'The destination target has too many fields.');
  }

  return {
    destination: value.destination,
    name: value.name.trim(),
    target: Object.freeze({ ...value.target }),
    writeMode: value.write_mode ?? WriteMode.CREATE,
    environment: value.environment ?? Environment.UNKNOWN,
    ...(value.description === undefined ? {} : { description: value.description }),
  };
}
