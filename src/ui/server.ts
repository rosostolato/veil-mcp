/**
 * Loopback secure-input UI (SPEC.md §7, §8, §9, §34).
 *
 * This is the trusted boundary the human interacts with. It binds to the
 * loopback interface only, rejects non-loopback `Host` headers (DNS rebinding),
 * never places credential material in a URL or a log line, uses POST/redirect/GET
 * so the back button cannot resubmit a secret, and passes every rendered page
 * through the broker's tripwire before it is sent.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { spawn } from 'node:child_process';

import type { SecretBroker, SecretRequest } from '../broker.js';
import type { VeilConfig } from '../config.js';
import { ErrorCode, VeilError, veilError } from '../errors.js';
import { tokenEquals } from '../ids.js';
import { AuditLogger, getLogger } from '../logging.js';
import { RequestState } from '../model.js';
import { MAX_SECRET_BYTES, wipe } from '../secretBuffer.js';
import * as render from './render.js';

export const MAX_BODY_BYTES = MAX_SECRET_BYTES + 4096;
/**
 * How much of an oversized body to read and throw away before hanging up.
 *
 * Draining a bounded amount lets the client see the 413 instead of a connection
 * reset; past that, the sender is not worth the bandwidth.
 */
export const DRAIN_LIMIT_BYTES = 1 << 20;
/**
 * Above this many pending requests Veil stops opening windows by itself: an
 * agent that spams `secret.store` must not be able to carpet the screen.
 */
export const MAX_AUTO_OPENED_WINDOWS = 3;

const ALLOWED_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

/** The exact shape of a Veil authorization URL, and nothing else. */
const OPENABLE_URL =
  /^http:\/\/(?:127\.0\.0\.1|localhost|\[::1\]):\d{1,5}\/r\/[A-Za-z0-9_-]{1,64}\/[A-Za-z0-9_-]{1,128}$/;

const STATUS_FOR_CODE: Record<string, number> = {
  [ErrorCode.REQUEST_NOT_FOUND]: 404,
  [ErrorCode.UNAUTHORIZED]: 403,
  [ErrorCode.REQUEST_EXPIRED]: 410,
  [ErrorCode.REQUEST_CANCELLED]: 410,
  [ErrorCode.REQUEST_NOT_ACTIVE]: 410,
  [ErrorCode.INVALID_STATE]: 409,
  [ErrorCode.EMPTY_SECRET]: 400,
  [ErrorCode.SECRET_TOO_LARGE]: 413,
};

export class SecureInputUI {
  readonly identity = render.newIdentityPhrase();
  readonly log: AuditLogger;
  #server: Server | null = null;
  #baseUrl: string | null = null;

  constructor(
    readonly broker: SecretBroker,
    readonly config: VeilConfig,
    options: { logger?: AuditLogger } = {},
  ) {
    this.log = options.logger ?? getLogger();
  }

  get baseUrl(): string | null {
    return this.#baseUrl;
  }

  async start(): Promise<string> {
    const server = createServer((request, response) => {
      this.#handle(request, response).catch(() => {
        this.#sendPage(response, 500, (nonce) =>
          render.messagePage('Error', 'The request could not be completed.', {
            nonce,
            identity: this.identity,
          }),
        );
      });
    });

    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(this.config.uiPort, this.config.uiHost, () => {
        server.off('error', reject);
        resolve();
      });
    });

    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('failed to bind the secure UI');
    const host = address.address.includes(':') ? `[${address.address}]` : address.address;
    this.#baseUrl = `http://${host}:${address.port}`;
    this.#server = server;
    this.broker.setUiBaseUrl(this.#baseUrl);
    this.broker.setAuthorizationNotifier((requestId, url) => {
      this.present(requestId, url);
    });
    this.log.event('ui_started', {
      component: 'ui',
      detail: { url: this.#baseUrl, identity: this.identity },
    });
    return this.#baseUrl;
  }

  /**
   * Show a new request to the human, not to the agent.
   *
   * The URL is printed to Veil's own console — the operator's channel — and,
   * unless disabled, opened directly in the user's browser. It is not returned
   * through MCP by default (SPEC.md §4.2, §7).
   */
  present(requestId: string, url: string): void {
    this.log.event('authorization_requested', {
      request_id: requestId,
      component: 'ui',
      detail: { url, identity: this.identity },
    });
    if (!this.config.openBrowser) return;
    if (this.broker.activeIds().length > MAX_AUTO_OPENED_WINDOWS) {
      this.log.event('browser_open_suppressed', { request_id: requestId, component: 'ui' });
      return;
    }
    // Belt and braces: the URL is generated here, but nothing that reaches a
    // command line is trusted on the strength of where it came from.
    if (!OPENABLE_URL.test(url)) {
      this.log.security('browser_open_refused', { request_id: requestId, component: 'ui' });
      return;
    }
    try {
      const opener =
        process.platform === 'darwin'
          ? { command: 'open', args: [url] }
          : process.platform === 'win32'
            ? // `cmd /c start` would re-parse the argument; explorer.exe takes
              // it literally.
              { command: 'explorer.exe', args: [url] }
            : { command: 'xdg-open', args: [url] };
      // No shell anywhere in this path.
      const child = spawn(opener.command, opener.args, { stdio: 'ignore', detached: true });
      child.on('error', () => {
        this.log.event('browser_open_failed', { request_id: requestId, component: 'ui' });
      });
      child.unref();
    } catch {
      this.log.event('browser_open_failed', { request_id: requestId, component: 'ui' });
    }
  }

  async stop(): Promise<void> {
    this.broker.setAuthorizationNotifier(null);
    const server = this.#server;
    this.#server = null;
    if (server) {
      await new Promise<void>((resolve) => {
        server.closeAllConnections?.();
        server.close(() => {
          resolve();
        });
      });
    }
    this.broker.setUiBaseUrl(null);
  }

  // -- request handling ------------------------------------------------------

  async #handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    if (!this.#hostOk(request)) {
      this.#errorPage(response, 400, 'Invalid Host header.');
      return;
    }
    const parts = splitPath(request.url ?? '/');

    if (request.method === 'GET') {
      if (parts.length === 3 && parts[0] === 'r') {
        this.#view(response, parts[1] as string, parts[2] as string);
        return;
      }
      this.#errorPage(response, 404, 'Nothing to see here.');
      return;
    }

    if (request.method !== 'POST') {
      this.#errorPage(response, 405, 'Unsupported method.');
      return;
    }
    if (parts.length !== 4 || parts[0] !== 'r') {
      this.#errorPage(response, 404, 'Nothing to see here.');
      return;
    }

    const [, requestId, token, action] = parts as [string, string, string, string];
    const declared = Number(request.headers['content-length'] ?? '0');
    if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
      // Do not read a hostile body; answer and drop the connection.
      response.setHeader('connection', 'close');
      this.#errorPage(response, 413, 'The submitted value is too large.');
      request.destroy();
      return;
    }

    const { body, tooLarge } = await readBody(request);
    if (tooLarge) {
      response.setHeader('connection', 'close');
      this.#errorPage(response, 413, 'The submitted value is too large.');
      return;
    }
    try {
      switch (action) {
        case 'submit':
          await this.#submit(requestId, token, body);
          break;
        case 'confirm':
          await this.#confirm(requestId, token, body);
          break;
        case 'cancel':
          this.#cancel(requestId, token);
          break;
        default:
          this.#errorPage(response, 404, 'Unsupported action.');
          return;
      }
    } catch (error) {
      if (error instanceof VeilError) {
        this.#errorPage(response, STATUS_FOR_CODE[error.public.code] ?? 400, error.public.message);
        return;
      }
      throw error;
    } finally {
      wipe(body);
    }

    // POST/redirect/GET: the back button cannot resubmit a credential.
    response.writeHead(303, {
      location: `/r/${encodeURIComponent(requestId)}/${encodeURIComponent(token)}`,
      'cache-control': 'no-store',
      'content-length': '0',
    });
    response.end();
  }

  #hostOk(request: IncomingMessage): boolean {
    return isLoopbackHost(request.headers.host ?? '');
  }

  #resolve(requestId: string, token: string): SecretRequest {
    const request = this.broker.get(requestId);
    if (!tokenEquals(request.submitToken, token) && !tokenEquals(request.confirmToken, token)) {
      this.log.security('ui_token_mismatch', { request_id: request.requestId, component: 'ui' });
      throw veilError(ErrorCode.UNAUTHORIZED, 'Invalid or expired authorization link.');
    }
    return request;
  }

  #view(response: ServerResponse, requestId: string, token: string): void {
    let request: SecretRequest;
    try {
      request = this.#resolve(requestId, token);
    } catch (error) {
      if (error instanceof VeilError) {
        this.#errorPage(response, STATUS_FOR_CODE[error.public.code] ?? 400, error.public.message);
        return;
      }
      throw error;
    }

    const basePath = `/r/${request.requestId}/${token}`;
    if (request.state === RequestState.AWAITING_SECRET_AUTHORIZATION) {
      this.#sendPage(response, 200, (nonce) =>
        render.stageAPage(request, { nonce, identity: this.identity, basePath }),
      );
      return;
    }
    if (request.state === RequestState.AWAITING_EXECUTION_CONFIRMATION) {
      this.#sendPage(response, 200, (nonce) =>
        render.stageBPage(request, {
          nonce,
          identity: this.identity,
          basePath,
          confirmToken: request.confirmToken,
        }),
      );
      return;
    }
    this.#sendPage(response, 200, (nonce) =>
      render.statusPage(request, { nonce, identity: this.identity }),
    );
  }

  async #submit(requestId: string, token: string, body: Buffer): Promise<void> {
    const request = this.#resolve(requestId, token);
    const value = formValue(body, 'secret');
    try {
      await this.broker.submitSecret(request.requestId, request.submitToken, value);
    } finally {
      wipe(value);
    }
    this.log.event('ui_secret_submitted', {
      request_id: request.requestId,
      component: 'ui',
      state: request.state,
    });
  }

  async #confirm(requestId: string, token: string, body: Buffer): Promise<void> {
    const request = this.#resolve(requestId, token);
    const provided = formValue(body, 'confirm_token').toString('utf8');
    await this.broker.confirmExecution(request.requestId, provided);
  }

  #cancel(requestId: string, token: string): void {
    const request = this.#resolve(requestId, token);
    this.broker.cancel(request.requestId, { token, reason: 'user_cancelled' });
  }

  #sendPage(response: ServerResponse, status: number, build: (nonce: string) => string): void {
    const nonce = render.newNonce();
    let html = build(nonce);
    let code = status;
    if (this.broker.containsLiveSecret(html)) {
      this.log.security('ui_response_blocked', { component: 'ui', status_code: status });
      html = render.messagePage(
        'Blocked',
        'The page could not be rendered safely and was suppressed.',
        { nonce, identity: this.identity },
      );
      code = 500;
    }
    const payload = Buffer.from(html, 'utf8');
    response.writeHead(code, {
      ...render.securityHeaders(nonce),
      'content-length': String(payload.byteLength),
    });
    response.end(payload);
  }

  #errorPage(response: ServerResponse, status: number, message: string): void {
    this.#sendPage(response, status, (nonce) =>
      render.messagePage('Credential request', message, { nonce, identity: this.identity }),
    );
  }
}

/**
 * Accept only loopback `Host` values (DNS-rebinding defence).
 *
 * Parsed by hand because the port must be stripped without swallowing an IPv6
 * literal, and a permissive regex here silently disables the check.
 */
export function isLoopbackHost(host: string): boolean {
  const trimmed = host.trim();
  if (trimmed.length === 0) return false;
  if (ALLOWED_HOSTS.has(trimmed)) return true;

  let hostname = trimmed;
  if (trimmed.startsWith('[')) {
    const end = trimmed.indexOf(']');
    if (end === -1) return false;
    hostname = trimmed.slice(1, end);
    const rest = trimmed.slice(end + 1);
    if (rest.length > 0 && !/^:\d+$/.test(rest)) return false;
  } else {
    const colon = trimmed.lastIndexOf(':');
    if (colon !== -1) {
      const port = trimmed.slice(colon + 1);
      if (!/^\d+$/.test(port)) return false;
      hostname = trimmed.slice(0, colon);
    }
  }
  return ALLOWED_HOSTS.has(hostname);
}

function splitPath(url: string): string[] {
  const path = url.split('?')[0] ?? '/';
  return path
    .split('/')
    .filter((segment) => segment.length > 0)
    .map((segment) => decodeURIComponent(segment));
}

interface BodyResult {
  readonly body: Buffer;
  readonly tooLarge: boolean;
}

/**
 * Read a bounded request body.
 *
 * A client can hide the size by using chunked encoding, so the cap is enforced
 * while reading as well as from `Content-Length`. Overshooting stops the read,
 * wipes what was buffered and reports the reason: answering "you sent nothing"
 * to an oversized body would be both wrong and confusing.
 */
async function readBody(request: IncomingMessage): Promise<BodyResult> {
  const chunks: Buffer[] = [];
  let total = 0;
  let tooLarge = false;

  for await (const chunk of request) {
    const buffer = chunk as Buffer;
    total += buffer.byteLength;

    if (tooLarge || total > MAX_BODY_BYTES) {
      if (!tooLarge) {
        tooLarge = true;
        for (const seen of chunks) wipe(seen);
        chunks.length = 0;
      }
      wipe(buffer);
      if (total > DRAIN_LIMIT_BYTES) {
        request.destroy();
        break;
      }
      continue;
    }
    chunks.push(buffer);
  }

  if (tooLarge) return { body: Buffer.alloc(0), tooLarge: true };
  const body = Buffer.concat(chunks);
  for (const chunk of chunks) wipe(chunk);
  return { body, tooLarge: false };
}

/**
 * Extract one urlencoded field as raw, wipeable bytes.
 *
 * Parsed by hand rather than with `URLSearchParams` so the credential is never
 * materialised as a JavaScript string inside a parser's data structures. The
 * percent-decoding below writes into a Buffer we own and can wipe.
 */
export function formValue(body: Buffer, field: string): Buffer {
  const prefix = Buffer.from(`${field}=`, 'utf8');
  let start = 0;
  while (start <= body.length) {
    let end = body.indexOf(0x26 /* & */, start);
    if (end === -1) end = body.length;
    const part = body.subarray(start, end);
    if (part.length >= prefix.length && part.subarray(0, prefix.length).equals(prefix)) {
      return percentDecode(part.subarray(prefix.length));
    }
    start = end + 1;
  }
  return Buffer.alloc(0);
}

function percentDecode(input: Buffer): Buffer {
  const out = Buffer.alloc(input.length);
  let length = 0;
  for (let index = 0; index < input.length; index += 1) {
    const byte = input[index] as number;
    if (byte === 0x2b /* + */) {
      out[length++] = 0x20;
    } else if (byte === 0x25 /* % */ && index + 2 < input.length) {
      const hex = input.subarray(index + 1, index + 3).toString('latin1');
      const parsed = Number.parseInt(hex, 16);
      if (Number.isNaN(parsed)) {
        out[length++] = byte;
      } else {
        out[length++] = parsed;
        index += 2;
      }
    } else {
      out[length++] = byte;
    }
  }
  const result = Buffer.alloc(length);
  out.copy(result, 0, 0, length);
  wipe(out);
  return result;
}
