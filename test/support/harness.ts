/**
 * Full-stack test harness: MCP server + broker + live loopback UI.
 *
 * Everything that crosses a boundary is recorded into a `LeakScanner`, so any
 * test can end with `harness.scanner.assertClean(canary)`.
 */

import { AdapterRegistry } from '../../src/adapters/registry.js';
import { SecretBroker } from '../../src/broker.js';
import { defaultConfig, type VeilConfig } from '../../src/config.js';
import { AuditLogger } from '../../src/logging.js';
import { MCPServer, type JsonRpcResponse } from '../../src/mcp/server.js';
import { SecureInputUI } from '../../src/ui/server.js';
import { LeakScanner } from './canary.js';

export interface HttpResult {
  readonly status: number;
  readonly headers: Headers;
  readonly body: string;
}

/**
 * Test configuration.
 *
 * The harness plays the human, so it needs the link a browser would receive;
 * `test/security/authorization/out-of-band.test.ts` covers the production
 * default, where the agent never sees it.
 */
export function testConfig(overrides: Partial<VeilConfig> = {}): VeilConfig {
  return defaultConfig({
    requestTtlSeconds: 60,
    adapterTimeoutSeconds: 5,
    uiHost: '127.0.0.1',
    uiPort: 0,
    openBrowser: false,
    discloseAuthorizationUrl: true,
    ...overrides,
  });
}

export class Harness {
  readonly scanner = new LeakScanner();
  readonly logRecords: Record<string, unknown>[] = [];
  logText = '';
  readonly broker: SecretBroker;
  readonly ui: SecureInputUI;
  readonly server: MCPServer;
  #nextId = 0;

  private constructor(
    readonly config: VeilConfig,
    readonly registry: AdapterRegistry,
  ) {
    const logger = new AuditLogger({
      stream: {
        write: (chunk: string): boolean => {
          this.logText += chunk;
          return true;
        },
      },
      sink: (record) => this.logRecords.push(record),
    });
    this.broker = new SecretBroker(config, registry, { logger });
    this.ui = new SecureInputUI(this.broker, config, { logger });
    this.server = new MCPServer(this.broker, registry, { logger });
  }

  static async start(config: VeilConfig, registry: AdapterRegistry): Promise<Harness> {
    const harness = new Harness(config, registry);
    await harness.ui.start();
    return harness;
  }

  async stop(): Promise<void> {
    this.broker.shutdown();
    await this.ui.stop();
  }

  // -- MCP --------------------------------------------------------------------

  async rpc(method: string, params?: Record<string, unknown>): Promise<JsonRpcResponse> {
    this.#nextId += 1;
    const message: Record<string, unknown> = { jsonrpc: '2.0', id: this.#nextId, method };
    if (params !== undefined) message.params = params;
    this.scanner.add('mcp_traffic', JSON.stringify(message));
    this.scanner.add('mcp_tool_arguments', JSON.stringify(params ?? {}));

    const response = await this.server.handleMessage(message);
    const rendered = JSON.stringify(response);
    this.scanner.add('mcp_traffic', rendered);
    this.scanner.add('mcp_tool_results', rendered);
    if (!response) throw new Error(`no response for ${method}`);
    return response;
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
    const response = await this.rpc('tools/call', { name, arguments: args });
    const result = response.result;
    if (!result) throw new Error(`tool call failed: ${JSON.stringify(response)}`);
    return result.structuredContent as Record<string, unknown>;
  }

  // -- HTTP -------------------------------------------------------------------

  /**
   * Behaves like the one browser Veil opened: the first GET of a link trades it
   * for a session cookie and follows the redirect; later GETs of the same link
   * go straight to the request page, and POSTs to `<link>/<action>` are sent to
   * `/r/<id>/<action>` with the cookie. `{ browser: false }` sends the request
   * as-is, with no cookie, like a second party holding the link.
   */
  async get(path: string, options: { browser?: boolean } = {}): Promise<HttpResult> {
    this.scanner.add('http_urls', path);
    const browser = options.browser ?? true;
    const link = parseLink(path);
    if (browser && link && this.#sessions.has(link.requestId)) {
      return this.#send(`/r/${link.requestId}`, { method: 'GET' });
    }
    const result = await this.#send(path, { method: 'GET' }, browser);
    if (browser && link && result.status === 303 && this.#sessions.has(link.requestId)) {
      return this.#send(result.headers.get('location') ?? '/', { method: 'GET' });
    }
    return result;
  }

  async post(
    path: string,
    fields: Record<string, string>,
    options: { browser?: boolean } = {},
  ): Promise<HttpResult> {
    this.scanner.add('http_urls', path);
    const browser = options.browser ?? true;
    let target = path;
    const action = /^\/r\/([^/]+)\/[^/]+\/([a-z]+)$/.exec(path);
    if (browser && action) {
      const linkPath = path.slice(0, path.lastIndexOf('/'));
      if (!this.#sessions.has(action[1] as string)) await this.get(linkPath);
      if (this.#sessions.has(action[1] as string)) target = `/r/${action[1]}/${action[2]}`;
    }
    return this.#send(
      target,
      {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(fields).toString(),
      },
      browser,
    );
  }

  readonly #sessions = new Map<string, string>();

  async #send(path: string, init: RequestInit, browser = true): Promise<HttpResult> {
    const requestId = /^\/r\/([^/?]+)/.exec(path)?.[1];
    const headers: Record<string, string> = {
      host: '127.0.0.1',
      ...(init.headers as Record<string, string> | undefined),
    };
    const session = requestId ? this.#sessions.get(requestId) : undefined;
    if (browser && session) headers.cookie = `veil_session=${session}`;
    const response = await fetch(`${this.ui.baseUrl ?? ''}${path}`, {
      ...init,
      redirect: 'manual',
      headers,
    });
    const cookie = /veil_session=([^;]+)/.exec(response.headers.get('set-cookie') ?? '')?.[1];
    if (browser && cookie && requestId) this.#sessions.set(requestId, cookie);
    const text = await response.text();
    if (response.status !== 303) this.scanner.add('ui_html', text);
    return { status: response.status, headers: response.headers, body: text };
  }

  // -- flows ------------------------------------------------------------------

  pathFor(payload: Record<string, unknown>): string {
    const url = payload.authorization_url;
    if (typeof url !== 'string') throw new Error('the payload carries no authorization_url');
    return new URL(url).pathname;
  }

  submitSecret(payload: Record<string, unknown>, value: string): Promise<HttpResult> {
    return this.post(`${this.pathFor(payload)}/submit`, { secret: value });
  }

  async confirm(payload: Record<string, unknown>): Promise<HttpResult> {
    const path = this.pathFor(payload);
    const page = await this.get(path);
    const token = /name="confirm_token" value="([^"]+)"/.exec(page.body)?.[1];
    if (!token) throw new Error('stage B page did not render a confirmation token');
    const name = /data-expect="([^"]*)"/.exec(page.body)?.[1];
    if (name === undefined) throw new Error('stage B page did not render a confirmation name');
    return this.post(`${path}/confirm`, {
      confirm_token: token,
      confirm_name: name
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'")
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&'),
    });
  }

  cancel(payload: Record<string, unknown>): Promise<HttpResult> {
    return this.post(`${this.pathFor(payload)}/cancel`, {});
  }

  status(requestId: string): Promise<Record<string, unknown>> {
    return this.callTool('secret_status', { request_id: requestId });
  }

  /** Stage A (+ Stage B when required) through to a terminal state. */
  async finishFlow(
    payload: Record<string, unknown>,
    value: string,
  ): Promise<Record<string, unknown>> {
    await this.get(this.pathFor(payload));
    await this.submitSecret(payload, value);
    let status = await this.status(payload.request_id as string);
    if (status.state === 'AWAITING_EXECUTION_CONFIRMATION') {
      await this.confirm(payload);
      status = await this.status(payload.request_id as string);
    }
    return status;
  }

  collectLogs(): void {
    this.scanner.add('application_logs', this.logText);
    this.scanner.add('audit_records', JSON.stringify(this.logRecords));
  }
}

/** `/r/<id>/<link>` — a single-use authorization link path. */
function parseLink(path: string): { requestId: string } | null {
  const match = /^\/r\/([^/?]+)\/([^/?]+)$/.exec(path);
  return match ? { requestId: match[1] as string } : null;
}

export function storeArgs(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    destination: 'fake-store',
    name: 'STRIPE_SECRET_KEY',
    target: { project: 'acme-dev-project', secret: 'STRIPE_SECRET_KEY' },
    write_mode: 'create',
    environment: 'development',
    ...overrides,
  };
}
