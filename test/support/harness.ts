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

  async get(path: string): Promise<HttpResult> {
    this.scanner.add('http_urls', path);
    const response = await fetch(`${this.ui.baseUrl ?? ''}${path}`, {
      redirect: 'manual',
      headers: { host: '127.0.0.1' },
    });
    const body = await response.text();
    this.scanner.add('ui_html', body);
    return { status: response.status, headers: response.headers, body };
  }

  async post(path: string, fields: Record<string, string>): Promise<HttpResult> {
    this.scanner.add('http_urls', path);
    const body = new URLSearchParams(fields).toString();
    const response = await fetch(`${this.ui.baseUrl ?? ''}${path}`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded', host: '127.0.0.1' },
      body,
    });
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
    return this.post(`${path}/confirm`, { confirm_token: token });
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
