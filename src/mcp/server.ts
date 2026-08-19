/**
 * JSON-RPC / MCP stdio server (SPEC.md §13, §18.3, §24 SEC-002).
 *
 * Implemented in-tree, with no framework between the protocol and the broker,
 * for two reasons: the trusted computing base stays small (SPEC.md §42) — the
 * official SDK pulls ~90 packages, including HTTP and OAuth stacks this server
 * never uses — and every outbound frame passes through a single choke point
 * where the tripwire runs.
 *
 * `handleMessage` is pure with respect to transport, which makes the complete
 * MCP conversation trivially recordable in tests.
 */

import { createInterface } from 'node:readline';

import type { AdapterRegistry } from '../adapters/registry.js';
import type { SecretBroker } from '../broker.js';
import { getLogger, type AuditLogger } from '../logging.js';
import { safeDisplay } from '../redaction.js';
import { ToolRouter, toolResultToMcp } from './tools.js';

export const VEIL_VERSION = '0.1.0';
export const PROTOCOL_VERSION = '2025-06-18';
export const SUPPORTED_PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'] as const;
export const MAX_FRAME_BYTES = 1 << 20;

export const PARSE_ERROR = -32700;
export const INVALID_REQUEST = -32600;
export const METHOD_NOT_FOUND = -32601;
export const INTERNAL_ERROR = -32603;

export const INSTRUCTIONS = [
  'Veil stores credentials without revealing them to you.',
  '',
  'You describe where a credential should go; the user types the value into Veil’s own',
  'window and authorizes the destination there. No Veil tool accepts or returns a',
  'credential value.',
  '',
  'Typical flow: call secret_store, tell the user Veil has opened its window, then poll',
  'secret_status. An authorized operation cannot be edited — secret_revise invalidates the',
  'old authorization and asks the user again.',
].join('\n');

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: unknown;
  result?: Record<string, unknown>;
  error?: { code: number; message: string };
}

export class MCPServer {
  readonly tools: ToolRouter;
  readonly log: AuditLogger;

  constructor(
    readonly broker: SecretBroker,
    readonly registry: AdapterRegistry,
    options: { logger?: AuditLogger } = {},
  ) {
    this.log = options.logger ?? getLogger();
    this.tools = new ToolRouter(broker, registry, this.log);
  }

  async handleMessage(message: unknown): Promise<JsonRpcResponse | null> {
    if (typeof message !== 'object' || message === null || Array.isArray(message)) {
      return errorResponse(null, INVALID_REQUEST, 'Invalid request.');
    }
    const record = message as Record<string, unknown>;
    const id = record.id ?? null;
    const method = record.method;
    if (typeof method !== 'string') {
      return errorResponse(id, INVALID_REQUEST, 'Invalid request.');
    }

    const params =
      typeof record.params === 'object' && record.params !== null && !Array.isArray(record.params)
        ? (record.params as Record<string, unknown>)
        : {};

    if (method.startsWith('notifications/')) return null;

    switch (method) {
      case 'initialize':
        return resultResponse(id, this.#initialize(params));
      case 'ping':
        return resultResponse(id, {});
      case 'tools/list':
        return resultResponse(id, { tools: this.tools.listTools() });
      case 'tools/call': {
        const name = params.name;
        this.log.event('tool_called', { tool: safeDisplay(String(name), 40) });
        const result = await this.tools.call(name, params.arguments);
        return resultResponse(id, toolResultToMcp(result));
      }
      case 'resources/list':
        return resultResponse(id, { resources: [] });
      case 'prompts/list':
        return resultResponse(id, { prompts: [] });
      default:
        return record.id === undefined
          ? null
          : errorResponse(id, METHOD_NOT_FOUND, 'Unknown method.');
    }
  }

  #initialize(params: Record<string, unknown>): Record<string, unknown> {
    const requested = params.protocolVersion;
    const version =
      typeof requested === 'string' &&
      (SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(requested)
        ? requested
        : PROTOCOL_VERSION;
    return {
      protocolVersion: version,
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: 'veil', version: VEIL_VERSION },
      instructions: INSTRUCTIONS,
    };
  }

  /** Newline-delimited JSON-RPC over stdio, the MCP stdio transport. */
  async serve(
    input: NodeJS.ReadableStream,
    output: { write(chunk: string): unknown },
  ): Promise<void> {
    const lines = createInterface({ input, crlfDelay: Infinity });
    for await (const line of lines) {
      if (line.length > MAX_FRAME_BYTES) {
        this.#write(output, errorResponse(null, INVALID_REQUEST, 'Frame too large.'));
        continue;
      }
      const trimmed = line.trim();
      if (trimmed.length === 0) continue;

      let message: unknown;
      try {
        message = JSON.parse(trimmed);
      } catch {
        this.#write(output, errorResponse(null, PARSE_ERROR, 'Malformed message.'));
        continue;
      }

      if (Array.isArray(message)) {
        for (const item of message) {
          const response = await this.#safeHandle(item);
          if (response) this.#write(output, response);
        }
        continue;
      }
      const response = await this.#safeHandle(message);
      if (response) this.#write(output, response);
    }
  }

  async #safeHandle(message: unknown): Promise<JsonRpcResponse | null> {
    try {
      return await this.handleMessage(message);
    } catch {
      const id =
        typeof message === 'object' && message !== null
          ? ((message as Record<string, unknown>).id ?? null)
          : null;
      this.log.error('mcp_handler_failed', { component: 'mcp' });
      return errorResponse(id, INTERNAL_ERROR, 'Internal error.');
    }
  }

  /** Single outbound choke point: nothing reaches the client unchecked. */
  #write(output: { write(chunk: string): unknown }, response: JsonRpcResponse): void {
    let payload = JSON.stringify(response);
    if (this.broker.containsLiveSecret(payload)) {
      this.log.security('mcp_frame_blocked', { component: 'mcp' });
      payload = JSON.stringify(
        errorResponse(
          response.id,
          INTERNAL_ERROR,
          'The response was suppressed because it contained sensitive data.',
        ),
      );
    }
    output.write(`${payload}\n`);
  }

  writeForTesting(output: { write(chunk: string): unknown }, response: JsonRpcResponse): void {
    this.#write(output, response);
  }
}

function resultResponse(id: unknown, result: Record<string, unknown>): JsonRpcResponse {
  return { jsonrpc: '2.0', id, result };
}

function errorResponse(id: unknown, code: number, message: string): JsonRpcResponse {
  return { jsonrpc: '2.0', id, error: { code, message } };
}
