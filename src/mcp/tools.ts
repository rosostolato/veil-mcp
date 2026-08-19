/**
 * MCP tool contract (SPEC.md §6, §13, §18.3).
 *
 * The schemas here are the structural security guarantee: there is no property
 * capable of carrying credential content, every object is closed
 * (`additionalProperties: false`), and arguments are screened for both
 * secret-shaped field names and credential-shaped values before they reach the
 * broker.
 *
 * Descriptions follow the Anthropic connector review criteria: they state what
 * the tool does, what it returns and what it does not do, and they never
 * instruct the model how to behave. Workflow guidance belongs in the server's
 * `instructions`, not in a tool description.
 *
 * Why not elicitation? The spec-native way to collect user input mid-tool would
 * deliver the value back through the MCP protocol and into the model's context —
 * exactly what Veil exists to prevent (SPEC.md §5). The out-of-band browser
 * window is not a workaround for missing elicitation support; it is the point.
 */

import { z } from 'zod';

import type { AdapterRegistry } from '../adapters/registry.js';
import { parseStoreParams, type SecretBroker } from '../broker.js';
import { ErrorCode, VeilError, publicError, publicErrorToJSON, veilError } from '../errors.js';
import type { AuditLogger } from '../logging.js';
import { Environment, WriteMode } from '../model.js';
import { looksLikeCredential, safeDisplay } from '../redaction.js';

export const STORE_TOOL = 'secret_store';
export const STATUS_TOOL = 'secret_status';
export const CANCEL_TOOL = 'secret_cancel';
export const REVISE_TOOL = 'secret_revise';
export const DESTINATIONS_TOOL = 'secret_destinations';

/**
 * Field names that would betray an attempt to smuggle credential material
 * through an unmodelled property (SPEC.md §6, §26.5).
 */
export const SECRET_SHAPED_FIELD =
  /(secret[_-]?value|secretvalue|raw[_-]?secret|rawsecret|password|passwd|pwd|passphrase|credential|credentials|api[_-]?key[_-]?value|token[_-]?value|private[_-]?key|client[_-]?secret|access[_-]?key|content|payload|value|data|blob|bytes|material)/i;

export const MAX_ARGUMENT_DEPTH = 6;
/**
 * A blocking status call occupies the single-threaded stdio loop, so it is kept
 * short: the human's window runs independently and is never blocked by it.
 */
export const MAX_STATUS_WAIT_SECONDS = 60;

const ALLOWED_ARGUMENT_KEYS = new Set([
  'destination',
  'name',
  'target',
  'write_mode',
  'environment',
  'description',
  'request_id',
  'reason',
  'wait_seconds',
  'project',
  'secret',
  'collection',
  'document',
  'field',
  'path',
  'key',
]);

export interface McpTool {
  readonly name: string;
  readonly title: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
  readonly annotations: Record<string, unknown>;
}

export interface ToolResult {
  readonly payload: Record<string, unknown>;
  readonly isError: boolean;
}

export function toolResultToMcp(result: ToolResult): Record<string, unknown> {
  return {
    content: [{ type: 'text', text: JSON.stringify(result.payload, null, 2) }],
    structuredContent: result.payload,
    isError: result.isError,
  };
}

export const statusArgsSchema = z
  .object({
    request_id: z.string().max(64),
    wait_seconds: z.number().int().min(0).max(MAX_STATUS_WAIT_SECONDS).optional(),
  })
  .strict();

export const cancelArgsSchema = z
  .object({ request_id: z.string().max(64), reason: z.string().max(200).optional() })
  .strict();

export class ToolRouter {
  constructor(
    readonly broker: SecretBroker,
    readonly registry: AdapterRegistry,
    readonly log: AuditLogger,
  ) {}

  listTools(): McpTool[] {
    return [
      {
        name: STORE_TOOL,
        title: 'Request credential storage',
        description:
          'Creates a request to store a credential at the described destination and opens ' +
          "Veil's own authorization window on the user's machine, where the user reviews " +
          'the destination and types the value. Returns a request id, the normalized ' +
          'destination, a risk classification and the request state — never the credential ' +
          'value, which no Veil tool accepts or returns. Does not write anything by itself: ' +
          'the write happens only after the user authorizes it. Use secret_status to follow ' +
          'the request, and secret_revise to change an already-authorized destination.',
        inputSchema: this.storeSchema(),
        annotations: {
          title: 'Request credential storage',
          readOnlyHint: false,
          destructiveHint: true,
          idempotentHint: false,
          openWorldHint: true,
        },
      },
      {
        name: STATUS_TOOL,
        title: 'Check a credential request',
        description:
          'Returns the current state of one credential request: its stage, destination, ' +
          'risk, and the outcome once it is finished. Never returns credential material. ' +
          'Reads only — use secret_store to create a request.',
        inputSchema: {
          type: 'object',
          additionalProperties: false,
          required: ['request_id'],
          properties: {
            request_id: {
              type: 'string',
              maxLength: 64,
              description: 'Identifier returned by secret_store or secret_revise.',
            },
            wait_seconds: {
              type: 'integer',
              minimum: 0,
              maximum: MAX_STATUS_WAIT_SECONDS,
              description:
                'Block until the request reaches a terminal state or this many seconds ' +
                'elapse. Omit or use 0 to return immediately.',
            },
          },
        },
        annotations: {
          title: 'Check a credential request',
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      },
      {
        name: CANCEL_TOOL,
        title: 'Cancel a credential request',
        description:
          'Cancels a pending credential request and destroys any value the user already ' +
          'entered. Returns the final state. Cannot cancel a request that is already ' +
          'writing to its destination, and cannot undo a completed write.',
        inputSchema: {
          type: 'object',
          additionalProperties: false,
          required: ['request_id'],
          properties: {
            request_id: {
              type: 'string',
              maxLength: 64,
              description: 'Identifier of the request to cancel.',
            },
            reason: {
              type: 'string',
              maxLength: 200,
              description: 'Short, non-sensitive note recorded in the audit log.',
            },
          },
        },
        annotations: {
          title: 'Cancel a credential request',
          readOnlyHint: false,
          destructiveHint: true,
          idempotentHint: true,
          openWorldHint: false,
        },
      },
      {
        name: REVISE_TOOL,
        title: 'Replace a credential request',
        description:
          'Cancels a pending request and creates a replacement with different details. The ' +
          'original authorization is invalidated and the user authorizes the new operation ' +
          'from scratch; an authorized operation is never edited in place. Returns the new ' +
          'request id. Use secret_cancel when no replacement is wanted.',
        inputSchema: this.reviseSchema(),
        annotations: {
          title: 'Replace a credential request',
          readOnlyHint: false,
          destructiveHint: true,
          idempotentHint: false,
          openWorldHint: true,
        },
      },
      {
        name: DESTINATIONS_TOOL,
        title: 'List credential destinations',
        description:
          'Lists the destinations this Veil instance can write to, with the target fields ' +
          'and write modes each one accepts. Reads only; creates no request.',
        inputSchema: { type: 'object', additionalProperties: false, properties: {} },
        annotations: {
          title: 'List credential destinations',
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      },
    ];
  }

  storeSchema(): Record<string, unknown> {
    const targetProperties: Record<string, unknown> = {};
    for (const adapter of this.registry.list()) {
      for (const [key, definition] of Object.entries(adapter.targetSchema().properties)) {
        targetProperties[key] ??= definition;
      }
    }
    return {
      type: 'object',
      additionalProperties: false,
      required: ['destination', 'name', 'target'],
      properties: {
        destination: {
          type: 'string',
          enum: [...this.registry.ids()],
          description: 'Destination adapter that will receive the credential.',
        },
        name: {
          type: 'string',
          maxLength: 128,
          description:
            'Logical name of the credential, e.g. STRIPE_SECRET_KEY. A label only: this ' +
            'field must never contain the credential value.',
        },
        target: {
          type: 'object',
          additionalProperties: false,
          properties: targetProperties,
          description:
            'Where the credential goes. Accepted fields depend on the destination; ' +
            'secret_destinations returns the exact contract for each.',
        },
        write_mode: {
          type: 'string',
          enum: Object.values(WriteMode),
          default: WriteMode.CREATE,
          description:
            "'create' fails if a value already exists, 'new-version' adds a version, " +
            "'replace' overwrites. Availability depends on the destination.",
        },
        environment: {
          type: 'string',
          enum: Object.values(Environment),
          description:
            'Environment this destination is believed to belong to. Advisory only: Veil ' +
            'classifies the destination itself and applies the stricter of the two.',
        },
        description: {
          type: 'string',
          maxLength: 512,
          description: 'Short, non-sensitive purpose shown to the user on the review screen.',
        },
      },
    };
  }

  reviseSchema(): Record<string, unknown> {
    const schema = this.storeSchema();
    const properties = schema.properties as Record<string, unknown>;
    return {
      ...schema,
      required: ['request_id', ...(schema.required as string[])],
      properties: {
        request_id: {
          type: 'string',
          maxLength: 64,
          description: 'Identifier of the request being replaced.',
        },
        ...properties,
      },
    };
  }

  async call(name: unknown, args: unknown): Promise<ToolResult> {
    const argumentObject: Record<string, unknown> =
      args === null || args === undefined
        ? {}
        : typeof args === 'object' && !Array.isArray(args)
          ? (args as Record<string, unknown>)
          : (undefined as never);

    if (argumentObject === undefined) {
      return errorResult(veilError(ErrorCode.INVALID_ARGUMENTS, 'Arguments must be an object.'));
    }

    try {
      this.#screenArguments(name, argumentObject);
      switch (name) {
        case STORE_TOOL:
          return await this.#store(argumentObject);
        case STATUS_TOOL:
          return await this.#status(argumentObject);
        case CANCEL_TOOL:
          return this.#cancel(argumentObject);
        case REVISE_TOOL:
          return await this.#revise(argumentObject);
        case DESTINATIONS_TOOL:
          return this.#destinations();
        default:
          throw veilError(ErrorCode.INVALID_ARGUMENTS, 'Unknown tool.');
      }
    } catch (error) {
      if (error instanceof VeilError) return errorResult(error);
      this.log.error('tool_call_failed', { tool: safeDisplay(String(name), 40) });
      return {
        payload: publicErrorToJSON(
          publicError(ErrorCode.INTERNAL_ERROR, 'The request could not be processed.'),
        ),
        isError: true,
      };
    }
  }

  /** Reject covert secret transport before anything else looks at the args. */
  #screenArguments(tool: unknown, args: Record<string, unknown>): void {
    const findings: string[] = [];

    const walk = (node: unknown, depth: number): void => {
      if (depth > MAX_ARGUMENT_DEPTH) {
        findings.push('nesting');
        return;
      }
      if (Array.isArray(node)) {
        for (const item of node) walk(item, depth + 1);
        return;
      }
      if (node !== null && typeof node === 'object') {
        for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
          if (!ALLOWED_ARGUMENT_KEYS.has(key) && SECRET_SHAPED_FIELD.test(key)) {
            findings.push(`field:${safeDisplay(key, 40)}`);
          }
          walk(value, depth + 1);
        }
        return;
      }
      if (typeof node === 'string' && looksLikeCredential(node)) {
        findings.push('credential-shaped-value');
      }
    };

    walk(args, 0);
    if (findings.length > 0) {
      this.log.security('secret_shaped_argument_rejected', {
        tool: safeDisplay(String(tool), 40),
        detail: { findings: [...new Set(findings)].slice(0, 5) },
      });
      throw veilError(
        ErrorCode.FORBIDDEN_FIELD,
        'This tool never accepts credential material. Remove the offending field and let ' +
          'the user enter the value in Veil.',
      );
    }
  }

  async #store(args: Record<string, unknown>): Promise<ToolResult> {
    const params = parseStoreParams(args, this.registry);
    const request = await this.broker.createRequest(params);
    return { payload: this.#pendingPayload(request.requestId), isError: false };
  }

  async #revise(args: Record<string, unknown>): Promise<ToolResult> {
    const requestId = args.request_id;
    if (typeof requestId !== 'string') {
      throw veilError(ErrorCode.INVALID_ARGUMENTS, 'A request_id is required.');
    }
    const rest = Object.fromEntries(Object.entries(args).filter(([key]) => key !== 'request_id'));
    const params = parseStoreParams(rest, this.registry);
    const request = await this.broker.revise(requestId, params);
    const payload = this.#pendingPayload(request.requestId);
    payload.previous_request_id = safeDisplay(requestId, 64);
    payload.notice =
      'The previous authorization was invalidated. The user authorizes this operation again.';
    return { payload, isError: false };
  }

  async #status(args: Record<string, unknown>): Promise<ToolResult> {
    const parsed = statusArgsSchema.safeParse(args);
    if (!parsed.success) {
      throw veilError(ErrorCode.INVALID_ARGUMENTS, 'A request_id is required.');
    }
    const wait = parsed.data.wait_seconds ?? 0;
    if (wait > 0) {
      return {
        payload: await this.broker.waitForTerminal(parsed.data.request_id, wait),
        isError: false,
      };
    }
    return { payload: this.broker.publicStatus(parsed.data.request_id), isError: false };
  }

  #cancel(args: Record<string, unknown>): ToolResult {
    const parsed = cancelArgsSchema.safeParse(args);
    if (!parsed.success) {
      throw veilError(ErrorCode.INVALID_ARGUMENTS, 'A request_id is required.');
    }
    this.broker.cancel(parsed.data.request_id, {
      reason: parsed.data.reason ? safeDisplay(parsed.data.reason, 80) : 'agent_cancelled',
    });
    return { payload: this.broker.publicStatus(parsed.data.request_id), isError: false };
  }

  #destinations(): ToolResult {
    return {
      payload: {
        destinations: this.registry.list().map((adapter) => ({
          id: adapter.id,
          title: adapter.displayName,
          destination_class: adapter.destinationClass,
          write_modes: [...adapter.supportedWriteModes()],
          target_schema: adapter.targetSchema(),
        })),
        note:
          'No destination accepts a credential value through this API. Veil collects the ' +
          'value from the user directly.',
      },
      isError: false,
    };
  }

  #pendingPayload(requestId: string): Record<string, unknown> {
    return this.broker.publicStatus(requestId);
  }
}

function errorResult(error: VeilError): ToolResult {
  return { payload: publicErrorToJSON(error.public), isError: true };
}
