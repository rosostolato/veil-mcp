#!/usr/bin/env node
/**
 * Veil entry point: `veil-mcp serve` runs the MCP server and the secure UI.
 *
 * Two process-level protections are set up here:
 *
 * - stdout is reserved exclusively for the MCP protocol. Console output is
 *   redirected to stderr, so a stray `console.log` anywhere in the process — or
 *   in a dependency — cannot corrupt or contaminate protocol traffic (SEC-004).
 * - a crash handler wipes every live secret before the process exits, and never
 *   serializes an in-flight request (SPEC.md §18.9).
 */

import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { defaultRegistry } from './adapters/registry.js';
import { SecretBroker } from './broker.js';
import { configFromEnv, type VeilConfig } from './config.js';
import { AuditLogger, installCrashHandler } from './logging.js';
import { MCPServer, VEIL_VERSION } from './mcp/server.js';
import { SecureInputUI } from './ui/server.js';

const SWEEP_INTERVAL_MS = 5_000;

/**
 * Hand the protocol the real stdout and redirect everything else to stderr.
 *
 * Returns the writer the MCP transport must use; after this call, ordinary
 * stdout writes — including `console.log` — go to stderr instead.
 */
export function reserveStdout(): { write(chunk: string): boolean } {
  const originalWrite = process.stdout.write.bind(process.stdout);
  const protocolOut = {
    write(chunk: string): boolean {
      return originalWrite(chunk);
    },
  };
  process.stdout.write = (chunk: string | Uint8Array, ...rest: unknown[]): boolean => {
    const callback = rest.find((argument) => typeof argument === 'function');
    const written = process.stderr.write(chunk);
    if (typeof callback === 'function') (callback as () => void)();
    return written;
  };
  return protocolOut;
}

export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  if (argv.includes('--version') || argv.includes('-v')) {
    process.stderr.write(`veil ${VEIL_VERSION}\n`);
    return 0;
  }
  if (argv.includes('--help') || argv.includes('-h')) {
    process.stderr.write(
      [
        'veil-mcp — secure credential input broker (MCP stdio server)',
        '',
        'Usage: veil-mcp [serve]',
        '',
        'Veil is started by an MCP client. See the README for client configuration.',
        '',
      ].join('\n'),
    );
    return 0;
  }

  const command = argv.find((argument) => !argument.startsWith('-')) ?? 'serve';
  if (command !== 'serve') {
    process.stderr.write(`unknown command: ${command}\n`);
    return 2;
  }
  return serve(configFromEnv());
}

export async function serve(config: VeilConfig): Promise<number> {
  const logger = new AuditLogger({ stream: process.stderr });
  const registry = await defaultRegistry(config);
  const broker = new SecretBroker(config, registry, { logger });
  const ui = new SecureInputUI(broker, config, { logger });
  const server = new MCPServer(broker, registry, { logger });

  installCrashHandler(() => {
    broker.shutdown();
  }, logger);

  await ui.start();

  const sweeper = setInterval(() => {
    try {
      broker.sweepExpired();
    } catch {
      logger.error('sweeper_failed', { component: 'broker' });
    }
  }, SWEEP_INTERVAL_MS);
  sweeper.unref();

  // stdout belongs to the protocol alone. The real writer is captured first,
  // then process.stdout.write is pointed at stderr — the Node equivalent of
  // dup2'ing fd 1, so neither console.log nor a direct process.stdout.write
  // from anywhere in the process can contaminate protocol traffic (SEC-004).
  const protocolOut = reserveStdout();

  logger.event('server_started', {
    component: 'mcp',
    detail: {
      version: VEIL_VERSION,
      adapters: [...registry.ids()],
      ui: ui.baseUrl ?? '',
      identity: ui.identity,
    },
  });

  const shutdown = async (): Promise<void> => {
    clearInterval(sweeper);
    broker.shutdown();
    await ui.stop();
    logger.event('server_stopped', { component: 'mcp' });
  };

  process.once('SIGINT', () => {
    void shutdown().then(() => process.exit(0));
  });
  process.once('SIGTERM', () => {
    void shutdown().then(() => process.exit(0));
  });

  try {
    await server.serve(process.stdin, protocolOut);
  } finally {
    await shutdown();
  }
  return 0;
}

/**
 * True when this module is the process entry point.
 *
 * npm installs `bin` entries as symlinks, so `process.argv[1]` is the link and
 * `import.meta.url` is its target: comparing them directly makes the CLI do
 * nothing at all when launched the way users actually launch it.
 */
function isEntryPoint(): boolean {
  const invoked = process.argv[1];
  if (invoked === undefined) return false;
  const here = fileURLToPath(import.meta.url);
  if (invoked === here) return true;
  try {
    return realpathSync(invoked) === realpathSync(here);
  } catch {
    return false;
  }
}

if (isEntryPoint()) {
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch(() => {
      process.exitCode = 1;
    });
}
