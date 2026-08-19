/**
 * Child process for crash tests (SPEC.md §31).
 *
 * Runs a real credential flow against the built output, then dies at a chosen
 * point. The parent inspects stdout, stderr and the filesystem for canary
 * material. Nothing here is a mock: the crash handler, the audit logger and the
 * broker are the production ones.
 *
 * Usage: crashChild.mjs <stage> <workdir>, with the canary on stdin.
 */

import { SecretBroker, parseStoreParams } from '../../dist/broker.js';
import { defaultConfig } from '../../dist/config.js';
import { AuditLogger, installCrashHandler } from '../../dist/logging.js';
import { AdapterRegistry } from '../../dist/adapters/registry.js';
import { SecretDestinationAdapter } from '../../dist/adapters/base.js';
import { DestinationClass, RiskLevel, normalizedTarget } from '../../dist/model.js';

export const STAGES = [
  'secret_entry',
  'secret_received',
  'during_destination_call',
  'after_destination_success',
];

class CrashingAdapter extends SecretDestinationAdapter {
  id = 'fake-store';
  displayName = 'Fake Secret Store';
  destinationClass = DestinationClass.SECRET_STORE;
  riskClass = RiskLevel.LOW;

  constructor(config, stage) {
    super(config);
    this.stage = stage;
  }

  targetSchema() {
    return {
      type: 'object',
      additionalProperties: false,
      required: ['project', 'secret'],
      properties: { project: { type: 'string' }, secret: { type: 'string' } },
    };
  }

  normalizeTarget(target, context) {
    return Promise.resolve(
      normalizedTarget({
        adapterId: this.id,
        destinationClass: this.destinationClass,
        providerLabel: 'Fake Secret Store',
        accountLabel: String(target.project ?? ''),
        resourceLabel: String(target.secret ?? context.name),
        environment: this.environmentFor(context.environmentHint, String(target.project ?? '')),
        fields: { project: String(target.project ?? ''), secret: String(target.secret ?? '') },
      }),
    );
  }

  preflight() {
    return Promise.resolve({ ok: true, exists: true });
  }

  calculateRisk() {
    return Promise.resolve({ level: RiskLevel.LOW, reasons: [], requiresStageB: false });
  }

  store() {
    if (this.stage === 'during_destination_call') {
      process.kill(process.pid, 'SIGKILL');
    }
    if (this.stage === 'after_destination_success') {
      throw new Error('crash after the destination write succeeded');
    }
    return Promise.resolve({ stored: true, destinationRef: 'fake/versions/1' });
  }
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8').trim();
}

const [stage, workdir] = process.argv.slice(2);
const secret = await readStdin();

const config = defaultConfig({
  envAllowedRoots: [workdir],
  requestTtlSeconds: 60,
  openBrowser: false,
  uiPort: 0,
});
const adapter = new CrashingAdapter(config, stage);
const registry = new AdapterRegistry([adapter]);
const logger = new AuditLogger({ stream: process.stderr });
const broker = new SecretBroker(config, registry, { logger });
installCrashHandler(() => broker.shutdown(), logger);

const request = await broker.createRequest(
  parseStoreParams(
    {
      destination: 'fake-store',
      name: 'CRASH_KEY',
      target: { project: 'acme-production', secret: 'CRASH_KEY' },
      write_mode: 'replace',
      environment: 'production',
    },
    registry,
  ),
);

if (stage === 'secret_entry') {
  throw new Error('crash while the user was entering the value');
}

await broker.submitSecret(request.requestId, request.submitToken, Buffer.from(secret, 'utf8'));
if (stage === 'secret_received') {
  throw new Error('crash after the secret was received');
}

await broker.confirmExecution(request.requestId, request.confirmToken);
throw new Error('crash before the response was returned');
