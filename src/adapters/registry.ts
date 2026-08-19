/**
 * Adapter registry (SPEC.md §16, §17).
 *
 * Only adapters registered here can ever be selected. The `arbitrary-network`
 * destination class is rejected at registration time: it is disabled by default
 * per SPEC.md §16 and is not implemented in this version, so there is no code
 * path that could enable it by accident.
 */

import type { VeilConfig } from '../config.js';
import { ErrorCode, veilError } from '../errors.js';
import { DestinationClass } from '../model.js';
import type { SecretDestinationAdapter } from './base.js';

export class AdapterRegistry {
  #adapters = new Map<string, SecretDestinationAdapter>();

  constructor(adapters: readonly SecretDestinationAdapter[] = []) {
    for (const adapter of adapters) this.register(adapter);
  }

  register(adapter: SecretDestinationAdapter): void {
    if (adapter.destinationClass === DestinationClass.ARBITRARY_NETWORK) {
      throw new Error('arbitrary-network destinations are not permitted');
    }
    if (this.#adapters.has(adapter.id)) {
      throw new Error(`duplicate adapter id: ${adapter.id}`);
    }
    this.#adapters.set(adapter.id, adapter);
  }

  get(adapterId: unknown): SecretDestinationAdapter {
    const adapter = typeof adapterId === 'string' ? this.#adapters.get(adapterId) : undefined;
    if (!adapter) {
      throw veilError(ErrorCode.UNKNOWN_DESTINATION, 'The requested destination is not available.');
    }
    return adapter;
  }

  has(adapterId: unknown): boolean {
    return typeof adapterId === 'string' && this.#adapters.has(adapterId);
  }

  list(): readonly SecretDestinationAdapter[] {
    return [...this.#adapters.values()];
  }

  ids(): readonly string[] {
    return [...this.#adapters.keys()];
  }
}

/** Build the adapters enabled for this process. */
export async function defaultRegistry(config: VeilConfig): Promise<AdapterRegistry> {
  const { EnvFileAdapter } = await import('./envFile.js');
  const { GcpSecretManagerAdapter } = await import('./gcpSecretManager.js');
  const { FirestoreAdapter } = await import('./firestore.js');

  const candidates: SecretDestinationAdapter[] = [
    new GcpSecretManagerAdapter(config),
    new EnvFileAdapter(config),
    new FirestoreAdapter(config),
  ];
  const allowed = config.enabledAdapters;
  return new AdapterRegistry(
    allowed ? candidates.filter((adapter) => allowed.includes(adapter.id)) : candidates,
  );
}
