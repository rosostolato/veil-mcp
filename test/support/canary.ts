/**
 * Canary secret harness (SPEC.md §22, §23).
 *
 * A canary is a unique, high-entropy value used as the credential in a test.
 * After the flow runs, every channel the harness can observe is searched for the
 * canary *and every encoding of it* that `redaction` knows about. Any hit in a
 * channel that was not explicitly declared as an approved secret boundary fails
 * the test.
 *
 * The product and the harness deliberately share `derivations` so a leak cannot
 * hide behind an encoding the tests forgot about.
 */

import { randomInt } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { derivations } from '../../src/redaction.js';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

function chunk(length: number): string {
  return Array.from({ length }, () => ALPHABET[randomInt(ALPHABET.length)]).join('');
}

export class Canary {
  readonly value: string;

  private constructor(value: string) {
    this.value = value;
  }

  /**
   * Build a canary whose fragment searches cannot produce false positives.
   *
   * SPEC.md §23 requires searching for the first and last 8 bytes, which means
   * those 8 bytes must be unmistakable. Two properties make them so:
   *
   * - both ends are random and carry an uppercase letter, so a fragment cannot
   *   collide with the lowercase hex of a sha256 digest or with another canary;
   * - the `VEIL_CANARY_` marker sits where the product's own credential-shape
   *   screen still recognises the value as credential material.
   */
  static create(label = ''): Canary {
    return new Canary(`Q${chunk(7)}VEIL_CANARY_${label}${chunk(10)}Z`);
  }

  get raw(): Buffer {
    return Buffer.from(this.value, 'utf8');
  }

  get variants(): Buffer[] {
    return derivations(this.raw);
  }

  hitsIn(data: Buffer | string): string[] {
    const blob = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    if (blob.length === 0) return [];
    const lowered = Buffer.from(blob.toString('latin1').toLowerCase(), 'latin1');
    const found: string[] = [];
    for (const variant of this.variants) {
      const loweredVariant = Buffer.from(variant.toString('latin1').toLowerCase(), 'latin1');
      if (blob.includes(variant) || lowered.includes(loweredVariant)) {
        found.push(variant.toString('utf8').slice(0, 24));
      }
    }
    return found;
  }
}

/** Collects observable channels and asserts the canary is absent from them. */
export class LeakScanner {
  readonly channels = new Map<string, Buffer[]>();

  add(name: string, data: Buffer | string): void {
    const blob = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    const existing = this.channels.get(name) ?? [];
    existing.push(blob);
    this.channels.set(name, existing);
  }

  /** Add every file under `root`, except explicitly approved destinations. */
  addTree(name: string, root: string, exclude: readonly string[] = []): void {
    const excluded = new Set(exclude.map((path) => resolve(path)));
    const walk = (directory: string): void => {
      let entries: string[];
      try {
        entries = readdirSync(directory);
      } catch {
        return;
      }
      for (const entry of entries) {
        const path = join(directory, entry);
        let stats;
        try {
          stats = statSync(path);
        } catch {
          continue;
        }
        if (stats.isDirectory()) {
          walk(path);
        } else if (!excluded.has(resolve(path))) {
          try {
            this.add(`${name}:${entry}`, readFileSync(path));
          } catch {
            /* unreadable files cannot leak to the test either */
          }
        }
      }
    };
    walk(root);
  }

  assertClean(canary: Canary, options: { allow?: readonly string[] } = {}): void {
    const allowed = new Set(options.allow ?? []);
    const leaks: string[] = [];
    for (const [name, blobs] of this.channels) {
      if (allowed.has(name)) continue;
      for (const blob of blobs) {
        const hits = canary.hitsIn(blob);
        if (hits.length > 0) leaks.push(`${name}: ${JSON.stringify(hits[0])}`);
      }
    }
    if (leaks.length > 0) {
      throw new Error(`canary leaked into observable channels: ${leaks.sort().join('; ')}`);
    }
  }

  assertPresent(canary: Canary, name: string): void {
    const blobs = this.channels.get(name) ?? [];
    const found = blobs.some((blob) => canary.hitsIn(blob).length > 0);
    if (!found) {
      throw new Error(`expected the canary to reach the approved channel ${JSON.stringify(name)}`);
    }
  }
}
