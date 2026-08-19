/** Focused unit tests for configuration, policy and the timeout helper. */

import { describe, expect, it } from 'vitest';

import { TimeoutError, withTimeout } from '../src/broker.js';
import { configFromEnv, defaultConfig } from '../src/config.js';
import {
  DestinationClass,
  Environment,
  RiskLevel,
  WriteMode,
  normalizedTarget,
} from '../src/model.js';
import { evaluateRisk } from '../src/policy.js';

function target(overrides: Partial<Parameters<typeof normalizedTarget>[0]> = {}) {
  return normalizedTarget({
    adapterId: 'fake',
    destinationClass: DestinationClass.SECRET_STORE,
    providerLabel: 'Fake',
    resourceLabel: 'TOKEN',
    environment: Environment.DEVELOPMENT,
    ...overrides,
  });
}

const baseline = { level: RiskLevel.LOW, reasons: [], requiresStageB: false };

describe('policy', () => {
  it('never lowers the adapter floor', () => {
    const risk = evaluateRisk(defaultConfig(), {
      adapterAssessment: baseline,
      adapterFloor: RiskLevel.MEDIUM,
      target: target(),
      operation: WriteMode.CREATE,
      claimedEnvironment: Environment.DEVELOPMENT,
      exists: false,
    });
    expect(risk.level).toBe(RiskLevel.MEDIUM);
  });

  it('requires stage B for plaintext and application-database destinations', () => {
    const plaintext = evaluateRisk(defaultConfig(), {
      adapterAssessment: baseline,
      adapterFloor: RiskLevel.LOW,
      target: target({ destinationClass: DestinationClass.LOCAL_PLAINTEXT }),
      operation: WriteMode.CREATE,
      claimedEnvironment: Environment.DEVELOPMENT,
      exists: false,
    });
    expect(plaintext.level).toBe(RiskLevel.MEDIUM);
    expect(plaintext.requiresStageB).toBe(true);

    const database = evaluateRisk(defaultConfig(), {
      adapterAssessment: baseline,
      adapterFloor: RiskLevel.LOW,
      target: target({ destinationClass: DestinationClass.REMOTE_APPLICATION_STORAGE }),
      operation: WriteMode.CREATE,
      claimedEnvironment: Environment.DEVELOPMENT,
      exists: false,
    });
    expect(database.requiresStageB).toBe(true);
  });

  it('escalates when the claimed environment contradicts the destination', () => {
    const risk = evaluateRisk(defaultConfig(), {
      adapterAssessment: baseline,
      adapterFloor: RiskLevel.LOW,
      target: target({ environment: Environment.PRODUCTION }),
      operation: WriteMode.NEW_VERSION,
      claimedEnvironment: Environment.DEVELOPMENT,
      exists: false,
    });
    expect(risk.level).toBe(RiskLevel.HIGH);
    expect(risk.requiresStageB).toBe(true);
    expect(risk.reasons.some((reason) => reason.includes('contradicts'))).toBe(true);
  });

  it('honours a stricter operator policy but not a looser one', () => {
    const strict = evaluateRisk(defaultConfig({ stageBForLow: true }), {
      adapterAssessment: baseline,
      adapterFloor: RiskLevel.LOW,
      target: target(),
      operation: WriteMode.CREATE,
      claimedEnvironment: Environment.DEVELOPMENT,
      exists: false,
    });
    expect(strict.requiresStageB).toBe(true);

    const loose = evaluateRisk(defaultConfig({ stageBForMedium: false }), {
      adapterAssessment: baseline,
      adapterFloor: RiskLevel.LOW,
      target: target({ environment: Environment.PRODUCTION }),
      operation: WriteMode.REPLACE,
      claimedEnvironment: Environment.PRODUCTION,
      exists: true,
    });
    // Replacing a production credential is high risk; the operator cannot opt out.
    expect(loose.level).toBe(RiskLevel.HIGH);
    expect(loose.requiresStageB).toBe(true);
  });
});

describe('configuration', () => {
  it('reads the environment and clamps hostile values', () => {
    const config = configFromEnv({
      VEIL_REQUEST_TTL_SECONDS: '99999',
      VEIL_ADAPTER_TIMEOUT_SECONDS: '0',
      VEIL_STAGE_B_FOR_MEDIUM: 'false',
      VEIL_OPEN_BROWSER: 'no',
      VEIL_DISCLOSE_AUTHORIZATION_URL: 'true',
      VEIL_ENABLED_ADAPTERS: 'env-file, gcp-secret-manager',
      VEIL_UI_PORT: '0',
    });

    expect(config.requestTtlSeconds).toBe(3600);
    expect(config.adapterTimeoutSeconds).toBe(1);
    expect(config.stageBForMedium).toBe(false);
    expect(config.openBrowser).toBe(false);
    expect(config.discloseAuthorizationUrl).toBe(true);
    expect(config.enabledAdapters).toEqual(['env-file', 'gcp-secret-manager']);
  });

  it('defaults to the safest behaviour', () => {
    const config = configFromEnv({});
    expect(config.discloseAuthorizationUrl).toBe(false);
    expect(config.stageBForMedium).toBe(true);
    expect(config.allowGitTrackedEnv).toBe(false);
    expect(config.enabledAdapters).toBeUndefined();
  });
});

describe('withTimeout', () => {
  it('rejects with TimeoutError when the work outlives the bound', async () => {
    const pending = new Promise<string>((resolve) => {
      const timer = setTimeout(() => resolve('too late'), 5_000);
      timer.unref?.();
    });
    await expect(withTimeout(pending, 20)).rejects.toBeInstanceOf(TimeoutError);
  });

  it('passes through a value that arrives in time', async () => {
    await expect(withTimeout(Promise.resolve('in time'), 1_000)).resolves.toBe('in time');
  });
});
