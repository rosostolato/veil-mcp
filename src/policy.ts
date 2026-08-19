/**
 * Risk classification and confirmation policy (SPEC.md §10, §16, §26).
 *
 * Every rule in this module is monotonic: it can only raise the risk level or
 * turn Stage B on. Nothing an agent sends can lower a classification, and a
 * claimed `environment` that contradicts the destination's own naming raises
 * risk rather than lowering it.
 */

import type { VeilConfig } from './config.js';
import {
  DestinationClass,
  Environment,
  RiskLevel,
  WriteMode,
  environmentSeverity,
  escalateRisk,
  type NormalizedTarget,
  type RiskAssessment,
} from './model.js';

export function evaluateRisk(
  config: VeilConfig,
  input: {
    adapterAssessment: RiskAssessment;
    adapterFloor: RiskLevel;
    target: NormalizedTarget;
    operation: WriteMode;
    claimedEnvironment: Environment;
    exists: boolean;
  },
): RiskAssessment {
  const { adapterAssessment, adapterFloor, target, operation, claimedEnvironment, exists } = input;

  let level = escalateRisk(adapterAssessment.level, adapterFloor);
  const reasons: string[] = [...adapterAssessment.reasons];
  let forceStageB = adapterAssessment.requiresStageB;

  if (target.destinationClass === DestinationClass.LOCAL_PLAINTEXT) {
    level = escalateRisk(level, RiskLevel.MEDIUM);
    reasons.push('Destination stores the credential as plaintext on this machine.');
  }

  if (target.destinationClass === DestinationClass.REMOTE_APPLICATION_STORAGE) {
    level = escalateRisk(level, RiskLevel.MEDIUM);
    forceStageB = true;
    reasons.push('Destination may not be designed to store secrets.');
  }

  if (target.destinationClass === DestinationClass.ARBITRARY_NETWORK) {
    // Unreachable: the registry refuses these adapters. Kept as a floor so a
    // future adapter cannot quietly land in a lower band.
    level = RiskLevel.HIGH;
    forceStageB = true;
    reasons.push('Destination is an arbitrary network endpoint.');
  }

  if (operation === WriteMode.REPLACE) {
    level = escalateRisk(level, RiskLevel.MEDIUM);
    forceStageB = true;
    reasons.push('Operation replaces an existing credential.');
  }

  if (exists && operation !== WriteMode.NEW_VERSION) {
    level = escalateRisk(level, RiskLevel.MEDIUM);
    forceStageB = true;
    reasons.push('A value already exists at this destination and will be overwritten.');
  }

  if (target.environment === Environment.PRODUCTION) {
    level = escalateRisk(level, RiskLevel.MEDIUM);
    reasons.push('Destination is classified as production.');
    if (exists || operation === WriteMode.REPLACE) {
      level = escalateRisk(level, RiskLevel.HIGH);
      forceStageB = true;
    }
  }

  if (target.environment === Environment.UNKNOWN) {
    reasons.push('Environment could not be determined from the destination.');
  }

  if (environmentSeverity(claimedEnvironment) < environmentSeverity(target.environment)) {
    if (target.environment === Environment.PRODUCTION) {
      level = RiskLevel.HIGH;
      forceStageB = true;
    } else {
      level = escalateRisk(level, RiskLevel.MEDIUM);
    }
    reasons.push(
      `Requested environment '${claimedEnvironment}' contradicts the destination, ` +
        `which Veil classified as '${target.environment}'.`,
    );
  }

  return {
    level,
    reasons: [...new Set(reasons)],
    requiresStageB: forceStageB || stageBByLevel(config, level),
  };
}

function stageBByLevel(config: VeilConfig, level: RiskLevel): boolean {
  if (level === RiskLevel.HIGH) return true;
  if (level === RiskLevel.MEDIUM) return config.stageBForMedium;
  return config.stageBForLow;
}
