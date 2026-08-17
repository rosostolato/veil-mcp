"""Risk classification and confirmation policy (SPEC.md §10, §16, §26).

Every rule in this module is monotonic: it can only raise the risk level or turn
Stage B on. Nothing an agent sends can lower a classification, and a claimed
``environment`` that contradicts the destination's own naming raises risk rather
than lowering it.
"""

from __future__ import annotations

from veil.config import VeilConfig
from veil.model import (
    DestinationClass,
    Environment,
    NormalizedTarget,
    RiskAssessment,
    RiskLevel,
    WriteMode,
)


def evaluate_risk(
    config: VeilConfig,
    *,
    adapter_assessment: RiskAssessment,
    adapter_floor: RiskLevel,
    target: NormalizedTarget,
    operation: WriteMode,
    claimed_environment: Environment,
    exists: bool,
) -> RiskAssessment:
    level = adapter_assessment.level.escalate(adapter_floor)
    reasons: list[str] = list(adapter_assessment.reasons)
    force_stage_b = adapter_assessment.requires_stage_b

    if target.destination_class is DestinationClass.LOCAL_PLAINTEXT:
        level = level.escalate(RiskLevel.MEDIUM)
        reasons.append("Destination stores the credential as plaintext on this machine.")

    if target.destination_class is DestinationClass.REMOTE_APPLICATION_STORAGE:
        level = level.escalate(RiskLevel.MEDIUM)
        force_stage_b = True
        reasons.append("Destination may not be designed to store secrets.")

    if target.destination_class is DestinationClass.ARBITRARY_NETWORK:
        # Unreachable: the registry refuses these adapters. Kept as a floor so a
        # future adapter cannot quietly land in a lower band.
        level = RiskLevel.HIGH
        force_stage_b = True
        reasons.append("Destination is an arbitrary network endpoint.")

    if operation is WriteMode.REPLACE:
        level = level.escalate(RiskLevel.MEDIUM)
        force_stage_b = True
        reasons.append("Operation replaces an existing credential.")

    if exists and operation is not WriteMode.NEW_VERSION:
        level = level.escalate(RiskLevel.MEDIUM)
        force_stage_b = True
        reasons.append("A value already exists at this destination and will be overwritten.")

    if target.environment is Environment.PRODUCTION:
        level = level.escalate(RiskLevel.MEDIUM)
        reasons.append("Destination is classified as production.")
        if exists or operation is WriteMode.REPLACE:
            level = level.escalate(RiskLevel.HIGH)
            force_stage_b = True

    if target.environment is Environment.UNKNOWN:
        reasons.append("Environment could not be determined from the destination.")

    if claimed_environment.severity < target.environment.severity:
        if target.environment is Environment.PRODUCTION:
            level = RiskLevel.HIGH
            force_stage_b = True
        else:
            level = level.escalate(RiskLevel.MEDIUM)
        reasons.append(
            f"Requested environment '{claimed_environment}' contradicts the destination, "
            f"which Veil classified as '{target.environment}'."
        )

    requires_stage_b = force_stage_b or _stage_b_by_level(config, level)
    return RiskAssessment(
        level=level,
        reasons=tuple(dict.fromkeys(reasons)),
        requires_stage_b=requires_stage_b,
    )


def _stage_b_by_level(config: VeilConfig, level: RiskLevel) -> bool:
    if level is RiskLevel.HIGH:
        return True
    if level is RiskLevel.MEDIUM:
        return config.stage_b_for_medium
    return config.stage_b_for_low
