import math
from dataclasses import dataclass
from typing import Dict, Any
from enum import Enum


class RiskTier(Enum):
    LOW = "LOW"             # 0 - 39: Standard monitoring
    MEDIUM = "MEDIUM"       # 40 - 69: SOC watchlist
    HIGH = "HIGH"           # 70 - 89: Escalation & candidate for unmasking
    CRITICAL = "CRITICAL"   # 90 - 100: Immediate session revocation & legal escalation


@dataclass
class BehavioralProfile:
    user_pseudonym: str
    is_resignation_notice: bool = False
    is_on_pip: bool = False
    flight_risk_score: float = 0.0  # Normalized 0.0 to 1.0
    access_blast_radius_tier: str = "TIER_3"  # TIER_1 (Prod/Keys), TIER_2 (Financial), TIER_3 (Standard)


@dataclass
class TechnicalTelemetrySignals:
    off_hours_egress_mb: float = 0.0
    privilege_escalation_detected: bool = False
    usb_staging_detected: bool = False
    scripted_client_used: bool = False
    historical_mean_daily_mb: float = 50.0
    historical_std_daily_mb: float = 20.0


class InsiderRiskScoringEngine:
    """
    Weighted Risk Scoring Engine combining technical indicator severities,
    non-linear behavioral context multipliers, and dynamic baseline Z-scores.
    """
    TECHNICAL_WEIGHTS = {
        "cloud_egress": 0.30,
        "priv_esc": 0.25,
        "usb_staging": 0.25,
        "scripted_client": 0.20
    }

    BLAST_RADIUS_MULTIPLIERS = {
        "TIER_1": 1.25,
        "TIER_2": 1.15,
        "TIER_3": 1.00
    }

    def _normalize_egress(self, mb: float) -> float:
        """Converts raw egress volume into a normalized 0-100 score via sigmoidal scaling."""
        if mb <= 50:
            return 0.0
        return min(100.0, 100.0 / (1.0 + math.exp(-(mb - 500) / 250)))

    def _calculate_anomaly_penalty(self, current_mb: float, mean_mb: float, std_mb: float) -> float:
        """Calculates statistical z-score penalty capped at 20 points."""
        if std_mb <= 0:
            return 0.0
        z_score = max(0.0, (current_mb - mean_mb) / std_mb)
        return min(20.0, z_score * 4.0)

    def evaluate_risk(
        self,
        signals: TechnicalTelemetrySignals,
        behavior: BehavioralProfile
    ) -> Dict[str, Any]:
        # 1. Base Technical Indicators
        t_egress = self._normalize_egress(signals.off_hours_egress_mb)
        t_priv = 100.0 if signals.privilege_escalation_detected else 0.0
        t_usb = 100.0 if signals.usb_staging_detected else 0.0
        t_client = 100.0 if signals.scripted_client_used else 0.0

        raw_technical_base = (
            t_egress * self.TECHNICAL_WEIGHTS["cloud_egress"] +
            t_priv * self.TECHNICAL_WEIGHTS["priv_esc"] +
            t_usb * self.TECHNICAL_WEIGHTS["usb_staging"] +
            t_client * self.TECHNICAL_WEIGHTS["scripted_client"]
        )

        # 2. Behavioral Context Multipliers
        multiplier = 1.0
        if behavior.is_resignation_notice:
            multiplier *= 1.60
        if behavior.is_on_pip:
            multiplier *= 1.35
        if behavior.flight_risk_score > 0.6:
            multiplier *= (1.0 + (behavior.flight_risk_score * 0.3))

        multiplier *= self.BLAST_RADIUS_MULTIPLIERS.get(behavior.access_blast_radius_tier, 1.0)

        # 3. Dynamic Baseline Anomaly Penalty
        anomaly_bonus = self._calculate_anomaly_penalty(
            signals.off_hours_egress_mb,
            signals.historical_mean_daily_mb,
            signals.historical_std_daily_mb
        )

        # 4. Composite Score Formulation
        final_score = min(100.0, (raw_technical_base * multiplier) + anomaly_bonus)
        final_score = round(final_score, 2)

        # 5. Risk Tier Assignment
        if final_score >= 90.0:
            tier = RiskTier.CRITICAL
        elif final_score >= 70.0:
            tier = RiskTier.HIGH
        elif final_score >= 40.0:
            tier = RiskTier.MEDIUM
        else:
            tier = RiskTier.LOW

        return {
            "entity": behavior.user_pseudonym,
            "composite_risk_score": final_score,
            "risk_tier": tier.value,
            "breakdown": {
                "raw_technical_score": round(raw_technical_base, 2),
                "applied_multiplier": round(multiplier, 2),
                "anomaly_penalty_points": round(anomaly_bonus, 2)
            },
            "triggers_tripped": {
                "off_hours_egress": signals.off_hours_egress_mb > 0,
                "privilege_escalation": signals.privilege_escalation_detected,
                "usb_staging": signals.usb_staging_detected,
                "scripted_ua": signals.scripted_client_used,
                "active_notice_period": behavior.is_resignation_notice,
                "pip_status": behavior.is_on_pip
            },
            "unmasking_eligible": final_score >= 70.0
        }
