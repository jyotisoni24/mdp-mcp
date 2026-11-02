"""Decision Policy Engine for the MCP Security Gateway.

Combines cryptographic verification, ML detector inferences, drift telemetry,
and mandatory security rules to select an enforcement action:
    - ALLOW: Tool description is verified and meets all security constraints.
    - QUARANTINE: Tool is unverified, modified, or has uncertain risk; held for review.
    - BLOCK: Strong evidence of an attack or mandatory security policy violation.

CRITICAL INVARIANTS:
1. Mandatory security checks CANNOT be overridden by a low ML risk score.
2. Unapproved new tools or modified descriptors are NEVER automatically ALLOWed;
   they must be held in QUARANTINE until explicitly authorized.
3. Thresholds and policy rules are strictly configurable, not hardcoded.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import datetime as dt
import json
import logging
from pathlib import Path
import re
from typing import Any

from gateway.audit_logger import AuditLogger
from gateway.change_detector import ChangeDetectionResult
from gateway.descriptor_registry import DescriptorRegistry
from gateway.ml_detector import DetectionResult

logger = logging.getLogger("policy_engine")

# Action constants
ACTION_ALLOW = "ALLOW"
ACTION_QUARANTINE = "QUARANTINE"
ACTION_BLOCK = "BLOCK"

# Policy modes
POLICY_MODE_THRESHOLD = "threshold"
POLICY_MODE_MDP = "mdp"

# MDP State constants (aligned with training/train_mdp.py)
STATE_LOW_RISK_APPROVED = 0
STATE_LOW_RISK_UNVERIFIED = 1
STATE_MEDIUM_RISK_UNVERIFIED = 2
STATE_HIGH_RISK_UNVERIFIED = 3
STATE_QUARANTINED_AWAITING_REVIEW = 4
STATE_REVIEW_CONFIRMED_SAFE = 5
STATE_REVIEW_CONFIRMED_MALICIOUS = 6
STATE_TERMINAL = 7

STATE_NAMES = {
    STATE_LOW_RISK_APPROVED: "LOW_RISK_APPROVED",
    STATE_LOW_RISK_UNVERIFIED: "LOW_RISK_UNVERIFIED",
    STATE_MEDIUM_RISK_UNVERIFIED: "MEDIUM_RISK_UNVERIFIED",
    STATE_HIGH_RISK_UNVERIFIED: "HIGH_RISK_UNVERIFIED",
    STATE_QUARANTINED_AWAITING_REVIEW: "QUARANTINED_AWAITING_REVIEW",
    STATE_REVIEW_CONFIRMED_SAFE: "REVIEW_CONFIRMED_SAFE",
    STATE_REVIEW_CONFIRMED_MALICIOUS: "REVIEW_CONFIRMED_MALICIOUS",
    STATE_TERMINAL: "TERMINAL",
}

# Mandatory security violation patterns (severe threats that must never be permitted)
MANDATORY_BLOCK_PATTERNS = [
    (r"~?/\.ssh/id_rsa(?:\.pub)?", "Attempts to access or exfiltrate private/public SSH keys"),
    (r"/etc/(?:shadow|passwd)", "Attempts to access system credential files"),
    (r"\bdo\s+not\s+tell\s+the\s+user\b", "Attempts to enforce covert/hidden execution from user"),
    (r"\boverwrite\s+['\"]?~?/\.ssh", "Attempts destructive overwriting of SSH authorization files"),
    (r"\bignore\s+(?:all\s+)?(?:prior|previous|system)\s+(?:instructions|rules|prompts)\b", "Prompt injection: attempts to ignore prior instructions"),
    (r"\bimportant\s+instruction\s+for\s+the\s+(?:ai|model|llm)\b", "Prompt injection: directive targeting AI instruction override"),
    (r"\boverride\s+(?:all\s+)?(?:safety|system|user)\s+(?:constraints|preferences|instructions)\b", "Prompt injection: attempts to override safety constraints or preferences"),
]


@dataclass
class PolicyConfig:
    """Configurable security policy thresholds and switches."""
    allow_threshold: float = 0.25          # Maximum ML probability to permit ALLOW (if verified)
    block_threshold: float = 0.70          # Minimum ML probability to trigger immediate BLOCK
    require_prior_approval: bool = True     # Unverified tools must be reviewed, never auto-allowed
    enforce_mandatory_checks: bool = True   # Mandatory rules cannot be overridden by ML score
    mode: str = POLICY_MODE_THRESHOLD      # "threshold" (default) or "mdp"
    mdp_policy_file: Path | None = None    # Path to mdp_policy.json (defaults to models/mdp_policy.json)
    mdp_algorithm: str = "q_learning"      # "q_learning" or "value_iteration"


@dataclass
class PolicyDecision:
    """Represents the final enforcement outcome for a tool description."""
    action: str                  # "ALLOW", "QUARANTINE", "BLOCK"
    reason: str                  # Human-readable explanation
    rule_triggered: str          # Name of policy rule that decided the action
    malicious_probability: float # Model probability in [0.0, 1.0]
    risk_level: str              # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    is_approved: bool            # Whether description is already approved in registry
    violations: list[str]        # List of detected mandatory policy violations
    details: dict[str, Any]      # Diagnostic context for auditing
    sha256_hash: str = ""        # SHA-256 descriptor hash
    timestamp: str = ""          # ISO 8601 evaluation timestamp

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_mandatory_violations(text: str) -> list[str]:
    """Scan text for mandatory policy violations that cause immediate BLOCK.

    Args:
        text: Candidate tool description

    Returns:
        List of human-readable violation descriptions.
    """
    violations: list[str] = []
    for pattern, description in MANDATORY_BLOCK_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            violations.append(description)
    return violations


class PolicyEngine:
    """Evaluates security evidence and enforces ALLOW / QUARANTINE / BLOCK decisions."""

    def __init__(
        self,
        config: PolicyConfig | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.config = config or PolicyConfig()
        self.audit_logger = audit_logger or AuditLogger()
        self._mdp_policy: dict[str, str] | None = None

    @property
    def mdp_policy(self) -> dict[str, str]:
        """Lazy-load and cache the optimal MDP policy table."""
        if self._mdp_policy is None:
            self._mdp_policy = self._load_mdp_policy()
        return self._mdp_policy

    def _load_mdp_policy(self) -> dict[str, str]:
        """Load optimal MDP policy from disk or fallback to sound defaults."""
        policy_file = self.config.mdp_policy_file
        if policy_file is None:
            default_file = Path(__file__).resolve().parent.parent / "models" / "mdp_policy.json"
            if default_file.exists():
                policy_file = default_file

        if policy_file and Path(policy_file).exists():
            try:
                with open(policy_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                key = (
                    "q_learning_policy"
                    if self.config.mdp_algorithm == "q_learning"
                    else "value_iteration_policy"
                )
                if key in data:
                    logger.info(f"Loaded MDP policy ({key}) from {policy_file}")
                    return data[key]
            except Exception as e:
                logger.warning(f"Could not read MDP policy from {policy_file}: {e}. Using default.")

        # Built-in sound default policy aligned with MDP training
        return {
            "LOW_RISK_APPROVED": ACTION_ALLOW,
            "LOW_RISK_UNVERIFIED": ACTION_QUARANTINE,
            "MEDIUM_RISK_UNVERIFIED": ACTION_QUARANTINE,
            "HIGH_RISK_UNVERIFIED": ACTION_BLOCK,
            "QUARANTINED_AWAITING_REVIEW": ACTION_QUARANTINE,
            "REVIEW_CONFIRMED_SAFE": ACTION_ALLOW,
            "REVIEW_CONFIRMED_MALICIOUS": ACTION_BLOCK,
            "TERMINAL": ACTION_ALLOW,
        }

    def map_to_mdp_state(
        self,
        change_result: ChangeDetectionResult,
        review_status: str | None = None,
    ) -> tuple[int, str]:
        """Map an incoming inspection result to the MDP state space.

        Args:
            change_result: Standardized change detection result.
            review_status: Optional administrative review status:
                "CONFIRMED_SAFE", "CONFIRMED_MALICIOUS", or None.

        Returns:
            Tuple of (state_id: int, state_name: str).
        """
        # 1. Check for manual/analyst review disposition
        if review_status == "CONFIRMED_SAFE":
            return STATE_REVIEW_CONFIRMED_SAFE, "REVIEW_CONFIRMED_SAFE"
        elif review_status == "CONFIRMED_MALICIOUS":
            return STATE_REVIEW_CONFIRMED_MALICIOUS, "REVIEW_CONFIRMED_MALICIOUS"

        ml = change_result.detection_result
        mal_prob = ml.malicious_probability if ml else 0.0
        risk_level = ml.risk_level if ml else "LOW"

        # 2. Approved baseline match character-for-character with low risk
        if change_result.is_approved and not change_result.has_changed and risk_level == "LOW":
            return STATE_LOW_RISK_APPROVED, "LOW_RISK_APPROVED"

        # 3. New tool or changed description categorized by ML risk tier
        if risk_level in ["HIGH", "CRITICAL"] or mal_prob >= 0.60:
            return STATE_HIGH_RISK_UNVERIFIED, "HIGH_RISK_UNVERIFIED"
        elif risk_level == "MEDIUM" or mal_prob >= 0.30:
            return STATE_MEDIUM_RISK_UNVERIFIED, "MEDIUM_RISK_UNVERIFIED"
        else:
            return STATE_LOW_RISK_UNVERIFIED, "LOW_RISK_UNVERIFIED"

    def evaluate(
        self,
        change_result: ChangeDetectionResult,
        review_status: str | None = None,
    ) -> PolicyDecision:
        """Evaluate an incoming tool inspection result and return an enforcement decision.

        Args:
            change_result: Result from DescriptorChangeDetector.inspect_tool()
            review_status: Optional administrative review disposition ("CONFIRMED_SAFE" or "CONFIRMED_MALICIOUS")

        Returns:
            PolicyDecision (ALLOW, QUARANTINE, or BLOCK).
        """
        tool_name = change_result.tool_name
        server_name = change_result.server_name
        desc = change_result.new_description
        is_approved = change_result.is_approved
        has_changed = change_result.has_changed
        ml = change_result.detection_result

        mal_prob = ml.malicious_probability if ml else 0.0
        risk_level = ml.risk_level if ml else "LOW"

        # -------------------------------------------------------------
        # Rule 1: Mandatory Security Policy Enforcement
        # Cannot be overridden by low ML risk score or MDP policy.
        # -------------------------------------------------------------
        violations: list[str] = []
        if self.config.enforce_mandatory_checks:
            violations = evaluate_mandatory_violations(desc)
            if violations:
                decision = PolicyDecision(
                    action=ACTION_BLOCK,
                    reason=f"Mandatory security violation: {'; '.join(violations)}",
                    rule_triggered="RULE_MANDATORY_SECURITY_VIOLATION",
                    malicious_probability=mal_prob,
                    risk_level="CRITICAL",
                    is_approved=is_approved,
                    violations=violations,
                    details={"matched_violations": violations},
                )
                self._log_decision(change_result, decision)
                return decision

        # -------------------------------------------------------------
        # Mode Check: MDP-based Sequential Decision Policy
        # -------------------------------------------------------------
        if self.config.mode == POLICY_MODE_MDP:
            state_id, state_name = self.map_to_mdp_state(change_result, review_status=review_status)
            action = self.mdp_policy.get(state_name, ACTION_QUARANTINE)

            reason = (
                f"MDP Policy ({self.config.mdp_algorithm}) selected action '{action}' "
                f"for state '{state_name}' (ML risk: {risk_level}, prob: {mal_prob:.1%})."
            )
            rule = f"RULE_MDP_POLICY_{state_name}"

            decision = PolicyDecision(
                action=action,
                reason=reason,
                rule_triggered=rule,
                malicious_probability=mal_prob,
                risk_level=risk_level,
                is_approved=is_approved,
                violations=[],
                details={
                    "mdp_state_id": state_id,
                    "mdp_state_name": state_name,
                    "mdp_algorithm": self.config.mdp_algorithm,
                    "drift": ml.drift if ml else {},
                },
            )
            self._log_decision(change_result, decision)
            return decision

        # -------------------------------------------------------------
        # Rule 2: Verified Approved Baseline (Threshold Mode)
        # Description matches approved SHA-256 hash character-for-character.
        # -------------------------------------------------------------
        if is_approved and not has_changed:
            decision = PolicyDecision(
                action=ACTION_ALLOW,
                reason="Tool description is verified and matches the approved cryptographic baseline.",
                rule_triggered="RULE_APPROVED_BASELINE_MATCH",
                malicious_probability=mal_prob,
                risk_level=risk_level,
                is_approved=True,
                violations=[],
                details={"approved_hash": change_result.old_hash},
            )
            self._log_decision(change_result, decision)
            return decision

        # -------------------------------------------------------------
        # Rule 3: High-Confidence ML Attack Detection (Threshold Mode)
        # ML model probability meets or exceeds block_threshold.
        # -------------------------------------------------------------
        if mal_prob >= self.config.block_threshold or risk_level in ["HIGH", "CRITICAL"]:
            decision = PolicyDecision(
                action=ACTION_BLOCK,
                reason=(
                    f"ML Detector identified severe attack patterns with {mal_prob:.1%} malicious probability "
                    f"({risk_level} risk)."
                ),
                rule_triggered="RULE_ML_HIGH_RISK_ATTACK",
                malicious_probability=mal_prob,
                risk_level=risk_level,
                is_approved=is_approved,
                violations=[],
                details={"ml_probability": mal_prob, "signals": ml.signals if ml else {}},
            )
            self._log_decision(change_result, decision)
            return decision

        # -------------------------------------------------------------
        # Rule 4: Unverified Changes / New Tools with Low Risk (Threshold Mode)
        # Description changed, looks benign (low ML risk), but has not been authorized.
        # -------------------------------------------------------------
        if has_changed or not is_approved:
            if self.config.require_prior_approval:
                action = ACTION_QUARANTINE
                rule = "RULE_UNVERIFIED_DRIFT_QUARANTINED"
                reason = (
                    f"Description was modified or newly registered (ML risk: {risk_level}, {mal_prob:.1%}). "
                    f"Held in QUARANTINE pending administrative authorization."
                )
            else:
                action = ACTION_ALLOW if mal_prob <= self.config.allow_threshold else ACTION_QUARANTINE
                rule = "RULE_UNVERIFIED_ALLOW_POLICY_RELAXED"
                reason = "Prior approval check disabled; allowed on low risk."

            decision = PolicyDecision(
                action=action,
                reason=reason,
                rule_triggered=rule,
                malicious_probability=mal_prob,
                risk_level=risk_level,
                is_approved=is_approved,
                violations=[],
                details={"drift": ml.drift if ml else {}},
            )
            self._log_decision(change_result, decision)
            return decision

        # -------------------------------------------------------------
        # Rule 5: Fallback Fail-Safe (Threshold Mode)
        # Any ambiguous condition is held in QUARANTINE.
        # -------------------------------------------------------------
        decision = PolicyDecision(
            action=ACTION_QUARANTINE,
            reason="Ambiguous risk signals. Held in QUARANTINE under fail-safe policy.",
            rule_triggered="RULE_FAILSAFE_QUARANTINE",
            malicious_probability=mal_prob,
            risk_level=risk_level,
            is_approved=is_approved,
            violations=[],
            details={},
        )
        self._log_decision(change_result, decision)
        return decision

    def _log_decision(self, change_result: ChangeDetectionResult, decision: PolicyDecision) -> None:
        """Emit audit log entry and record decision provenance."""
        decision.sha256_hash = change_result.new_hash
        if not decision.timestamp:
            decision.timestamp = dt.datetime.now(dt.timezone.utc).isoformat()

        self.audit_logger.log(
            event_type="POLICY_ENFORCEMENT",
            server_name=change_result.server_name,
            tool_name=change_result.tool_name,
            decision=decision.action,
            reason=decision.reason,
            rule_triggered=decision.rule_triggered,
            new_hash=change_result.new_hash,
            old_hash=change_result.old_hash,
            malicious_probability=decision.malicious_probability,
            risk_level=decision.risk_level,
            has_changed=change_result.has_changed,
            metadata=decision.details,
        )
