"""Descriptor Change Detection Engine for the MCP Security Gateway.

Detects when an MCP tool description changes using deterministic SHA-256 hashing.
Dispatches changed descriptions to the ML detector for security risk evaluation.

CRITICAL SECURITY PRINCIPLE:
    Hash Mismatch == Description Changed.
    Hash Mismatch != Description is Malicious.

A cryptographic hash mismatch proves modification; only the ML detector and policy
engine evaluate whether that modification constitutes a benign rewrite or an attack.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import logging
from typing import Any

from gateway.descriptor_registry import (
    DescriptorRegistry,
    STATUS_APPROVED,
    STATUS_PENDING_REVIEW,
    STATUS_QUARANTINED,
    compute_description_hash,
)
from gateway.feature_extractor import normalize_text
from gateway.ml_detector import DetectionResult, MLDetector

logger = logging.getLogger("change_detector")

# Change type identifiers
CHANGE_NO_CHANGE = "NO_CHANGE"
CHANGE_NEW_TOOL = "NEW_TOOL"
CHANGE_MODIFIED = "DESCRIPTION_MODIFIED"
CHANGE_SCHEMA_MODIFIED = "SCHEMA_MODIFIED"


def compute_schema_hash(schema: dict[str, Any] | None) -> str:
    """Compute deterministic SHA-256 hash of a tool inputSchema dictionary.

    Args:
        schema: Input schema dict or None

    Returns:
        Hexadecimal SHA-256 digest or empty string if schema is empty.
    """
    if not schema:
        return ""
    try:
        serialized = json.dumps(schema, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    except Exception:
        return ""


@dataclass
class ChangeDetectionResult:
    """Standardized result returned by the Change Detector."""
    tool_name: str
    server_name: str
    has_changed: bool
    change_type: str              # "NO_CHANGE", "NEW_TOOL", "DESCRIPTION_MODIFIED"
    old_hash: str | None
    new_hash: str
    old_description: str | None
    new_description: str
    is_approved: bool             # Whether the incoming description is already approved
    detection_result: DetectionResult | None  # ML inference result (if evaluated)
    summary: str

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        d = asdict(self)
        if self.detection_result:
            d["detection_result"] = self.detection_result.to_dict()
        return d


class DescriptorChangeDetector:
    """Coordinates cryptographic integrity checks and ML risk evaluation."""

    def __init__(
        self,
        registry: DescriptorRegistry | None = None,
        detector: MLDetector | None = None,
    ) -> None:
        self.registry = registry or DescriptorRegistry()
        self.detector = detector

    @staticmethod
    def compare_descriptions(
        old_description: str | None,
        new_description: str,
    ) -> tuple[bool, str, str | None, str]:
        """Normalize two descriptions, calculate SHA-256 hashes, and compare.

        Args:
            old_description: Existing description (or None if unseeded)
            new_description: Incoming description candidate

        Returns:
            Tuple of:
            - has_changed (bool): True if hashes differ or old is None
            - change_type (str): "NO_CHANGE", "NEW_TOOL", or "DESCRIPTION_MODIFIED"
            - old_hash (str | None): SHA-256 of old description
            - new_hash (str): SHA-256 of new description
        """
        norm_new = normalize_text(new_description)
        new_hash = compute_description_hash(norm_new)

        if old_description is None:
            return True, CHANGE_NEW_TOOL, None, new_hash

        norm_old = normalize_text(old_description)
        old_hash = compute_description_hash(norm_old)

        if old_hash == new_hash:
            return False, CHANGE_NO_CHANGE, old_hash, new_hash

        return True, CHANGE_MODIFIED, old_hash, new_hash

    def inspect_tool(
        self,
        tool_name: str,
        server_name: str,
        incoming_description: str,
        incoming_schema: dict[str, Any] | None = None,
        auto_record_candidate: bool = True,
    ) -> ChangeDetectionResult:
        """Inspect an incoming tool description against the approved registry.

        Workflow:
        1. Query registry for currently approved descriptor.
        2. Normalize description and compute SHA-256 hash.
        3. Compare hashes (and inputSchema if baseline schema is tracked).
        4. If hash mismatch: pass to ML detector for risk estimation.
        5. Record candidate in registry (pending review/quarantine) without trusting it.

        Args:
            tool_name: Name of tool
            server_name: MCP server name
            incoming_description: Description provided by server
            incoming_schema: Optional input schema dict
            auto_record_candidate: Whether to stage candidate in registry

        Returns:
            ChangeDetectionResult with cryptographic and ML diagnostics.
        """
        approved_desc = self.registry.get_approved(tool_name, server_name)
        old_text = approved_desc.description if approved_desc else None

        has_changed, change_type, old_hash, new_hash = self.compare_descriptions(
            old_description=old_text,
            new_description=incoming_description,
        )

        # Check inputSchema integrity if baseline schema is recorded in metadata
        schema_changed = False
        if approved_desc and approved_desc.metadata and incoming_schema is not None:
            old_schema = approved_desc.metadata.get("inputSchema")
            if old_schema is not None:
                old_s_hash = compute_schema_hash(old_schema)
                new_s_hash = compute_schema_hash(incoming_schema)
                if old_s_hash != new_s_hash:
                    schema_changed = True
                    has_changed = True
                    if change_type == CHANGE_NO_CHANGE:
                        change_type = CHANGE_SCHEMA_MODIFIED

        ml_result: DetectionResult | None = None
        is_already_approved = (not has_changed and approved_desc is not None and approved_desc.status == STATUS_APPROVED)

        # If description changed (or is brand new), trigger ML risk evaluation
        if has_changed:
            if self.detector is not None:
                try:
                    ml_result = self.detector.predict(
                        description=incoming_description,
                        old_description=old_text,
                    )
                except Exception as e:
                    logger.error(f"ML prediction error for {server_name}:{tool_name}: {e}. Failing closed.")
                    ml_result = DetectionResult(
                        predicted_label=1,
                        malicious_probability=1.0,
                        risk_level="CRITICAL",
                        model_name=getattr(self.detector, "model_name", "Unknown"),
                        signals={"prediction_error": 1},
                        drift={},
                        confidence_assessment=f"ML prediction failed ({e}). Fail-closed policy assigned CRITICAL risk.",
                    )
            else:
                logger.warning(f"No ML detector loaded for {server_name}:{tool_name}. Failing closed under unverified change.")
                ml_result = DetectionResult(
                    predicted_label=1,
                    malicious_probability=1.0,
                    risk_level="CRITICAL",
                    model_name="None",
                    signals={"detector_missing": 1},
                    drift={},
                    confidence_assessment="ML detector is not loaded; failing closed.",
                )

            # Stage in registry as PENDING_REVIEW or QUARANTINED based on ML risk
            if auto_record_candidate:
                initial_status = (
                    STATUS_QUARANTINED
                    if (ml_result.risk_level in ["HIGH", "CRITICAL"])
                    else STATUS_PENDING_REVIEW
                )
                self.registry.record_candidate(
                    tool_name=tool_name,
                    server_name=server_name,
                    description=incoming_description,
                    status=initial_status,
                )

        # Formulate clear diagnostic summary
        if not has_changed:
            summary = (
                f"Tool '{server_name}:{tool_name}' description matches approved SHA-256 hash ({new_hash[:8]}...). "
                f"No changes detected. Status: APPROVED."
            )
        elif change_type == CHANGE_NEW_TOOL:
            risk_desc = f", evaluated as {ml_result.risk_level} risk ({ml_result.malicious_probability:.1%})" if ml_result else ""
            summary = (
                f"Tool '{server_name}:{tool_name}' is newly discovered (SHA: {new_hash[:8]}...){risk_desc}. "
                f"Not yet approved. Requires authorization."
            )
        else:
            risk_desc = f" ML Detector assessed {ml_result.risk_level} risk ({ml_result.malicious_probability:.1%})." if ml_result else ""
            summary = (
                f"Tool '{server_name}:{tool_name}' description hash changed "
                f"(Old: {old_hash[:8]}... -> New: {new_hash[:8]}...).{risk_desc} "
                f"Remember: Hash mismatch indicates modification, not malice."
            )

        return ChangeDetectionResult(
            tool_name=tool_name,
            server_name=server_name,
            has_changed=has_changed,
            change_type=change_type,
            old_hash=old_hash,
            new_hash=new_hash,
            old_description=old_text,
            new_description=incoming_description,
            is_approved=is_already_approved,
            detection_result=ml_result,
            summary=summary,
        )
