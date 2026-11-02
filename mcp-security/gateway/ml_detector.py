"""Supervised Machine Learning Detection Engine for MCP Tool Descriptions.

This component evaluates candidate MCP tool descriptions using a trained statistical
ML model (TF-IDF + Logistic Regression with probability calibration).

Key guarantees:
1. Outputs continuous malicious probabilities [0.0, 1.0], not just binary flags.
2. Maps probabilities into structured risk levels: LOW, MEDIUM, HIGH, CRITICAL.
3. Explicitly caveats probabilities as empirical risk estimates, not guaranteed certainty.
4. Provides interpretable signal diagnostics alongside ML inferences.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from gateway.feature_extractor import MCPFeatureExtractor, compute_drift_features, extract_signal_counts, normalize_text

logger = logging.getLogger("ml_detector")

# Risk thresholds for mapping continuous probability into operational categories
RISK_THRESHOLDS = {
    "LOW": 0.30,       # Below 0.30: Minimal risk
    "MEDIUM": 0.60,    # 0.30 to 0.60: Moderate/uncertain risk (needs attention/quarantine)
    "HIGH": 0.85,      # 0.60 to 0.85: Elevated attack likelihood
    # >= 0.85: Critical attack likelihood
}


@dataclass
class DetectionResult:
    """Standardized detection result output by the ML detector."""
    predicted_label: int          # 0 = Safe, 1 = Malicious
    malicious_probability: float  # Model probability in [0.0, 1.0]
    risk_level: str               # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    model_name: str               # e.g., "TfidfLogisticRegression"
    signals: dict[str, int]       # Detected heuristic directive/target counts
    drift: dict[str, float]       # Difference metrics against approved version
    confidence_assessment: str    # Plain English explanation of the uncertainty

    def to_dict(self) -> dict[str, Any]:
        """Convert result to serializable dictionary."""
        return asdict(self)


def categorize_risk(prob: float) -> str:
    """Map a continuous probability score into an operational risk tier.

    Args:
        prob: Estimated malicious probability in [0.0, 1.0]

    Returns:
        Risk level string: "LOW", "MEDIUM", "HIGH", or "CRITICAL".
    """
    if prob < RISK_THRESHOLDS["LOW"]:
        return "LOW"
    elif prob < RISK_THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    elif prob < RISK_THRESHOLDS["HIGH"]:
        return "HIGH"
    return "CRITICAL"


class PredictionError(RuntimeError):
    """Raised when ML model prediction or transformation fails."""
    pass


class MLDetector:
    """Production ML Detector for analyzing MCP tool descriptions."""

    def __init__(
        self,
        model: Any | None = None,
        extractor: MCPFeatureExtractor | None = None,
        model_name: str = "TfidfLogisticRegression",
    ) -> None:
        self.model = model
        self.extractor = extractor or MCPFeatureExtractor()
        self.model_name = model_name

    @classmethod
    def from_files(
        cls,
        model_path: Path,
        vectorizer_path: Path,
        model_name: str = "TfidfLogisticRegression",
    ) -> "MLDetector":
        """Load detector directly from explicit model and vectorizer file paths.

        Args:
            model_path: Path to serialized scikit-learn classifier (.joblib)
            vectorizer_path: Path to serialized vectorizer (.joblib)
            model_name: Descriptive identifier for the model

        Returns:
            Initialized MLDetector instance.
        """
        if not model_path.exists():
            raise FileNotFoundError(f"Missing classifier artifact: {model_path}")
        if not vectorizer_path.exists():
            raise FileNotFoundError(f"Missing vectorizer artifact: {vectorizer_path}")

        model = joblib.load(model_path)
        vectorizer = joblib.load(vectorizer_path)
        extractor = MCPFeatureExtractor(vectorizer=vectorizer)
        return cls(model=model, extractor=extractor, model_name=model_name)

    @classmethod
    def load(
        cls,
        model_dir: Path,
        model_filename: str = "detector_model.joblib",
        vectorizer_filename: str = "vectorizer.joblib",
        metadata_filename: str | None = "metadata.json",
        fallback_to_baseline: bool = False,
    ) -> "MLDetector":
        """Load a serialized model and feature extractor from a directory.

        Args:
            model_dir: Directory containing model artifacts
            model_filename: Filename of classifier artifact
            vectorizer_filename: Filename of vectorizer artifact
            metadata_filename: Optional metadata filename
            fallback_to_baseline: If True and requested files are missing, attempt
                                  falling back to baseline model artifacts.
                                  Defaults to False (fail-closed).

        Returns:
            Initialized MLDetector instance.
        """
        model_path = model_dir / model_filename
        vec_path = model_dir / vectorizer_filename

        if not model_path.exists() or not vec_path.exists():
            if fallback_to_baseline and (model_filename != "detector_model.joblib"):
                logger.warning(
                    f"Requested model '{model_filename}' not found in {model_dir}. "
                    "Falling back to baseline 'detector_model.joblib' as explicitly configured."
                )
                return cls.load(model_dir, "detector_model.joblib", "vectorizer.joblib", metadata_filename)

            raise FileNotFoundError(
                f"Missing model artifacts in {model_dir} ({model_filename}, {vectorizer_filename}). "
                "Fail-closed policy requires valid model artifacts."
            )

        model = joblib.load(model_path)
        vectorizer = joblib.load(vec_path)
        extractor = MCPFeatureExtractor(vectorizer=vectorizer)

        model_name = "TfidfLogisticRegression"
        if metadata_filename:
            meta_path = model_dir / metadata_filename
            if meta_path.exists():
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                    model_name = meta.get("model_name", model_name)

        return cls(model=model, extractor=extractor, model_name=model_name)

    @classmethod
    def load_expanded(
        cls,
        model_dir: Path,
        fallback_to_baseline: bool = False,
    ) -> "MLDetector":
        """Load the expanded statistical ML detector model and vectorizer.

        Integrates 'expanded_detector_model.joblib' and 'expanded_vectorizer.joblib'.

        Args:
            model_dir: Directory containing expanded model artifacts
            fallback_to_baseline: If True and expanded artifacts are missing,
                                  fall back to baseline model. Defaults to False.

        Returns:
            Initialized MLDetector configured with the expanded model.
        """
        model_path = model_dir / "expanded_detector_model.joblib"
        vec_path = model_dir / "expanded_vectorizer.joblib"
        report_path = model_dir / "expanded_training_report.json"

        if not model_path.exists() or not vec_path.exists():
            if fallback_to_baseline:
                logger.warning(
                    f"Expanded model artifacts not found in {model_dir}. "
                    "Falling back to baseline model as explicitly configured."
                )
                return cls.load(model_dir)

            raise FileNotFoundError(
                f"Expanded model artifacts missing in {model_dir}: "
                f"{model_path.name if not model_path.exists() else ''} "
                f"{vec_path.name if not vec_path.exists() else ''}. "
                "Set fallback_to_baseline=True if baseline fallback is permitted."
            )

        model = joblib.load(model_path)
        vectorizer = joblib.load(vec_path)
        extractor = MCPFeatureExtractor(vectorizer=vectorizer)

        model_name = "expanded_baseline_detector"
        if report_path.exists():
            try:
                with open(report_path, "r", encoding="utf-8") as f:
                    report = json.load(f)
                    model_name = report.get("pipeline_metadata", {}).get("model_name", model_name)
            except Exception as e:
                logger.warning(f"Could not load metadata from {report_path}: {e}")

        return cls(model=model, extractor=extractor, model_name=model_name)

    def predict(
        self,
        description: str,
        old_description: str | None = None,
    ) -> DetectionResult:
        """Evaluate a tool description candidate.

        Args:
            description: Incoming candidate tool description
            old_description: Currently approved description (if updating), or None

        Returns:
            DetectionResult containing label, calibrated probability, risk level, and explanation.

        Raises:
            PredictionError: If the model is uninitialized or prediction fails unexpectedly.
        """
        if self.model is None:
            raise PredictionError("MLDetector model has not been trained or loaded.")

        norm_desc = normalize_text(description)

        # Handle empty, missing, or whitespace-only descriptions safely (fail-closed)
        if not norm_desc:
            drift = compute_drift_features(old_description, norm_desc)
            signals = {
                "directive_signals": 0,
                "sensitive_target_signals": 0,
                "total_security_signals": 0,
                "empty_description": 1,
            }
            return DetectionResult(
                predicted_label=1,
                malicious_probability=1.0,
                risk_level="CRITICAL",
                model_name=self.model_name,
                signals=signals,
                drift=drift,
                confidence_assessment=(
                    "Fail-closed evaluation: empty or missing tool description represents an "
                    "anomalous or evasive descriptor. Assigned CRITICAL risk (probability 100.0%)."
                ),
            )

        signals = extract_signal_counts(norm_desc)
        drift = compute_drift_features(old_description, norm_desc)

        try:
            # Vectorize incoming description
            features = self.extractor.transform([norm_desc])

            # Obtain continuous probability for class 1 (malicious)
            probabilities = self.model.predict_proba(features)[0]
            mal_prob = float(probabilities[1])
            # Clamp probability to strict [0.0, 1.0] range
            mal_prob = max(0.0, min(1.0, mal_prob))
            predicted_label = int(mal_prob >= 0.50)

            risk_level = categorize_risk(mal_prob)

            confidence_text = (
                f"Estimated malicious probability is {mal_prob:.2%} based on empirical statistical patterns. "
                f"Classified as {risk_level} risk. This is a probabilistic risk estimate, not an absolute guarantee."
            )

            return DetectionResult(
                predicted_label=predicted_label,
                malicious_probability=round(mal_prob, 4),
                risk_level=risk_level,
                model_name=self.model_name,
                signals=signals,
                drift=drift,
                confidence_assessment=confidence_text,
            )
        except Exception as exc:
            logger.error(f"Prediction failed for description '{norm_desc[:50]}...': {exc}")
            raise PredictionError(f"ML prediction pipeline error: {exc}") from exc
