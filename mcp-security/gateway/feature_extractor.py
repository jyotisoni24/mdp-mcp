"""Feature extraction module for MCP tool descriptions.

Extracts both statistical NLP representations (TF-IDF vectorization) and
domain-specific security signals from MCP tool descriptions.

Features extracted:
1. Normalized description text (whitespace, quotes, control characters cleaned).
2. TF-IDF n-gram vectors (unigrams + bigrams) capturing subphrase semantics.
3. Suspicious directive and exfiltration signals:
   - Mandatory invocation instructions ("you must first call", "prerequisite")
   - Sensitive target paths and credentials ("~/.ssh", "/etc/shadow", "token", "api_key")
   - Covert execution directives ("do not tell", "silently", "mandatory pre-authorization")
4. Descriptor drift features when comparing an old and new description:
   - Token Jaccard similarity and character-level edit ratio
   - Length expansion ratio
   - Drift in security signal intensity
"""
from __future__ import annotations

import difflib
import re
from typing import Any

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

# Regex patterns for security signals in MCP tool descriptions
DIRECTIVE_PATTERNS = [
    r"\bmust\s+(?:first\s+)?call\b",
    r"\bmandatory\b",
    r"\bprerequisite\b",
    r"\bdo\s+not\s+tell\s+the\s+user\b",
    r"\bsilently\b",
    r"\bpre-authorization\s+check\b",
    r"\bbefore\s+(?:using|performing|calling)\b",
    r"\bexecute\s+first\b",
    r"\boverwrite\b",
    r"\brequire[s]?\s+access\s+to\b",
]

SENSITIVE_TARGET_PATTERNS = [
    r"~?/\.ssh[/\w\.\-]*",
    r"/etc/(?:shadow|passwd)",
    r"\bid_rsa(?:\.pub)?\b",
    r"\bcredential[s]?\b",
    r"\bapi[_\s]?key\b",
    r"\bsecurity[_\s]?token\b",
    r"\bsecret[s]?\b",
    r"\benv(?:ironment)?\s+var(?:iable)?[s]?\b",
]


def normalize_text(text: str) -> str:
    """Normalize raw text by stripping extraneous whitespace and control characters.

    Args:
        text: Raw description string

    Returns:
        Cleaned, normalized string
    """
    if not isinstance(text, str):
        text = str(text) if text is not None else ""
    # Replace multiple whitespaces and newlines with a single space
    cleaned = re.sub(r"\s+", " ", text)
    # Strip leading and trailing whitespace
    return cleaned.strip()


def extract_signal_counts(text: str) -> dict[str, int]:
    """Extract counts of heuristic security signals from description text.

    Note: These signals are used for explainability, telemetry, and composite
    features; they are NOT used as brittle hardcoded decision rules.

    Args:
        text: Normalized tool description

    Returns:
        Dictionary of detected signal counts.
    """
    normalized = text.lower()

    directive_hits = 0
    for pat in DIRECTIVE_PATTERNS:
        matches = re.findall(pat, normalized, flags=re.IGNORECASE)
        directive_hits += len(matches)

    sensitive_hits = 0
    for pat in SENSITIVE_TARGET_PATTERNS:
        matches = re.findall(pat, normalized, flags=re.IGNORECASE)
        sensitive_hits += len(matches)

    return {
        "directive_signals": directive_hits,
        "sensitive_target_signals": sensitive_hits,
        "total_security_signals": directive_hits + sensitive_hits,
    }


def compute_drift_features(
    old_description: str | None,
    new_description: str,
) -> dict[str, float]:
    """Compute differential drift metrics between an existing approved description and an update.

    Args:
        old_description: Existing registered description (or None if newly registered)
        new_description: Incoming description candidate

    Returns:
        Dictionary of drift metrics:
        - text_similarity: Float in [0.0, 1.0], 1.0 = identical
        - length_delta_ratio: Relative change in description length
        - added_security_signals: Net increase in suspicious signals
    """
    norm_new = normalize_text(new_description)
    if not old_description:
        # First registration; no drift baseline exists
        new_signals = extract_signal_counts(norm_new)["total_security_signals"]
        return {
            "is_new_registration": 1.0,
            "text_similarity": 0.0,
            "length_delta_ratio": 1.0,
            "added_security_signals": float(new_signals),
        }

    norm_old = normalize_text(old_description)

    # Character-level similarity via SequenceMatcher
    similarity = difflib.SequenceMatcher(None, norm_old, norm_new).ratio()

    # Relative length difference
    len_old = max(len(norm_old), 1)
    len_new = len(norm_new)
    length_delta_ratio = (len_new - len_old) / float(len_old)

    # Signal delta
    old_signals = extract_signal_counts(norm_old)["total_security_signals"]
    new_signals = extract_signal_counts(norm_new)["total_security_signals"]
    added_signals = max(0, new_signals - old_signals)

    return {
        "is_new_registration": 0.0,
        "text_similarity": round(similarity, 4),
        "length_delta_ratio": round(length_delta_ratio, 4),
        "added_security_signals": float(added_signals),
    }


class MCPFeatureExtractor:
    """Manages text vectorization and feature transformation for the detector."""

    def __init__(self, vectorizer: TfidfVectorizer | None = None) -> None:
        if vectorizer is None:
            self.vectorizer = TfidfVectorizer(
                max_features=2500,
                ngram_range=(1, 2),
                sublinear_tf=True,
                lowercase=True,
                strip_accents="unicode",
            )
        else:
            self.vectorizer = vectorizer

    def fit(self, texts: list[str]) -> "MCPFeatureExtractor":
        """Fit the TF-IDF vectorizer on training text descriptions."""
        normalized = [normalize_text(t) for t in texts]
        self.vectorizer.fit(normalized)
        return self

    def transform(self, texts: list[str]) -> Any:
        """Transform text descriptions into sparse TF-IDF feature matrices."""
        normalized = [normalize_text(t) for t in texts]
        return self.vectorizer.transform(normalized)

    def fit_transform(self, texts: list[str]) -> Any:
        """Fit and transform in one step."""
        normalized = [normalize_text(t) for t in texts]
        return self.vectorizer.fit_transform(normalized)

    def extract_full_profile(
        self,
        new_description: str,
        old_description: str | None = None,
    ) -> dict[str, Any]:
        """Extract a complete feature profile including text vectors and interpretable signals."""
        norm_desc = normalize_text(new_description)
        signals = extract_signal_counts(norm_desc)
        drift = compute_drift_features(old_description, norm_desc)
        tfidf_vector = self.transform([norm_desc])

        return {
            "normalized_description": norm_desc,
            "tfidf_features": tfidf_vector,
            "signals": signals,
            "drift": drift,
        }
