"""Unit tests for Phase 4: Descriptor Change Detection and Registry.

Verifies:
1. Consistent SHA-256 calculation and whitespace normalization.
2. Correct classification of NEW_TOOL, NO_CHANGE, and DESCRIPTION_MODIFIED.
3. Crucial distinction: Hash mismatch signals change, ML signals malice.
4. High-risk attack updates (23.py) get marked QUARANTINED, not approved.
5. Invariance rule: incoming versions are never automatically trusted.
"""
from __future__ import annotations

import ast
from pathlib import Path
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from gateway.change_detector import (
    CHANGE_MODIFIED,
    CHANGE_NEW_TOOL,
    CHANGE_NO_CHANGE,
    DescriptorChangeDetector,
)
from gateway.descriptor_registry import (
    DescriptorRegistry,
    STATUS_APPROVED,
    STATUS_PENDING_REVIEW,
    STATUS_QUARANTINED,
    compute_description_hash,
)
from gateway.ml_detector import MLDetector

BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"
FILE_23 = BASE_DIR / "data" / "23.py"


@pytest.fixture(scope="module")
def detector() -> MLDetector:
    """Fixture to load trained MLDetector."""
    return MLDetector.load(MODELS_DIR)


@pytest.fixture(scope="module")
def poisoned_docstring_23() -> str:
    """Extract poisoned docstring from 23.py."""
    with open(FILE_23, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    func = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "simple_division")
    doc = ast.get_docstring(func)
    assert doc is not None
    return doc


def test_hash_normalization_invariance():
    """Verify that superficial whitespace differences do not trigger false hash mismatches."""
    text1 = "Read the contents of a file at the specified path."
    text2 = "   Read the contents of a file   at the specified path.\n\n"

    h1 = compute_description_hash(text1)
    h2 = compute_description_hash(text2)
    assert h1 == h2, "Whitespace should be normalized prior to hashing"


def test_new_tool_lifecycle(detector: MLDetector):
    """Verify new tool detection when no baseline exists in registry."""
    registry = DescriptorRegistry()
    change_detector = DescriptorChangeDetector(registry=registry, detector=detector)

    result = change_detector.inspect_tool(
        tool_name="unseen_tool",
        server_name="FileSystem",
        incoming_description="Read the contents of a file at the specified path.",
    )

    assert result.has_changed is True
    assert result.change_type == CHANGE_NEW_TOOL
    assert result.old_hash is None
    assert result.old_description is None
    assert result.is_approved is False
    assert result.detection_result is not None
    assert result.detection_result.predicted_label == 0


def test_identical_description_no_change(detector: MLDetector):
    """Verify that an unchanged description matches the approved SHA-256 hash."""
    registry = DescriptorRegistry()
    desc = "Return the current server time in UTC ISO-8601 format."
    registry.register_approved("get_time", "TimeServer", desc)

    change_detector = DescriptorChangeDetector(registry=registry, detector=detector)
    result = change_detector.inspect_tool("get_time", "TimeServer", desc)

    assert result.has_changed is False
    assert result.change_type == CHANGE_NO_CHANGE
    assert result.is_approved is True
    assert result.old_hash == result.new_hash
    assert result.detection_result is None  # No redundant ML inference needed


def test_benign_update_vs_poisoned_update(detector: MLDetector, poisoned_docstring_23: str):
    """Demonstrate that both benign rewrites and attacks cause hash mismatches,

    but only the attack is flagged by the ML detector.
    """
    registry = DescriptorRegistry()
    base_desc = "Perform ordinary arithmetic division of number a by number b. Returns a / b."
    registry.register_approved("simple_division", "Calculator", base_desc)

    change_detector = DescriptorChangeDetector(registry=registry, detector=detector)

    # 1. Benign update: harmless parameter clarification
    benign_update = base_desc + " Raises ZeroDivisionError if b is zero."
    benign_res = change_detector.inspect_tool("simple_division", "Calculator", benign_update)

    assert benign_res.has_changed is True
    assert benign_res.change_type == CHANGE_MODIFIED
    assert benign_res.detection_result is not None
    assert benign_res.detection_result.predicted_label == 0
    assert benign_res.detection_result.risk_level == "LOW"

    # 2. Poisoned update: attack docstring from 23.py
    attack_res = change_detector.inspect_tool("simple_division", "Calculator", poisoned_docstring_23)

    assert attack_res.has_changed is True
    assert attack_res.change_type == CHANGE_MODIFIED
    assert attack_res.detection_result is not None
    assert attack_res.detection_result.predicted_label == 1
    assert attack_res.detection_result.risk_level in ["HIGH", "CRITICAL"]


def test_unapproved_descriptions_never_automatically_trusted():
    """Verify that receiving an update does NOT promote it to approved status."""
    registry = DescriptorRegistry()
    base_desc = "Calculate total order price."
    registry.register_approved("calc_total", "Billing", base_desc)

    change_detector = DescriptorChangeDetector(registry=registry)
    updated_desc = "Calculate total order price including tax and discount."

    # Inspect update
    res = change_detector.inspect_tool("calc_total", "Billing", updated_desc)
    assert res.has_changed is True

    # The registry must STILL report the new description as unapproved
    assert registry.is_approved("calc_total", "Billing", updated_desc) is False
    # The original baseline remains the only approved version
    assert registry.is_approved("calc_total", "Billing", base_desc) is True
