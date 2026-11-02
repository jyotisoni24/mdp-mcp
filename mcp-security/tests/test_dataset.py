"""Unit tests for Phase 2: Dataset Preparation and Integrity.

Verifies:
1. Processed dataset existence and non-emptiness.
2. Exact schema compliance without missing columns.
3. Absence of null or empty values in critical fields.
4. Binary classification labels (0 for safe, 1 for malicious).
5. Data provenance (MCPTox vs verified safe sources).
6. Consistency between benchmark record FileSystem_23 and test case 23.py.
7. Prevention of label/metadata leakage into input description features.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pandas as pd
import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
PROCESSED_CSV = DATA_DIR / "processed_dataset.csv"
RAW_JSON = DATA_DIR / "pure_tool.json"
SAFE_JSON = DATA_DIR / "safe_examples.json"
TEST_FILE_23 = DATA_DIR / "23.py"


@pytest.fixture(scope="module")
def dataset_df() -> pd.DataFrame:
    """Fixture to load processed_dataset.csv once for all tests."""
    assert PROCESSED_CSV.exists(), f"processed_dataset.csv not found at {PROCESSED_CSV}"
    df = pd.read_csv(PROCESSED_CSV)
    return df


def test_dataset_exists_and_not_empty(dataset_df: pd.DataFrame):
    """Ensure dataset was generated and has expected row count."""
    assert len(dataset_df) > 500, f"Expected >500 records, got {len(dataset_df)}"


def test_schema_columns(dataset_df: pd.DataFrame):
    """Verify all required columns are present with exact names."""
    expected = [
        "record_id",
        "tool_name",
        "server_name",
        "description",
        "label",
        "attack_type",
        "paradigm",
        "source",
    ]
    for col in expected:
        assert col in dataset_df.columns, f"Missing required column: '{col}'"


def test_no_null_critical_fields(dataset_df: pd.DataFrame):
    """Ensure no null or empty values in description and label."""
    assert dataset_df["description"].isna().sum() == 0, "Found null descriptions"
    assert (dataset_df["description"].str.strip() == "").sum() == 0, "Found empty descriptions"
    assert dataset_df["label"].isna().sum() == 0, "Found null labels"


def test_binary_labels(dataset_df: pd.DataFrame):
    """Verify labels are strictly 0 (safe) or 1 (malicious)."""
    unique_labels = set(dataset_df["label"].unique())
    assert unique_labels == {0, 1}, f"Unexpected label values: {unique_labels}"


def test_class_balance_representation(dataset_df: pd.DataFrame):
    """Verify both safe and malicious classes are represented sufficiently."""
    safe_count = (dataset_df["label"] == 0).sum()
    mal_count = (dataset_df["label"] == 1).sum()
    assert safe_count >= 100, f"Insufficient safe examples: {safe_count}"
    assert mal_count >= 400, f"Insufficient malicious examples: {mal_count}"


def test_safe_records_semantics(dataset_df: pd.DataFrame):
    """Ensure all safe records have label 0 and attack_type 'benign'."""
    safe_records = dataset_df[dataset_df["label"] == 0]
    assert (safe_records["attack_type"] == "benign").all()
    assert set(safe_records["source"].unique()).issubset({"verified_safe_mcp", "test_server"})


def test_malicious_records_semantics(dataset_df: pd.DataFrame):
    """Ensure malicious records originate from MCPTox and have non-benign attack types."""
    mal_records = dataset_df[dataset_df["label"] == 1]
    assert (mal_records["source"] == "MCPTox").all()
    assert not (mal_records["attack_type"] == "benign").any()


def test_filesystem_23_matches_23_py(dataset_df: pd.DataFrame):
    """Verify that FileSystem_23 in the dataset matches 23.py docstring."""
    # Find FileSystem_23 in processed dataset
    rec = dataset_df[dataset_df["record_id"] == "FileSystem_23"]
    assert len(rec) == 1, "FileSystem_23 not found in processed dataset"

    tool_record = rec.iloc[0]
    assert tool_record["tool_name"] == "simple_division"
    assert tool_record["label"] == 1
    assert tool_record["attack_type"] == "Privacy Leakage"

    # Extract docstring from 23.py using AST parsing (safely without execution)
    assert TEST_FILE_23.exists(), f"23.py test file not found at {TEST_FILE_23}"
    with open(TEST_FILE_23, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())

    func_node = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "simple_division"), None)
    assert func_node is not None, "simple_division function definition not found in 23.py"

    docstring = ast.get_docstring(func_node)
    assert docstring is not None, "Docstring missing from simple_division in 23.py"

    # Normalize whitespace for comparison
    assert docstring.strip() == tool_record["description"].strip(), (
        "Docstring in 23.py does not match description in processed dataset"
    )


def test_no_metadata_leakage_in_features(dataset_df: pd.DataFrame):
    """Ensure labels or provenance columns are not leaked into the description field."""
    for idx, row in dataset_df.iterrows():
        desc = row["description"]
        # The description should not literally start with labels
        assert not desc.startswith("label="), f"Leaked label at index {idx}"
        assert not desc.startswith("attack_type="), f"Leaked attack_type at index {idx}"
