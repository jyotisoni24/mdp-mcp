"""Dataset preparation pipeline for the MCP Security Gateway.

This module processes raw MCP attack records (from the MCPTox benchmark: pure_tool.json)
and merges them with curated, verified benign MCP tool descriptions (safe_examples.json).

Key responsibilities:
1. Traverse nested records from pure_tool.json (45 server groups, ~485 tools).
2. Extract the tool docstring/content ('tool_content') as the candidate text field.
3. Label attack records as malicious (label=1) and benign records as safe (label=0).
4. Preserve provenance metadata (record_id, tool_name, server_name, attack_type, paradigm, source).
5. Ensure attack metadata is NOT mixed into the feature text (preventing label leakage).
6. Perform defensive schema validation, data cleaning, and deduplication.
7. Export the clean, balanced dataset to 'data/processed_dataset.csv'.
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys
from typing import Any

import pandas as pd

# Configure structured logging for clear developer visibility
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("prepare_dataset")

# Expected schema for the processed training dataset
EXPECTED_COLUMNS = [
    "record_id",
    "tool_name",
    "server_name",
    "description",
    "label",
    "attack_type",
    "paradigm",
    "source",
]


def load_mcptox_records(json_path: Path) -> list[dict[str, Any]]:
    """Load and parse malicious tool description records from MCPTox benchmark.

    The MCPTox benchmark structure consists of a top-level list containing
    server group dictionaries. Each group maps a unique record ID (e.g., 'FileSystem_23')
    to an attack record object containing:
    - server_name: The simulated MCP server
    - tool_name: The target MCP tool
    - tool_content: The poisoned tool docstring (candidate text for detection)
    - security risk: The MITRE/benchmark attack category (e.g., 'Privacy Leakage')
    - paradigm: The injection template used ('Template-1', 'Template-2', 'Template-3')
    - tool_address: Path to definition file (e.g., 'def_tool/23.py')

    Args:
        json_path: Path to pure_tool.json

    Returns:
        List of normalized record dictionaries labeled as malicious (label=1).
    """
    if not json_path.exists():
        raise FileNotFoundError(f"MCPTox benchmark file not found at: {json_path}")

    logger.info(f"Loading raw MCPTox benchmark from: {json_path}")
    with open(json_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    if not isinstance(raw_data, list):
        raise ValueError(
            f"Expected pure_tool.json top-level to be a list, got {type(raw_data).__name__}"
        )

    records: list[dict[str, Any]] = []
    skipped_count = 0

    for group_idx, group in enumerate(raw_data):
        if not isinstance(group, dict):
            logger.warning(f"Skipping malformed group at index {group_idx}: {group}")
            skipped_count += 1
            continue

        for record_id, record in group.items():
            if not isinstance(record, dict):
                logger.warning(f"Skipping malformed record {record_id}: {record}")
                skipped_count += 1
                continue

            # Extract tool_content as the candidate text field
            tool_content = record.get("tool_content")
            if not tool_content or not str(tool_content).strip():
                logger.warning(f"Record {record_id} missing tool_content; skipping.")
                skipped_count += 1
                continue

            # Normalize text: strip surrounding whitespace
            normalized_desc = str(tool_content).strip()

            tool_name = str(record.get("tool_name", "unknown_tool")).strip()
            server_name = str(record.get("server_name", "unknown_server")).strip()
            security_risk = str(record.get("security risk", "Unknown Attack")).strip()
            paradigm = str(record.get("paradigm", "unknown_paradigm")).strip()

            records.append({
                "record_id": str(record_id),
                "tool_name": tool_name,
                "server_name": server_name,
                "description": normalized_desc,
                "label": 1,  # 1 = malicious (attack example)
                "attack_type": security_risk,
                "paradigm": paradigm,
                "source": "MCPTox",
            })

    logger.info(
        f"Parsed {len(records)} malicious records from MCPTox "
        f"({skipped_count} skipped/malformed)."
    )
    return records


def load_safe_records(json_path: Path) -> list[dict[str, Any]]:
    """Load curated legitimate (safe) MCP tool description records.

    Args:
        json_path: Path to safe_examples.json

    Returns:
        List of normalized record dictionaries labeled as safe (label=0).
    """
    if not json_path.exists():
        raise FileNotFoundError(f"Safe examples file not found at: {json_path}")

    logger.info(f"Loading curated safe tool examples from: {json_path}")
    with open(json_path, "r", encoding="utf-8") as f:
        safe_data = json.load(f)

    if not isinstance(safe_data, list):
        raise ValueError(
            f"Expected safe_examples.json to be a list, got {type(safe_data).__name__}"
        )

    records: list[dict[str, Any]] = []
    for item in safe_data:
        desc = str(item.get("description", "")).strip()
        if not desc:
            continue

        records.append({
            "record_id": str(item.get("record_id", f"safe_{len(records)+1:03d}")),
            "tool_name": str(item.get("tool_name", "unknown_tool")).strip(),
            "server_name": str(item.get("server_name", "SafeServer")).strip(),
            "description": desc,
            "label": 0,  # 0 = safe (benign)
            "attack_type": str(item.get("attack_type", "benign")).strip(),
            "paradigm": str(item.get("paradigm", "benign")),
            "source": str(item.get("source", "verified_safe_mcp")),
        })

    logger.info(f"Loaded {len(records)} verified safe records.")
    return records


def build_processed_dataset(
    mcptox_path: Path,
    safe_path: Path,
    output_csv_path: Path,
    random_seed: int = 42,
) -> pd.DataFrame:
    """Merge, validate, shuffle, and export the training dataset.

    Args:
        mcptox_path: Path to pure_tool.json
        safe_path: Path to safe_examples.json
        output_csv_path: Path where processed_dataset.csv will be saved
        random_seed: Seed for reproducible dataset shuffling

    Returns:
        Cleaned pandas DataFrame containing the processed dataset.
    """
    # 1. Load both sources
    malicious_records = load_mcptox_records(mcptox_path)
    safe_records = load_safe_records(safe_path)

    all_records = malicious_records + safe_records
    if not all_records:
        raise ValueError("No records found to build dataset.")

    # 2. Convert to DataFrame
    df = pd.DataFrame(all_records)

    # 3. Ensure all expected columns are present
    for col in EXPECTED_COLUMNS:
        if col not in df.columns:
            raise KeyError(f"Missing expected column in dataset: '{col}'")

    # Reorder columns explicitly
    df = df[EXPECTED_COLUMNS]

    # 4. Data hygiene: check for null values or empty strings in crucial columns
    null_desc = df["description"].isna().sum()
    empty_desc = (df["description"].str.strip() == "").sum()
    if null_desc > 0 or empty_desc > 0:
        logger.warning(f"Found {null_desc} null and {empty_desc} empty descriptions. Dropping.")
        df = df[df["description"].str.strip() != ""].dropna(subset=["description"])

    # 5. Check and handle potential duplicate descriptions
    dup_desc = df.duplicated(subset=["description"]).sum()
    if dup_desc > 0:
        logger.info(f"Identified {dup_desc} exact duplicate descriptions across sources.")
        # Retain first occurrence to ensure consistency
        df = df.drop_duplicates(subset=["description"], keep="first").reset_index(drop=True)

    # 6. Shuffle dataset deterministically
    df = df.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)

    # 7. Ensure output directory exists and save CSV
    output_csv_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_csv_path, index=False, encoding="utf-8")
    logger.info(f"Saved processed dataset to: {output_csv_path} (Total rows: {len(df)})")

    # 8. Print comprehensive summary statistics
    print_dataset_summary(df)

    return df


def print_dataset_summary(df: pd.DataFrame) -> None:
    """Print clean summary statistics for developer inspection."""
    total = len(df)
    safe_count = int((df["label"] == 0).sum())
    mal_count = int((df["label"] == 1).sum())

    print("\n" + "=" * 65)
    print("  MCP SECURITY GATEWAY — DATASET PREPARATION SUMMARY")
    print("=" * 65)
    print(f"Total processed records : {total}")
    print(f"Safe examples (0)       : {safe_count:4d} ({safe_count / total * 100:.1f}%)")
    print(f"Malicious examples (1)  : {mal_count:4d} ({mal_count / total * 100:.1f}%)")
    print(f"Unique tool names       : {df['tool_name'].nunique()}")
    print(f"Unique server names     : {df['server_name'].nunique()}")
    print("-" * 65)
    print("Attack Types Breakdown (Malicious Subset):")
    mal_df = df[df["label"] == 1]
    attack_counts = mal_df["attack_type"].value_counts()
    for atype, cnt in attack_counts.items():
        print(f"  - {atype:<26}: {cnt:3d} ({cnt / mal_count * 100:.1f}%)")
    print("-" * 65)
    print("Data Sources Breakdown:")
    source_counts = df["source"].value_counts()
    for src, cnt in source_counts.items():
        print(f"  - {src:<26}: {cnt:3d} ({cnt / total * 100:.1f}%)")
    print("=" * 65 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract and prepare the MCP security dataset from raw files."
    )
    base_dir = Path(__file__).resolve().parent.parent
    parser.add_argument(
        "--mcptox",
        type=Path,
        default=base_dir / "data" / "pure_tool.json",
        help="Path to pure_tool.json",
    )
    parser.add_argument(
        "--safe",
        type=Path,
        default=base_dir / "data" / "safe_examples.json",
        help="Path to safe_examples.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=base_dir / "data" / "processed_dataset.csv",
        help="Output CSV path",
    )
    args = parser.parse_args()

    build_processed_dataset(
        mcptox_path=args.mcptox,
        safe_path=args.safe,
        output_csv_path=args.output,
    )


if __name__ == "__main__":
    main()
