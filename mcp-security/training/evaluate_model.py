"""Evaluation script for the MCP Tool Description Attack Detector.

Evaluates the trained supervised model across:
1. Aggregate metrics: Accuracy, Precision, Recall, F1-Score, FPR, FNR.
2. Breakdown by MCPTox attack category (Privacy Leakage, Credential Leakage, etc.).
3. Specific evaluation on the demonstration test case 23.py (simple_division poisoning).
4. Prediction latency benchmarks (milliseconds per tool description check).
"""
from __future__ import annotations

import argparse
import ast
import json
import logging
from pathlib import Path
import sys
import time

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

from gateway.ml_detector import MLDetector, normalize_text

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("evaluate_model")


def run_evaluation(
    dataset_csv: Path,
    model_dir: Path,
    test_file_23: Path,
    test_size: float = 0.20,
    random_seed: int = 42,
) -> dict:
    """Run full evaluation suite and print detailed report."""
    logger.info(f"Loading model from {model_dir}...")
    detector = MLDetector.load(model_dir)

    logger.info(f"Loading evaluation dataset from {dataset_csv}...")
    df = pd.read_csv(dataset_csv)

    # Reconstruct test split identically to train_model
    train_df, test_df = train_test_split(
        df,
        test_size=test_size,
        random_state=random_seed,
        stratify=df["label"],
    )

    descriptions = test_df["description"].tolist()
    y_true = test_df["label"].to_numpy()

    # Latency benchmarking
    start_time = time.perf_counter()
    results = [detector.predict(d) for d in descriptions]
    total_time_ms = (time.perf_counter() - start_time) * 1000.0
    latency_per_sample_ms = total_time_ms / max(len(descriptions), 1)

    y_pred = np.array([r.predicted_label for r in results])
    y_prob = np.array([r.malicious_probability for r in results])

    # Confusion matrix & Rates
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    acc = float((tp + tn) / len(y_true))
    prec, rec, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)

    # Attack breakdown
    test_df_eval = test_df.copy()
    test_df_eval["predicted_label"] = y_pred
    test_df_eval["mal_prob"] = y_prob

    mal_slice = test_df_eval[test_df_eval["label"] == 1]
    attack_breakdown = {}
    for atype, group in mal_slice.groupby("attack_type"):
        detected = (group["predicted_label"] == 1).sum()
        total = len(group)
        attack_breakdown[atype] = {
            "total": int(total),
            "detected": int(detected),
            "recall": float(detected / total) if total > 0 else 0.0,
            "avg_probability": float(group["mal_prob"].mean()),
        }

    # Demonstration Test Case: 23.py
    logger.info(f"Evaluating demonstration test case: {test_file_23}...")
    with open(test_file_23, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    func = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "simple_division")
    doc_23 = ast.get_docstring(func)

    res_23 = detector.predict(doc_23)
    benign_desc = "Perform ordinary arithmetic division of number a by number b. Returns a / b."
    res_benign = detector.predict(benign_desc)
    res_drift = detector.predict(description=doc_23, old_description=benign_desc)

    # Print comprehensive output
    print("\n" + "=" * 70)
    print("        MCP SECURITY GATEWAY — ML DETECTION EVALUATION REPORT")
    print("=" * 70)
    print(f"Test Set Size           : {len(y_true)} samples (Safe: {tn+fp}, Malicious: {tp+fn})")
    print(f"Accuracy                : {acc:.4%}")
    print(f"Precision               : {prec:.4%}")
    print(f"Recall (Sensitivity)    : {rec:.4%}")
    print(f"F1-Score                : {f1:.4%}")
    print(f"False Positive Rate (FPR): {fpr:.4%} (Goal: minimize legitimate disruption)")
    print(f"False Negative Rate (FNR): {fnr:.4%} (Goal: minimize missed attacks)")
    print(f"Average Detection Latency: {latency_per_sample_ms:.2f} ms per tool check")
    print("-" * 70)
    print("Confusion Matrix:")
    print(f"  True Negatives  (Safe correctly allowed)     : {tn:3d}")
    print(f"  False Positives (Safe incorrectly flagged)   : {fp:3d}")
    print(f"  False Negatives (Attacks missed)             : {fn:3d}")
    print(f"  True Positives  (Attacks correctly detected) : {tp:3d}")
    print("-" * 70)
    print("Per-Attack-Category Recall Breakdown:")
    for atype, stats in sorted(attack_breakdown.items()):
        print(f"  - {atype:<26}: {stats['detected']}/{stats['total']} "
              f"({stats['recall']:.1%}) | Avg Prob: {stats['avg_probability']:.2f}")
    print("-" * 70)
    print("Demonstration Case (23.py: simple_division poisoning):")
    print("  [1] Benign Baseline Description:")
    print(f"      Text: '{benign_desc}'")
    print(f"      Label: {res_benign.predicted_label} | Prob: {res_benign.malicious_probability:.2%} | Risk: {res_benign.risk_level}")
    print("  [2] Poisoned Description from 23.py:")
    print(f"      Text Snippet: '{doc_23[:95]}...'")
    print(f"      Label: {res_23.predicted_label} | Prob: {res_23.malicious_probability:.2%} | Risk: {res_23.risk_level}")
    print("  [3] Drift Analysis (Updating from Benign to Poisoned):")
    print(f"      Text Similarity: {res_drift.drift['text_similarity']:.2f}")
    print(f"      Added Signals  : {int(res_drift.drift['added_security_signals'])}")
    print(f"      Assessment     : {res_drift.confidence_assessment}")
    print("=" * 70 + "\n")

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr,
        "latency_ms": latency_per_sample_ms,
        "test_case_23": res_23.to_dict(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the MCP security detection model.")
    base_dir = Path(__file__).resolve().parent.parent
    parser.add_argument(
        "--dataset",
        type=Path,
        default=base_dir / "data" / "processed_dataset.csv",
        help="Path to processed_dataset.csv",
    )
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=base_dir / "models",
        help="Directory containing trained model artifacts",
    )
    parser.add_argument(
        "--test-file",
        type=Path,
        default=base_dir / "data" / "23.py",
        help="Path to 23.py demonstration file",
    )
    args = parser.parse_args()

    run_evaluation(
        dataset_csv=args.dataset,
        model_dir=args.model_dir,
        test_file_23=args.test_file,
    )


if __name__ == "__main__":
    main()
