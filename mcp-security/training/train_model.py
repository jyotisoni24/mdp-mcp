"""Training pipeline for the MCP Tool Description Detection Model.

Trains a supervised statistical ML model (TF-IDF + Logistic Regression) on the
processed benchmark dataset. Evaluates initial performance and saves serialized
artifacts for the gateway detector.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
from pathlib import Path
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from gateway.feature_extractor import MCPFeatureExtractor, normalize_text

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("train_model")


def train_and_save_model(
    dataset_csv: Path,
    output_model_dir: Path,
    test_size: float = 0.20,
    random_seed: int = 42,
) -> dict[str, float]:
    """Train the detector model and serialize model artifacts.

    Args:
        dataset_csv: Path to processed_dataset.csv
        output_model_dir: Directory where models will be saved
        test_size: Fraction of dataset allocated to evaluation
        random_seed: Reproducibility seed

    Returns:
        Dictionary of test metrics.
    """
    if not dataset_csv.exists():
        raise FileNotFoundError(f"Dataset not found at {dataset_csv}. Run prepare_dataset.py first.")

    logger.info(f"Loading processed dataset from {dataset_csv}...")
    df = pd.read_csv(dataset_csv)

    # 1. Clean descriptions and extract features/labels
    descriptions = df["description"].apply(normalize_text).tolist()
    labels = df["label"].to_numpy(dtype=int)

    logger.info(
        f"Total examples: {len(df)} (Safe: {(labels==0).sum()}, Malicious: {(labels==1).sum()})"
    )

    # 2. Stratified train/test split to preserve class ratios
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        descriptions,
        labels,
        test_size=test_size,
        random_state=random_seed,
        stratify=labels,
    )

    logger.info(f"Split sizes: Train={len(X_train_raw)}, Test={len(X_test_raw)}")

    # 3. Fit TF-IDF Feature Extractor on training descriptions only (no data leakage)
    logger.info("Fitting TF-IDF Feature Extractor (unigrams + bigrams)...")
    extractor = MCPFeatureExtractor()
    X_train_vec = extractor.fit_transform(X_train_raw)
    X_test_vec = extractor.transform(X_test_raw)

    # 4. Train Logistic Regression classifier with balanced class weighting
    logger.info("Training Logistic Regression classifier (C=2.0, class_weight='balanced')...")
    clf = LogisticRegression(
        C=2.0,
        max_iter=1000,
        class_weight="balanced",
        random_state=random_seed,
        solver="lbfgs",
    )
    clf.fit(X_train_vec, y_train)

    # 5. Evaluate on held-out test split
    y_pred = clf.predict(X_test_vec)
    y_prob = clf.predict_proba(X_test_vec)[:, 1]

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
    }

    # 6. Save model, vectorizer, and metadata
    output_model_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_model_dir / "detector_model.joblib"
    vectorizer_path = output_model_dir / "vectorizer.joblib"
    metadata_path = output_model_dir / "metadata.json"

    joblib.dump(clf, model_path)
    joblib.dump(extractor.vectorizer, vectorizer_path)

    metadata = {
        "model_name": "TfidfLogisticRegression",
        "created_at": dt.datetime.now().isoformat(),
        "total_dataset_size": len(df),
        "train_size": len(X_train_raw),
        "test_size": len(X_test_raw),
        "metrics": metrics,
        "hyperparameters": {
            "C": 2.0,
            "max_iter": 1000,
            "class_weight": "balanced",
            "ngram_range": [1, 2],
            "max_features": 2500,
        },
    }

    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"Model saved to {model_path}")
    logger.info(f"Vectorizer saved to {vectorizer_path}")
    logger.info(f"Metadata saved to {metadata_path}")

    # Print summary
    print("\n" + "=" * 65)
    print("  MODEL TRAINING EVALUATION SUMMARY (TEST SPLIT)")
    print("=" * 65)
    print(f"Accuracy  : {metrics['accuracy']:.4f}")
    print(f"Precision : {metrics['precision']:.4f}")
    print(f"Recall    : {metrics['recall']:.4f}")
    print(f"F1-Score  : {metrics['f1']:.4f}")
    print("-" * 65)
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe (0)", "Malicious (1)"]))
    print("=" * 65 + "\n")

    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the MCP security detection model.")
    base_dir = Path(__file__).resolve().parent.parent
    parser.add_argument(
        "--dataset",
        type=Path,
        default=base_dir / "data" / "processed_dataset.csv",
        help="Path to processed_dataset.csv",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=base_dir / "models",
        help="Directory to save trained model artifacts",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.20,
        help="Fraction of dataset for test evaluation",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed",
    )
    args = parser.parse_args()

    train_and_save_model(
        dataset_csv=args.dataset,
        output_model_dir=args.output_dir,
        test_size=args.test_size,
        random_seed=args.seed,
    )


if __name__ == "__main__":
    main()
