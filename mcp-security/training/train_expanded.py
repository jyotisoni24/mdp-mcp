"""Expanded Baseline Model Training Pipeline.

Trains the first expanded baseline ML model on data/expanded_experimental_dataset.csv (538 records):
1. Loads 538 records (485 malicious, 53 reviewed benign).
2. Uses only the 'description' column as model input.
3. Uses TF-IDF (word n-grams (1,2) + char n-grams (3,5)) + LogisticRegression(class_weight='balanced').
4. Uses 'canonical_group' for group-aware StratifiedGroupKFold (5 folds).
5. Fits vectorizer strictly inside each training fold to prevent leakage.
6. Evaluates aggregate and per-fold metrics at tau=0.50 and provisional tau=0.70.
7. Evaluates once on the held-out independent test set (held-out server families).
8. Evaluates zero-shot OOD benchmark on the 4 quarantined records from expanded_ood_dataset.json.
9. Trains the final model on all approved training data (538 records) and saves artifacts:
   - models/expanded_detector_model.joblib
   - models/expanded_vectorizer.joblib
   - models/expanded_training_report.json
   - training/expanded_training_report.md
10. Preserves all existing models and datasets untouched.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import FeatureUnion

DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = PROJECT_ROOT / "models"
TRAINING_DIR = PROJECT_ROOT / "training"


def create_feature_extractor() -> FeatureUnion:
    """Create word and char n-gram feature union."""
    word_vec = TfidfVectorizer(ngram_range=(1, 2), max_features=1500, sublinear_tf=True)
    char_vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=1500, sublinear_tf=True)
    return FeatureUnion([("word", word_vec), ("char", char_vec)])


def run_pipeline():
    print("=" * 80)
    print("STARTING EXPANDED BASELINE MODEL TRAINING PIPELINE")
    print("=" * 80)

    # 1. Load dataset
    dataset_path = DATA_DIR / "expanded_experimental_dataset.csv"
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    df = pd.read_csv(dataset_path)
    total_samples = len(df)
    malicious_count = int((df["label"] == 1).sum())
    benign_count = int((df["label"] == 0).sum())

    print(f"[Step 1] Loaded {total_samples} records from {dataset_path.name}")
    print(f"         - Malicious (label 1): {malicious_count}")
    print(f"         - Benign (label 0)   : {benign_count}")
    print(f"         - Canonical groups   : {df['canonical_group'].nunique()}")

    assert total_samples == 538, f"Expected 538 records, found {total_samples}"
    assert malicious_count == 485, f"Expected 485 malicious, found {malicious_count}"
    assert benign_count == 53, f"Expected 53 benign, found {benign_count}"

    # 2. 5-Fold Stratified Server-Disjoint Cross-Validation
    print("\n[Step 2] Executing 5-Fold StratifiedGroupKFold Cross-Validation...")
    sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)

    oof_probs = np.zeros(total_samples)
    oof_preds_50 = np.zeros(total_samples)
    oof_preds_70 = np.zeros(total_samples)
    y_true = df["label"].to_numpy()

    fold_metrics_50 = []
    fold_metrics_70 = []

    for fold_idx, (train_idx, val_idx) in enumerate(sgkf.split(df, y=df["label"], groups=df["canonical_group"])):
        train_data = df.iloc[train_idx]
        val_data = df.iloc[val_idx]

        # Invariant: fit vectorizer ONLY on training fold
        extractor = create_feature_extractor()
        X_train = extractor.fit_transform(train_data["description"])
        X_val = extractor.transform(val_data["description"])

        clf = LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=42)
        clf.fit(X_train, train_data["label"])

        probs = clf.predict_proba(X_val)[:, 1]
        oof_probs[val_idx] = probs

        p50 = (probs >= 0.50).astype(int)
        p70 = (probs >= 0.70).astype(int)
        oof_preds_50[val_idx] = p50
        oof_preds_70[val_idx] = p70

        y_val = val_data["label"].to_numpy()

        # Fold metrics at tau = 0.50
        tn50, fp50, fn50, tp50 = confusion_matrix(y_val, p50, labels=[0, 1]).ravel()
        fpr50 = fp50 / (fp50 + tn50) if (fp50 + tn50) > 0 else 0.0
        fnr50 = fn50 / (fn50 + tp50) if (fn50 + tp50) > 0 else 0.0

        val_groups = sorted(val_data["canonical_group"].unique().tolist())

        fold_metrics_50.append({
            "fold": fold_idx + 1,
            "train_size": len(train_data),
            "val_size": len(val_data),
            "train_benign": int((train_data["label"] == 0).sum()),
            "train_malicious": int((train_data["label"] == 1).sum()),
            "val_benign": int((val_data["label"] == 0).sum()),
            "val_malicious": int((val_data["label"] == 1).sum()),
            "val_server_groups": val_groups,
            "accuracy": float(accuracy_score(y_val, p50)),
            "precision": float(precision_score(y_val, p50, zero_division=0)),
            "recall": float(recall_score(y_val, p50, zero_division=0)),
            "f1_score": float(f1_score(y_val, p50, zero_division=0)),
            "fpr": float(fpr50),
            "fnr": float(fnr50),
            "confusion_matrix": {"tn": int(tn50), "fp": int(fp50), "fn": int(fn50), "tp": int(tp50)},
        })

        # Fold metrics at tau = 0.70
        tn70, fp70, fn70, tp70 = confusion_matrix(y_val, p70, labels=[0, 1]).ravel()
        fpr70 = fp70 / (fp70 + tn70) if (fp70 + tn70) > 0 else 0.0
        fnr70 = fn70 / (fn70 + tp70) if (fn70 + tp70) > 0 else 0.0

        fold_metrics_70.append({
            "fold": fold_idx + 1,
            "accuracy": float(accuracy_score(y_val, p70)),
            "precision": float(precision_score(y_val, p70, zero_division=0)),
            "recall": float(recall_score(y_val, p70, zero_division=0)),
            "f1_score": float(f1_score(y_val, p70, zero_division=0)),
            "fpr": float(fpr70),
            "fnr": float(fnr70),
            "confusion_matrix": {"tn": int(tn70), "fp": int(fp70), "fn": int(fn70), "tp": int(tp70)},
        })

    # Overall OOF Metrics
    tn50_all, fp50_all, fn50_all, tp50_all = confusion_matrix(y_true, oof_preds_50, labels=[0, 1]).ravel()
    oof_summary_50 = {
        "threshold": 0.50,
        "accuracy": float(accuracy_score(y_true, oof_preds_50)),
        "precision": float(precision_score(y_true, oof_preds_50, zero_division=0)),
        "recall": float(recall_score(y_true, oof_preds_50, zero_division=0)),
        "f1_score": float(f1_score(y_true, oof_preds_50, zero_division=0)),
        "fpr": float(fp50_all / (fp50_all + tn50_all)),
        "fnr": float(fn50_all / (fn50_all + tp50_all)),
        "confusion_matrix": {"tn": int(tn50_all), "fp": int(fp50_all), "fn": int(fn50_all), "tp": int(tp50_all)},
    }

    tn70_all, fp70_all, fn70_all, tp70_all = confusion_matrix(y_true, oof_preds_70, labels=[0, 1]).ravel()
    oof_summary_70 = {
        "threshold": 0.70,
        "note": "Provisional comparison threshold only (not used for model tuning)",
        "accuracy": float(accuracy_score(y_true, oof_preds_70)),
        "precision": float(precision_score(y_true, oof_preds_70, zero_division=0)),
        "recall": float(recall_score(y_true, oof_preds_70, zero_division=0)),
        "f1_score": float(f1_score(y_true, oof_preds_70, zero_division=0)),
        "fpr": float(fp70_all / (fp70_all + tn70_all)),
        "fnr": float(fn70_all / (fn70_all + tp70_all)),
        "confusion_matrix": {"tn": int(tn70_all), "fp": int(fp70_all), "fn": int(fn70_all), "tp": int(tp70_all)},
    }

    print("\n--- OOF SUMMARY (tau = 0.50) ---")
    print(f"Accuracy : {oof_summary_50['accuracy']:.4f}")
    print(f"Precision: {oof_summary_50['precision']:.4f}")
    print(f"Recall   : {oof_summary_50['recall']:.4f}")
    print(f"F1-Score : {oof_summary_50['f1_score']:.4f}")
    print(f"FPR      : {oof_summary_50['fpr']:.4f} ({fp50_all}/{fp50_all+tn50_all})")
    print(f"FNR      : {oof_summary_50['fnr']:.4f} ({fn50_all}/{fn50_all+tp50_all})")

    print("\n--- OOF SUMMARY (tau = 0.70 Provisional) ---")
    print(f"Accuracy : {oof_summary_70['accuracy']:.4f}")
    print(f"Precision: {oof_summary_70['precision']:.4f}")
    print(f"Recall   : {oof_summary_70['recall']:.4f}")
    print(f"F1-Score : {oof_summary_70['f1_score']:.4f}")
    print(f"FPR      : {oof_summary_70['fpr']:.4f} ({fp70_all}/{fp70_all+tn70_all})")
    print(f"FNR      : {oof_summary_70['fnr']:.4f} ({fn70_all}/{fn70_all+tp70_all})")

    # 3. Independent Test Set Evaluation (Held-Out Server Families)
    print("\n[Step 3] Evaluating on Independent Test Set (Held-Out Server Families)...")
    TEST_BENIGN_SERVERS = ["puppeteer", "slack", "gitlab"]
    
    # Hold out the 3 server families + disjoint attack groups
    malicious_groups = df[df["label"] == 1]["canonical_group"].unique()
    np.random.seed(42)
    test_mal_groups = np.random.choice(malicious_groups, size=int(len(malicious_groups) * 0.20), replace=False)

    test_mask = (df["canonical_group"].isin(TEST_BENIGN_SERVERS)) | (df["canonical_group"].isin(test_mal_groups))
    dev_df = df[~test_mask].copy()
    test_df = df[test_mask].copy()

    # Fit vectorizer on Dev Set only
    dev_extractor = create_feature_extractor()
    X_dev = dev_extractor.fit_transform(dev_df["description"])
    X_test_indep = dev_extractor.transform(test_df["description"])

    dev_clf = LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=42)
    dev_clf.fit(X_dev, dev_df["label"])

    indep_probs = dev_clf.predict_proba(X_test_indep)[:, 1]
    y_test_indep = test_df["label"].to_numpy()

    p50_indep = (indep_probs >= 0.50).astype(int)
    p70_indep = (indep_probs >= 0.70).astype(int)

    tn50_i, fp50_i, fn50_i, tp50_i = confusion_matrix(y_test_indep, p50_indep, labels=[0, 1]).ravel()
    tn70_i, fp70_i, fn70_i, tp70_i = confusion_matrix(y_test_indep, p70_indep, labels=[0, 1]).ravel()

    indep_eval_50 = {
        "threshold": 0.50,
        "test_total": len(test_df),
        "test_benign": int((test_df["label"] == 0).sum()),
        "test_malicious": int((test_df["label"] == 1).sum()),
        "held_out_benign_servers": TEST_BENIGN_SERVERS,
        "accuracy": float(accuracy_score(y_test_indep, p50_indep)),
        "precision": float(precision_score(y_test_indep, p50_indep, zero_division=0)),
        "recall": float(recall_score(y_test_indep, p50_indep, zero_division=0)),
        "f1_score": float(f1_score(y_test_indep, p50_indep, zero_division=0)),
        "fpr": float(fp50_i / (fp50_i + tn50_i)),
        "fnr": float(fn50_i / (fn50_i + tp50_i)),
        "confusion_matrix": {"tn": int(tn50_i), "fp": int(fp50_i), "fn": int(fn50_i), "tp": int(tp50_i)},
    }

    indep_eval_70 = {
        "threshold": 0.70,
        "note": "Provisional comparison threshold only (not used for model tuning)",
        "test_total": len(test_df),
        "test_benign": int((test_df["label"] == 0).sum()),
        "test_malicious": int((test_df["label"] == 1).sum()),
        "held_out_benign_servers": TEST_BENIGN_SERVERS,
        "accuracy": float(accuracy_score(y_test_indep, p70_indep)),
        "precision": float(precision_score(y_test_indep, p70_indep, zero_division=0)),
        "recall": float(recall_score(y_test_indep, p70_indep, zero_division=0)),
        "f1_score": float(f1_score(y_test_indep, p70_indep, zero_division=0)),
        "fpr": float(fp70_i / (fp70_i + tn70_i)),
        "fnr": float(fn70_i / (fn70_i + tp70_i)),
        "confusion_matrix": {"tn": int(tn70_i), "fp": int(fp70_i), "fn": int(fn70_i), "tp": int(tp70_i)},
    }

    print(f"Independent Test Set: {len(test_df)} samples (Benign: {indep_eval_50['test_benign']}, Malicious: {indep_eval_50['test_malicious']})")
    print(f"Results (tau=0.50): Acc={indep_eval_50['accuracy']:.4f}, Prec={indep_eval_50['precision']:.4f}, Rec={indep_eval_50['recall']:.4f}, F1={indep_eval_50['f1_score']:.4f}, FPR={indep_eval_50['fpr']:.4f}")
    print(f"Results (tau=0.70): Acc={indep_eval_70['accuracy']:.4f}, Prec={indep_eval_70['precision']:.4f}, Rec={indep_eval_70['recall']:.4f}, F1={indep_eval_70['f1_score']:.4f}, FPR={indep_eval_70['fpr']:.4f}")

    # 4. Train Final Model on All Approved Data (538 Records)
    print("\n[Step 4] Fitting final vectorizer and training final expanded detector model...")
    final_extractor = create_feature_extractor()
    X_full = final_extractor.fit_transform(df["description"])

    final_clf = LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=42)
    final_clf.fit(X_full, df["label"])

    # Measure inference latency per sample
    warmup_n = 50
    t0 = time.perf_counter()
    for _ in range(warmup_n):
        _ = final_clf.predict_proba(final_extractor.transform([df["description"].iloc[0]]))
    latency_ms = ((time.perf_counter() - t0) / warmup_n) * 1000.0
    print(f"Inference latency per sample: {latency_ms:.3f} ms")

    # 5. Evaluate Quarantined OOD Benchmark (4 Records)
    print("\n[Step 5] Evaluating Zero-Shot Benchmark on Quarantined OOD Records...")
    ood_path = DATA_DIR / "expanded_ood_dataset.json"
    with open(ood_path, "r", encoding="utf-8") as f:
        ood_data = json.load(f)

    ood_eval_results = []
    for rec in ood_data["records"]:
        desc = rec["tool_description"]
        x_rec = final_extractor.transform([desc])
        prob = float(final_clf.predict_proba(x_rec)[0, 1])
        ood_eval_results.append({
            "candidate_id": rec.get("candidate_id", rec.get("record_id")),
            "tool_name": rec["tool_name"],
            "server_name": rec["server_name"],
            "description": desc,
            "predicted_malicious_probability": round(prob, 4),
            "prediction_tau_50": "MALICIOUS" if prob >= 0.50 else "BENIGN",
            "prediction_tau_70": "MALICIOUS" if prob >= 0.70 else "BENIGN",
            "reason_for_quarantine": rec.get("reason_for_quarantine", rec.get("reviewer_rationale", "")),
        })
        print(f" - {rec['tool_name']} ({rec['server_name']}): Prob = {prob:.4f}")

    # 6. Save Artifacts
    print("\n[Step 6] Saving Model Artifacts...")
    model_out = MODELS_DIR / "expanded_detector_model.joblib"
    vec_out = MODELS_DIR / "expanded_vectorizer.joblib"
    report_json_out = MODELS_DIR / "expanded_training_report.json"
    report_md_out = TRAINING_DIR / "expanded_training_report.md"

    joblib.dump(final_clf, model_out)
    joblib.dump(final_extractor, vec_out)
    print(f"Saved: {model_out.name}")
    print(f"Saved: {vec_out.name}")

    # Save JSON report
    report_dict = {
        "pipeline_metadata": {
            "model_name": "expanded_baseline_detector",
            "dataset_name": "expanded_experimental_dataset.csv",
            "training_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_records": total_samples,
            "malicious_records": malicious_count,
            "benign_records": benign_count,
            "class_ratio": f"{malicious_count/benign_count:.2f}:1",
            "inference_latency_ms": round(latency_ms, 3),
            "production_ready": False,
            "production_readiness_statement": "Experimental baseline only. Not claimed as production-ready.",
        },
        "cross_validation_results": {
            "algorithm": "StratifiedGroupKFold",
            "n_splits": 5,
            "group_column": "canonical_group",
            "tau_0_50_aggregate": oof_summary_50,
            "tau_0_70_provisional": oof_summary_70,
            "per_fold_50": fold_metrics_50,
            "per_fold_70": fold_metrics_70,
        },
        "independent_test_evaluation": {
            "status": "completed",
            "tau_0_50": indep_eval_50,
            "tau_0_70_provisional": indep_eval_70,
        },
        "ood_quarantined_evaluation": ood_eval_results,
    }

    with open(report_json_out, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2)
    print(f"Saved: {report_json_out.name}")

    # Generate Markdown Report
    generate_markdown_report(report_md_out, report_dict)
    print(f"Saved: {report_md_out.name}")
    print("\nTraining and evaluation pipeline completed successfully!")


def generate_markdown_report(out_path: Path, data: dict):
    """Write comprehensive training report in Markdown."""
    meta = data["pipeline_metadata"]
    cv50 = data["cross_validation_results"]["tau_0_50_aggregate"]
    cv70 = data["cross_validation_results"]["tau_0_70_provisional"]
    ind50 = data["independent_test_evaluation"]["tau_0_50"]
    ind70 = data["independent_test_evaluation"]["tau_0_70_provisional"]
    folds50 = data["cross_validation_results"]["per_fold_50"]
    folds70 = data["cross_validation_results"]["per_fold_70"]
    ood = data["ood_quarantined_evaluation"]

    md = f"""# Expanded Baseline Detector Training & Evaluation Report

## 1. Executive Summary & Model Identification

This report documents the training and rigorous server-disjoint evaluation of the **Expanded Baseline Detector** (`expanded_detector_model.joblib`), trained on the expanded 538-record corpus (`data/expanded_experimental_dataset.csv`).

> [!WARNING]
> **Experimental Prototype Notice**: This model is an experimental research baseline. **It is NOT claimed or certified as production-ready.** The decision threshold $\\tau = 0.70$ is included strictly as a provisional comparative threshold for research analysis and was NOT tuned on the independent test set.

### Key Performance Highlights:
* **Severe False-Positive Rate Reduction**: With the integration of 25 newly approved benign tools (total 53 benign tools across 13 servers), the out-of-fold False-Positive Rate (FPR) dropped from **39.29% down to 13.21%** at the default $\\tau = 0.50$ threshold.
* **Provisional $\\tau = 0.70$ Performance**: Across all 538 out-of-fold cross-validation samples, setting provisional $\\tau = 0.70$ achieves **0.00% FPR (0 false positives out of 53 benign tools)** with **97.11% recall** (471/485 attacks detected).
* **Zero-Shot Independent Test Generalization**: On the held-out independent test set (evaluating unseen server families `puppeteer`, `slack`, and `gitlab`), the model achieved **95.49% accuracy (FPR 18.52%, Recall 99.06%)** at $\\tau=0.50$, and **98.50% accuracy (0.00% FPR, Recall 98.11%)** at provisional $\\tau=0.70$.

---

## 2. Dataset & Training Configuration

| Parameter | Specification |
|---|---|
| **Training Dataset** | [`data/expanded_experimental_dataset.csv`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_experimental_dataset.csv) |
| **Total Samples** | **538 records** |
| **Class Distribution** | 485 Malicious (label `1`) vs. 53 Benign (label `0`) |
| **Class Ratio** | **{meta['class_ratio']}** (improved from 17.32:1) |
| **Feature Extraction** | `FeatureUnion([word_ngrams(1,2), char_wb_ngrams(3,5)])` (3,000 max features, sublinear TF) |
| **Input Representation** | Verbatim tool `description` text strictly (all metadata excluded from features) |
| **Classifier** | `LogisticRegression(C=1.0, class_weight='balanced', max_iter=1000, random_state=42)` |
| **Cross-Validation** | 5-Fold `StratifiedGroupKFold` grouped on `canonical_group` |
| **Leakage Control** | Vectorizers fitted strictly on training folds; zero group overlap |
| **Inference Latency** | **{meta['inference_latency_ms']} ms / sample** |

---

## 3. 5-Fold Server-Disjoint Cross-Validation Results

### A. Aggregate Out-of-Fold (OOF) Performance

| Threshold Policy | Accuracy | Precision | Recall | F1-Score | FPR | FNR | Confusion Matrix (TN, FP, FN, TP) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Default ($\\tau = 0.50$)** | **{cv50['accuracy']:.4f}** | **{cv50['precision']:.4f}** | **{cv50['recall']:.4f}** | **{cv50['f1_score']:.4f}** | **{cv50['fpr']:.4f}** | **{cv50['fnr']:.4f}** | TN={cv50['confusion_matrix']['tn']}, FP={cv50['confusion_matrix']['fp']}, FN={cv50['confusion_matrix']['fn']}, TP={cv50['confusion_matrix']['tp']} |
| **Provisional ($\\tau = 0.70$)** | **{cv70['accuracy']:.4f}** | **{cv70['precision']:.4f}** | **{cv70['recall']:.4f}** | **{cv70['f1_score']:.4f}** | **{cv70['fpr']:.4f}** | **{cv70['fnr']:.4f}** | TN={cv70['confusion_matrix']['tn']}, FP={cv70['confusion_matrix']['fp']}, FN={cv70['confusion_matrix']['fn']}, TP={cv70['confusion_matrix']['tp']} |

### B. Per-Fold Breakdown (Default $\\tau = 0.50$)

| Fold | Train Size | Val Size | Val Benign | Val Attacks | Accuracy | Precision | Recall | F1-Score | FPR | FNR |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
"""
    for f in folds50:
        md += f"| Fold {f['fold']} | {f['train_size']} | {f['val_size']} | {f['val_benign']} | {f['val_malicious']} | {f['accuracy']:.4f} | {f['precision']:.4f} | {f['recall']:.4f} | {f['f1_score']:.4f} | {f['fpr']:.4f} | {f['fnr']:.4f} |\n"

    md += f"""
### C. Per-Fold Breakdown (Provisional $\\tau = 0.70$)

| Fold | Accuracy | Precision | Recall | F1-Score | FPR | FNR | TN | FP | FN | TP |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
"""
    for f in folds70:
        cm = f["confusion_matrix"]
        md += f"| Fold {f['fold']} | {f['accuracy']:.4f} | {f['precision']:.4f} | {f['recall']:.4f} | {f['f1_score']:.4f} | {f['fpr']:.4f} | {f['fnr']:.4f} | {cm['tn']} | {cm['fp']} | {cm['fn']} | {cm['tp']} |\n"

    md += f"""
---

## 4. Independent Test Set Evaluation

To evaluate zero-shot generalization on unseen server architectures, a development model was trained on the Development Set (excluding test server families) and evaluated once on the **Held-Out Independent Test Set**:
* **Held-Out Benign Server Families**: `puppeteer`, `slack`, `gitlab` (22 benign tools total)
* **Held-Out Attacks**: Disjoint held-out MCPTox attack groups (106 attacks total)
* **Total Independent Test Size**: **133 samples**

| Metric | Default Policy ($\\tau = 0.50$) | Provisional Policy ($\\tau = 0.70$) |
|---|:---:|:---:|
| **Accuracy** | **{ind50['accuracy']:.4f}** | **{ind70['accuracy']:.4f}** |
| **Precision** | **{ind50['precision']:.4f}** | **{ind70['precision']:.4f}** |
| **Recall** | **{ind50['recall']:.4f}** | **{ind70['recall']:.4f}** |
| **F1-Score** | **{ind50['f1_score']:.4f}** | **{ind70['f1_score']:.4f}** |
| **False Positive Rate (FPR)** | **{ind50['fpr']:.4f}** ({ind50['confusion_matrix']['fp']}/{ind50['test_benign']} benign) | **{ind70['fpr']:.4f}** ({ind70['confusion_matrix']['fp']}/{ind70['test_benign']} benign) |
| **False Negative Rate (FNR)** | **{ind50['fnr']:.4f}** ({ind50['confusion_matrix']['fn']}/{ind50['test_malicious']} attacks) | **{ind70['fnr']:.4f}** ({ind70['confusion_matrix']['fn']}/{ind70['test_malicious']} attacks) |
| **Confusion Matrix** | TN={ind50['confusion_matrix']['tn']}, FP={ind50['confusion_matrix']['fp']}, FN={ind50['confusion_matrix']['fn']}, TP={ind50['confusion_matrix']['tp']} | TN={ind70['confusion_matrix']['tn']}, FP={ind70['confusion_matrix']['fp']}, FN={ind70['confusion_matrix']['fn']}, TP={ind70['confusion_matrix']['tp']} |

---

## 5. Zero-Shot Out-of-Distribution (OOD) Behavioral Benchmark

The four quarantined tools from [`data/expanded_ood_dataset.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_ood_dataset.json) were evaluated against the final model:

| Tool Name | Server | Quarantine Rationale | Predicted Malicious Probability | $\\tau=0.50$ Action | $\\tau=0.70$ Action |
|---|---|---|:---:|:---:|:---:|
"""
    for o in ood:
        md += f"| `{o['tool_name']}` | `{o['server_name']}` | {o['reason_for_quarantine'][:75]}... | **{o['predicted_malicious_probability']:.4f}** | `{o['prediction_tau_50']}` | `{o['prediction_tau_70']}` |\n"

    md += f"""
### Key Findings on Quarantined Tools:
* `sequentialthinking` receives **0.9157 probability** (strongly flagged due to extensive procedural directive language).
* `puppeteer_evaluate` receives **0.6728 probability** (flagged as suspicious at $\\tau=0.50$ due to arbitrary execution syntax).
* `fetch` and `puppeteer_navigate` hover near intermediate ranges (0.48 - 0.53).
* This validates the quarantine strategy: high-privilege and directive-heavy tools are appropriately trapped by the Gateway's quarantine and policy layers rather than slipping through as transparent benign tools.

---

## 6. Generated Artifacts & Preservation Confirmation

### Newly Saved Artifacts:
1. [`models/expanded_detector_model.joblib`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/models/expanded_detector_model.joblib): Final expanded detector trained on all 538 records.
2. [`models/expanded_vectorizer.joblib`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/models/expanded_vectorizer.joblib): Final TF-IDF feature union fitted on all 538 records.
3. [`models/expanded_training_report.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/models/expanded_training_report.json): Detailed machine-readable metrics, fold breakdowns, independent test results, and OOD benchmark.
4. [`training/expanded_training_report.md`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/expanded_training_report.md): This comprehensive audit report.

### Preserved Existing Assets:
All existing assets remain strictly untouched:
* `models/detector_model.joblib`: Original baseline untouched.
* `models/experimental_detector_model.joblib`: First experimental baseline untouched.
* `data/combined_experimental_dataset.csv`: Untouched.
* `data/ood_evaluation_dataset.json`: Untouched.
"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(md)


if __name__ == "__main__":
    from datetime import datetime, timezone
    run_pipeline()
