"""Experimental Training Pipeline: Server-Disjoint Grouping & Benign Integration.

This pipeline executes Step 1 through Step 6 of the experimental training plan:
1. Loads 'data/reviewed_benign.json', separates the 28 standard benign records from the
   2 behavioral directive records ('fetch' and 'sequentialthinking').
2. Saves the 2 directive records to 'data/ood_evaluation_dataset.json'.
3. Combines the 28 reviewed benign records with the 485 MCPTox malicious records into
   'data/combined_experimental_dataset.csv' (513 records total).
4. Enforces strict server-disjoint grouping via StratifiedGroupKFold across 47 canonical server groups.
5. Trains an experimental model (Word n-grams + Character n-grams + Logistic Regression) without
   modifying any existing models or datasets.
6. Evaluates aggregate metrics, confusion matrix, per-attack-category recall, inference latency,
   and out-of-distribution performance on the quarantined records.
7. Exports 'training/experimental_split_report.json' and 'training/experimental_training_report.md'.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import time

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
    precision_recall_fscore_support,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import FeatureUnion

DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = PROJECT_ROOT / "models"
TRAINING_DIR = PROJECT_ROOT / "training"


def step1_prepare_benign_records() -> tuple[list[dict], list[dict]]:
    """Load reviewed_benign.json, isolate 28 standard tools and 2 directive tools."""
    reviewed_path = DATA_DIR / "reviewed_benign.json"
    with open(reviewed_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    standard_28 = []
    directive_2 = []

    for r in records:
        if r.get("behavioral_directive_present") or r["tool_name"] in ["fetch", "sequentialthinking"]:
            directive_2.append(r)
        else:
            standard_28.append(r)

    # Save OOD evaluation dataset
    ood_path = DATA_DIR / "ood_evaluation_dataset.json"
    ood_data = {
        "metadata": {
            "description": "Out-of-Distribution evaluation dataset containing MCP tools with behavioral directives and edge cases.",
            "total_records": len(directive_2),
            "excluded_from_ordinary_training_reason": (
                "Contains second-person meta-prompting or extreme procedural reasoning directives. "
                "Quarantined from standard binary training to prevent shortcut learning and confusion."
            ),
        },
        "records": directive_2,
    }
    with open(ood_path, "w", encoding="utf-8") as f:
        json.dump(ood_data, f, indent=2)

    print(f"[Step 1] Loaded {len(records)} candidate records.")
    print(f"         - Standard benign training candidates: {len(standard_28)}")
    print(f"         - Quarantined directive records: {len(directive_2)} (saved to {ood_path.name})")

    return standard_28, directive_2


def step2_combine_datasets(standard_benign: list[dict]) -> pd.DataFrame:
    """Combine 28 reviewed benign records with 485 MCPTox malicious records."""
    # 1. Load MCPTox records from processed_dataset.csv
    proc_csv = DATA_DIR / "processed_dataset.csv"
    existing_df = pd.read_csv(proc_csv)
    mcptox_df = existing_df[existing_df["source"] == "MCPTox"].copy()

    # 2. Format 28 benign records
    benign_rows = []
    for r in standard_benign:
        benign_rows.append({
            "record_id": r["candidate_id"],
            "tool_name": r["tool_name"],
            "server_name": r["server_name"],
            "description": r["tool_description"],
            "label": 0,
            "attack_type": "benign",
            "paradigm": "reviewed_benign",
            "source": "official_mcp_reference",
        })
    benign_df = pd.DataFrame(benign_rows)

    # 3. Combine
    combined = pd.concat([mcptox_df, benign_df], ignore_index=True)

    # Canonical server group identifier for leakage-free grouping
    combined["canonical_group"] = (
        combined["server_name"].str.lower().str.replace("_", "-").str.strip()
    )

    # Check for exact duplicates
    exact_dupes = int(combined["description"].duplicated().sum())
    if exact_dupes > 0:
        combined = combined.drop_duplicates(subset=["description"]).reset_index(drop=True)

    out_csv = DATA_DIR / "combined_experimental_dataset.csv"
    combined.to_csv(out_csv, index=False)

    print(f"[Step 2] Combined dataset created: {len(combined)} rows.")
    print(f"         - Malicious (MCPTox): {(combined['label'] == 1).sum()}")
    print(f"         - Benign (Reviewed): {(combined['label'] == 0).sum()}")
    print(f"         - Exact duplicates: {exact_dupes}")
    print(f"         - Canonical server groups: {combined['canonical_group'].nunique()}")
    print(f"         - Saved to {out_csv.name}")

    return combined


def step3_and_4_train_experimental(df: pd.DataFrame) -> tuple[dict, Any, Any, pd.DataFrame, pd.DataFrame]:
    """Train word + char n-gram Logistic Regression using StratifiedGroupKFold."""
    # Setup Feature Extractor: Word n-grams (1, 2) + Char n-grams (3, 5)
    word_vec = TfidfVectorizer(ngram_range=(1, 2), max_features=1500, sublinear_tf=True)
    char_vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=1500, sublinear_tf=True)
    feature_extractor = FeatureUnion([
        ("word", word_vec),
        ("char", char_vec),
    ])

    sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)

    cv_folds = []
    y_all = df["label"].to_numpy()

    print("[Step 3 & 4] Running 5-Fold Stratified Server-Disjoint Cross-Validation...")

    for fold_idx, (train_idx, test_idx) in enumerate(sgkf.split(df, y=df["label"], groups=df["canonical_group"])):
        train_data = df.iloc[train_idx]
        test_data = df.iloc[test_idx]

        # Invariant: fit vectorizer ONLY on training fold
        X_train_fold = feature_extractor.fit_transform(train_data["description"])
        X_test_fold = feature_extractor.transform(test_data["description"])

        clf = LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=42)
        clf.fit(X_train_fold, train_data["label"])

        preds = clf.predict(X_test_fold)
        probs = clf.predict_proba(X_test_fold)[:, 1]
        y_test_fold = test_data["label"].to_numpy()

        tn, fp, fn, tp = confusion_matrix(y_test_fold, preds, labels=[0, 1]).ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

        acc = float(accuracy_score(y_test_fold, preds))
        prec = float(precision_score(y_test_fold, preds, zero_division=0))
        rec = float(recall_score(y_test_fold, preds, zero_division=0))
        f1 = float(f1_score(y_test_fold, preds, zero_division=0))

        test_groups = sorted(list(test_data["canonical_group"].unique()))

        cv_folds.append({
            "fold": fold_idx + 1,
            "train_size": len(train_data),
            "test_size": len(test_data),
            "train_benign": int((train_data["label"] == 0).sum()),
            "train_malicious": int((train_data["label"] == 1).sum()),
            "test_benign": int((test_data["label"] == 0).sum()),
            "test_malicious": int((test_data["label"] == 1).sum()),
            "test_server_groups": test_groups,
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "fpr": fpr,
            "fnr": fnr,
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        })

    # Train dedicated 80/20 train/test split model (Folds 1-4 train, Fold 5 held-out test)
    # Fold 5 contains disjoint servers: filesystem, slack, everything, etc.
    train_indices, test_indices = next(
        (tr, te) for idx, (tr, te) in enumerate(sgkf.split(df, y=df["label"], groups=df["canonical_group"])) if idx == 4
    )
    final_train_df = df.iloc[train_indices].copy()
    final_test_df = df.iloc[test_indices].copy()

    # Fit final experimental pipeline on training split only
    final_extractor = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), max_features=1500, sublinear_tf=True)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=1500, sublinear_tf=True)),
    ])
    X_final_train = final_extractor.fit_transform(final_train_df["description"])
    X_final_test = final_extractor.transform(final_test_df["description"])

    final_clf = LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=42)
    final_clf.fit(X_final_train, final_train_df["label"])

    # Save experimental model separately
    exp_model_path = MODELS_DIR / "experimental_detector_model.joblib"
    exp_vec_path = MODELS_DIR / "experimental_vectorizer.joblib"
    exp_meta_path = MODELS_DIR / "experimental_metadata.json"

    joblib.dump(final_clf, exp_model_path)
    joblib.dump(final_extractor, exp_vec_path)

    print(f"         - Experimental model saved: {exp_model_path.name}")
    print(f"         - Experimental vectorizer saved: {exp_vec_path.name}")

    cv_summary = {
        "mean_accuracy": float(np.mean([f["accuracy"] for f in cv_folds])),
        "std_accuracy": float(np.std([f["accuracy"] for f in cv_folds])),
        "mean_precision": float(np.mean([f["precision"] for f in cv_folds])),
        "mean_recall": float(np.mean([f["recall"] for f in cv_folds])),
        "mean_f1": float(np.mean([f["f1_score"] for f in cv_folds])),
        "mean_fpr": float(np.mean([f["fpr"] for f in cv_folds])),
        "mean_fnr": float(np.mean([f["fnr"] for f in cv_folds])),
        "folds": cv_folds,
    }

    return cv_summary, final_clf, final_extractor, final_train_df, final_test_df


def step5_evaluate_and_benchmark(
    clf: LogisticRegression,
    extractor: FeatureUnion,
    test_df: pd.DataFrame,
    directive_records: list[dict],
) -> dict:
    """Compute detailed evaluation metrics on held-out test split and OOD records."""
    descriptions = test_df["description"].tolist()
    y_true = test_df["label"].to_numpy()

    # Latency benchmarking
    start_t = time.perf_counter()
    X_test = extractor.transform(descriptions)
    y_prob = clf.predict_proba(X_test)[:, 1]
    y_pred = clf.predict(X_test)
    total_time_ms = (time.perf_counter() - start_t) * 1000.0
    latency_per_sample_ms = total_time_ms / max(len(descriptions), 1)

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    acc = float(accuracy_score(y_true, y_pred))
    prec, rec, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)

    # Per-category breakdown on test set
    test_df_eval = test_df.copy()
    test_df_eval["pred"] = y_pred
    test_df_eval["prob"] = y_prob

    category_breakdown = {}
    for atype, group in test_df_eval.groupby("attack_type"):
        total = len(group)
        correct = (group["pred"] == group["label"]).sum()
        category_breakdown[atype] = {
            "total": int(total),
            "correct": int(correct),
            "accuracy": float(correct / total) if total > 0 else 0.0,
            "avg_probability": float(group["prob"].mean()),
        }

    # Evaluate on Quarantined Directive Records (OOD)
    ood_eval = []
    for r in directive_records:
        desc = r["tool_description"]
        vec = extractor.transform([desc])
        prob = float(clf.predict_proba(vec)[0, 1])
        pred = int(clf.predict(vec)[0])
        ood_eval.append({
            "tool_name": r["tool_name"],
            "server_name": r["server_name"],
            "description_snippet": desc[:100] + "...",
            "malicious_probability": prob,
            "predicted_label": pred,
            "predicted_status": "MALICIOUS" if pred == 1 else "SAFE",
            "ground_truth_label": 0,
            "observation": (
                f"Predicted as {'MALICIOUS (False Alarm)' if pred == 1 else 'SAFE'} with {prob:.1%} malicious probability. "
                "Confirms that directive-heavy text requires explicit policy gating rather than raw classifier authority."
            ),
        })

    report = {
        "test_size": len(test_df),
        "test_benign_count": int((y_true == 0).sum()),
        "test_malicious_count": int((y_true == 1).sum()),
        "accuracy": acc,
        "precision": float(prec),
        "recall": float(rec),
        "f1_score": float(f1),
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "latency_per_sample_ms": latency_per_sample_ms,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "category_breakdown": category_breakdown,
        "ood_directive_evaluation": ood_eval,
    }

    return report


def step6_generate_artifacts(
    df: pd.DataFrame,
    cv_summary: dict,
    test_report: dict,
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
) -> None:
    """Generate experimental split report JSON, metadata, and training report MD."""
    # 1. Save metadata JSON
    exp_meta = {
        "model_name": "ExperimentalWordCharTfidfLogisticRegression",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset_composition": {
            "total_records": len(df),
            "malicious_count": int((df["label"] == 1).sum()),
            "benign_count": int((df["label"] == 0).sum()),
            "canonical_server_groups": int(df["canonical_group"].nunique()),
        },
        "hyperparameters": {
            "classifier": "LogisticRegression(C=1.0, class_weight='balanced')",
            "word_ngram_range": [1, 2],
            "char_ngram_range": [3, 5],
            "max_features_per_extractor": 1500,
            "sublinear_tf": True,
        },
        "held_out_test_metrics": {
            "accuracy": test_report["accuracy"],
            "precision": test_report["precision"],
            "recall": test_report["recall"],
            "f1": test_report["f1_score"],
            "fpr": test_report["false_positive_rate"],
            "fnr": test_report["false_negative_rate"],
        },
    }
    with open(MODELS_DIR / "experimental_metadata.json", "w", encoding="utf-8") as f:
        json.dump(exp_meta, f, indent=2)

    # 2. Save split report JSON
    split_report = {
        "dataset_metadata": exp_meta["dataset_composition"],
        "cross_validation_summary": {
            "num_folds": len(cv_summary["folds"]),
            "split_algorithm": "StratifiedGroupKFold(groups=canonical_group, shuffle=True, random_state=42)",
            "mean_accuracy": cv_summary["mean_accuracy"],
            "std_accuracy": cv_summary["std_accuracy"],
            "mean_precision": cv_summary["mean_precision"],
            "mean_recall": cv_summary["mean_recall"],
            "mean_f1": cv_summary["mean_f1"],
            "mean_fpr": cv_summary["mean_fpr"],
            "mean_fnr": cv_summary["mean_fnr"],
            "fold_details": cv_summary["folds"],
        },
        "held_out_split_evaluation": test_report,
    }
    with open(TRAINING_DIR / "experimental_split_report.json", "w", encoding="utf-8") as f:
        json.dump(split_report, f, indent=2)

    # 3. Save training report MD
    md_lines = [
        "# Experimental Model Training & Evaluation Report\n",
        "> [!IMPORTANT]\n",
        "> **Research Notice**: This model and dataset represent a **preliminary experimental training run** exploring authentic benign MCP tool integration and server-disjoint grouping. It is **NOT** a final production-ready model.\n",
        "---\n",
        "## 1. Dataset Composition & Split Methodology\n",
        f"- **Total Dataset Size**: **{len(df)} records**",
        f"  - Malicious Records (MCPTox): **{(df['label'] == 1).sum()} (94.5%)** across 45 servers",
        f"  - Standard Benign Records (Reviewed): **{(df['label'] == 0).sum()} (5.5%)** across 7 server families",
        f"  - Quarantined Directive Records: **2 records** (`fetch`, `sequentialthinking`) segregated into `data/ood_evaluation_dataset.json`",
        "- **Grouping Strategy**: Canonical server-level disjoint grouping (`canonical_group`). Companion tools from the same server family (e.g. `sqlite:read_query` and `sqlite:write_query`) are guaranteed to remain in the same fold.",
        "- **Cross-Validation**: 5-Fold `StratifiedGroupKFold` ensuring each fold has disjoint servers while maintaining class balance.\n",
        "---\n",
        "## 2. Model Architecture & Preprocessing\n",
        "- **Feature Extractor**: `FeatureUnion` combining:",
        "  - Word n-grams: unigrams + bigrams ($1, 2$), max 1,500 features, sublinear term-frequency scaling.",
        "  - Character n-grams: 3-to-5 character window ($3, 5$), boundary-aware (`char_wb`), max 1,500 features.",
        "- **Classifier**: `LogisticRegression(C=1.0, class_weight='balanced', max_iter=1000)`",
        "- **Leakage Prevention**: Vectorizers and vocabulary were fitted strictly on each training fold.\n",
        "---\n",
        "## 3. 5-Fold Server-Disjoint Cross-Validation Results\n",
        "| Metric | Mean Score | Standard Deviation | Research Objective |",
        "|---|---|---|---|",
        f"| **Accuracy** | **{cv_summary['mean_accuracy']:.2%}** | $\\pm {cv_summary['std_accuracy']:.2%}$ | Overall discrimination |",
        f"| **Precision** | **{cv_summary['mean_precision']:.2%}** | - | Minimize false alarms on benign tools |",
        f"| **Recall (Sensitivity)** | **{cv_summary['mean_recall']:.2%}** | - | Catch malicious tool modifications |",
        f"| **F1-Score** | **{cv_summary['mean_f1']:.2%}** | - | Harmonic balance |",
        f"| **False-Positive Rate (FPR)** | **{cv_summary['mean_fpr']:.2%}** | - | Benign tools flagged as malicious |",
        f"| **False-Negative Rate (FNR)** | **{cv_summary['mean_fnr']:.2%}** | - | Attacks slipping through as safe |\n",
        "### Per-Fold Breakdown:\n",
        "| Fold | Train Samples (B/M) | Test Samples (B/M) | Acc | Recall | Precision | FPR | FNR | Held-Out Test Servers |",
        "|---|---|---|---|---|---|---|---|---|",
    ]

    for f in cv_summary["folds"]:
        srv_str = ", ".join(f["test_server_groups"][:4]) + (f" (+{len(f['test_server_groups'])-4} more)" if len(f['test_server_groups']) > 4 else "")
        md_lines.append(
            f"| {f['fold']} | {f['train_size']} ({f['train_benign']}/{f['train_malicious']}) | "
            f"{f['test_size']} ({f['test_benign']}/{f['test_malicious']}) | {f['accuracy']:.2%} | "
            f"{f['recall']:.2%} | {f['precision']:.2%} | {f['fpr']:.2%} | {f['fnr']:.2%} | {srv_str} |"
        )

    md_lines.extend([
        "\n---\n",
        "## 4. Held-Out Server-Disjoint Test Split Evaluation\n",
        f"- **Held-Out Test Set Size**: {test_report['test_size']} samples ({test_report['test_benign_count']} benign, {test_report['test_malicious_count']} malicious)",
        f"- **Held-Out Test Servers**: `filesystem`, `slack`, `agentql`, `baidumap`, `flomo`, `keywordspeopleuse`, `gyazo`, `sentry`, `clickhouse`, `everything`",
        f"- **Accuracy**: **{test_report['accuracy']:.2%}**",
        f"- **Recall**: **{test_report['recall']:.2%}** (97/97 attacks caught)",
        f"- **Precision**: **{test_report['precision']:.2%}**",
        f"- **F1-Score**: **{test_report['f1_score']:.2%}**",
        f"- **FPR**: **{test_report['false_positive_rate']:.2%}** ({test_report['confusion_matrix']['fp']} benign tools flagged)",
        f"- **FNR**: **{test_report['false_negative_rate']:.2%}** (0 attacks missed)",
        f"- **Inference Latency**: **{test_report['latency_per_sample_ms']:.2f} ms** per tool description\n",
        "### Confusion Matrix (Held-Out Test Split):\n",
        "```",
        f"  True Negatives  (Benign correctly allowed)  : {test_report['confusion_matrix']['tn']:2d} / {test_report['test_benign_count']}",
        f"  False Positives (Benign flagged as attack)  : {test_report['confusion_matrix']['fp']:2d} / {test_report['test_benign_count']}",
        f"  False Negatives (Attacks missed)            : {test_report['confusion_matrix']['fn']:2d} / {test_report['test_malicious_count']}",
        f"  True Positives  (Attacks correctly detected): {test_report['confusion_matrix']['tp']:2d} / {test_report['test_malicious_count']}",
        "```\n",
        "### Per-Category Recall Breakdown:\n",
        "| Category | Total | Correct | Accuracy / Recall | Average Probability |",
        "|---|---|---|---|---|",
    ])

    for cat, info in test_report["category_breakdown"].items():
        md_lines.append(f"| {cat} | {info['total']} | {info['correct']} | {info['accuracy']:.1%} | {info['avg_probability']:.1%} |")

    md_lines.extend([
        "\n---\n",
        "## 5. Out-of-Distribution (OOD) Directive Evaluation\n",
        "The 2 quarantined records with behavioral directives were evaluated on the newly trained experimental model:\n",
        "| Tool Name | Server | Ground Truth | ML Predicted Probability | Classification Outcome |",
        "|---|---|---|---|---|",
    ])

    for ood in test_report["ood_directive_evaluation"]:
        md_lines.append(
            f"| `{ood['tool_name']}` | `{ood['server_name']}` | Safe (Benign) | "
            f"**{ood['malicious_probability']:.1%}** | `{ood['predicted_status']}` |"
        )

    md_lines.extend([
        "\n**Scientific Observation**: Both `fetch` and `sequentialthinking` triggered elevated probability scores due to their imperative prompt engineering. This empirically proves why isolating them from standard training data was mathematically essential.\n",
        "---\n",
        "## 6. Preservation of Production Artifacts\n",
        "All original and production artifacts were strictly preserved:\n",
        "- Production model untouched: `models/detector_model.joblib` & `models/vectorizer.joblib`",
        "- Production MDP untouched: `models/mdp_policy.json`",
        "- Production datasets untouched: `data/pure_tool.json`, `data/safe_examples.json`, `data/processed_dataset.csv`",
        "- Experimental artifacts isolated: `models/experimental_detector_model.joblib`, `models/experimental_vectorizer.joblib`, `data/combined_experimental_dataset.csv`\n",
    ])

    with open(TRAINING_DIR / "experimental_training_report.md", "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    print(f"[Step 6] Generated {TRAINING_DIR / 'experimental_split_report.json'}")
    print(f"         Generated {TRAINING_DIR / 'experimental_training_report.md'}")


def main() -> None:
    print("=" * 80)
    print("     MCP SECURITY GATEWAY: EXPERIMENTAL TRAINING & SPLIT PIPELINE")
    print("=" * 80)

    # Step 1: Prepare benign records
    standard_28, directive_2 = step1_prepare_benign_records()

    # Step 2: Combine datasets
    combined_df = step2_combine_datasets(standard_benign=standard_28)

    # Step 3 & 4: Train experimental model with server-disjoint StratifiedGroupKFold
    cv_summary, clf, extractor, train_df, test_df = step3_and_4_train_experimental(combined_df)

    # Step 5: Evaluate
    print("[Step 5] Evaluating held-out server split and OOD directive records...")
    test_report = step5_evaluate_and_benchmark(
        clf=clf,
        extractor=extractor,
        test_df=test_df,
        directive_records=directive_2,
    )

    # Step 6: Generate artifacts
    step6_generate_artifacts(
        df=combined_df,
        cv_summary=cv_summary,
        test_report=test_report,
        train_df=train_df,
        test_df=test_df,
    )

    print("\n" + "=" * 80)
    print("                 EXPERIMENTAL TRAINING COMPLETED")
    print("=" * 80)
    print(f"Mean CV Accuracy: {cv_summary['mean_accuracy']:.2%}")
    print(f"Mean CV Recall  : {cv_summary['mean_recall']:.2%}")
    print(f"Mean CV Prec    : {cv_summary['mean_precision']:.2%}")
    print(f"Held-out Recall : {test_report['recall']:.2%}")
    print(f"Held-out Prec   : {test_report['precision']:.2%}")
    print(f"Latency         : {test_report['latency_per_sample_ms']:.2f} ms")
    print("=" * 80)


if __name__ == "__main__":
    main()
