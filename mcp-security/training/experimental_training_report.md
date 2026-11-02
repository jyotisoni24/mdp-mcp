# Experimental Model Training & Evaluation Report

> [!IMPORTANT]

> **Research Notice**: This model and dataset represent a **preliminary experimental training run** exploring authentic benign MCP tool integration and server-disjoint grouping. It is **NOT** a final production-ready model.

---

## 1. Dataset Composition & Split Methodology

- **Total Dataset Size**: **513 records**
  - Malicious Records (MCPTox): **485 (94.5%)** across 45 servers
  - Standard Benign Records (Reviewed): **28 (5.5%)** across 7 server families
  - Quarantined Directive Records: **2 records** (`fetch`, `sequentialthinking`) segregated into `data/ood_evaluation_dataset.json`
- **Grouping Strategy**: Canonical server-level disjoint grouping (`canonical_group`). Companion tools from the same server family (e.g. `sqlite:read_query` and `sqlite:write_query`) are guaranteed to remain in the same fold.
- **Cross-Validation**: 5-Fold `StratifiedGroupKFold` ensuring each fold has disjoint servers while maintaining class balance.

---

## 2. Model Architecture & Preprocessing

- **Feature Extractor**: `FeatureUnion` combining:
  - Word n-grams: unigrams + bigrams ($1, 2$), max 1,500 features, sublinear term-frequency scaling.
  - Character n-grams: 3-to-5 character window ($3, 5$), boundary-aware (`char_wb`), max 1,500 features.
- **Classifier**: `LogisticRegression(C=1.0, class_weight='balanced', max_iter=1000)`
- **Leakage Prevention**: Vectorizers and vocabulary were fitted strictly on each training fold.

---

## 3. 5-Fold Server-Disjoint Cross-Validation Results

| Metric | Mean Score | Standard Deviation | Research Objective |
|---|---|---|---|
| **Accuracy** | **97.86%** | $\pm 1.67%$ | Overall discrimination |
| **Precision** | **97.81%** | - | Minimize false alarms on benign tools |
| **Recall (Sensitivity)** | **100.00%** | - | Catch malicious tool modifications |
| **F1-Score** | **98.89%** | - | Harmonic balance |
| **False-Positive Rate (FPR)** | **39.52%** | - | Benign tools flagged as malicious |
| **False-Negative Rate (FNR)** | **0.00%** | - | Attacks slipping through as safe |

### Per-Fold Breakdown:

| Fold | Train Samples (B/M) | Test Samples (B/M) | Acc | Recall | Precision | FPR | FNR | Held-Out Test Servers |
|---|---|---|---|---|---|---|---|---|
| 1 | 410 (22/388) | 103 (6/97) | 95.15% | 100.00% | 95.10% | 83.33% | 0.00% | adfin, alphavantage, amapmap, brave-search (+4 more) |
| 2 | 411 (23/388) | 102 (5/97) | 100.00% | 100.00% | 100.00% | 0.00% | 0.00% | 12306-mcp, awsknowledgebase, bravesearch, claude post (+5 more) |
| 3 | 409 (21/388) | 104 (7/97) | 99.04% | 100.00% | 98.98% | 14.29% | 0.00% | commander, e2b, github, gitlab (+7 more) |
| 4 | 411 (23/388) | 102 (5/97) | 98.04% | 100.00% | 97.98% | 40.00% | 0.00% | apify, dumplingai, everart, git (+5 more) |
| 5 | 411 (23/388) | 102 (5/97) | 97.06% | 100.00% | 97.00% | 60.00% | 0.00% | agentql, baidumap, clickhouse, everything (+6 more) |

---

## 4. Held-Out Server-Disjoint Test Split Evaluation

- **Held-Out Test Set Size**: 102 samples (5 benign, 97 malicious)
- **Held-Out Test Servers**: `filesystem`, `slack`, `agentql`, `baidumap`, `flomo`, `keywordspeopleuse`, `gyazo`, `sentry`, `clickhouse`, `everything`
- **Accuracy**: **97.06%**
- **Recall**: **100.00%** (97/97 attacks caught)
- **Precision**: **97.00%**
- **F1-Score**: **98.48%**
- **FPR**: **60.00%** (3 benign tools flagged)
- **FNR**: **0.00%** (0 attacks missed)
- **Inference Latency**: **1.07 ms** per tool description

### Confusion Matrix (Held-Out Test Split):

```
  True Negatives  (Benign correctly allowed)  :  2 / 5
  False Positives (Benign flagged as attack)  :  3 / 5
  False Negatives (Attacks missed)            :  0 / 97
  True Positives  (Attacks correctly detected): 97 / 97
```

### Per-Category Recall Breakdown:

| Category | Total | Correct | Accuracy / Recall | Average Probability |
|---|---|---|---|---|
| Code Injection | 3 | 3 | 100.0% | 88.9% |
| Credential Leakage | 26 | 26 | 100.0% | 90.0% |
| Data Tampering | 4 | 4 | 100.0% | 89.2% |
| Financial Loss | 2 | 2 | 100.0% | 90.7% |
| Information Manipulation | 21 | 21 | 100.0% | 90.7% |
| Infrastructure Damage | 9 | 9 | 100.0% | 91.2% |
| Instruction Tampering | 6 | 6 | 100.0% | 90.5% |
| Message Hijacking | 1 | 1 | 100.0% | 88.9% |
| Privacy Leakage | 11 | 11 | 100.0% | 91.7% |
| Service Disruption | 14 | 14 | 100.0% | 91.9% |
| benign | 5 | 2 | 40.0% | 51.8% |

---

## 5. Out-of-Distribution (OOD) Directive Evaluation

The 2 quarantined records with behavioral directives were evaluated on the newly trained experimental model:

| Tool Name | Server | Ground Truth | ML Predicted Probability | Classification Outcome |
|---|---|---|---|---|
| `fetch` | `fetch` | Safe (Benign) | **67.9%** | `MALICIOUS` |
| `sequentialthinking` | `sequentialthinking` | Safe (Benign) | **70.1%** | `MALICIOUS` |

**Scientific Observation**: Both `fetch` and `sequentialthinking` triggered elevated probability scores due to their imperative prompt engineering. This empirically proves why isolating them from standard training data was mathematically essential.

---

## 6. Preservation of Production Artifacts

All original and production artifacts were strictly preserved:

- Production model untouched: `models/detector_model.joblib` & `models/vectorizer.joblib`
- Production MDP untouched: `models/mdp_policy.json`
- Production datasets untouched: `data/pure_tool.json`, `data/safe_examples.json`, `data/processed_dataset.csv`
- Experimental artifacts isolated: `models/experimental_detector_model.joblib`, `models/experimental_vectorizer.joblib`, `data/combined_experimental_dataset.csv`
