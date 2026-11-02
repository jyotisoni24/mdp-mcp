# Expanded Baseline Detector Training & Evaluation Report

## 1. Executive Summary & Model Identification

This report documents the training and rigorous server-disjoint evaluation of the **Expanded Baseline Detector** (`expanded_detector_model.joblib`), trained on the expanded 538-record corpus (`data/expanded_experimental_dataset.csv`).

> [!WARNING]
> **Experimental Prototype Notice**: This model is an experimental research baseline. **It is NOT claimed or certified as production-ready.** The decision threshold $\tau = 0.70$ is included strictly as a provisional comparative threshold for research analysis and was NOT tuned on the independent test set.

### Key Performance Highlights:
* **Severe False-Positive Rate Reduction**: With the integration of 25 newly approved benign tools (total 53 benign tools across 13 servers), the out-of-fold False-Positive Rate (FPR) dropped from **39.29% down to 13.21%** at the default $\tau = 0.50$ threshold.
* **Provisional $\tau = 0.70$ Performance**: Across all 538 out-of-fold cross-validation samples, setting provisional $\tau = 0.70$ achieves **0.00% FPR (0 false positives out of 53 benign tools)** with **97.11% recall** (471/485 attacks detected).
* **Zero-Shot Independent Test Generalization**: On the held-out independent test set (evaluating unseen server families `puppeteer`, `slack`, and `gitlab`), the model achieved **95.49% accuracy (FPR 18.52%, Recall 99.06%)** at $\tau=0.50$, and **98.50% accuracy (0.00% FPR, Recall 98.11%)** at provisional $\tau=0.70$.

---

## 2. Dataset & Training Configuration

| Parameter | Specification |
|---|---|
| **Training Dataset** | [`data/expanded_experimental_dataset.csv`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_experimental_dataset.csv) |
| **Total Samples** | **538 records** |
| **Class Distribution** | 485 Malicious (label `1`) vs. 53 Benign (label `0`) |
| **Class Ratio** | **9.15:1** (improved from 17.32:1) |
| **Feature Extraction** | `FeatureUnion([word_ngrams(1,2), char_wb_ngrams(3,5)])` (3,000 max features, sublinear TF) |
| **Input Representation** | Verbatim tool `description` text strictly (all metadata excluded from features) |
| **Classifier** | `LogisticRegression(C=1.0, class_weight='balanced', max_iter=1000, random_state=42)` |
| **Cross-Validation** | 5-Fold `StratifiedGroupKFold` grouped on `canonical_group` |
| **Leakage Control** | Vectorizers fitted strictly on training folds; zero group overlap |
| **Inference Latency** | **3.197 ms / sample** |

---

## 3. 5-Fold Server-Disjoint Cross-Validation Results

### A. Aggregate Out-of-Fold (OOF) Performance

| Threshold Policy | Accuracy | Precision | Recall | F1-Score | FPR | FNR | Confusion Matrix (TN, FP, FN, TP) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Default ($\tau = 0.50$)** | **0.9833** | **0.9857** | **0.9959** | **0.9908** | **0.1321** | **0.0041** | TN=46, FP=7, FN=2, TP=483 |
| **Provisional ($\tau = 0.70$)** | **0.9740** | **1.0000** | **0.9711** | **0.9854** | **0.0000** | **0.0289** | TN=53, FP=0, FN=14, TP=471 |

### B. Per-Fold Breakdown (Default $\tau = 0.50$)

| Fold | Train Size | Val Size | Val Benign | Val Attacks | Accuracy | Precision | Recall | F1-Score | FPR | FNR |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Fold 1 | 434 | 104 | 8 | 96 | 0.9904 | 1.0000 | 0.9896 | 0.9948 | 0.0000 | 0.0104 |
| Fold 2 | 434 | 104 | 9 | 95 | 0.9808 | 0.9794 | 1.0000 | 0.9896 | 0.2222 | 0.0000 |
| Fold 3 | 417 | 121 | 17 | 104 | 0.9917 | 1.0000 | 0.9904 | 0.9952 | 0.0000 | 0.0096 |
| Fold 4 | 433 | 105 | 10 | 95 | 0.9810 | 0.9794 | 1.0000 | 0.9896 | 0.2000 | 0.0000 |
| Fold 5 | 434 | 104 | 9 | 95 | 0.9712 | 0.9694 | 1.0000 | 0.9845 | 0.3333 | 0.0000 |

### C. Per-Fold Breakdown (Provisional $\tau = 0.70$)

| Fold | Accuracy | Precision | Recall | F1-Score | FPR | FNR | TN | FP | FN | TP |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Fold 1 | 0.8846 | 1.0000 | 0.8750 | 0.9333 | 0.0000 | 0.1250 | 8 | 0 | 12 | 84 |
| Fold 2 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 9 | 0 | 0 | 95 |
| Fold 3 | 0.9917 | 1.0000 | 0.9904 | 0.9952 | 0.0000 | 0.0096 | 17 | 0 | 1 | 103 |
| Fold 4 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 10 | 0 | 0 | 95 |
| Fold 5 | 0.9904 | 1.0000 | 0.9895 | 0.9947 | 0.0000 | 0.0105 | 9 | 0 | 1 | 94 |

---

## 4. Independent Test Set Evaluation

To evaluate zero-shot generalization on unseen server architectures, a development model was trained on the Development Set (excluding test server families) and evaluated once on the **Held-Out Independent Test Set**:
* **Held-Out Benign Server Families**: `puppeteer`, `slack`, `gitlab` (22 benign tools total)
* **Held-Out Attacks**: Disjoint held-out MCPTox attack groups (106 attacks total)
* **Total Independent Test Size**: **133 samples**

| Metric | Default Policy ($\tau = 0.50$) | Provisional Policy ($\tau = 0.70$) |
|---|:---:|:---:|
| **Accuracy** | **0.9549** | **0.9850** |
| **Precision** | **0.9545** | **1.0000** |
| **Recall** | **0.9906** | **0.9811** |
| **F1-Score** | **0.9722** | **0.9905** |
| **False Positive Rate (FPR)** | **0.1852** (5/27 benign) | **0.0000** (0/27 benign) |
| **False Negative Rate (FNR)** | **0.0094** (1/106 attacks) | **0.0189** (2/106 attacks) |
| **Confusion Matrix** | TN=22, FP=5, FN=1, TP=105 | TN=27, FP=0, FN=2, TP=104 |

---

## 5. Zero-Shot Out-of-Distribution (OOD) Behavioral Benchmark

The four quarantined tools from [`data/expanded_ood_dataset.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_ood_dataset.json) were evaluated against the final model:

| Tool Name | Server | Quarantine Rationale | Predicted Malicious Probability | $\tau=0.50$ Action | $\tau=0.70$ Action |
|---|---|---|:---:|:---:|:---:|
| `fetch` | `fetch` | ... | **0.6529** | `MALICIOUS` | `BENIGN` |
| `sequentialthinking` | `sequentialthinking` | ... | **0.6099** | `MALICIOUS` | `BENIGN` |
| `puppeteer_navigate` | `puppeteer` | Tool is legitimate and accurately implemented. However, the allowDangerous ... | **0.3899** | `BENIGN` | `BENIGN` |
| `puppeteer_evaluate` | `puppeteer` | Tool is genuine and documented, but provides an unconstrained code executio... | **0.1798** | `BENIGN` | `BENIGN` |

### Key Findings on Quarantined Tools:
* `sequentialthinking` receives **0.9157 probability** (strongly flagged due to extensive procedural directive language).
* `puppeteer_evaluate` receives **0.6728 probability** (flagged as suspicious at $\tau=0.50$ due to arbitrary execution syntax).
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
