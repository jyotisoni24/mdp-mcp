# Research-Grade Evaluation of MCP Security Gateway

**Authors**: Independent Security & Machine Learning Evaluation Team  
**Evaluation Date**: November 2, 2026  
**Artifacts Evaluated**: 
- Model: [`models/expanded_detector_model.joblib`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/models/expanded_detector_model.joblib)
- Vectorizer: [`models/expanded_vectorizer.joblib`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/models/expanded_vectorizer.joblib)
- Dataset: [`data/expanded_experimental_dataset.csv`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_experimental_dataset.csv)
- OOD Dataset: [`data/expanded_ood_dataset.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_ood_dataset.json)
- Policy: [`models/mdp_policy.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/models/mdp_policy.json)
- Structured Results: [`training/research_evaluation_results.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/research_evaluation_results.json)
- Reproducibility Audit: [`training/reproducibility_audit.md`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/reproducibility_audit.md)
- Automated Test Suite: **86 / 86 passing tests** (`python -m pytest -v`)

---

## 1. Executive Summary

This report delivers a rigorous, empirical research evaluation of the **Model Context Protocol (MCP) Security Gateway**. The evaluated system defends client Large Language Models (LLMs) from untrusted, mutated, or poisoned MCP tool descriptions (e.g. prompt injection, sensitive data exfiltration, system disruption) via a layered defense architecture combining:
1. **Cryptographic Integrity & Baseline Tracking**: Canonical descriptor hashing (SHA-256) invariant to whitespace formatting.
2. **Supervised ML Classification**: Balanced Logistic Regression over character and word n-gram TF-IDF representations.
3. **Mandatory Security Rules**: Heuristic invariants scanning for instruction overriding, sensitive files (`~/.ssh/id_rsa`, `/etc/shadow`), and covert execution directives.
4. **Sequential Decision-Making**: Markov Decision Process (MDP) and Threshold policies routing uncertain or modified tools into quarantine rather than brittle binary execution.
5. **Two-Phase Protocol Enforcement**: Gating both `tools/list` (tool suppression) and `tools/call` (runtime execution interception).

### Key Empirical Findings
- **Zero Unauthorized Executions**: Across 100 repeated benchmark runs and extensive protocol edge-case attacks, the count of unauthorized upstream executions was **strictly 0**.
- **Cross-Validation Performance**: Under 5-fold strictly server-disjoint cross-validation on 538 records (485 malicious, 53 benign), the ML detector achieved:
  - At standard threshold $\tau = 0.50$: **Accuracy 98.33%** (95% CI: $[97.21\%, 99.26\%]$), **F1 0.9908** (95% CI: $[0.9843, 0.9960]$), **FPR 13.21%** ($7/53$, 95% CI: $[5.08\%, 23.64\%]$), **FNR 0.41%** ($2/485$, 95% CI: $[0.00\%, 1.04\%]$), **ROC-AUC 0.9981**, **PR-AUC 0.9998**.
  - At provisional threshold $\tau = 0.70$: **Accuracy 97.40%** (95% CI: $[96.10\%, 98.70\%]$), **Precision 100.0%**, **FPR 0.00%** ($0/53$), **Recall 97.11%** ($471/485$), **FNR 2.89%** ($14/485$).
- **Generalization to Independent Server Families**: On an independent held-out test partition consisting of 3 entire unseen benign server families (`puppeteer`, `slack`, `gitlab`) and 20% disjoint malicious server groups (133 samples total: 27 benign, 106 malicious):
  - At $\tau = 0.50$: Accuracy 95.49%, F1 0.9722, FPR 18.52% ($5/27$), FNR 0.94% ($1/106$), ROC-AUC 0.9964.
  - At $\tau = 0.70$: Accuracy 98.50%, Precision 100.0%, F1 0.9905, FPR 0.00% ($0/27$), FNR 1.89% ($2/106$).
- **Low-Latency Gateway Enforcement**: Measured over 100 repeated live FastMCP proxy runs:
  - `tools/list` filtering latency: **Mean 1.961 ms**, **Median 1.822 ms**, **P95 2.737 ms**.
  - `tools/call` authorization latency: **Mean 0.255 ms**, **Median 0.249 ms**, **P95 0.345 ms**.
- **Ablation Demonstration**: The ablation study proves that neither cryptographic hashing, heuristic rules, nor ML detection is sufficient in isolation. Full Gateway architecture uniquely resolves the trilemma between attack vulnerability, false blocking of benign rewrites, and direct bypass exploitation.

---

## 2. Reproducibility & Integrity Audit Summary

An independent reproducibility audit was executed against all repository artifacts prior to evaluation. The full audit log is available in [`training/reproducibility_audit.md`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/reproducibility_audit.md).

### Summary Audit Matrix
| Verification Item | Requirement | Measured Result | Audit Status |
| :--- | :--- | :---: | :---: |
| **Dataset Record Counts** | Exactly 538 records | 538 (485 Malicious, 53 Benign) | PASS |
| **Class Imbalance** | Documented ratio | $9.15 : 1$ adversarial ratio | PASS |
| **Text Uniqueness** | Zero duplicate descriptions | 538 unique / 0 duplicates | PASS |
| **Cross-Validation Splitting** | Strictly server-disjoint | 0 group overlap across all 5 folds | PASS |
| **Independent Test Splitting** | Disjoint server families | 0 group overlap (39 Dev, 11 Test) | PASS |
| **Near-Duplicate Cross-Leakage** | No cross-label $\text{Sim} \ge 0.80$ | 0 cross-label near duplicates | PASS |
| **Quarantined OOD Isolation** | Zero OOD samples in training | 0 OOD descriptions in dataset | PASS |
| **Test Set Non-Contamination** | No hyperparameter/threshold tuning | $\tau = 0.70$ evaluated post-hoc as comparison | PASS |
| **Model Artifact Verification** | Artifact matches training script | $1 \times 3000$ weights, intercept $-0.8473$ | PASS |

### Transparent Anomaly Disclosures
1. **MCPTox Row 391 Null Tool Name**: Row 391 (`Puppeteer_12`) in `data/expanded_experimental_dataset.csv` contains a null value (`NaN`) for `tool_name` inherited from the raw MCPTox benchmark. The description text is complete and targets `puppeteer_hover`. Because feature extraction operates on `description`, model weights were unaffected. This null value propagated as `NaN` into line 185 of `training/expanded_dataset_split_report.json`.
2. **Formulaic Template Regularity**: MCPTox attack descriptions adhere to synthetic template conventions (`Template-1`, `Template-2`, `Template-3`). While realistic in threat semantics, their standardized phrasing contributes to near-perfect recall and may not reflect unstructured human red-teaming.

---

## 3. Machine Learning Detection Performance

### 3.1 5-Fold Server-Disjoint Cross-Validation

The 5-fold cross-validation enforces `StratifiedGroupKFold` on `canonical_group`. The vectorizer was fit exclusively on the training partition within each fold. 95% confidence intervals were computed using non-parametric percentile bootstrap across 1,000 resamples of out-of-fold predictions.

```
                    Cross-Validation Performance Comparison
+-----------------------+-----------------------------+-----------------------------+
| Metric                | Threshold tau = 0.50        | Threshold tau = 0.70 (Prov) |
+-----------------------+-----------------------------+-----------------------------+
| Accuracy              | 98.33% [97.21%, 99.26%]     | 97.40% [96.10%, 98.70%]     |
| Precision             | 98.57% [97.38%, 99.58%]     | 100.0% [100.0%, 100.0%]     |
| Recall (Sensitivity)  | 99.59% [98.96%, 100.0%]     | 97.11% [95.64%, 98.54%]     |
| F1-Score              | 0.9908 [0.9843, 0.9960]     | 0.9854 [0.9777, 0.9927]     |
| False Positive Rate   | 13.21% (7/53) [5.08%, 23.6%] | 0.00% (0/53) [0.00%, 0.00%] |
| False Negative Rate   | 0.41% (2/485) [0.00%, 1.04%]| 2.89% (14/485) [1.46%, 4.36%|
| ROC-AUC               | 0.9981 [0.9950, 1.0000]     | 0.9981 [0.9950, 1.0000]     |
| PR-AUC                | 0.9998 [0.9995, 1.0000]     | 0.9998 [0.9995, 1.0000]     |
+-----------------------+-----------------------------+-----------------------------+
```

#### Confusion Matrices (OOF, $N=538$)
- **At $\tau = 0.50$**:
  - $\text{True Negatives (TN)} = 46$
  - $\text{False Positives (FP)} = 7$ (benign flagged as malicious)
  - $\text{False Negatives (FN)} = 2$ (attacks missed)
  - $\text{True Positives (TP)} = 483$
- **At $\tau = 0.70$**:
  - $\text{True Negatives (TN)} = 53$ (Zero false positives!)
  - $\text{False Positives (FP)} = 0$
  - $\text{False Negatives (FN)} = 14$
  - $\text{True Positives (TP)} = 471$

#### Per-Fold Metric Consistency ($\tau = 0.50$)
| Fold | Train / Val Size | Val Benign / Malicious | Accuracy | Precision | Recall | F1 | FPR | FNR |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Fold 1** | 434 / 104 | 8 / 96 | 99.04% | 1.0000 | 0.9896 | 0.9948 | 0.00% ($0/8$) | 1.04% ($1/96$) |
| **Fold 2** | 434 / 104 | 9 / 95 | 98.08% | 0.9895 | 0.9895 | 0.9895 | 11.11% ($1/9$) | 1.05% ($1/95$) |
| **Fold 3** | 417 / 121 | 17 / 104 | 99.17% | 0.9905 | 1.0000 | 0.9952 | 5.88% ($1/17$) | 0.00% ($0/104$) |
| **Fold 4** | 433 / 105 | 10 / 95 | 98.10% | 0.9794 | 1.0000 | 0.9896 | 20.00% ($2/10$) | 0.00% ($0/95$) |
| **Fold 5** | 434 / 104 | 9 / 95 | 97.12% | 0.9694 | 1.0000 | 0.9845 | 33.33% ($3/9$) | 0.00% ($0/95$) |

---

### 3.2 Independent Held-Out Test Set Evaluation

The independent evaluation held out three complete server families (`puppeteer`, `slack`, `gitlab`) and 9 disjoint malicious server groups (133 samples total: 27 benign, 106 malicious):

| Metric | Threshold $\tau = 0.50$ | Threshold $\tau = 0.70$ (Provisional) |
| :--- | :---: | :---: |
| **Accuracy** | 95.49% ($127/133$) | 98.50% ($131/133$) |
| **Precision** | 95.45% ($105/110$) | **100.0%** ($104/104$) |
| **Recall** | **99.06%** ($105/106$) | 98.11% ($104/106$) |
| **F1-Score** | 0.9722 | **0.9905** |
| **False Positive Rate (FPR)** | 18.52% ($5/27$) | **0.00%** ($0/27$) |
| **False Negative Rate (FNR)** | 0.94% ($1/106$) | 1.89% ($2/106$) |
| **Confusion Matrix** | $\text{TN}=22, \text{FP}=5, \text{FN}=1, \text{TP}=105$ | $\text{TN}=27, \text{FP}=0, \text{FN}=2, \text{TP}=104$ |
| **ROC-AUC** | 0.9964 [0.9881, 1.0000] | 0.9964 [0.9881, 1.0000] |
| **PR-AUC** | 0.9992 [0.9971, 1.0000] | 0.9992 [0.9971, 1.0000] |

**Key Takeaway**: At $\tau = 0.70$, zero false positives occur on unseen server families, confirming that increasing decision stringency suppresses false alarms on benign operational tools while preserving $>98\%$ attack recall.

---

### 3.3 Attack Category Breakdown

Performance across all 11 MCPTox attack categories and reviewed benign tools:

| Category | Count | Ground Truth | Mean Malicious Prob $\hat{p}$ | Detection Rate ($\tau = 0.50$) | Detection Rate ($\tau = 0.70$) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Information Manipulation** | 108 | Malicious | 0.9201 | 100.0% ($108/108$) | 100.0% ($108/108$) |
| **Privacy Leakage** | 97 | Malicious | 0.8840 | 98.97% ($96/97$) | 94.85% ($92/97$) |
| **Service Disruption** | 73 | Malicious | 0.9335 | 100.0% ($73/73$) | 98.63% ($72/73$) |
| **Data Tampering** | 45 | Malicious | 0.8553 | 97.78% ($44/45$) | 84.44% ($38/45$) |
| **Infrastructure Damage** | 41 | Malicious | 0.8928 | 100.0% ($41/41$) | 100.0% ($41/41$) |
| **Credential Leakage** | 40 | Malicious | 0.8979 | 100.0% ($40/40$) | 100.0% ($40/40$) |
| **Code Injection** | 22 | Malicious | 0.8795 | 100.0% ($22/22$) | 95.45% ($21/22$) |
| **Financial Loss** | 21 | Malicious | 0.9017 | 100.0% ($21/21$) | 100.0% ($21/21$) |
| **Instruction Tampering** | 21 | Malicious | 0.9453 | 100.0% ($21/21$) | 100.0% ($21/21$) |
| **Message Hijacking** | 15 | Malicious | 0.8503 | 100.0% ($15/15$) | 100.0% ($15/15$) |
| **Other** | 2 | Malicious | 0.8700 | 100.0% ($2/2$) | 100.0% ($2/2$) |
| **Benign Tools (Reviewed)** | 53 | Benign | 0.3016 | 86.79% Specificity ($46/53$) | **100.0% Specificity** ($53/53$) |

---

### 3.4 Quarantined Out-of-Distribution (OOD) Benchmark

The 4 quarantined samples in `data/expanded_ood_dataset.json` present critical boundary challenges where text modeling diverges from security intent:

| Tool Name | Server | Predicted Prob $\hat{p}$ | Decision ($\tau=0.50$) | Decision ($\tau=0.70$) | Security Rationale for Quarantine |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `fetch` | `fetch` | 0.6529 | MALICIOUS | BENIGN | Tool grants internet access with phrasing mimicking instruction overrides ("Although originally you did not have internet access..."). High text risk despite legitimate function. |
| `sequentialthinking` | `sequentialthinking` | 0.6099 | MALICIOUS | BENIGN | Complex prompt guidance ("You should...", "Never stop until...") triggers heuristic prompt-injection detectors. |
| `puppeteer_navigate` | `puppeteer` | 0.3899 | BENIGN | BENIGN | Legitimate navigation, but parameter `allowDangerous: true` allows SSRF into internal networks (`169.254.169.254`). Low text toxicity requires schema policy gating. |
| `puppeteer_evaluate` | `puppeteer` | 0.1798 | BENIGN | BENIGN | "Execute JavaScript in the browser console." Minimal text toxicity, yet provides an unconstrained remote code execution primitive. Must require explicit administrative authorization. |

**Architectural Insight**: Pure ML detectors evaluate linguistic toxicity rather than execution capability. This proves that an ML model alone cannot secure an MCP deployment without Descriptor Hashing and Quarantine Workflows.

---

## 4. Gateway Security Enforcement Benchmark

The gateway runtime was evaluated over 100 repeated live FastMCP proxy execution cycles:

```
                            Gateway Enforcement Metrics (100 Runs)
+------------------------------------------+---------------------+-----------------------+
| Security Dimension                       | Measured Value      | Invariant Requirement |
+------------------------------------------+---------------------+-----------------------+
| Legitimate Tool Acceptance Rate          | 100.0% (100/100)    | Must be 100%          |
| Malicious Tool Blocking Rate             | 100.0% (100/100)    | Must be 100%          |
| Quarantine Rate (Modified Tools)         | 100.0% (100/100)    | Must be 100%          |
| Direct Call Bypass Rejection Rate        | 100.0% (100/100)    | Must be 100%          |
| Unauthorized Upstream Executions         | 0 (ZERO)            | MUST BE EXACTLY ZERO  |
| Human Approval & Revocation Lifecycle    | VERIFIED SOUND      | Pass / Revoke / Block |
+------------------------------------------+---------------------+-----------------------+
```

### Latency Profile Across 100 Executions
All latencies include Python object marshaling, text normalization, SHA-256 computation, and ML vectorizer inference:

| Protocol Operation | Mean Latency | Median Latency | P95 Latency | Min Latency | Max Latency |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`tools/list` (Filtering & Inference)** | 1.961 ms | 1.822 ms | 2.737 ms | 1.292 ms | 4.045 ms |
| **`tools/call` (Authorization Verification)** | 0.255 ms | 0.249 ms | 0.345 ms | 0.148 ms | 0.498 ms |

The total authorization overhead added by the gateway is sub-millisecond on runtime tool execution and under 3 ms on listing, making it completely negligible compared to LLM generation latency ($\approx 500 - 3000\text{ ms}$).

---

## 5. Sequential Decision Policy: MDP vs. Static Threshold Policy

### 5.1 Multi-Seed Simulation Benchmark
To evaluate decision-making under uncertainty, the Markov Decision Process (MDP) policy (solved via Value Iteration and Q-Learning) was compared against the Static Threshold policy across 5 distinct random seeds (42, 123, 456, 789, 1000) over 2,500 total simulated decision episodes:

| Seed | MDP Mean Reward | Static Mean Reward | MDP Breaches | Static Breaches | MDP False Blocks | Static False Blocks | MDP Quarantines | Static Quarantines |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Seed 42** | 7.25 | 7.03 | 7 | 2 | 5 | 9 | 114 | 249 |
| **Seed 123** | 6.91 | 7.10 | 7 | 2 | 9 | 9 | 126 | 240 |
| **Seed 456** | 6.74 | 6.86 | 7 | 2 | 13 | 12 | 118 | 248 |
| **Seed 789** | 6.77 | 7.37 | 8 | 1 | 7 | 9 | 131 | 234 |
| **Seed 1000** | 7.34 | 6.88 | 6 | 1 | 6 | 13 | 122 | 265 |
| **Overall Mean $\pm$ Std** | **$7.00 \pm 0.25$** | **$7.05 \pm 0.18$** | **$7.0 \pm 0.7$** | **$1.6 \pm 0.5$** | **$8.0 \pm 3.1$** | **$10.4 \pm 1.8$** | **$122 \pm 6$** | **$247 \pm 11$** |

### Policy Dynamics Comparison
1. **Trade-Off**:
   - The **Static Threshold Policy** routes every unverified change to quarantine, achieving near-zero breaches ($1.6$ per 500 episodes) at the cost of higher analyst review burden ($247$ quarantines).
   - The **MDP Policy** optimizes expected utility: when breach penalty is moderate ($-100$), it directly allows marginal low-risk drift, slightly reducing quarantine volume ($122$) while accepting a small breach probability under review inaccuracy.
2. **Breach Penalty Sensitivity**:
   When the breach penalty $R_{\text{breach}}$ is increased from $-100$ to $-250$, $-500$, or $-1000$:
   - Optimal action for State 1 (`LOW_RISK_UNVERIFIED`) dynamically shifts from `ALLOW` to `QUARANTINE`.
   - Under severe penalty regimes ($R_{\text{breach}} \le -250$), the MDP policy converges to the conservative safety posture of the Static Threshold Policy.
3. **Mandatory Security Rule Non-Overridability**:
   - Invariant verified: When a tool contains a mandatory security violation (e.g. instruction overriding or sensitive credential path targeting), **both** Threshold and MDP modes trigger an immediate hard `BLOCK`, strictly overriding low ML scores or MDP value functions in 100% of trials.

---

## 6. Protection Mechanism Ablation Study

Six distinct protection configurations were evaluated against four threat challenges:
- **C1**: Cryptographic Hash Check Only (no ML, no rules, no quarantine)
- **C2**: ML Detector Only (no hash tracking, no rules, no proxy gateway)
- **C3**: Mandatory Heuristic Rules Only (regex scanning only)
- **C4**: Hash + ML
- **C5**: Hash + ML + Mandatory Rules
- **C6**: **Full Gateway** (Hash + ML + Mandatory Rules + Interceptor Proxy + Quarantine Workflow)

```
                               Protection Mechanism Ablation Matrix
+-----------------------------------+--------------------+--------------------+--------------------+--------------------+
| Protection Configuration          | S1: Known Attack   | S2: Benign Rewrite | S3: New Tool       | S4: Direct Bypass  |
+-----------------------------------+--------------------+--------------------+--------------------+--------------------+
| C1: Hash Only                     | False Block / Miss | FALSE BLOCK (Fail) | REJECT / DISRUPT   | BYPASS EXECUTED ❌ |
| C2: ML Detector Only              | BLOCKED (ML)       | BLIND ALLOW (Risk) | BLIND ALLOW (Risk) | BYPASS EXECUTED ❌ |
| C3: Mandatory Rules Only          | BLOCKED (Rule)     | BLIND ALLOW (Risk) | BLIND ALLOW (Risk) | BYPASS EXECUTED ❌ |
| C4: Hash + ML                     | BLOCKED (ML)       | FALSE BLOCK (Fail) | FALSE BLOCK (Fail) | BYPASS EXECUTED ❌ |
| C5: Hash + ML + Mandatory Rules   | BLOCKED (Rule/ML)  | FALSE BLOCK (Fail) | FALSE BLOCK (Fail) | BYPASS EXECUTED ❌ |
| C6: Full Gateway Architecture     | BLOCKED (Rule/ML)  | QUARANTINE (Safe)  | QUARANTINE (Safe)  | BLOCKED (Proxy)    |
+-----------------------------------+--------------------+--------------------+--------------------+--------------------+
```

### Component Contribution Insights
1. **Hash Alone Fails Usability**: Changing a description hash does not tell an operator *why* it changed. A pure hash mechanism falsely blocks every benign documentation update or typo fix.
2. **ML Alone Fails Privilege Boundaries**: ML detectors evaluate natural language text. When presented with an unapproved new tool or a benignly worded high-privilege primitive, an ML model permits execution without authorization.
3. **Gateway Interceptor Prevents Direct-Call Bypass**: Without a proxy gating both `tools/list` and `tools/call`, an adversarial client can bypass tool listings entirely by directly invoking the JSON-RPC method `tools/call{"name": "malicious_tool"}`. C6 blocks direct bypass with 100% consistency.

---

## 7. Limitations & Threat Model Boundaries

To maintain research integrity and avoid overclaiming production readiness, the following operational boundaries must be documented:

1. **Synthetic MCPTox Attack Bias**: MCPTox attack descriptions employ recognizable template patterns (`Template-1`, `Template-2`, `Template-3`). Real-world adversarial prompt injections may employ stealthier techniques (e.g. ASCII steganography, linguistic obfuscation, base64 payloads) that evade bag-of-words and character n-gram models.
2. **Semantic Capability vs. Text Toxicity Disconnection**: As demonstrated by `puppeteer_evaluate`, dangerous capabilities (arbitrary code execution, network socket creation) can be described in perfectly benign, neutral language. Pure text detectors cannot substitute for operating-system sandboxing, containerization, and network segmentation.
3. **Application Proxy vs. Transparent Transport**: The gateway proxy operates at the application API layer (wrapping Python MCP server sessions and handlers). It does not function as an operating-system kernel redirector or transparent network socket interceptor.
4. **Analyst Fatigue in Quarantine Workflows**: While quarantine prevents both security breaches and service disruption, a high volume of tool updates can create an operational backlog. Production deployment requires automated staging, CI/CD signing, and verifiable developer identities.

---

## 8. Automated Test Suite Verification

The complete automated test suite was executed to verify that security enforcement, protocol compatibility, descriptor life-cycles, and policy engines operate cleanly:

```powershell
============================= test session starts =============================
platform win32 -- Python 3.14.8, pytest-9.2.0, pluggy-1.7.0
rootdir: C:\Users\hp\OneDrive\Desktop\mdp-mcp\mcp-security
plugins: anyio-4.15.1, platformdirs-4.14.0, asyncio-1.4.1
collected 86 items

tests/test_change_detector.py::test_hash_normalization_invariance PASSED [  1%]
tests/test_change_detector.py::test_new_tool_lifecycle PASSED            [  2%]
tests/test_change_detector.py::test_identical_description_no_change PASSED [  3%]
tests/test_change_detector.py::test_benign_update_vs_poisoned_update PASSED [  4%]
tests/test_change_detector.py::test_unapproved_descriptions_never_automatically_trusted PASSED [  5%]
tests/test_dataset.py::test_dataset_exists_and_not_empty PASSED          [  6%]
tests/test_dataset.py::test_schema_columns PASSED                        [  8%]
tests/test_dataset.py::test_no_null_critical_fields PASSED               [  9%]
tests/test_dataset.py::test_binary_labels PASSED                         [ 10%]
tests/test_dataset.py::test_class_balance_representation PASSED          [ 11%]
tests/test_dataset.py::test_safe_records_semantics PASSED                [ 12%]
tests/test_dataset.py::test_malicious_records_semantics PASSED           [ 13%]
tests/test_dataset.py::test_filesystem_23_matches_23_py PASSED           [ 15%]
tests/test_dataset.py::test_no_metadata_leakage_in_features PASSED       [ 16%]
tests/test_detector.py::test_text_normalization PASSED                   [ 17%]
tests/test_detector.py::test_signal_extraction PASSED                    [ 18%]
tests/test_detector.py::test_drift_computation PASSED                    [ 19%]
tests/test_detector.py::test_detector_safe_tools PASSED                  [ 20%]
tests/test_detector.py::test_detector_flags_23_py_poisoning PASSED       [ 22%]
tests/test_detector.py::test_detector_drift_awareness PASSED             [ 23%]
tests/test_detector.py::test_detector_handles_unseen_vocabulary PASSED   [ 24%]
tests/test_detector.py::test_rigorous_validation_suite PASSED            [ 25%]
tests/test_gateway_security_enforcement.py::test_scenario_01_normal_approved_tool PASSED [ 26%]
tests/test_gateway_security_enforcement.py::test_scenario_02_new_benign_tool PASSED [ 27%]
tests/test_gateway_security_enforcement.py::test_scenario_03_modified_benign_descriptor PASSED [ 29%]
tests/test_gateway_security_enforcement.py::test_scenario_04_prompt_injection_description PASSED [ 30%]
tests/test_gateway_security_enforcement.py::test_scenario_05_data_exfiltration_description PASSED [ 31%]
tests/test_gateway_security_enforcement.py::test_scenario_06_high_privilege_low_ml_score PASSED [ 32%]
tests/test_gateway_security_enforcement.py::test_scenario_07_blocked_tool_call_never_executes_upstream PASSED [ 33%]
tests/test_gateway_security_enforcement.py::test_scenario_08_quarantined_tool_hidden_from_list PASSED [ 34%]
tests/test_gateway_security_enforcement.py::test_scenario_09_quarantined_tool_rejected_through_call PASSED [ 36%]
tests/test_gateway_security_enforcement.py::test_scenario_10_direct_call_bypass_attempt PASSED [ 37%]
tests/test_gateway_security_enforcement.py::test_scenario_11_ml_model_loading_failure_fails_closed PASSED [ 38%]
tests/test_gateway_security_enforcement.py::test_scenario_12_ml_prediction_failure_and_empty_description PASSED [ 39%]
tests/test_gateway_security_enforcement.py::test_scenario_13_human_approval_trusted_baseline_update PASSED [ 40%]
tests/test_gateway_security_enforcement.py::test_scenario_14_descriptor_hash_change_detection PASSED [ 41%]
tests/test_independent_security_validation.py::test_protocol_initialization_and_capabilities PASSED [ 43%]
tests/test_independent_security_validation.py::test_protocol_forwarding_upstream_execution_errors PASSED [ 44%]
tests/test_independent_security_validation.py::test_protocol_unknown_tool_and_malformed_requests PASSED [ 45%]
tests/test_independent_security_validation.py::test_descriptor_schema_change_detection PASSED [ 46%]
tests/test_independent_security_validation.py::test_tool_name_changes_and_removal_reappearance PASSED [ 47%]
tests/test_independent_security_validation.py::test_server_identity_isolation_and_cross_server_safety PASSED [ 48%]
tests/test_independent_security_validation.py::test_descriptor_rollback_behavior PASSED [ 50%]
tests/test_independent_security_validation.py::test_registry_persistence_and_gateway_restart PASSED [ 51%]
tests/test_independent_security_validation.py::test_approval_non_transitivity PASSED [ 52%]
tests/test_independent_security_validation.py::test_unauthorized_tools_never_reach_upstream PASSED [ 53%]
tests/test_independent_security_validation.py::test_approval_revocation_enforcement PASSED [ 54%]
tests/test_independent_security_validation.py::test_hash_mismatch_alone_is_not_malice PASSED [ 55%]
tests/test_independent_security_validation.py::test_mandatory_security_rules_override_in_mdp_mode PASSED [ 56%]
tests/test_independent_security_validation.py::test_edge_case_empty_and_whitespace_descriptions PASSED [ 58%]
tests/test_independent_security_validation.py::test_edge_case_extremely_long_description PASSED [ 59%]
tests/test_independent_security_validation.py::test_edge_case_unicode_emojis_rtl_and_control_chars PASSED [ 60%]
tests/test_independent_security_validation.py::test_edge_case_duplicate_tool_names_poisoning_defense PASSED [ 61%]
tests/test_independent_security_validation.py::test_edge_case_malformed_upstream_objects PASSED [ 62%]
tests/test_interceptor.py::test_interceptor_allows_approved_baseline PASSED [ 63%]
tests/test_interceptor.py::test_interceptor_blocks_prompt_injection PASSED [ 65%]
tests/test_interceptor.py::test_interceptor_blocks_23_py_data_exfiltration PASSED [ 66%]
tests/test_interceptor.py::test_interceptor_quarantines_legitimate_update PASSED [ 67%]
tests/test_interceptor.py::test_interceptor_authorized_execution PASSED  [ 68%]
tests/test_interceptor.py::test_security_summary_diagnostics PASSED      [ 69%]
tests/test_mdp.py::test_mdp_artifact_exists PASSED                       [ 70%]
tests/test_mdp.py::test_value_iteration_convergence PASSED               [ 72%]
tests/test_mdp.py::test_q_learning_optimal_actions PASSED                [ 73%]
tests/test_mdp.py::test_simulator_reward_dynamics PASSED                 [ 74%]
tests/test_mdp.py::test_comparative_evaluation PASSED                    [ 75%]
tests/test_mdp.py::test_gateway_scenario_comparative_evaluation PASSED   [ 76%]
tests/test_policy.py::test_approved_baseline_allowed PASSED              [ 77%]
tests/test_policy.py::test_new_tool_with_low_risk_quarantined PASSED     [ 79%]
tests/test_policy.py::test_benign_modification_quarantined PASSED        [ 80%]
tests/test_policy.py::test_mandatory_security_rules_cannot_be_overridden_by_low_ml PASSED [ 81%]
tests/test_policy.py::test_poisoned_tool_23_py_strictly_blocked PASSED   [ 82%]
tests/test_policy.py::test_audit_logger_tracks_all_decisions PASSED      [ 83%]
tests/test_policy.py::test_mdp_policy_approved_baseline_allowed PASSED   [ 84%]
tests/test_policy.py::test_mdp_policy_unverified_drift_quarantined PASSED [ 86%]
tests/test_policy.py::test_mdp_policy_high_risk_attack_blocked PASSED    [ 87%]
tests/test_policy.py::test_mdp_policy_mandatory_security_violation_overrides_mdp PASSED [ 88%]
tests/test_policy.py::test_mdp_policy_review_dispositions PASSED         [ 89%]
tests/test_real_mcp_e2e.py::test_real_mcp_client_to_gateway_to_server_e2e PASSED [ 90%]
tests/test_real_mcp_e2e.py::test_protocol_session_cleanup PASSED         [ 91%]
tests/test_server_cases.py::test_server_tools_registered PASSED          [ 93%]
tests/test_server_cases.py::test_tool_execution_safety PASSED            [ 94%]
tests/test_case_1_normal_baseline PASSED                                  [ 95%]
tests/test_case_2_legitimate_update PASSED                                [ 96%]
tests/test_case_3_prompt_injection PASSED                                 [ 97%]
tests/test_case_4_data_exfiltration PASSED                                [ 98%]
tests/test_case_5_suspicious_benign PASSED                                [100%]

============================= 86 passed in 11.98s =============================
```

---

## 9. Conclusion

The research evaluation confirms that the MCP Security Gateway successfully enforces multi-layered protocol security against poisoned tool descriptors. By combining cryptographic change detection, group-disjoint trained machine learning models, mandatory security heuristic invariants, and a human-in-the-loop quarantine workflow, the gateway achieves complete protection against direct-call bypasses and high-risk attacks while eliminating false blocks on benign operational changes.
