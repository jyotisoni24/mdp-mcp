# Final Independent Verification of MCP Security Gateway Research Evaluation

**Audit Date**: 2026-11-02  
**Auditor**: Antigravity Independent Verification Engine  
**Target Repository**: `mdp-mcp/mcp-security`  
**Evaluated Artifacts**:
- Dataset: [`data/expanded_experimental_dataset.csv`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_experimental_dataset.csv)
- OOD Dataset: [`data/expanded_ood_dataset.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_ood_dataset.json)
- Model: [`models/expanded_detector_model.joblib`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/models/expanded_detector_model.joblib)
- Vectorizer: [`models/expanded_vectorizer.joblib`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/models/expanded_vectorizer.joblib)
- Machine-Readable Audit Data: [`training/final_verified_results.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/final_verified_results.json)
- Record-Level Discrepancy Matrix: [`training/final_prediction_discrepancies.csv`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/final_prediction_discrepancies.csv)

---

## Executive Summary & Audit Verdict

### Final Verdict: **VERIFIED WITH LIMITATIONS**

> [!CAUTION]
> **Production Readiness Statement**: This codebase is an **experimental academic prototype** designed for rigorous, reproducible research evaluation of tool-description security enforcement. It is **NOT production-ready**. Although it provides strong detection on synthetic MCPTox prompt injections and demonstrates robust protocol mediation, it exhibits fundamental limitations: a small benign sample size ($N=53$), distribution shift vulnerabilities against zero-day adversarial jailbreaks, an application-layer proxy boundary that cannot replace container isolation, and substantial operational review overhead under strict static policy.

The research evaluation methodology, statistical metrics, timing boundaries, ablation configurations, and test suite reproducibility have undergone an exhaustive independent audit. All claims, metrics, and code implementations have been empirically audited, reconciled, and documented below.

---

## 1. Metric Discrepancy Reconciliation

### Root Cause Analysis of Reported Metrics
In the preceding conversation turn, an apparent discrepancy was observed where the assistant's Markdown chat summary reported:
- Cross-Validation at $\tau = 0.50$: Reported as $1\text{ FP} / 9\text{ FN}$ ($\text{FPR} = 1/53$, $\text{FNR} = 9/485$)
- Held-out Test at $\tau = 0.50$: Reported as $0\text{ FP} / 1\text{ FN}$ ($\text{FPR} = 0/27$, $\text{FNR} = 1/106$)

Whereas prior reports had documented:
- Cross-Validation at $\tau = 0.50$: $7\text{ FP} / 2\text{ FN}$ ($\text{FPR} = 7/53$, $\text{FNR} = 2/485$)
- Held-out Test at $\tau = 0.50$: $5\text{ FP} / 1\text{ FN}$ ($\text{FPR} = 5/27$, $\text{FNR} = 1/106$)

### Empirical Verification
A clean-process verification script was executed to extract out-of-fold and held-out predictions directly from the underlying model artifacts and evaluation pipelines:
1. **Artifact Inspection**: Both [`training/research_evaluation_results.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/research_evaluation_results.json), [`training/corrected_research_evaluation_results.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/corrected_research_evaluation_results.json), and [`models/expanded_training_report.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/models/expanded_training_report.json) were inspected. All three persistent files contain **identical underlying confusion matrices**:
   - CV $\tau = 0.50$: $\text{TN}=46, \text{FP}=7, \text{FN}=2, \text{TP}=483$
   - Held-out Test $\tau = 0.50$: $\text{TN}=22, \text{FP}=5, \text{FN}=1, \text{TP}=105$
   - CV $\tau = 0.70$: $\text{TN}=53, \text{FP}=0, \text{FN}=14, \text{TP}=471$
   - Held-out Test $\tau = 0.70$: $\text{TN}=27, \text{FP}=0, \text{FN}=2, \text{TP}=104$
2. **Record-Level Differences**: Generated [`training/final_prediction_discrepancies.csv`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/final_prediction_discrepancies.csv) across all $538$ records. The column `r1_vs_r2_discrepancy` equals **$0$ for every single record**. There are **zero** prediction discrepancies between evaluation scripts.
3. **Conclusion**: The numbers $1\text{ FP} / 9\text{ FN}$ and $0\text{ FP} / 1\text{ FN}$ were **transcription errors in the chat markdown text** of the previous turn; the actual codebase, model weights, dataset splits, and saved JSON evaluation reports have always consistently contained $7\text{ FP} / 2\text{ FN}$ and $5\text{ FP} / 1\text{ FN}$.

### Detailed Record-Level Error Breakdown

#### Cross-Validation Errors at $\tau = 0.50$ ($N=538$)
- **7 False Positives** (Benign tools flagged as malicious):
  1. `git:git_status` (Fold 3, $p = 0.5962$) — Flagged due to Git status/inspection vocabulary overlap with MCPTox git targets.
  2. `git:git_log` (Fold 3, $p = 0.5205$) — Flagged due to commit log phrasing.
  3. `brave-search:brave_web_search` (Fold 1, $p = 0.6037$) — Flagged due to search/query parameters.
  4. `brave-search:brave_local_search` (Fold 1, $p = 0.6190$) — Flagged due to location/search keywords.
  5. `puppeteer:puppeteer_click` (Fold 4, $p = 0.5269$) — Browser automation interaction verbs.
  6. `puppeteer:puppeteer_select` (Fold 4, $p = 0.5464$) — Browser automation interaction verbs.
  7. `puppeteer:puppeteer_hover` (Fold 4, $p = 0.5424$) — Browser automation interaction verbs.
- **2 False Negatives** (Malicious tools missed by ML):
  1. `gitlab:common_validation` (Fold 2, $p = 0.4057$) — Mild phrasing resembling benign validation helper.
  2. `email:count_messages` (Fold 0, $p = 0.2646$) — Sparse text resembling routine count utility.

#### Cross-Validation Errors at $\tau = 0.70$ ($N=538$)
- **0 False Positives**: All 7 benign tools that scored between $0.52$ and $0.62$ are correctly categorized as benign ($p < 0.70$).
- **14 False Negatives**: $12$ tools from the `email` family, $1$ from `gitlab` (`common_validation`, $p=0.4057$), and $1$ from `puppeteer` (`get_current_time`, $p=0.6968$).

#### Held-Out Test Errors at $\tau = 0.50$ ($N=133$)
- **5 False Positives**: `git:git_status` ($p=0.6785$), `git:git_log` ($p=0.6123$), `puppeteer:puppeteer_select` ($p=0.5348$), `slack:slack_add_reaction` ($p=0.5200$), `gitlab:fork_repository` ($p=0.5304$).
- **1 False Negative**: `gitlab:common_validation` ($p=0.4376$).

#### Held-Out Test Errors at $\tau = 0.70$ ($N=133$)
- **0 False Positives**: Zero false positives observed across all $27$ benign held-out tools.
- **2 False Negatives**: `puppeteer:get_current_time` ($p=0.6589$) and `gitlab:common_validation` ($p=0.4376$).

---

## 2. Confidence Interval Audit

### Mathematical Degeneracy of Cluster Bootstrap on Zero-Count Events
An inspection of `compute_cluster_bootstrap_ci` in [`training/run_corrected_research_evaluation.py`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/run_corrected_research_evaluation.py) revealed why the cluster bootstrap reports $[0.0\%, 0.0\%]$ for FPR at $\tau = 0.70$:
1. The cluster bootstrap resamples canonical server groups with replacement from the empirical dataset $\hat{F}_n$.
2. In the observed sample at $\tau = 0.70$, there are **zero** false positive predictions across all benign samples ($FP = 0$).
3. Because every benign tool description in the dataset has $\hat{y}_i = 0$, every bootstrap resample—regardless of which clusters are selected—inevitably contains $FP_b = 0$.
4. Consequently, $FPR_b = 0 / (0 + TN_b) = 0.0$ for all $1{,}000$ bootstrap iterations. The 2.5th and 97.5th percentiles collapse to $[0.0\%, 0.0\%]$.
5. **Critical Statistical Principle**: Resampling zero occurrences can never generate non-zero occurrences. Non-parametric bootstrap (whether sample-level or cluster-level) cannot estimate uncertainty for zero-numerator proportions.

### Primary Uncertainty Standard: Exact Clopper-Pearson Intervals
To prevent misleading claims of zero uncertainty, **Exact Clopper-Pearson Binomial Confidence Intervals** (`scipy.stats.binomtest`) are retained as the authoritative uncertainty bounds:

| Evaluation Partition | Threshold | Metric | Observed Count | Exact Rate | Exact Clopper-Pearson 95% CI | Non-Parametric Bootstrap CI |
|---|---|---|---|---|---|---|
| **5-Fold CV ($N=538$)** | $\tau = 0.70$ | **FPR** | $0 / 53$ | **$0.00\%$** | **$[0.00\%, 6.72\%]$** | $[0.00\%, 0.00\%]$ *(Degenerate)* |
| **5-Fold CV ($N=538$)** | $\tau = 0.70$ | **FNR** | $14 / 485$ | **$2.89\%$** | **$[1.59\%, 4.79\%]$** | $[0.59\%, 5.86\%]$ |
| **5-Fold CV ($N=538$)** | $\tau = 0.70$ | **Precision** | $471 / 471$ | **$100.00\%$** | **$[99.22\%, 100.00\%]$** | $[100.00\%, 100.00\%]$ |
| **5-Fold CV ($N=538$)** | $\tau = 0.70$ | **Recall** | $471 / 485$ | **$97.11\%$** | **$[95.21\%, 98.41\%]$** | $[94.14\%, 99.41\%]$ |
| **Held-Out Test ($N=133$)** | $\tau = 0.70$ | **FPR** | $0 / 27$ | **$0.00\%$** | **$[0.00\%, 12.77\%]$** | $[0.00\%, 0.00\%]$ *(Degenerate)* |
| **Held-Out Test ($N=133$)** | $\tau = 0.70$ | **FNR** | $2 / 106$ | **$1.89\%$** | **$[0.23\%, 6.65\%]$** | $[0.00\%, 5.88\%]$ |
| **Held-Out Test ($N=133$)** | $\tau = 0.70$ | **Precision** | $104 / 104$ | **$100.00\%$** | **$[96.52\%, 100.00\%]$** | $[100.00\%, 100.00\%]$ |
| **Held-Out Test ($N=133$)** | $\tau = 0.70$ | **Recall** | $104 / 106$ | **$98.11\%$** | **$[93.35\%, 99.77\%]$** | $[94.12\%, 100.00\%]$ |
| **5-Fold CV ($N=538$)** | $\tau = 0.50$ | **FPR** | $7 / 53$ | **$13.21\%$** | **$[5.48\%, 25.34\%]$** | $[0.00\%, 29.42\%]$ |
| **5-Fold CV ($N=538$)** | $\tau = 0.50$ | **FNR** | $2 / 485$ | **$0.41\%$** | **$[0.05\%, 1.48\%]$** | $[0.00\%, 0.98\%]$ |
| **Held-Out Test ($N=133$)** | $\tau = 0.50$ | **FPR** | $5 / 27$ | **$18.52\%$** | **$[6.30\%, 38.08\%]$** | $[11.11\%, 40.00\%]$ |
| **Held-Out Test ($N=133$)** | $\tau = 0.50$ | **FNR** | $1 / 106$ | **$0.94\%$** | **$[0.02\%, 5.14\%]$** | $[0.00\%, 3.28\%]$ |

> [!IMPORTANT]
> **Zero Observed Errors $\neq$ Zero Population Error**: Observing $0$ false positives out of $27$ benign tools on the independent test set guarantees only that the true FPR is under **$12.77\%$** with 95% confidence. Claims of near-zero false alarms across open-source MCP repositories cannot be made without substantially larger benign test sets.

### Cluster Sampling Dynamics
- **Sampling Units**: Resampling is performed on `canonical_group` ($50$ clusters in CV, $11$ clusters in held-out test).
- **Mixed-Class Clusters**: There are $8$ mixed-class clusters (`filesystem`, `git`, `github`, `gitlab`, `memory`, `puppeteer`, `slack`, `sqlite`) that contain both authentic benign tools and synthetic malicious tools. When sampled, both classes from that server family enter the replicate simultaneously, accurately preserving intra-server correlation.
- **Single-Class Replicate Handling**: In the held-out test split ($11$ clusters: $3$ benign, $8$ malicious), $7$ of $1{,}000$ bootstrap iterations sampled exclusively malicious clusters ($\text{len}(\text{unique}(y)) < 2$). These $7$ degenerate iterations were explicitly skipped, leaving $993$ valid multi-class replicates.

---

## 3. Latency Verification

### Resolving the ~11.8 ms vs. 5.226 ms Observation
The initial prototype observation of $\sim 11.8\text{ ms}$ protocol call latency was reconciled against the corrected $5.226\text{ ms}$ (and newly measured $4.246\text{ ms}$) benchmark:
1. **Unwarmed Stream & Exception Generation**: The initial scratch test ran only $20$ iterations without pre-warming the AnyIO task loop, and called `calculate_total` with invalid arguments `{"a": 10, "b": 20}` instead of `{"subtotal": 100.0, "tax_rate": 0.05}`. This triggered Python `ToolError` exception construction, traceback assembly, and JSON error serialization on every iteration.
2. **Controlled Protocol Measurement**: Under clean, warmed conditions ($20$ warmup iterations, $100$ measurement iterations) over AnyIO memory streams with valid tool arguments, protocol call latency measures **Mean: $4.246\text{ ms}$, Median: $3.886\text{ ms}$, P95: $6.826\text{ ms}$, P99: $8.579\text{ ms}$**.

### Dissection of Granular Timing Boundaries
Timing boundaries were independently benchmarked to verify where latency is actually incurred:

```
+-----------------------------------------------------------------------------------------+
|                                    GATEWAY TIMING PROFILE                                |
+-----------------------------------------------------------------------------------------+
|  1. Pure ML Inference (TF-IDF + LogisticRegression.predict_proba):                      |
|     Mean: 3.410 ms | Median: 3.017 ms | P95: 5.469 ms | P99: 10.024 ms (N=200)          |
|                                                                                         |
|  2. Pure Policy Decision Engine (PolicyEngine.evaluate):                                |
|     Mean: 0.188 ms | Median: 0.188 ms | P95: 0.238 ms | P99: 0.354 ms (N=200)            |
|                                                                                         |
|  3. In-Memory Proxy Tool Listing (MCPGatewayProxy.list_tools):                          |
|     Mean: 1.534 ms | Median: 1.505 ms | P95: 2.002 ms | P99: 2.846 ms (N=200)            |
|                                                                                         |
|  4. Isolated Tool-Call Authorization Check (MCPGatewayInterceptor.authorize_tool_call): |
|     Mean: 0.0007 ms | Median: 0.0007 ms | P95: 0.0008 ms | P99: 0.0016 ms (N=200)       |
|                                                                                         |
|  5. Full MCP Protocol List Round-Trip (ClientSession.list_tools over AnyIO streams):    |
|     Mean: 1.557 ms | Median: 1.298 ms | P95: 3.054 ms | P99: 3.813 ms (N=100)           |
|                                                                                         |
|  6. Full MCP Protocol Call Round-Trip (ClientSession.call_tool + Upstream Execution):   |
|     Mean: 4.246 ms | Median: 3.886 ms | P95: 6.826 ms | P99: 8.579 ms (N=100)           |
+-----------------------------------------------------------------------------------------+
```

### Critical Latency Insight
- **ML inference ($3.41\text{ ms}$) is NOT executed during `tools/call`**: When a client calls an approved tool, the gateway performs an in-memory dictionary lookup [`authorize_tool_call`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/gateway/interceptor.py#L182-L210) taking less than $1$ microsecond ($0.0007\text{ ms}$).
- **The $4.2\text{ ms}$ round-trip consists of**: Client JSON-RPC encoding $\rightarrow$ Stream context switch $\rightarrow$ Gateway parsing $\rightarrow$ Registry lookup ($0.0007\text{ ms}$) $\rightarrow$ Stream forward $\rightarrow$ Upstream server execution ($<0.1\text{ ms}$) $\rightarrow$ Upstream JSON-RPC response $\rightarrow$ Stream context switch $\rightarrow$ Gateway forward $\rightarrow$ Client parsing.

---

## 4. Executable Component Ablation Audit

### Concrete Defect Identified in Previous Ablation Code
In `run_corrected_research_evaluation.py`, lines 580–625:
For configurations C1–C5, in Scenario S4 (Direct-Call Bypass), the script contained:
```python
if sc["is_direct_bypass"]:
    c1_decision, c1_upstream = "BYPASS_SUCCEEDED", 1
```
This was a **manual assignment of outcome**, not an executed protocol dispatch. C1–C5 were written as standalone classes (`HashOnlyEnforcer`, `MLOnlyEnforcer`, etc.) implementing only `def evaluate(tool_name, server_name, description)`. They lacked protocol proxy handlers and had no implementation of `call_tool`.

### Audit Correction
Because MCP `tools/call` payloads contain only `{"name": "...", "arguments": {...}}` and do not include the tool's description, standalone description filters (C1–C5) **cannot intercept or evaluate runtime tool-call protocol requests**.
In accordance with research standards:
- For Scenario S4, configurations C1 through C5 are formally designated **`NOT_EVALUATED_STANDALONE`** rather than claiming an empirical execution count.
- Configuration C6 ([`MCPGatewayProxy`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/gateway/interceptor.py#L42-L130)) was empirically executed through real protocol calls and verified to throw [`ToolExecutionDeniedError`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/gateway/interceptor.py#L27-L40), maintaining an upstream execution count of exactly **$0$**.

### Audited Ablation Matrix

| Configuration ID | Security Layer Composition | S1: Known Malicious | S2: Benign Rewrite | S3: New Unseen Tool | S4: Direct-Call Bypass |
|---|---|---|---|---|---|
| **C1** | SHA-256 Hash Only | `BLOCK` ($0$ calls) | `FALSE_BLOCK` ($0$ calls) | `FALSE_BLOCK` ($0$ calls) | `NOT_EVALUATED_STANDALONE` |
| **C2** | Standalone ML Detector Only | `BLOCK` ($0$ calls) | `ALLOW` ($1$ call, unverified) | `ALLOW` ($1$ call, unverified) | `NOT_EVALUATED_STANDALONE` |
| **C3** | Heuristic Rules Only | `ALLOW` ($1$ call, breach) | `ALLOW` ($1$ call, unverified) | `ALLOW` ($1$ call, unverified) | `NOT_EVALUATED_STANDALONE` |
| **C4** | Hash + ML Detector | `BLOCK` ($0$ calls) | `FALSE_BLOCK` ($0$ calls) | `FALSE_BLOCK` ($0$ calls) | `NOT_EVALUATED_STANDALONE` |
| **C5** | Hash + ML + Rules (No Proxy) | `BLOCK` ($0$ calls) | `FALSE_BLOCK` ($0$ calls) | `FALSE_BLOCK` ($0$ calls) | `NOT_EVALUATED_STANDALONE` |
| **C6** | **Full MCP Gateway Proxy** | **`BLOCK` ($0$ calls)** | **`QUARANTINE` ($0$ calls)** | **`QUARANTINE` ($0$ calls)** | **`BLOCKED` ($0$ calls, Empirically Verified)** |

---

## 5. MDP Simulation Reality Check

A multi-seed simulation was conducted across 5 random seeds ($42, 123, 456, 789, 1000$) simulating $2{,}500$ operational episodes:

| Performance Metric | Static Threshold Policy | MDP Dynamic Policy | Empirical Delta | Superiority Assessment |
|---|---|---|---|---|
| **Mean Cumulative Reward** | **$7.05 \pm 0.18$** | $7.00 \pm 0.25$ | $+0.05$ | **Static Threshold** |
| **Total Security Breaches** | **$8 / 2{,}500$ ($0.32\%$)** | $35 / 2{,}500$ ($1.40\%$) | **$-27$ breaches** | **Static Threshold ($4.38\times$ safer)** |
| **Quarantine Rate** | $30.84\%$ | $24.72\%$ | $+6.12\%$ | MDP (lower human review) |
| **Approval Rate** | $64.84\%$ | $70.88\%$ | $-6.04\%$ | MDP (higher throughput) |
| **Direct Block Rate** | $4.32\%$ | $4.40\%$ | $-0.08\%$ | Comparable |

### Why the Static Policy Outperformed the MDP
The MDP optimizes a mathematical reward function where quarantine incurs an administrative penalty ($-2.0$). In doing so, the MDP policy learns to allow marginal low-risk unverified drift (`LOW_RISK_UNVERIFIED`). However, because roughly $5\%$ of unverified updates in the simulator harbor latent attacks, directly allowing unverified tools produced **$35$ security breaches vs. only $8$ under the static policy**. In security-critical environments, conservative quarantine is objectively superior.

---

## 6. Reproducibility & Environment Audit

### Cryptographic Artifact Hashes (SHA-256)
- [`data/expanded_experimental_dataset.csv`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_experimental_dataset.csv): `22d61291d917e4d25187b0bae8e7768f35f1e897d47ba863c328231777c5f2f8`
- [`data/expanded_ood_dataset.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_ood_dataset.json): `c332e863976a377951894ad4051cdacced9f1175a471895236e829af906a76c6`
- [`models/expanded_detector_model.joblib`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/models/expanded_detector_model.joblib): `3fb96f90c310527fa52d1e38c165886f86626b24f3d9d2fdf81bbc164c1f9946`
- [`models/expanded_vectorizer.joblib`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/models/expanded_vectorizer.joblib): `9327fe28c46969d8e7a0590c15276ba4292dd68a78335af3612ff393ccf344b0`
- [`models/expanded_training_report.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/models/expanded_training_report.json): `ebaa3f7a9d2d49e5b5048cfcad12523b16a73e19f25464e01877af2ee8b90f5f`
- [`training/run_research_evaluation.py`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/run_research_evaluation.py): `bce338531de5268837d6935ad494aa3eb5ad640f6fb3979c858b17bd117f226a`
- [`training/run_corrected_research_evaluation.py`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/run_corrected_research_evaluation.py): `6593d261b5f01ad871952ec9ef32a4ae4a8544b417db2a7fe929e9ec319243f4`
- [`training/final_prediction_discrepancies.csv`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/final_prediction_discrepancies.csv): `e15a77cfbc98aa70eb31b34fa3227bda297dd24ea152b14641957c4c1a5d6fe5`
- [`training/final_verified_results.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/final_verified_results.json): `f05021e0952d7ee0c38fc7183eec1e07b820a4066cbb45e35bbdb4b486a4ea11`

### Execution Environment
- **Operating System**: Microsoft Windows 11 Pro [Version 10.0.26100.3037]
- **Python**: 3.14.8
- **Core Dependencies**: pytest 9.2.0, scipy 1.18.1, scikit-learn 1.6.1, anyio 4.15.1, mcp SDK 1.4.1
- **Random Seeds Fixed**: 42 for split/model fit, 42 for cluster bootstrap, [42, 123, 456, 789, 1000] for MDP simulation.

### Automated Test Suite Execution
The entire test suite was executed from a clean process:
```text
============================= test session starts =============================
platform win32 -- Python 3.14.8, pytest-9.2.0, pluggy-1.7.0 -- C:\Python314\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\hp\OneDrive\Desktop\mdp-mcp\mcp-security
plugins: anyio-4.15.1, platformdirs-4.14.0, asyncio-1.4.1
asyncio: mode=Mode.STRICT, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 86 items

tests/test_change_detector.py .....                                      [  5%]
tests/test_dataset.py .........                                          [ 16%]
tests/test_detector.py ........                                          [ 25%]
tests/test_gateway_security_enforcement.py ..............                [ 41%]
tests/test_independent_security_validation.py ..................         [ 62%]
tests/test_interceptor.py ......                                         [ 69%]
tests/test_mdp.py ......                                                 [ 76%]
tests/test_policy.py ...........                                         [ 89%]
tests/test_real_mcp_e2e.py ..                                            [ 91%]
tests/test_server_cases.py .......                                       [100%]

============================= 86 passed in 12.06s =============================
```

---

## 7. Concrete Limitations Documented

1. **Small Benign Sample Size ($N=53$)**:
   Although $53$ benign tools were carefully extracted and manually audited across authentic open-source MCP repositories, this represents an order of magnitude fewer samples than the $485$ malicious samples. Observing $0$ false positives at $\tau=0.70$ yields an exact 95% Clopper-Pearson upper bound of **$6.72\%$** (CV) and **$12.77\%$** (Test). Generalization claims to arbitrary open-source servers cannot be made.
2. **Distribution Shift Vulnerabilities**:
   The ML detector is a linear TF-IDF n-gram classifier. While highly effective at identifying prompt-injection keywords, administrative override verbs, and exfiltration directives present in MCPTox, it remains vulnerable to semantic paraphrasing, multilingual prompts, or subtle dual-use capabilities (e.g. `puppeteer_evaluate`) that do not contain overt toxic wording.
3. **Application-Layer Proxy Boundary**:
   The gateway inspects and filters MCP protocol JSON-RPC messages. It does not enforce kernel-level isolation, OS file sandboxing, or outbound network firewalling. If an approved tool body contains a memory corruption exploit or backdoor, the gateway cannot prevent internal payload execution.
4. **Human Review Operational Overhead**:
   Under the recommended static threshold policy, any tool modification or new registration must be held in quarantine. In real developer environments with rapid tool updates, quarantine fatigue could lead administrators to routinely approve uninspected tools.
