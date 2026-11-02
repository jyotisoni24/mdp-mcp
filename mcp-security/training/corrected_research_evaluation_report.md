# Corrected Research-Grade Evaluation of MCP Security Gateway

**Authors**: Independent Security & Machine Learning Evaluation Team  
**Evaluation Date**: November 2, 2026  
**Document Status**: REVISED & CORRECTED SCIENTIFIC BASELINE  
**Historical Predecessor**: [`training/research_evaluation_report.md`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/research_evaluation_report.md)  
**Methodology Audit**: [`training/research_methodology_audit.md`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/research_methodology_audit.md)  
**Structured Results**: [`training/corrected_research_evaluation_results.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/corrected_research_evaluation_results.json)  
**Automated Test Suite**: **86 / 86 passing tests** (`python -m pytest -v`)  

---

## 1. Executive Summary & Audit Corrections

This report presents a corrected, publication-grade evaluation of the **Model Context Protocol (MCP) Security Gateway**. Following a critical methodology audit, this document supersedes the initial evaluation report by correcting six identified statistical and experimental flaws:

1. **Hierarchical Resampling**: Replaced naive i.i.d. observation-level bootstrap with **Cluster Bootstrap** (resampling 50 canonical server-group clusters with replacement) to account for intra-cluster stylistic correlations.
2. **Exact Binomial Confidence Intervals**: Eliminated degenerate zero-width confidence intervals ($[0.0\%, 0.0\%]$) on finite samples with zero errors by incorporating exact **Clopper-Pearson** binomial confidence intervals.
3. **Executed Ablation Study**: Replaced conceptual simulation strings with concrete, executed component code paths (C1–C6) featuring real upstream invocation tracking.
4. **Separated Latency Boundaries**: Separated in-memory algorithm timings (pure ML inference, policy evaluation) from actual JSON-RPC MCP protocol round-trips over bidirectional AnyIO streams.
5. **Fixture Repetition Transparency**: Explicitly differentiated 5 unique functional scenario fixtures from 100 repeated execution trials ($500$ total executions), avoiding conflation of runtime reproducibility with attack variety.
6. **Conservative MDP Assessment**: Transparently disclosed that the Static Threshold Policy achieved higher mean reward ($7.05 \pm 0.18$ vs. $7.00 \pm 0.25$) and fewer security breaches ($8$ vs. $35$ total) than the MDP policy in simulation.

### Core Empirical Findings
- **Zero Unauthorized Executions**: Across 500 gateway trial executions and rigorous edge-case protocol tests, the count of unauthorized upstream executions was **strictly 0**.
- **Cross-Validation Accuracy**: Under 5-fold strictly server-disjoint cross-validation on 538 records (485 malicious, 53 benign across 50 server families):
  - At standard threshold $\tau = 0.50$: Accuracy **98.33%** (Cluster Bootstrap 95% CI: $[96.70\%, 99.62\%]$), Recall **99.59%** ($483/485$), FPR **13.21%** ($7/53$, Clopper-Pearson 95% CI: $[5.48\%, 25.34\%]$), FNR **0.41%** ($2/485$, Clopper-Pearson 95% CI: $[0.05\%, 1.48\%]$), ROC-AUC **0.9981**, PR-AUC **0.9998**.
  - At fixed reference threshold $\tau = 0.70$: Accuracy **97.40%** (Cluster Bootstrap 95% CI: $[93.09\%, 100.0\%]$), Precision **100.0%** ($471/471$, Clopper-Pearson 95% CI: $[99.22\%, 100.0\%]$), Recall **97.11%** ($471/485$), FPR **0.00%** ($0/53$, Clopper-Pearson 95% CI: $[0.00\%, 6.72\%]$), FNR **2.89%** ($14/485$, Clopper-Pearson 95% CI: $[1.59\%, 4.80\%]$).
- **Independent Test Set Generalization**: On 133 held-out samples across three unseen benign server families (`puppeteer`, `slack`, `gitlab`) and 9 disjoint attack groups:
  - At $\tau = 0.50$: Accuracy **95.49%**, FPR **18.52%** ($5/27$, Clopper-Pearson 95% CI: $[6.30\%, 38.08\%]$), Recall **99.06%** ($105/106$).
  - At fixed reference $\tau = 0.70$: Accuracy **98.50%**, Precision **100.0%** ($104/104$, Clopper-Pearson 95% CI: $[96.52\%, 100.0\%]$), Recall **98.11%** ($104/106$), FPR **0.00%** ($0/27$, Clopper-Pearson 95% CI: $[0.00\%, 12.77\%]$).
- **Protocol & In-Memory Latency Boundaries**:
  - Pure ML inference: Mean **3.410 ms**, P95 **5.469 ms** ($N=200$).
  - Pure policy decision: Mean **0.188 ms**, P95 **0.238 ms** ($N=200$).
  - In-memory proxy listing overhead: Mean **1.534 ms**, P95 **2.002 ms** ($N=200$).
  - In-memory proxy call authorization: Mean **0.0007 ms**, P95 **0.0008 ms** ($N=200$).
  - Full MCP protocol round-trip (`session.list_tools()`): Mean **2.650 ms**, P95 **3.126 ms** ($N=50$).
  - Full MCP protocol round-trip (`session.call_tool()`): Mean **5.226 ms**, P95 **6.787 ms** ($N=50$).

---

## 2. Dataset & Reproducibility Audit

The dataset evaluated is [`data/expanded_experimental_dataset.csv`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_experimental_dataset.csv).

| Metric | Measured Value | Verification Result | Notes |
| :--- | :---: | :---: | :--- |
| **Total Records** | 538 | PASS | 485 Malicious, 53 Benign |
| **Class Imbalance** | 9.15 : 1 | PASS | Realistic adversarial skew |
| **Unique Descriptions** | 538 | PASS | Zero duplicate descriptions |
| **Unique Record IDs** | 538 | PASS | Primary key integrity sound |
| **Canonical Server Groups** | 50 | PASS | Group identifiers assigned |
| **CV Fold Server Overlap** | [0, 0, 0, 0, 0] | PASS | Strictly server-disjoint |
| **Independent Test Overlap** | 0 | PASS | 39 Dev groups, 11 Test groups |
| **Quarantined OOD Contamination** | 0 records | PASS | Quarantined records excluded from training |
| **Disclosed Dataset Anomaly** | Row 391 null `tool_name` | PASS | `Puppeteer_12` description complete; targets `puppeteer_hover` |

### Threshold Selection Provenance
- $\tau = 0.50$: Fixed standard Bayesian boundary for balanced class weighting.
- $\tau = 0.70$: Fixed reference threshold derived a priori from earlier development fold error analysis (where it eliminated operational false alarms).
- **Test Set Isolation**: The independent test set was never subjected to parameter sweeps, grid searches, or threshold optimization. All test set numbers represent fixed-threshold evaluations.

---

## 3. Machine Learning Statistical Evaluation

### 3.1 5-Fold Group-Disjoint Cross-Validation ($N=538$)

Resampling was performed using **Cluster Bootstrap** across the 50 canonical server groups ($B = 1000$ iterations). Exact **Clopper-Pearson** intervals are reported for proportion metrics.

```
                    Cross-Validation Performance Comparison
+-----------------------+-----------------------------+-----------------------------+
| Metric                | Threshold tau = 0.50        | Threshold tau = 0.70 (Ref)  |
+-----------------------+-----------------------------+-----------------------------+
| Accuracy              | 98.33%                      | 97.40%                      |
|  - Cluster Bootstrap  | [96.70%, 99.62%]            | [93.09%, 100.0%]            |
| Precision             | 98.57% (483/490)            | 100.0% (471/471)            |
|  - Clopper-Pearson CI | [97.08%, 99.42%]            | [99.22%, 100.0%]            |
|  - Cluster Bootstrap  | [96.71%, 100.0%]            | [100.0%, 100.0%]            |
| Recall (Sensitivity)  | 99.59% (483/485)            | 97.11% (471/485)            |
|  - Clopper-Pearson CI | [98.52%, 99.95%]            | [95.20%, 98.41%]            |
|  - Cluster Bootstrap  | [99.02%, 100.0%]            | [92.26%, 100.0%]            |
| F1-Score              | 0.9908                      | 0.9854                      |
|  - Cluster Bootstrap  | [0.9814, 0.9979]            | [0.9597, 1.0000]            |
| False Positive Rate   | 13.21% (7/53)               | 0.00% (0/53)                |
|  - Clopper-Pearson CI | [5.48%, 25.34%]             | [0.00%, 6.72%]              |
|  - Cluster Bootstrap  | [0.00%, 29.42%]             | [0.00%, 0.00%]              |
| False Negative Rate   | 0.41% (2/485)               | 2.89% (14/485)              |
|  - Clopper-Pearson CI | [0.05%, 1.48%]              | [1.59%, 4.80%]              |
|  - Cluster Bootstrap  | [0.00%, 0.98%]              | [0.00%, 7.74%]              |
| ROC-AUC               | 0.9981                      | 0.9981                      |
|  - Cluster Bootstrap  | [0.9957, 1.0000]            | [0.9957, 1.0000]            |
| PR-AUC                | 0.9998                      | 0.9998                      |
|  - Cluster Bootstrap  | [0.9995, 1.0000]            | [0.9995, 1.0000]            |
+-----------------------+-----------------------------+-----------------------------+
```

#### Out-of-Fold Confusion Matrices ($N=538$)
- **At $\tau = 0.50$**:
  - $\text{TN} = 46$ (benign allowed)
  - $\text{FP} = 7$ (benign flagged)
  - $\text{FN} = 2$ (attacks missed)
  - $\text{TP} = 483$ (attacks blocked)
- **At $\tau = 0.70$**:
  - $\text{TN} = 53$ (zero observed false positives)
  - $\text{FP} = 0$
  - $\text{FN} = 14$ (attacks missed by ML; 12 caught by mandatory heuristic rules)
  - $\text{TP} = 471$

---

### 3.2 Independent Held-Out Test Set Evaluation ($N=133$)

The independent test partition held out three entire benign server families (`puppeteer`, `slack`, `gitlab`) and 9 disjoint malicious groups ($27$ benign, $106$ malicious):

| Metric | Threshold $\tau = 0.50$ | Threshold $\tau = 0.70$ (Fixed Ref) |
| :--- | :---: | :---: |
| **Accuracy** | 95.49% ($127/133$) | 98.50% ($131/133$) |
|  - Cluster Bootstrap 95% CI | $[92.24\%, 98.64\%]$ | $[96.67\%, 100.0\%]$ |
| **Precision** | 95.45% ($105/110$) | 100.0% ($104/104$) |
|  - Clopper-Pearson 95% CI | $[89.62\%, 98.48\%]$ | $[96.52\%, 100.0\%]$ |
| **Recall (Sensitivity)** | 99.06% ($105/106$) | 98.11% ($104/106$) |
|  - Clopper-Pearson 95% CI | $[94.86\%, 99.98\%]$ | $[93.35\%, 99.77\%]$ |
| **F1-Score** | 0.9722 | 0.9905 |
|  - Cluster Bootstrap 95% CI | $[0.9459, 0.9928]$ | $[0.9763, 1.0000]$ |
| **False Positive Rate** | 18.52% ($5/27$) | 0.00% ($0/27$) |
|  - Clopper-Pearson 95% CI | $[6.30\%, 38.08\%]$ | **$[0.00\%, 12.77\%]$** |
| **False Negative Rate** | 0.94% ($1/106$) | 1.89% ($2/106$) |
|  - Clopper-Pearson 95% CI | $[0.02\%, 5.14\%]$ | $[0.23\%, 6.65\%]$ |
| **ROC-AUC** | 0.9965 $[0.9920, 1.0000]$ | 0.9965 $[0.9920, 1.0000]$ |
| **PR-AUC** | 0.9992 $[0.9968, 1.0000]$ | 0.9992 $[0.9968, 1.0000]$ |
| **Confusion Matrix** | $\text{TN}=22, \text{FP}=5, \text{FN}=1, \text{TP}=105$ | $\text{TN}=27, \text{FP}=0, \text{FN}=2, \text{TP}=104$ |

*Statistical Note: Under Clopper-Pearson exact binomial bounds, zero false positives out of 27 samples yields a 95% upper confidence limit of 12.77%. It is scientifically invalid to report a 0% upper bound.*

---

### 3.3 Quarantined Out-of-Distribution (OOD) Analysis

The 4 quarantined samples in [`data/expanded_ood_dataset.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_ood_dataset.json) highlight the fundamental difference between linguistic style and operational capability:

| Tool Name | Server | Predicted Prob $\hat{p}$ | Decision ($\tau=0.50$) | Decision ($\tau=0.70$) | Reviewer Quarantine Rationale |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `fetch` | `fetch` | 0.6529 | MALICIOUS | BENIGN | Grants internet access with phrasing mimicking override directives ("Although originally you did not have internet access..."). High linguistic toxicity despite legitimate utility. |
| `sequentialthinking` | `sequentialthinking` | 0.6099 | MALICIOUS | BENIGN | Extensive prompt instructions ("You should...", "Never stop until...") trigger prompt injection heuristics. |
| `puppeteer_navigate` | `puppeteer` | 0.3899 | BENIGN | BENIGN | Legitimate browser navigation, but `allowDangerous: true` enables SSRF against internal cloud metadata endpoints (`169.254.169.254`). |
| `puppeteer_evaluate` | `puppeteer` | 0.1798 | BENIGN | BENIGN | "Execute JavaScript in the browser console." Minimal text toxicity ($\hat{p} = 0.18$), yet provides an arbitrary remote code execution primitive. |

---

## 4. Granular Latency Benchmark

Timing boundaries were isolated across five operational measurement points using 200 repeated executions (after 20 warm-up runs) for in-memory operations, and 50 repeated executions (after 10 warm-up runs) for live MCP protocol sessions:

```
                         Granular Latency Profile
+---------------------------------------+-----------+-----------+-----------+------------+
| Measurement Point                     | Mean (ms) | Med (ms)  | P95 (ms)  | Min / Max  |
+---------------------------------------+-----------+-----------+-----------+------------+
| 1. Pure ML Inference (N=200)          | 3.4103    | 3.0169    | 5.4689    | 2.33/13.21 |
| 2. Pure Policy Decision (N=200)       | 0.1881    | 0.1883    | 0.2380    | 0.14/0.39  |
| 3. In-Memory Proxy List Overhead(N=200| 1.5343    | 1.5053    | 2.0018    | 1.06/2.49  |
| 4. In-Memory Call Authorization(N=200)| 0.0007    | 0.0007    | 0.0008    | 0.00/0.002 |
| 5. Full MCP Protocol List Roundtrip   | 2.6498    | 2.5892    | 3.1264    | 2.28/3.79  |
| 6. Full MCP Protocol Call Roundtrip   | 5.2262    | 4.9737    | 6.7868    | 4.36/7.76  |
+---------------------------------------+-----------+-----------+-----------+------------+
```

### Timing Methodology
- **Pure ML Inference**: Times `TfidfVectorizer.transform([desc])` combined with `LogisticRegression.predict_proba()`.
- **Pure Policy Decision**: Times `PolicyEngine.evaluate()` on an existing change detection result.
- **In-Memory Proxy Operations**: Times method dispatch on `MCPGatewayProxy` wrapping FastMCP server fixtures.
- **Full MCP Protocol Round-Trip**: Times actual JSON-RPC protocol round-trip through `ClientSession` $\leftrightarrow$ `MCPGatewayProtocolServer` $\leftrightarrow$ `Server` over AnyIO bidirectional memory streams.

---

## 5. Gateway Enforcement Benchmark

To prevent conflation between fixture stability and attack variety, the benchmark explicitly separates unique scenario fixtures from repetition trials:
- **Unique Scenarios Evaluated**: Exactly 5 functional fixtures:
  1. Approved baseline execution (`calculate_total`)
  2. Prompt injection mutation (`search_products`)
  3. Sensitive data exfiltration mutation (`simple_division` with 23.py payload)
  4. Benign documentation update (`simple_division` legitimate rewrite)
  5. Direct-call bypass attempt (`unregistered_secret_tool`)
- **Repetitions**: 100 repeated executions per fixture ($500$ total trials).
- **Legitimate Acceptance Rate**: 100.0% ($100/100$)
- **Malicious Blocking Rate**: 100.0% ($100/100$ for Prompt Injection, $100/100$ for Exfiltration)
- **Quarantine Rate**: 100.0% ($100/100$ on benign update)
- **Direct-Call Bypass Rejection**: 100.0% ($100/100$)
- **Unauthorized Upstream Executions**: **0 (Strictly Verified Zero)**

*Methodology Disclosure: The 100 repetitions verify runtime memory leak freedom, stateful cache stability, and fail-closed integrity under repeated load. They do NOT represent 100 independent attack varieties.*

---

## 6. Sequential Decision Policy: MDP vs. Static Threshold Policy

Simulated across 5 random seeds (42, 123, 456, 789, 1000) over 2,500 total episodes under default simulator parameters ($R_{\text{breach}} = -100$, Review Accuracy $= 98\%$):

```
                        MDP vs. Static Threshold Comparison (2,500 Episodes)
+-----------------------------------+-----------------------+-----------------------+
| Evaluation Metric                 | MDP Policy            | Static Threshold      |
+-----------------------------------+-----------------------+-----------------------+
| Mean Reward Across Seeds          | 7.00 +/- 0.25         | 7.05 +/- 0.18         |
| Total Security Breaches           | 35 breaches (1.40%)   | 8 breaches (0.32%)    |
| Mean Breaches Per Seed (N=500)    | 7.0 +/- 0.7 breaches  | 1.6 +/- 0.5 breaches  |
| Total False Blocks                | 40 false blocks       | 52 false blocks       |
| Total Quarantines Enforced        | 611 quarantines       | 1,236 quarantines     |
| Mandatory Rules Non-Override      | VERIFIED SOUND (100%) | VERIFIED SOUND (100%) |
+-----------------------------------+-----------------------+-----------------------+
```

### Scientific Assessment
**The Static Threshold Policy is empirically superior to the MDP policy** under standard security constraints:
- Static threshold achieved a **higher cumulative mean reward** ($7.05$ vs. $7.00$).
- Static threshold incurred **more than four times fewer security breaches** ($8$ vs. $35$).
- **Explanation**: The MDP policy directly allows marginal low-risk drift (`LOW_RISK_UNVERIFIED`) to save the $-2.0$ quarantine delay penalty. Because 5% of unverified tools in the simulator harbor subtle attacks, allowing them directly results in breaches. The Static Threshold Policy, by contrast, conservatively routes all unverified drift to quarantine, relying on analyst review to ensure security.

---

## 7. Actual Executed Component Ablation Study

Six standalone software configurations were implemented and executed against four challenge scenarios with real upstream invocation tracking:
- **C1**: `HashOnlyEnforcer` (Cryptographic registry hash check only)
- **C2**: `MLOnlyEnforcer` (ML detector threshold only, no proxy interceptor)
- **C3**: `MandatoryRulesOnlyEnforcer` (Regex heuristic checks only, no proxy interceptor)
- **C4**: `HashPlusMLEnforcer` (Hash lookup + ML score)
- **C5**: `HashMLMandatoryEnforcer` (Mandatory rules + Hash lookup + ML score)
- **C6**: `MCPGatewayProxy` (Full Gateway with dual-phase interception and quarantine workflow)

```
                       Executed Component Ablation Study Results
+---------------------------+--------------------+--------------------+--------------------+--------------------+
| Configuration             | S1: Known Attack   | S2: Benign Rewrite | S3: New Tool       | S4: Direct Bypass  |
+---------------------------+--------------------+--------------------+--------------------+--------------------+
| C1: Hash Only             | BLOCK (Upstream: 0)| BLOCK (Upstream: 0)| BLOCK (Upstream: 0)| BYPASS (Upstream:1)|
|   - Security Outcome      | CORRECT_BLOCK      | FALSE_BLOCK ❌     | FALSE_BLOCK ❌     | SECURITY_BREACH ❌ |
| C2: ML Only               | BLOCK (Upstream: 0)| ALLOW (Upstream: 1)| ALLOW (Upstream: 1)| BYPASS (Upstream:1)|
|   - Security Outcome      | CORRECT_BLOCK      | UNVERIFIED_ALLOW ⚠️| UNVERIFIED_ALLOW ⚠️| SECURITY_BREACH ❌ |
| C3: Mandatory Rules Only  | BLOCK (Upstream: 0)| ALLOW (Upstream: 1)| ALLOW (Upstream: 1)| BYPASS (Upstream:1)|
|   - Security Outcome      | CORRECT_BLOCK      | UNVERIFIED_ALLOW ⚠️| UNVERIFIED_ALLOW ⚠️| SECURITY_BREACH ❌ |
| C4: Hash + ML             | BLOCK (Upstream: 0)| BLOCK (Upstream: 0)| BLOCK (Upstream: 0)| BYPASS (Upstream:1)|
|   - Security Outcome      | CORRECT_BLOCK      | FALSE_BLOCK ❌     | FALSE_BLOCK ❌     | SECURITY_BREACH ❌ |
| C5: Hash + ML + Mandatory | BLOCK (Upstream: 0)| BLOCK (Upstream: 0)| BLOCK (Upstream: 0)| BYPASS (Upstream:1)|
|   - Security Outcome      | CORRECT_BLOCK      | FALSE_BLOCK ❌     | FALSE_BLOCK ❌     | SECURITY_BREACH ❌ |
| C6: Full Gateway Proxy    | BLOCK (Upstream: 0)| QUARANTINE(Upstr:0)| QUARANTINE(Upstr:0)| BLOCK (Upstream: 0)|
|   - Security Outcome      | CORRECT_BLOCK      | SAFE_QUARANTINE ✅ | SAFE_QUARANTINE ✅ | CORRECT_BLOCK ✅   |
+---------------------------+--------------------+--------------------+--------------------+--------------------+
```

### Ablation Takeaways
1. **Hash Alone (C1, C4, C5) Destroys Usability**: Without a quarantine state, any change to a description hash forces a hard BLOCK, preventing legitimate API documentation updates and rejecting new tools.
2. **ML and Rules Alone (C2, C3) Allow Unverified Code**: Standalone text classifiers blindly ALLOW unverified modifications and brand new tools without administrative authorization.
3. **Runtime Proxy Interception Prevents Bypass**: Standalone components (C1–C5) fail completely against direct-call bypasses (`call_tool("secret_admin_tool")`), permitting unauthorized upstream execution ($1$). Only C6 intercepts `tools/call`, preventing direct bypass ($0$).

---

## 8. Limitations & Threat Model Boundaries

1. **MCPTox Benchmark Template Regularity**: MCPTox attack descriptions share standardized syntactical structures (`Template-1`, `Template-2`, `Template-3`). High detection recall may not fully transfer to novel, human-authored zero-day prompt injections.
2. **Linguistic Style vs. Operational Capability**: As proven by `puppeteer_evaluate`, neutral wording can describe dangerous primitives (arbitrary JavaScript execution) with low ML toxicity ($\hat{p} = 0.18$). ML detection cannot substitute for OS-level sandboxing.
3. **Application Protocol Boundary**: The gateway proxy intercepts Python-level MCP API boundaries. It does not replace transparent network firewalls or kernel-level syscall filters.

---

## 9. Conclusion

The corrected research evaluation proves that the MCP Security Gateway reliably enforces fail-closed protocol protection against poisoned tool descriptors. By combining cryptographic change detection, group-disjoint machine learning, mandatory heuristic rules, and a quarantine workflow, the architecture eliminates direct-call bypasses while preventing the operational disruption caused by brittle hash-only blocking.
