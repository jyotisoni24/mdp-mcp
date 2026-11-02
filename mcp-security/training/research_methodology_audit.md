# Critical Audit of Research Evaluation Methodology

**Target Document Audited**: [`training/research_evaluation_report.md`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/research_evaluation_report.md)  
**Auditor**: Independent Machine Learning & Security Audit Harness  
**Audit Date**: November 2, 2026  
**Status**: METHODOLOGICAL CORRECTIONS APPLIED & DOCUMENTED  

---

## 1. Executive Summary & Audit Motivation

A scientific evaluation must adhere to strict statistical integrity, transparent experimental design, and conservative reporting. An internal review of the initial research evaluation report revealed six critical methodological flaws:
1. **Flawed Resampling Hierarchy**: Non-parametric bootstrap confidence intervals were sampled at the i.i.d. observation level rather than the canonical server-group cluster level, underestimating variance in clustered data.
2. **Zero-Width Confidence Interval Fallacy**: For zero-error observations (such as False Positive Rate $= 0/53$ or $0/27$ at threshold $\tau = 0.70$), observation-level bootstrap resampled only zero-count vectors, generating degenerate $[0.0\%, 0.0\%]$ intervals that falsely implied zero population uncertainty.
3. **Conceptual Ablation Modeling**: The component ablation study reported hypothetical outcomes via simulation strings rather than executing actual, standalone configuration code paths with real upstream invocation tracking.
4. **Conflated Latency Timing Boundaries**: In-memory proxy filtering and authorization lookups were loosely presented without separating pure ML inference, policy logic, proxy application overhead, and true MCP JSON-RPC protocol round-trips.
5. **Fixture Repetition Ambiguity**: 100 repeated executions over a small set of fixed test server fixtures were presented in a manner that could be conflated with generalization across 100 independent attack varieties.
6. **Unsupported MDP Claims**: The previous narrative framed the Markov Decision Process (MDP) as superior, despite empirical simulation data demonstrating that the Static Threshold Policy achieved higher mean reward and four times fewer security breaches.

This document formally details each methodological defect, presents the mathematical corrections applied, and establishes the revised scientific baseline. The previous report is preserved as historical evidence in [`training/research_evaluation_report.md`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/research_evaluation_report.md); the corrected findings are published in [`training/corrected_research_evaluation_report.md`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/corrected_research_evaluation_report.md).

---

## 2. Confidence Interval & Resampling Hierarchy Audit

### 2.1 The Clustered Data Problem
In the MCP Security Gateway dataset ([`data/expanded_experimental_dataset.csv`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_experimental_dataset.csv)), descriptions are partitioned into 50 canonical server families (`canonical_group`). Multiple tools from the same server (e.g. `slack_post_message`, `slack_get_users`, `slack_add_reaction`) share terminology, formatting conventions, and authorial style.

**Methodological Error**:
The initial script performed uniform random sampling with replacement at the individual record level:
```python
# Flawed: Assumes i.i.d. observations
indices = rng.choice(n_samples, size=n_samples, replace=True)
```
Because tools within a server family exhibit non-zero intra-cluster correlation ($\rho > 0$), naive observation-level bootstrap treats correlated observations as independent, resulting in standard errors that are artificially deflated by a factor of roughly $\sqrt{1 + (m-1)\rho}$ (where $m$ is cluster size).

**Correction Applied**:
The resampling framework was updated to **Cluster Bootstrap**:
1. Resample the $M = 50$ canonical server clusters with replacement.
2. Include all records belonging to the selected clusters in each bootstrap iteration.
3. Compute metrics across 1,000 cluster-level resamples.

### 2.2 The Zero-Width Confidence Interval Fallacy
At threshold $\tau = 0.70$, zero false positives were observed out of 53 benign samples in cross-validation ($FP = 0, TN = 53$) and zero false positives out of 27 benign samples in the independent test set ($FP = 0, TN = 27$).

**Methodological Error**:
The initial report stated:
$$\text{FPR at } \tau = 0.70: 0.00\% \quad [0.00\%, 0.00\%]$$
$$\text{Precision at } \tau = 0.70: 100.0\% \quad [100.0\%, 100.0\%]$$
This is statistically invalid. A finite sample of 53 benign tools with zero observed false positives does not imply that the true population false positive rate is 0%. When an empirical sample contains zero errors, any non-parametric bootstrap resample of that sample will also contain zero errors, producing an empty variance estimate ($s^2 = 0$) and a zero-width interval $[0.0\%, 0.0\%]$.

**Correction Applied**:
For all proportion and rate metrics, the evaluation now computes exact **Clopper-Pearson Binomial Confidence Intervals** using the Beta distribution:
$$p_L = \text{Beta}\left(\frac{\alpha}{2}; k, n - k + 1\right) \quad \text{for } k > 0, \text{ else } 0$$
$$p_U = \text{Beta}\left(1 - \frac{\alpha}{2}; k + 1, n - k\right) \quad \text{for } k < n, \text{ else } 1$$

Under 95% confidence ($\alpha = 0.05$):
- **Cross-Validation FPR ($\tau = 0.70$, $k=0, n=53$)**:
  - Previously reported: $[0.00\%, 0.00\%]$ ❌
  - Exact Clopper-Pearson 95% CI: **$[0.00\%, 6.72\%]$** ✅
  *(Rule of three heuristic: $3/53 = 5.66\%$)*
- **Independent Test FPR ($\tau = 0.70$, $k=0, n=27$)**:
  - Previously reported: $[0.00\%, 0.00\%]$ ❌
  - Exact Clopper-Pearson 95% CI: **$[0.00\%, 12.77\%]$** ✅
  *(Rule of three heuristic: $3/27 = 11.11\%$)*
- **Cross-Validation Precision ($\tau = 0.70$, $k=471, n=471$)**:
  - Previously reported: $[100.0\%, 100.0\%]$ ❌
  - Exact Clopper-Pearson 95% CI: **$[99.22\%, 100.0\%]$** ✅

---

## 3. Threshold Selection & Test Set Isolation Audit

**Audit Questions**:
1. Were $\tau = 0.50$ and $\tau = 0.70$ chosen after observing independent test performance?
2. Did any iterative threshold tuning contaminate the held-out test split?

**Verification Findings**:
- **Threshold 0.50 Provenance**: $\tau = 0.50$ is the standard Bayesian maximum a posteriori boundary for binary logistic regression with inverse class-frequency weighting (`class_weight='balanced'`). It was fixed as the default operating point.
- **Threshold 0.70 Provenance**: $\tau = 0.70$ was identified during preliminary error analysis on Fold 5 of the earlier development dataset (`combined_experimental_dataset.csv`, 513 records) as a point that eliminated false positives on administrative and operational wording.
- **Test Set Isolation**: The independent test partition (133 records across `puppeteer`, `slack`, `gitlab`, and 9 disjoint malicious groups) was **never** subjected to grid search, threshold sweeps, or ROC curve optimization. Both $\tau = 0.50$ and $\tau = 0.70$ were applied *fixed a priori* as candidate operating points.
- **Methodological Correction**: In the initial report, $\tau = 0.70$ was labeled "optimal" in certain text passages. This has been corrected to **"Fixed Reference Threshold $\tau = 0.70$"** to prevent readers from assuming post-hoc test set optimization.

---

## 4. Ablation Study Methodology Audit

**Methodological Error in Initial Report**:
In `training/run_research_evaluation.py` (Module 5), the ablation matrix did not execute actual standalone code for configurations C1 through C5. Instead, it used an `if/else` construct that output pre-determined string descriptions (e.g. `BLOCK (False Block on benign / rejects new)`). This represented a conceptual model of what components *should* do, rather than measured software behavior.

**Correction Applied**:
Five concrete, standalone enforcer classes were implemented in [`training/run_corrected_research_evaluation.py`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/run_corrected_research_evaluation.py):
1. `HashOnlyEnforcer` (C1): Calls `DescriptorRegistry.is_approved()`.
2. `MLOnlyEnforcer` (C2): Calls `MLDetector.predict()`.
3. `MandatoryRulesOnlyEnforcer` (C3): Calls `evaluate_mandatory_violations()`.
4. `HashPlusMLEnforcer` (C4): Chains hash lookup with ML scoring.
5. `HashMLMandatoryEnforcer` (C5): Chains mandatory rules, hash lookup, and ML scoring.
6. `MCPGatewayProxy` (C6): The full gateway architecture with dual-phase interception, quarantine state, and human approval workflow.

Each configuration was executed against an actual upstream server exposing tools with an **upstream execution counter**:
- Recorded decisions: `ALLOW`, `QUARANTINE`, `BLOCK`, `BYPASS_SUCCEEDED`.
- Recorded upstream execution count: `0` (prevented) or `1` (executed).
- Concrete verification: Standalone components (C1-C5) have no runtime protocol interceptor on `tools/call`, permitting direct-call bypasses to execute upstream ($1$). Only C6 intercepts calls at runtime, raising `ToolExecutionDeniedError` and enforcing zero upstream executions ($0$).

---

## 5. Latency & Timing Boundary Audit

**Methodological Error in Initial Report**:
The initial report cited listing latency of $\approx 1.8\text{ ms}$ and call latency of $\approx 0.25\text{ ms}$ as "Gateway Protocol Latency". In reality, those measurements timed in-memory Python method calls on `MCPGatewayProxy`, completely omitting:
- JSON-RPC serialization and deserialization.
- Transport overhead across MCP communication channels.
- Real client-to-gateway and gateway-to-server protocol handshakes.

**Correction Applied**:
The latency benchmark was partitioned into five granular, isolated measurements, each utilizing warm-up runs and repeated trials:
1. **Pure ML Inference**: `MLDetector.predict()` (vectorization + logistic regression):
   - Sample Size: 200 runs (after 20 warm-up runs)
   - Mean: **3.410 ms**, Median: **3.017 ms**, P95: **5.469 ms**
2. **Pure Policy Decision**: `PolicyEngine.evaluate()` on existing `ChangeDetectionResult`:
   - Sample Size: 200 runs (after 20 warm-up runs)
   - Mean: **0.188 ms**, Median: **0.188 ms**, P95: **0.238 ms**
3. **Application Proxy Listing Overhead**: `Proxy.list_tools()` (in-memory descriptor inspection and filtering):
   - Sample Size: 200 runs (after 20 warm-up runs)
   - Mean: **1.534 ms**, Median: **1.505 ms**, P95: **2.002 ms**
4. **Application Proxy Call Authorization**: `Interceptor.authorize_tool_call()` (in-memory authorization check):
   - Sample Size: 200 runs (after 20 warm-up runs)
   - Mean: **0.0007 ms**, Median: **0.0007 ms**, P95: **0.0008 ms**
5. **Full MCP Protocol Round-Trip (Real JSON-RPC over AnyIO Streams)**:
   - Evaluated across real bidirectional `ClientSession` streams: Client $\leftrightarrow$ Gateway $\leftrightarrow$ Upstream.
   - `session.list_tools()`: Sample Size: 50 runs (after 10 warm-up runs). Mean: **2.650 ms**, P95: **3.126 ms**
   - `session.call_tool()`: Sample Size: 50 runs (after 10 warm-up runs). Mean: **5.226 ms**, P95: **6.787 ms**

---

## 6. Gateway Benchmark Fixture vs. Generalization Audit

**Methodological Error in Initial Report**:
The initial report stated: "100 runs evaluated: Legitimate tool acceptance 100%, Malicious blocking 100%." This could easily be misinterpreted as 100 distinct attack scenarios evaluated on the gateway. In reality, the test loop executed 100 repeated iterations of the same four fixture tools (`search_products`, `calculate_total`, `get_weather`, `simple_division`).

**Correction Applied**:
The benchmark structure is now explicitly reported with separate scenario and repetition counts:
- **Unique Scenarios**: Exactly 5 functional fixtures:
  1. Approved baseline call (`calculate_total`)
  2. Prompt injection mutation (`search_products`)
  3. Sensitive data exfiltration mutation (`simple_division` with 23.py payload)
  4. Benign documentation update (`simple_division` legitimate rewrite)
  5. Direct-call bypass attempt (`unregistered_secret_tool`)
- **Repetitions**: 100 repeated trials per fixture ($5 \times 100 = 500$ total trials).
- **Explicit Scope Disclosure**: Repeated fixture trials measure **runtime statefulness, memory leak freedom, and fail-closed consistency** under repeated load. They do **not** measure generalization across 100 distinct attack classes (which is evaluated on the 485 MCPTox dataset samples).

---

## 7. MDP vs. Static Threshold Policy Comparison Audit

**Methodological Error in Initial Report**:
The initial report discussed the MDP framework in optimistic terms, implying algorithmic superiority over static thresholding.

**Empirical Reality**:
When simulated across 5 random seeds (42, 123, 456, 789, 1000) over 2,500 total decision episodes under default simulator parameters ($R_{\text{breach}} = -100$, Review Accuracy $= 98\%$):
- **Mean Reward**: Static Threshold achieved **$7.05 \pm 0.18$**, whereas MDP achieved **$7.00 \pm 0.25$**.
- **Security Breaches**: Static Threshold incurred **8 total breaches** ($1.6 \pm 0.5$ per seed), whereas MDP incurred **35 total breaches** ($7.0 \pm 0.7$ per seed).
- **Root Cause**: The MDP policy directly allows marginal low-risk drift (`LOW_RISK_UNVERIFIED`) to avoid the $-2.0$ quarantine cost. In a stochastic environment where 5% of unverified tools contain subtle attacks, this optimization leads to security breaches. The Static Threshold Policy, by contrast, conservatively quarantines *all* unverified drift, relying on human review to achieve higher cumulative security.

**Correction Applied**:
The report now explicitly states that **the Static Threshold Policy is empirically superior to the MDP policy** under standard security-first reward formulations.

---

## 8. Summary of Corrected vs. Flawed Claims

| Evaluation Area | Initial Claim / Method (Flawed) | Corrected Scientific Evidence |
| :--- | :--- | :--- |
| **Resampling Hierarchy** | Sample-level i.i.d. bootstrap | Canonical Server-Group Cluster Bootstrap |
| **Zero-Error Uncertainty** | FPR $\tau=0.70$ CI: $[0.0\%, 0.0\%]$ | Clopper-Pearson Exact 95% CI: $[0.00\%, 6.72\%]$ ($N=53$), $[0.00\%, 12.77\%]$ ($N=27$) |
| **Threshold Selection** | Implied optimal operating point | Disclosed fixed-threshold reference point evaluated a priori |
| **Ablation Study** | Conceptual `if/else` simulation strings | Actual executed component code paths with upstream counters |
| **Latency Boundaries** | In-memory proxy call labeled "Protocol Latency" | Separated ML ($3.4\text{ ms}$), Policy ($0.19\text{ ms}$), and Real Protocol ($5.2\text{ ms}$) |
| **Gateway Benchmark** | "100 runs" implying attack diversity | Disclosed as 5 unique fixtures $\times$ 100 repetition trials ($500$ total) |
| **MDP Comparison** | Implied MDP superiority | Disclosed Static Threshold superiority in reward ($7.05$ vs $7.00$) and safety ($8$ vs $35$ breaches) |

**Audit Disposition**: CORRECTIONS COMPLETE — Publication Baseline Established.
