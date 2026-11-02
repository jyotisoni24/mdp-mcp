# Expanded Experimental Dataset Validation Report

## 1. Executive Summary

This report documents the construction, integrity verification, and leakage-prevention architecture for the newly generated **`data/expanded_experimental_dataset.csv`**.

In accordance with project requirements:
* **No model retraining was performed**.
* **Existing datasets and baseline model artifacts were strictly preserved**.
* **Zero unapproved candidates were added**.
* **All four out-of-distribution (OOD) and high-privilege tools were quarantined into [`data/expanded_ood_dataset.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_ood_dataset.json)**.

### Dataset Composition Summary

| Partition | Source | Label | Tool Count | Server Families Represented |
|---|---|:---:|:---:|---|
| **Original MCPTox Attacks** | `combined_experimental_dataset.csv` | `1` | **485** | 45 diverse attack categories / paradigms |
| **Original Reviewed Benign** | `combined_experimental_dataset.csv` | `0` | **28** | `filesystem`, `git`, `brave-search`, `sqlite`, `memory`, `time`, `github` |
| **Newly Approved Benign** | `expanded_benign_reviewed.json` | `0` | **25** | `puppeteer` (5), `slack` (8), `postgres` (1), `gdrive` (1), `aws-kb-retrieval` (1), `gitlab` (9) |
| **Total Constructed Dataset** | **`expanded_experimental_dataset.csv`** | **{0, 1}** | **538** | **58 Canonical Server & Attack Groups** |

### Key Improvements over Previous Dataset
1. **Benign Corpus Expansion**: Benign tools increased from **28 to 53 (+89.3%)**.
2. **Server Diversity**: Benign server families increased from **7 to 13 distinct server families (+85.7%)**.
3. **Class Ratio Rebalancing**: The malicious-to-benign ratio improved from **17.32:1 down to 9.15:1**, providing nearly double the negative training signal across diverse real-world APIs.

---

## 2. Integrity Verification & Validation Audit

Automated static integrity tests were executed across all 538 rows:

| Integrity Check | Target Expectation | Measured Result | Status |
|---|---|---|:---:|
| **Total Record Count** | 538 records | **538 records** | **PASSED** |
| **Binary Label Integrity** | Only `{0, 1}` | **`0`: 53, `1`: 485** | **PASSED** |
| **Missing Descriptions** | 0 nulls | **0 null descriptions** | **PASSED** |
| **Missing Critical Columns** | 0 nulls in required schema | **0 nulls** across all 9 schema columns | **PASSED** |
| **Exact Duplicate Descriptions** | 0 duplicates | **0 exact duplicates** | **PASSED** |
| **Exact Duplicate Record IDs** | 0 duplicates | **0 exact duplicate IDs** | **PASSED** |
| **Cross-Label Near Duplicates ($\ge 0.75$)** | 0 pairs | **0 cross-label duplicates** | **PASSED** |
| **Quarantined OOD Exclusions** | 4 records excluded | **4 records strictly excluded** | **PASSED** |

### Schema Structure Verification
All rows adhere strictly to the 9 canonical columns:
1. `record_id`: Unique deterministic identifier (e.g., `mcp_slack_slack_post_message`).
2. `tool_name`: Exact function/tool identifier.
3. `server_name`: Server family name.
4. `description`: Original, verbatim tool description.
5. `label`: Binary classification target (`0` = Benign, `1` = Malicious).
6. `attack_type`: Metadata taxonomy (`benign` or specific MCPTox attack type).
7. `paradigm`: Metadata category (`benign` or MCPTox attack paradigm).
8. `source`: Repository provenance URL.
9. `canonical_group`: Server group key used for leakage-resistant Stratified Group K-Fold splitting.

---

## 3. Duplicate & Near-Duplicate Analysis

### A. Exact Duplicates
* **Result**: **0 exact duplicate descriptions** and **0 duplicate record IDs** across the entire 538-record corpus.

### B. Near-Duplicates Among Benign Tools
A token-level `SequenceMatcher` scan across all 53 benign tools identified 15 pairs with $\ge 0.70$ lexical similarity. Crucially, these fall into two legitimate software engineering patterns:

1. **Intra-Server Functional Symmetry (Same Server Family)**:
   * `sqlite`: `read_query` vs. `write_query` ($0.80$ similarity)
   * `puppeteer`: `puppeteer_click` vs. `puppeteer_hover` ($0.82$ similarity)
   * `gitlab`: `create_repository` vs. `create_branch` ($0.82$ similarity)
   * *Resolution*: Handled automatically by Stratified Group K-Fold splitting. Because tools from the same server family share the same `canonical_group`, they are **guaranteed to stay together in the same fold**, preventing intra-server leakage.
2. **Inter-Platform Conceptual Overlap (`github` vs. `gitlab`)**:
   * `github_get_file_contents` vs. `gitlab_get_file_contents` ($0.88$ similarity)
   * `github_create_issue` vs. `gitlab_create_issue` ($0.81$ similarity)
   * *Resolution*: In the planned independent test split, `gitlab` is designated as a held-out test family while `github` remains in development. This provides an evaluation benchmark: testing whether the detector correctly recognizes the functional intent of Git operations regardless of whether the platform is GitHub or GitLab.

### C. Cross-Label Near Duplicates
* **Result**: **0 cross-label near-duplicate pairs** with similarity $\ge 0.75$. No benign tool description overlaps ambiguously with any malicious MCPTox attack prompt.

---

## 4. Quarantined Out-of-Distribution Dataset

The four excluded tools have been compiled into [`data/expanded_ood_dataset.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_ood_dataset.json):

| Candidate ID | Tool Name | Server | Quarantine Reason | Gateway Policy Requirement |
|---|---|---|---|---|
| `mcp_fetch_fetch` | `fetch` | `fetch` | **Behavioral Directive Present**: Contains meta-instructions directing the AI model's web retrieval format and behavior. | Route to OOD evaluation; verify model does not blindly follow embedded instructions. |
| `mcp_sequentialthinking_sequentialthinking` | `sequentialthinking` | `sequentialthinking` | **Behavioral Directive Present**: Directs the LLM's step-by-step reasoning process and thought expansion. | Route to OOD evaluation; isolate meta-cognitive tools. |
| `mcp_puppeteer_puppeteer_evaluate` | `puppeteer_evaluate` | `puppeteer` | **Arbitrary Code Execution**: Executes arbitrary JavaScript string in the browser context with access to cookies and DOM. | High-privilege quarantine tier; requires administrator pre-approval. |
| `mcp_puppeteer_puppeteer_navigate` | `puppeteer_navigate` | `puppeteer` | **SSRF & Security Bypass**: Arbitrary URL navigation + `allowDangerous: true` parameter bypassing Chromium sandboxing. | Runtime Gateway policy must enforce private IP blocking and reject `allowDangerous: true`. |

---

## 5. Split Architecture & Leakage Prevention Protocol

The split architecture documented in [`training/expanded_dataset_split_report.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/expanded_dataset_split_report.json) ensures zero information leakage:

### A. Group Disjointness
* All splits partition data strictly along `canonical_group` boundaries.
* Verification confirmed that **no server group appears in both the training and validation sets of any fold** ($\text{overlap} = \emptyset$).

### B. Planned Independent Evaluation Architecture
```
                         +-----------------------------------------------+
                         |      EXPANDED EXPERIMENTAL DATASET (538)      |
                         +-----------------------+-----------------------+
                                                 |
                   +-----------------------------+-----------------------------+
                   |                                                           |
                   v                                                           v
+----------------------------------------+       +----------------------------------------+
|      DEVELOPMENT SET (CV TUNING)       |       |       HELD-OUT INDEPENDENT TEST        |
+----------------------------------------+       +----------------------------------------+
| Benign Servers (31 tools):             |       | Held-Out Benign Servers (22 tools):    |
| - filesystem (5 tools)                 |       | - puppeteer (5 approved tools)         |
| - git (5 tools)                        |       | - slack (8 tools)                      |
| - brave-search (2 tools)               |       | - gitlab (9 tools)                     |
| - sqlite (4 tools)                     |       |                                        |
| - memory (5 tools)                     |       | Held-Out Malicious Prompts:            |
| - time (2 tools)                       |       | - Unseen MCPTox attack families        |
| - github (5 tools)                     |       |                                        |
| - postgres (1 tool)                    |       | Strict Protocol:                       |
| - gdrive (1 tool)                      |       | - Never used for TF-IDF vocabulary     |
| - aws-kb-retrieval (1 tool)            |       | - Never used for threshold tuning      |
|                                        |       | - Evaluated once on fixed final model  |
| 5-Fold StratifiedGroupKFold for        |       +----------------------------------------+
| internal threshold tuning (tau)        |
+----------------------------------------+
```

### C. Feature Isolation
* Columns `attack_type`, `paradigm`, `source`, and `canonical_group` are strictly excluded from TF-IDF feature extraction.
* Vectorizers will be fit solely on training folds when training commences.

---

## 6. Generated Artifacts

1. [`data/expanded_experimental_dataset.csv`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_experimental_dataset.csv): The complete 538-row dataset ready for experimental modeling.
2. [`data/expanded_ood_dataset.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_ood_dataset.json): Quarantined benchmark containing the 4 behavioral directive and high-privilege tools.
3. [`training/expanded_dataset_split_report.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/expanded_dataset_split_report.json): Machine-readable split specification detailing fold assignments and group disjointness.
4. [`training/expanded_dataset_validation_report.md`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/expanded_dataset_validation_report.md): This comprehensive verification report.
