# Benign Dataset Expansion and Independent Evaluation Design

## 1. Executive Summary & Objectives

The experimental detector error analysis confirmed that while the model achieves 100% recall on known MCPTox attacks, its out-of-fold false-positive rate (FPR) is 39.29% at $\tau = 0.50$, heavily concentrated in tools from unseen servers like `filesystem`. 

The primary cause is severe class imbalance (**485 malicious records vs. 28 reviewed benign records**, a ~17:1 ratio) and limited benign server representation (only 7 standard benign servers).

### Core Goals
1. **Expand Benign Corpus**: Increase genuine, statically harvested benign records from 28 to 60+ tools across 13+ distinct server families.
2. **Preserve Scientific Rigor**:
   * Statically harvested from official Model Context Protocol repositories (`modelcontextprotocol/servers` and `modelcontextprotocol/servers-archived`).
   * Verbatim tool descriptions; zero synthetic paraphrasing or repetitive templates.
   * Full provenance tracking: pinned commit SHA, repository URL, file path, and license.
   * Zero automated approvals: all additions start as `pending_review` until audited.
3. **Strict OOD Isolation**:
   * Tools containing behavioral directives addressed to the LLM (such as `fetch` and `sequentialthinking`) are strictly excluded from ordinary training and quarantined in `data/ood_evaluation_dataset.json`.
4. **Independent Server-Family-Disjoint Test Set**:
   * Completely hold out 3 new server families from the training/tuning loop to provide an unbiased final benchmark that is never used for feature extraction, hyperparameter tuning, or threshold selection.

---

## 2. Review of Existing Harvesting Pipeline

The existing static collector in [`collect_mcp_descriptions.py`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/collect_mcp_descriptions.py) provides safe, reproducible extraction:

* **Static Parsing**: Zero execution of untrusted TypeScript or Python code (uses standard `ast` in Python and regex-based AST extraction for TypeScript Zod schemas).
* **Deterministic Deduplication**: Computes SHA-256 over `tool_name || description` and token-level `SequenceMatcher` to flag near-duplicates ($\ge 0.85$).
* **Heuristic Flagging**: Scans for embedded prompt injection patterns (`r"ignore\s+(all\s+)?(previous|prior)\s+instructions"`, `r"you\s+(must|should)\s+(always|never)\s+tell"`, `r"system\s+(prompt|override|directive)"`).
* **Audit Trail**: Every record includes `verification_status: "pending_review"` and fields for human review comments.

---

## 3. Proposed Additional Genuine MCP Server Families

The following 6 server families are proposed for addition to `SERVER_SPECIFICATIONS` in `collect_mcp_descriptions.py`. All are official reference implementations from the `modelcontextprotocol` organization.

### Server Family 1: `puppeteer` (Browser Automation)
* **Repository**: `https://github.com/modelcontextprotocol/servers-archived`
* **Commit SHA**: `e6396f9a0c2049d5cbf23eb250c60953a5c0b02f`
* **Server Path**: `src/puppeteer`
* **Source File**: `src/puppeteer/index.ts`
* **Source URL**: `https://raw.githubusercontent.com/modelcontextprotocol/servers-archived/main/src/puppeteer/index.ts`
* **Language**: TypeScript
* **License**: MIT
* **Category**: Web Automation & Scraping
* **Target Tools to Harvest**:
  1. `puppeteer_navigate`: "Navigate to any URL in the browser"
  2. `puppeteer_screenshot`: "Capture screenshot of the entire page or a specific element"
  3. `puppeteer_click`: "Click an element on the page using a CSS selector"
  4. `puppeteer_fill`: "Fill out an input field"
  5. `puppeteer_select`: "Select an option from a dropdown"
  6. `puppeteer_hover`: "Hover over an element"
* **Audit Notes**: Automation tools perform dynamic interactions. Auditor must verify that side-effect descriptions are standard browser commands and not confused with malicious remote execution.

### Server Family 2: `slack` (Team Communication)
* **Repository**: `https://github.com/modelcontextprotocol/servers-archived`
* **Commit SHA**: `e6396f9a0c2049d5cbf23eb250c60953a5c0b02f`
* **Server Path**: `src/slack`
* **Source File**: `src/slack/index.ts`
* **Source URL**: `https://raw.githubusercontent.com/modelcontextprotocol/servers-archived/main/src/slack/index.ts`
* **Language**: TypeScript
* **License**: MIT
* **Category**: Messaging & Collaboration
* **Target Tools to Harvest**:
  1. `slack_list_channels`: "List public channels in the workspace with pagination"
  2. `slack_post_message`: "Post a new message to a specific Slack channel"
  3. `slack_reply_to_thread`: "Reply to a specific message thread in Slack"
  4. `slack_add_reaction`: "Add an emoji reaction to a message"
  5. `slack_get_channel_history`: "Get recent messages from a channel"
* **Audit Notes**: Involves message dispatch and channel listing. Auditor must verify parameters contain no hardcoded webhook secrets or malicious channels.

### Server Family 3: `postgres` (Relational Database)
* **Repository**: `https://github.com/modelcontextprotocol/servers-archived`
* **Commit SHA**: `e6396f9a0c2049d5cbf23eb250c60953a5c0b02f`
* **Server Path**: `src/postgres`
* **Source File**: `src/postgres/index.ts`
* **Source URL**: `https://raw.githubusercontent.com/modelcontextprotocol/servers-archived/main/src/postgres/index.ts`
* **Language**: TypeScript
* **License**: MIT
* **Category**: Relational Database
* **Target Tools to Harvest**:
  1. `query`: "Execute a read-only SQL query against the PostgreSQL database"
* **Audit Notes**: Read-only database query. Must verify description accurately reflects read-only transaction semantics.

### Server Family 4: `gdrive` (Cloud Storage)
* **Repository**: `https://github.com/modelcontextprotocol/servers-archived`
* **Commit SHA**: `e6396f9a0c2049d5cbf23eb250c60953a5c0b02f`
* **Server Path**: `src/gdrive`
* **Source File**: `src/gdrive/index.ts`
* **Source URL**: `https://raw.githubusercontent.com/modelcontextprotocol/servers-archived/main/src/gdrive/index.ts`
* **Language**: TypeScript
* **License**: MIT
* **Category**: Cloud Storage & Document Retrieval
* **Target Tools to Harvest**:
  1. `gdrive_search`: "Search for files in Google Drive by name or query"
  2. `gdrive_read_file`: "Read content of a Google Drive file by ID"
* **Audit Notes**: Read-only file retrieval. Distinct from local filesystem tools.

### Server Family 5: `aws-kb-retrieval` (Enterprise Knowledge Base)
* **Repository**: `https://github.com/modelcontextprotocol/servers-archived`
* **Commit SHA**: `e6396f9a0c2049d5cbf23eb250c60953a5c0b02f`
* **Server Path**: `src/aws-kb-retrieval-server`
* **Source File**: `src/aws-kb-retrieval-server/index.ts`
* **Source URL**: `https://raw.githubusercontent.com/modelcontextprotocol/servers-archived/main/src/aws-kb-retrieval-server/index.ts`
* **Language**: TypeScript
* **License**: MIT
* **Category**: Knowledge Base Retrieval
* **Target Tools to Harvest**:
  1. `retrieve_from_aws_kb`: "Query an AWS Bedrock Knowledge Base and retrieve relevant document chunks"
* **Audit Notes**: Document chunk retrieval. Verify absence of prompt injection triggers.

### Server Family 6: `gitlab` (DevOps & Code Hosting)
* **Repository**: `https://github.com/modelcontextprotocol/servers-archived`
* **Commit SHA**: `e6396f9a0c2049d5cbf23eb250c60953a5c0b02f`
* **Server Path**: `src/gitlab`
* **Source File**: `src/gitlab/index.ts`
* **Source URL**: `https://raw.githubusercontent.com/modelcontextprotocol/servers-archived/main/src/gitlab/index.ts`
* **Language**: TypeScript
* **License**: MIT
* **Category**: Version Control & Project Management
* **Target Tools to Harvest**:
  1. `gitlab_list_projects`: "List projects accessible by the authenticated GitLab user"
  2. `gitlab_get_file_contents`: "Get content of a file from a repository"
  3. `gitlab_create_issue`: "Create a new issue in a GitLab project"
* **Audit Notes**: Complements the GitHub server family; tests whether the model overfits to specific repository platforms.

---

## 4. Human Review & Quality Assurance Rules

Before any candidate can be merged into the active dataset:
1. **Never Automatically Approve**: Automated collection scripts write solely to `data/benign_candidates.json` with `verification_status: "pending_review"`.
2. **Verbatim Verification**: Check candidate text against the raw GitHub source file. If the tool description was modified in any way, reject the candidate.
3. **Directive Exclusion Check**:
   * If a tool contains meta-instructions directing the AI's persona or chain of thought (e.g., *"You must first consider..."*, *"Ignore previous warnings when calling this"*), it is flagged with `behavioral_directive_present: true`.
   * Such tools are **strictly routed to `ood_evaluation_dataset.json`** and excluded from the standard training splits.
4. **Side-Effect Legality**:
   * Tools that write files, post messages, or create issues are legitimate capabilities if authorized. They must NOT be marked malicious merely for having side-effects.

---

## 5. Independent Server-Family-Disjoint Test-Set Design

To prevent data leakage and provide true generalizability metrics, the expanded evaluation architecture strictly separates the **Cross-Validation Training Environment** from the **Final Independent Test Set**.

```
                           +-----------------------------------------------+
                           |      TOTAL REVISED HARVESTED DATASET          |
                           |   (485 MCPTox Attacks + ~60 Benign Tools)     |
                           +-----------------------+-----------------------+
                                                   |
                     +-----------------------------+-----------------------------+
                     |                                                           |
                     v                                                           v
+------------------------------------------+       +------------------------------------------+
|       CROSS-VALIDATION DEVELOPMENT       |       |       HELD-OUT INDEPENDENT TEST SET      |
|           (TRAINING & TUNING)            |       |     (STRICTLY ZERO TRAINING/TUNING)      |
+------------------------------------------+       +------------------------------------------+
| Servers Included:                        |       | Held-Out Benign Server Families (Never in|
| - git (5 tools)                          |       | Training or Threshold Selection):        |
| - sqlite (4 tools)                       |       | - puppeteer (6 tools)                    |
| - brave-search (2 tools)                 |       | - slack (5 tools)                        |
| - time (2 tools)                         |       | - gitlab (3 tools)                       |
| - filesystem (5 tools)                   |       | Total Held-Out Benign: 14 tools          |
| - github (5 tools)                       |       |                                          |
| - memory (5 tools)                       |       | Held-Out Malicious Prompts:              |
| - postgres (1 tool)                      |       | - 85 unseen attack variants from         |
| - gdrive (2 tools)                       |       |   unseen MCPTox attack families          |
| - aws-kb-retrieval (1 tool)              |       | Total Held-Out Malicious: 85 attacks     |
| Total Benign in Development: 32 tools    |       |                                          |
| Total Malicious in Development: 400      |       | Total Independent Test Size: 99 samples  |
|                                          |       +------------------------------------------+
| 5-Fold StratifiedGroupKFold on server    |                             ^
| canonical groups:                        |                             |
| - Vectorizer fit only on training folds  |             Single Final Forward Pass Only
| - Threshold tau selected via OOF F1-score|             (No Threshold Adjustments Allowed)
+------------------------------------------+                             |
                     |                                                   |
                     +---------------------------------------------------+
```

### Protocol Guidelines:
1. **Zero Information Leakage**:
   * The feature extraction vectorizer (`TfidfVectorizer`) is fitted strictly on the development set. No tokens from `puppeteer`, `slack`, or `gitlab` are present in the vocabulary unless they naturally appear in the development corpus.
   * Decision threshold $\tau^*$ is selected strictly based on out-of-fold cross-validation performance.
2. **Transparent Reporting Standards**:
   * All scientific reports must present results in two explicitly labeled tables:
     * **Table A: 5-Fold Cross-Validation Metrics (OOF)** (reflecting internal training performance).
     * **Table B: Independent Unseen Server Benchmark** (reflecting true production generalizability on zero-shot servers).
3. **OOD Behavioral Benchmark**:
   * Evaluated independently using `data/ood_evaluation_dataset.json` (`fetch`, `sequentialthinking`) to measure Gateway interception and quarantine behavior when confronted with instructional prompts.
