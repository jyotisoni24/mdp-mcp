# Expanded Benign Dataset Review Report

## 1. Executive Summary

This report documents the harvesting, static security verification, and manual review preparation for **27 new candidate MCP tools** across **six official Model Context Protocol server families**.

In accordance with the expansion protocol specified in [`benign_expansion_plan.md`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/benign_expansion_plan.md):
* **Zero Automated Approvals**: All 27 newly collected candidates are assigned `verification_status: "pending_review"`. None have been merged into the training dataset.
* **Exact Pinned Provenance**: All records are harvested from the official `modelcontextprotocol/servers-archived` repository at pinned commit SHA `e6396f9a0c2049d5cbf23eb250c60953a5c0b02f`.
* **Zero Model / Dataset Modifications**: The existing models (`detector_model.joblib`, `experimental_detector_model.joblib`), vectorizers, and datasets (`combined_experimental_dataset.csv`, `ood_evaluation_dataset.json`) remain strictly untouched.
* **Comprehensive Static Checks**: Every tool underwent preliminary static evaluation across six security vectors (behavioral directives, instruction overrides, hidden prerequisites, credential access, unauthorized data transfer, and implementation-purpose alignment).

---

## 2. Server Family Provenance & Collection Overview

| Server Family | Category | Source Path | Tools Collected | Primary Runtime / Capability |
|---|---|---|:---:|---|
| **`puppeteer`** | Web Automation & Scraping | `src/puppeteer/index.ts` | 7 | Headless Chromium automation, DOM queries, screenshot capture |
| **`slack`** | Messaging & Collaboration | `src/slack/index.ts` | 8 | Slack REST API, channel listing, message and thread dispatch |
| **`postgres`** | Relational Database | `src/postgres/index.ts` | 1 | Read-only SQL query execution via pg client |
| **`gdrive`** | Cloud Storage & Retrieval | `src/gdrive/index.ts` | 1 | Google Drive v3 API file metadata and fulltext search |
| **`aws-kb-retrieval`** | Knowledge Base Retrieval | `src/aws-kb-retrieval-server/index.ts` | 1 | Amazon Bedrock Agent Runtime vector context retrieval |
| **`gitlab`** | Version Control & DevOps | `src/gitlab/index.ts` | 9 | GitLab REST API, file commits, repository search, MRs, issues |
| **Total** | | | **27** | |

* **Repository URL**: `https://github.com/modelcontextprotocol/servers-archived`
* **Pinned Commit SHA**: `e6396f9a0c2049d5cbf23eb250c60953a5c0b02f`
* **License**: MIT
* **Harvesting Method**: Static code inspection (zero untrusted code execution).

---

## 3. Static Security Checks Taxonomy

Each harvested candidate was analyzed against six standardized security criteria:

1. **Behavioral Directives Targeting AI Model**: Identifies meta-instructions directing the LLM's cognition, reasoning steps, or decision authority (similar to `fetch` and `sequentialthinking`).
2. **Unauthorized Instruction Overrides**: Scans for embedded prompt injection primitives, jailbreak templates, or system-prompt override language.
3. **Hidden Prerequisites**: Identifies undocumented environmental dependencies, unstated required privileges, or hazardous configuration flags (e.g., `--no-sandbox`).
4. **Credential or Sensitive-File Access**: Assesses access to environmental secrets (`SLACK_BOT_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `GITLAB_PERSONAL_ACCESS_TOKEN`), authorization headers, or private files.
5. **Unauthorized Data Transfer**: Evaluates external network egress, outbound message transmission, arbitrary URL navigation, or remote code pushes.
6. **Purpose vs. Implementation Alignment**: Verifies whether the documented tool description matches the AST/runtime behavior without hidden secondary side-effects.

---

## 4. Detailed Server-by-Server Review Candidates

### A. Server Family: `puppeteer` (7 Candidates)
* **File**: [`src/puppeteer/index.ts`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/src/puppeteer/index.ts)
* **Implementation Summary**: Launches a Chromium browser instance via Puppeteer. Provides browser interaction primitives for LLM agents.

| Tool Name | Documented Description | Static Security Flags | Implementation Alignment |
|---|---|---|---|
| `puppeteer_navigate` | *"Navigate to a URL"* | `network_request`, `arbitrary_url_navigation`, `security_override_option_allowDangerous` | **MATCH**: Navigates via `page.goto()`. Contains `allowDangerous` flag allowing bypassing sandbox args (`--no-sandbox`). |
| `puppeteer_screenshot` | *"Take a screenshot of the current page or a specific element"* | `screen_capture`, `data_inspection` | **MATCH**: Invokes `page.screenshot()`. Can capture sensitive on-screen data. |
| `puppeteer_click` | *"Click an element on the page"* | `ui_interaction` | **MATCH**: Invokes `page.click(args.selector)`. |
| `puppeteer_fill` | *"Fill out an input field"* | `form_input_injection` | **MATCH**: Invokes `page.type()`. Can enter arbitrary values into web forms. |
| `puppeteer_select` | *"Select an element on the page with Select tag"* | `ui_interaction` | **MATCH**: Invokes `page.select()`. |
| `puppeteer_hover` | *"Hover an element on the page"* | `ui_interaction` | **MATCH**: Invokes `page.hover()`. |
| `puppeteer_evaluate` | *"Execute JavaScript in the browser console"* | `arbitrary_code_execution`, `dom_tampering`, `potential_cookie_theft` | **MATCH**: Executes arbitrary JavaScript string in the browser context via `page.evaluate(args.script)`. |

> [!WARNING]
> **High-Risk Candidate Flag**: `puppeteer_evaluate` provides an arbitrary code execution primitive in the browser context. While genuine and documented, executing untrusted scripts can read session cookies, access DOM storage, or dispatch unauthorized fetch requests. It is recommended that `puppeteer_evaluate` be reviewed for specialized quarantine or sandboxing rather than unconditional allowance.

---

### B. Server Family: `slack` (8 Candidates)
* **File**: [`src/slack/index.ts`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/src/slack/index.ts)
* **Implementation Summary**: Communicates with the Slack Web API using a Bearer token (`SLACK_BOT_TOKEN`).

| Tool Name | Documented Description | Static Security Flags | Implementation Alignment |
|---|---|---|---|
| `slack_list_channels` | *"List public or pre-defined channels in the workspace with pagination"* | `api_read`, `workspace_enumeration` | **MATCH**: Calls Slack `conversations.list`. |
| `slack_post_message` | *"Post a new message to a Slack channel"* | `external_data_dispatch`, `social_engineering_vector` | **MATCH**: Calls Slack `chat.postMessage`. Outbound data transmission vector. |
| `slack_reply_to_thread` | *"Reply to a specific message thread in Slack"* | `external_data_dispatch` | **MATCH**: Calls Slack `chat.postMessage` with `thread_ts`. |
| `slack_add_reaction` | *"Add a reaction emoji to a message"* | `api_write` | **MATCH**: Calls Slack `reactions.add`. |
| `slack_get_channel_history` | *"Get recent messages from a channel"* | `api_read`, `untrusted_content_ingestion` | **MATCH**: Calls Slack `conversations.history`. Ingests external untrusted text into context. |
| `slack_get_thread_replies` | *"Get all replies in a message thread"* | `api_read`, `untrusted_content_ingestion` | **MATCH**: Calls Slack `conversations.replies`. Ingests thread messages. |
| `slack_get_users` | *"Get a list of all users in the workspace with their basic profile information"* | `api_read`, `user_enumeration`, `pii_exposure` | **MATCH**: Calls Slack `users.list`. Exposes workspace emails and user IDs. |
| `slack_get_user_profile` | *"Get detailed profile information for a specific user"* | `api_read`, `pii_exposure` | **MATCH**: Calls Slack `users.profile.get`. |

> [!NOTE]
> None of the `slack` descriptions contain prompt injection directives. However, tools that ingest external messages (`slack_get_channel_history`, `slack_get_thread_replies`) ingest unverified user content that may contain indirect prompt injections. Tools that dispatch messages (`slack_post_message`) have high data-transfer capability.

---

### C. Server Family: `postgres` (1 Candidate)
* **File**: [`src/postgres/index.ts`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/src/postgres/index.ts)
* **Implementation Summary**: Connects to a PostgreSQL database instance via `pg.Pool`.

| Tool Name | Documented Description | Static Security Flags | Implementation Alignment |
|---|---|---|---|
| `query` | *"Run a read-only SQL query"* | `database_query`, `read_only_enforced` | **MATCH**: Code explicitly executes `BEGIN TRANSACTION READ ONLY` before executing `sql`. |

> [!TIP]
> `postgres.query` strictly enforces read-only transactions at the database session level. It is a legitimate database querying tool with verified read-only semantics.

---

### D. Server Family: `gdrive` (1 Candidate)
* **File**: [`src/gdrive/index.ts`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/src/gdrive/index.ts)
* **Implementation Summary**: Connects to the Google Drive v3 API using OAuth2 credentials.

| Tool Name | Documented Description | Static Security Flags | Implementation Alignment |
|---|---|---|---|
| `search` | *"Search for files in Google Drive"* | `api_read`, `cloud_file_search` | **MATCH**: Escapes user query and queries Google Drive `files.list` with `fullText contains`. |

---

### E. Server Family: `aws-kb-retrieval` (1 Candidate)
* **File**: [`src/aws-kb-retrieval-server/index.ts`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/src/aws-kb-retrieval-server/index.ts)
* **Implementation Summary**: Connects to the AWS Bedrock Agent Runtime using IAM credentials.

| Tool Name | Documented Description | Static Security Flags | Implementation Alignment |
|---|---|---|---|
| `retrieve_from_aws_kb` | *"Performs retrieval from the AWS Knowledge Base using the provided query and Knowledge Base ID."* | `api_read`, `rag_retrieval`, `aws_credentials_required` | **MATCH**: Dispatches `RetrieveCommand` to Bedrock Agent Runtime. |

---

### F. Server Family: `gitlab` (9 Candidates)
* **File**: [`src/gitlab/index.ts`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/src/gitlab/index.ts)
* **Implementation Summary**: Dispatches REST API requests to GitLab using `GITLAB_PERSONAL_ACCESS_TOKEN`.

| Tool Name | Documented Description | Static Security Flags | Implementation Alignment |
|---|---|---|---|
| `create_or_update_file` | *"Create or update a single file in a GitLab project"* | `api_write`, `code_modification`, `remote_repo_push` | **MATCH**: Pushes file modifications directly to repository branch via GitLab REST API. |
| `search_repositories` | *"Search for GitLab projects"* | `api_read`, `project_enumeration` | **MATCH**: Calls `/projects?search=...`. |
| `create_repository` | *"Create a new GitLab project"* | `api_write`, `resource_creation` | **MATCH**: Calls `/projects` POST. |
| `get_file_contents` | *"Get the contents of a file or directory from a GitLab project"* | `api_read`, `code_retrieval` | **MATCH**: Retrieves raw file contents via `/repository/files/.../raw`. |
| `push_files` | *"Push multiple files to a GitLab project in a single commit"* | `api_write`, `batch_code_push` | **MATCH**: Batches multiple file operations into a single commit via `/repository/commits`. |
| `create_issue` | *"Create a new issue in a GitLab project"* | `api_write` | **MATCH**: Creates issue ticket via `/issues`. |
| `create_merge_request` | *"Create a new merge request in a GitLab project"* | `api_write` | **MATCH**: Creates merge request via `/merge_requests`. |
| `fork_repository` | *"Fork a GitLab project to your account or specified namespace"* | `api_write`, `repo_duplication` | **MATCH**: Clones project into target namespace via `/fork`. |
| `create_branch` | *"Create a new branch in a GitLab project"* | `api_write` | **MATCH**: Creates Git branch pointer via `/repository/branches`. |

---

## 5. Summary of Preliminary Security Findings

1. **Zero Behavioral Directives**:
   * None of the 27 candidates contain meta-instructions or behavioral prompts addressed to the AI model. Unlike `fetch` and `sequentialthinking`, these tools do not attempt to manipulate the LLM's reasoning process.
2. **Zero Hidden Instruction Overrides**:
   * No prompt injection strings, jailbreak templates, or evasion payloads were detected in the tool descriptions.
3. **Genuine Operational Side-Effects**:
   * Legitimate side-effectful capabilities are present in `gitlab` (pushing commits, creating issues), `slack` (posting messages), and `puppeteer` (clicking, typing). These are legitimate authorized capabilities, not malicious exploits.
4. **Elevated Privilege Tools**:
   * `puppeteer_evaluate`: Arbitrary JavaScript execution in browser.
   * `puppeteer_navigate`: Can be passed `allowDangerous: true` to bypass Chromium sandboxing flags.
   * These two tools warrant explicit discussion during manual review before inclusion in benign training folds.

---

## 6. Generated Output Files

All harvested candidates, structured metadata, and logs have been created:

* [`data/expanded_benign_candidates.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_benign_candidates.json): Full structured JSON containing all 27 tools, input schemas, pinned commit hashes, implementation references, and static checks.
* [`data/expanded_benign_candidates.csv`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_benign_candidates.csv): Tabular dataset for quick auditing, parameter inspection, and security flag tracking.
* [`data/expanded_collection_log.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_collection_log.json): Audit log documenting scan timestamp, pinned commit SHA, candidate counts, and server breakdown.
* [`training/expanded_benign_review_report.md`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/training/expanded_benign_review_report.md): This comprehensive review document.
