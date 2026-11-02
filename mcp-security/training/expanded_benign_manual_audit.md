# Manual Security Audit of 27 Expanded MCP Benign Candidates

## 1. Executive Summary

This document presents the manual security audit of all **27 expanded MCP candidate tools** harvested from official Model Context Protocol repositories (`modelcontextprotocol/servers-archived` at pinned commit SHA `e6396f9a0c2049d5cbf23eb250c60953a5c0b02f`).

Each candidate was inspected against its original TypeScript source code, input schema, and execution handler to evaluate purpose-implementation alignment, behavioral directives, unauthorized data transfer risks, and dangerous execution capabilities.

### Audit Summary Statistics
* **Total Candidates Audited**: 27 tools across 6 server families.
* **Approved for Training (`approved_for_training`)**: **25 tools (92.6%)**
  * Standard browser DOM interactions (`puppeteer_screenshot`, `click`, `fill`, `select`, `hover`).
  * Workspace communication & enumeration tools (`slack_list_channels`, `post_message`, `reply_to_thread`, `add_reaction`, `get_channel_history`, `get_thread_replies`, `get_users`, `get_user_profile`).
  * Verified read-only relational database queries (`postgres.query`).
  * Cloud storage file discovery (`gdrive.search`).
  * Context retrieval from enterprise knowledge bases (`aws-kb-retrieval.retrieve_from_aws_kb`).
  * GitLab DevOps repository, branch, MR, and issue management (`gitlab` 9 tools).
* **Special Handling (`special_handling`)**: **2 tools (7.4%)**
  * `puppeteer_evaluate`: Unconstrained JavaScript execution in the browser context.
  * `puppeteer_navigate`: Arbitrary URL navigation combined with an explicit `allowDangerous` security bypass flag.
* **Rejected (`rejected`)**: **0 tools (0.0%)**
  * None of the 27 official tools contain deceptive backdoors, trojan payloads, or adversarial prompt injections.

The audited records are preserved in [`data/expanded_benign_reviewed.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_benign_reviewed.json). The original collected dataset [`data/expanded_benign_candidates.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/expanded_benign_candidates.json) remains unmodified.

---

## 2. Audit Framework & Classification Taxonomy

The audit distinguishes between five capability categories:

1. **Legitimate Operational Side Effects**: Actions like pushing a Git commit, posting a Slack message, or clicking a button. These are the stated, intended purpose of the server and are safe for ML training.
2. **Dangerous but Documented Capabilities**: Tools that grant high-privilege primitives (arbitrary script execution, security sandbox overrides). These require runtime isolation and policy rules.
3. **Suspicious Hidden Behavior**: Undocumented network calls, unstated file reads, or mismatched implementations.
4. **Behavioral Directives Targeting AI Cognition**: Meta-prompts that instruct the model to alter its persona, ignore safety guidelines, or suppress user disclosures (such as `fetch` and `sequentialthinking`).
5. **Unauthorized Data Access or Transfer**: Covert data exfiltration or access to environmental secrets outside the tool's documented scope.

---

## 3. Deep-Dive on Special Attention Candidates

### A. `puppeteer_evaluate`
* **Server**: `puppeteer` | **Decision**: `special_handling`
* **Description**: *"Execute JavaScript in the browser console"*
* **Implementation Evidence**: [`src/puppeteer/index.ts#L387-L414`](https://github.com/modelcontextprotocol/servers-archived/blob/e6396f9a0c2049d5cbf23eb250c60953a5c0b02f/src/puppeteer/index.ts#L387-L414) executes `await page.evaluate(args.script)` and captures console output.
* **Security Concerns**:
  * **Arbitrary Code Execution**: In a web browser session, arbitrary JavaScript execution allows reading session cookies (`document.cookie`), accessing `localStorage` and `sessionStorage`, rewriting the DOM, or dispatching unauthorized asynchronous requests (`fetch()`) to internal LAN services from the authenticated browser context.
* **Reviewer Rationale**: The implementation matches its documentation, but teaching an ML detector that "Execute JavaScript" is standard benign language risks desensitizing the gateway to malicious remote code execution payloads. **Recommendation**: Hold in a quarantine/sandboxed policy tier; do not mix into ordinary unconstrained training folds without policy safeguards.

### B. `puppeteer_navigate`
* **Server**: `puppeteer` | **Decision**: `special_handling`
* **Description**: *"Navigate to a URL"*
* **Implementation Evidence**: [`src/puppeteer/index.ts#L122`](https://github.com/modelcontextprotocol/servers-archived/blob/e6396f9a0c2049d5cbf23eb250c60953a5c0b02f/src/puppeteer/index.ts#L122) accepts `allowDangerous: boolean`. Lines 150–165 check against `DANGEROUS_ARGS` (`--no-sandbox`, `--disable-web-security`, `--allow-running-insecure-content`), but permit the caller to override security checks when `allowDangerous: true`. Line 279 executes `await page.goto(args.url)`.
* **Security Concerns**:
  * **SSRF (Server-Side Request Forgery)**: Arbitrary navigation allows probing internal network interfaces (e.g., `http://169.254.169.254/latest/meta-data/` in cloud deployments).
  * **Sandbox Disablement**: Callers can disable browser process sandboxing.
* **Reviewer Rationale**: Legitimate tool, but its parameter structure includes an explicit security override. **Recommendation**: Requires gateway policy constraints that reject `allowDangerous: true` and block private IP address ranges.

### C. `slack_post_message` & `slack_reply_to_thread`
* **Server**: `slack` | **Decision**: `approved_for_training`
* **Descriptions**:
  * `slack_post_message`: *"Post a new message to a Slack channel"*
  * `slack_reply_to_thread`: *"Reply to a specific message thread in Slack"*
* **Implementation Evidence**: Calls Slack Web API `chat.postMessage` using `channel_id` and `text`.
* **Security Concerns**: Outbound network communication could theoretically be abused for data exfiltration if an LLM is hijacked by an indirect prompt injection.
* **Reviewer Rationale**: Network transmission is the core purpose of a messaging server. Labeling legitimate messaging APIs as malicious would lead to catastrophic false-positive rates on all communication tools. Inclusion in training helps the model recognize standard collaboration verbs (`post`, `channel`, `message`). Data exfiltration prevention is best enforced at runtime via DLP policies rather than classifying standard communication verbs as malicious.

### D. `gitlab_create_or_update_file` & `gitlab_push_files`
* **Server**: `gitlab` | **Decision**: `approved_for_training`
* **Descriptions**:
  * `create_or_update_file`: *"Create or update a single file in a GitLab project"*
  * `push_files`: *"Push multiple files to a GitLab project in a single commit"*
* **Implementation Evidence**: Calls GitLab REST endpoints `POST/PUT /projects/:id/repository/files/:file_path` and `POST /projects/:id/repository/commits`.
* **Security Concerns**: Code modification capabilities on remote repositories.
* **Reviewer Rationale**: Authoring code and pushing commits is the intended operational purpose of a DevOps server. The descriptions are concise, technical, and match the underlying code verbatim. Training on these records teaches the detector that standard Git commit vocabulary is legitimate.

---

## 4. Comprehensive Audit Table (All 27 Candidates)

| # | Candidate ID | Server | Tool Name | Audit Decision | Key Evidence / Source Line | Identified Security Concerns |
|:---:|---|---|---|:---:|---|---|
| 1 | `mcp_puppeteer_puppeteer_navigate` | `puppeteer` | `puppeteer_navigate` | **`special_handling`** | `index.ts#L279` `page.goto()`; `allowDangerous` at `L122` | SSRF risk; caller-specified sandbox bypass |
| 2 | `mcp_puppeteer_puppeteer_screenshot` | `puppeteer` | `puppeteer_screenshot` | **`approved_for_training`** | `index.ts#L292` `page.screenshot()` | Screen buffer inspection; no active side effects |
| 3 | `mcp_puppeteer_puppeteer_click` | `puppeteer` | `puppeteer_click` | **`approved_for_training`** | `index.ts#L320` `page.click(selector)` | Active DOM UI click event |
| 4 | `mcp_puppeteer_puppeteer_fill` | `puppeteer` | `puppeteer_fill` | **`approved_for_training`** | `index.ts#L337` `page.type(selector, value)` | Form input typing; standard automation |
| 5 | `mcp_puppeteer_puppeteer_select` | `puppeteer` | `puppeteer_select` | **`approved_for_training`** | `index.ts#L354` `page.select(selector, value)` | Select dropdown value change |
| 6 | `mcp_puppeteer_puppeteer_hover` | `puppeteer` | `puppeteer_hover` | **`approved_for_training`** | `index.ts#L371` `page.hover(selector)` | Mouse hover event simulation |
| 7 | `mcp_puppeteer_puppeteer_evaluate` | `puppeteer` | `puppeteer_evaluate` | **`special_handling`** | `index.ts#L387` `page.evaluate(script)` | Unconstrained JavaScript execution; cookie/DOM access |
| 8 | `mcp_slack_slack_list_channels` | `slack` | `slack_list_channels` | **`approved_for_training`** | `index.ts` `conversations.list` API | Read-only public channel enumeration |
| 9 | `mcp_slack_slack_post_message` | `slack` | `slack_post_message` | **`approved_for_training`** | `index.ts` `chat.postMessage` API | Outbound message transmission |
| 10 | `mcp_slack_slack_reply_to_thread` | `slack` | `slack_reply_to_thread` | **`approved_for_training`** | `index.ts` `chat.postMessage` with `thread_ts` | Outbound message transmission to thread |
| 11 | `mcp_slack_slack_add_reaction` | `slack` | `slack_add_reaction` | **`approved_for_training`** | `index.ts` `reactions.add` API | Emoji reaction write; minimal impact |
| 12 | `mcp_slack_slack_get_channel_history` | `slack` | `slack_get_channel_history` | **`approved_for_training`** | `index.ts` `conversations.history` API | Ingests untrusted external user text into context |
| 13 | `mcp_slack_slack_get_thread_replies` | `slack` | `slack_get_thread_replies` | **`approved_for_training`** | `index.ts` `conversations.replies` API | Ingests untrusted thread replies into context |
| 14 | `mcp_slack_slack_get_users` | `slack` | `slack_get_users` | **`approved_for_training`** | `index.ts` `users.list` API | User directory enumeration (PII exposure) |
| 15 | `mcp_slack_slack_get_user_profile` | `slack` | `slack_get_user_profile` | **`approved_for_training`** | `index.ts` `users.profile.get` API | Detailed user profile metadata retrieval |
| 16 | `mcp_postgres_query` | `postgres` | `query` | **`approved_for_training`** | `index.ts` `BEGIN TRANSACTION READ ONLY` | Read-only database query; write protection enforced |
| 17 | `mcp_gdrive_search` | `gdrive` | `search` | **`approved_for_training`** | `index.ts` `drive.files.list` with query escaping | Cloud document discovery; sanitized input |
| 18 | `mcp_aws-kb-retrieval_retrieve_from_aws_kb` | `aws-kb-retrieval` | `retrieve_from_aws_kb` | **`approved_for_training`** | `index.ts` Bedrock `RetrieveCommand` | Context retrieval from enterprise RAG |
| 19 | `mcp_gitlab_create_or_update_file` | `gitlab` | `create_or_update_file` | **`approved_for_training`** | `index.ts` `POST/PUT /repository/files` | Remote source file authoring/modification |
| 20 | `mcp_gitlab_search_repositories` | `gitlab` | `search_repositories` | **`approved_for_training`** | `index.ts` `GET /projects?search=` | Repository project search |
| 21 | `mcp_gitlab_create_repository` | `gitlab` | `create_repository` | **`approved_for_training`** | `index.ts` `POST /projects` | Remote Git repository creation |
| 22 | `mcp_gitlab_get_file_contents` | `gitlab` | `get_file_contents` | **`approved_for_training`** | `index.ts` `GET /repository/files/.../raw` | Read-only source code inspection |
| 23 | `mcp_gitlab_push_files` | `gitlab` | `push_files` | **`approved_for_training`** | `index.ts` `POST /repository/commits` | Multi-file batch code commit |
| 24 | `mcp_gitlab_create_issue` | `gitlab` | `create_issue` | **`approved_for_training`** | `index.ts` `POST /issues` | Issue ticket creation |
| 25 | `mcp_gitlab_create_merge_request` | `gitlab` | `create_merge_request` | **`approved_for_training`** | `index.ts` `POST /merge_requests` | Pull/merge request initiation |
| 26 | `mcp_gitlab_fork_repository` | `gitlab` | `fork_repository` | **`approved_for_training`** | `index.ts` `POST /fork` | Project repository forking |
| 27 | `mcp_gitlab_create_branch` | `gitlab` | `create_branch` | **`approved_for_training`** | `index.ts` `POST /repository/branches` | Git branch creation |

---

## 5. Reviewer Recommendations for Gateway & Training Integration

1. **Training Dataset Integration**:
   * The **25 tools marked `approved_for_training`** are recommended for inclusion in the expanded benign dataset.
   * Combining these 25 tools with the existing 28 reviewed benign records increases the benign corpus to **53 genuine tools across 13 diverse server families** (eliminating the severe 17:1 class imbalance).
2. **Quarantine / Special Handling Policy for Elevated Primitives**:
   * The **2 tools marked `special_handling`** (`puppeteer_evaluate` and `puppeteer_navigate`) should **not** be included in naive baseline training.
   * Instead, they should be routed to a designated **High-Capability Policy Tier** in the Security Gateway:
     * `puppeteer_evaluate`: Mandatory policy interceptor requiring administrative pre-approval before arbitrary JS execution.
     * `puppeteer_navigate`: Gateway URL filter rejecting private IP addresses (preventing SSRF) and disallowing `allowDangerous: true`.
3. **Preservation of Isolation**:
   * Original datasets (`combined_experimental_dataset.csv`, `ood_evaluation_dataset.json`) and existing trained models remain strictly untouched.
