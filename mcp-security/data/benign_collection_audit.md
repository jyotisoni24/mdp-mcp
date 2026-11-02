# MCP Security Gateway: 30-Candidate Benign Collection Quality Audit

**Audit Date**: 2026-11-01  
**Auditor**: Senior ML & Cybersecurity Researcher  
**Target Dataset**: [`data/reviewed_benign.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/reviewed_benign.json)  
**Output Schema**: [`data/benign_collection_audit.json`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/data/benign_collection_audit.json)  

---

## 1. Executive Summary & Audit Dashboard

| Metric | Count / Percentage | Status / Finding |
|---|---|---|
| **Total Candidates Evaluated** | **30** | Complete evaluation of curated pool |
| **Verified Standard Benign** | **28 (93.3%)** | Full provenance & safe utility semantics |
| **Needing Re-Review / Segregation** | **2 (6.7%)** | `fetch` and `sequentialthinking` |
| **Behavioral Directives Present** | **2 (6.7%)** | Contain second-person AI instructions |
| **Side-Effectful Tools (Write/Mutate)** | **9 (30.0%)** | Verified legitimate; non-malicious |
| **Read-Only / Pure Tools** | **21 (70.0%)** | Inspection, retrieval, and conversion |
| **Provenance Completeness** | **100.0%** | 0 missing repository URLs, commits, or files |
| **Exact Duplicates** | **0** | Zero identical descriptions |
| **Near-Duplicate Lexical Groups** | **2** | Co-occurring API tools in same server |
| **Server Families Represented** | **9** | Grouped for leak-resistant GroupKFold |
| **Training Suitability Verdict** | **CONDITIONALLY_SUITABLE** | Safe to proceed under defined isolation protocol |

---

## 2. Complete Record Verification Table

| # | Candidate ID | Tool Name | Server Family | Category | Type | Directives? | Verification Status |
|---|---|---|---|---|---|---|---|
| 1 | `mcp_filesystem_read_text_file` | `read_text_file` | `filesystem` | Local Filesystem | Read-Only | No | `VERIFIED_BENIGN` |
| 2 | `mcp_filesystem_write_file` | `write_file` | `filesystem` | Local Filesystem | Write / Mutate | No | `VERIFIED_BENIGN` |
| 3 | `mcp_filesystem_list_directory` | `list_directory` | `filesystem` | Local Filesystem | Read-Only | No | `VERIFIED_BENIGN` |
| 4 | `mcp_filesystem_directory_tree` | `directory_tree` | `filesystem` | Local Filesystem | Read-Only | No | `VERIFIED_BENIGN` |
| 5 | `mcp_filesystem_search_files` | `search_files` | `filesystem` | Local Filesystem | Read-Only | No | `VERIFIED_BENIGN` |
| 6 | `mcp_git_git_status` | `git_status` | `git` | Version Control | Read-Only | No | `VERIFIED_BENIGN` |
| 7 | `mcp_git_git_diff_unstaged` | `git_diff_unstaged` | `git` | Version Control | Read-Only | No | `VERIFIED_BENIGN` |
| 8 | `mcp_git_git_commit` | `git_commit` | `git` | Version Control | Write / Mutate | No | `VERIFIED_BENIGN` |
| 9 | `mcp_git_git_add` | `git_add` | `git` | Version Control | Write / Mutate | No | `VERIFIED_BENIGN` |
| 10 | `mcp_git_git_log` | `git_log` | `git` | Version Control | Read-Only | No | `VERIFIED_BENIGN` |
| 11 | `mcp_fetch_fetch` | `fetch` | `fetch` | Web Retrieval | Read-Only | ⚠️ **YES** | `NEEDS_RE_REVIEW_BEFORE_TRAINING` |
| 12 | `mcp_brave-search_brave_web_search` | `brave_web_search` | `brave-search` | Web Search | Read-Only | No | `VERIFIED_BENIGN` |
| 13 | `mcp_brave-search_brave_local_search` | `brave_local_search` | `brave-search` | Web Search | Read-Only | No | `VERIFIED_BENIGN` |
| 14 | `mcp_sqlite_read_query` | `read_query` | `sqlite` | Relational Database | Read-Only | No | `VERIFIED_BENIGN` |
| 15 | `mcp_sqlite_write_query` | `write_query` | `sqlite` | Relational Database | Write / Mutate | No | `VERIFIED_BENIGN` |
| 16 | `mcp_sqlite_list_tables` | `list_tables` | `sqlite` | Relational Database | Read-Only | No | `VERIFIED_BENIGN` |
| 17 | `mcp_sqlite_describe_table` | `describe_table` | `sqlite` | Relational Database | Read-Only | No | `VERIFIED_BENIGN` |
| 18 | `mcp_memory_create_entities` | `create_entities` | `memory` | Knowledge Graph | Write / Mutate | No | `VERIFIED_BENIGN` |
| 19 | `mcp_memory_create_relations` | `create_relations` | `memory` | Knowledge Graph | Write / Mutate | No | `VERIFIED_BENIGN` |
| 20 | `mcp_memory_add_observations` | `add_observations` | `memory` | Knowledge Graph | Write / Mutate | No | `VERIFIED_BENIGN` |
| 21 | `mcp_memory_read_graph` | `read_graph` | `memory` | Knowledge Graph | Read-Only | No | `VERIFIED_BENIGN` |
| 22 | `mcp_memory_search_nodes` | `search_nodes` | `memory` | Knowledge Graph | Read-Only | No | `VERIFIED_BENIGN` |
| 23 | `mcp_time_get_current_time` | `get_current_time` | `time` | System Utilities | Read-Only | No | `VERIFIED_BENIGN` |
| 24 | `mcp_time_convert_time` | `convert_time` | `time` | System Utilities | Read-Only | No | `VERIFIED_BENIGN` |
| 25 | `mcp_sequentialthinking_sequentialthinking` | `sequentialthinking` | `sequentialthinking` | Reasoning | Read-Only | ⚠️ **YES** | `NEEDS_RE_REVIEW_BEFORE_TRAINING` |
| 26 | `mcp_github_search_repositories` | `search_repositories` | `github` | DevOps & Repositories | Read-Only | No | `VERIFIED_BENIGN` |
| 27 | `mcp_github_get_file_contents` | `get_file_contents` | `github` | DevOps & Repositories | Read-Only | No | `VERIFIED_BENIGN` |
| 28 | `mcp_github_create_issue` | `create_issue` | `github` | DevOps & Repositories | Write / Mutate | No | `VERIFIED_BENIGN` |
| 29 | `mcp_github_create_pull_request` | `create_pull_request` | `github` | DevOps & Repositories | Write / Mutate | No | `VERIFIED_BENIGN` |
| 30 | `mcp_github_list_commits` | `list_commits` | `github` | DevOps & Repositories | Read-Only | No | `VERIFIED_BENIGN` |

---

## 3. Deep-Dive on Behavioral Directives

Two records in this collection incorporate second-person directives directed at the AI model. While originating from authentic, official reference MCP servers, their phrasing presents unique machine learning risks.

### Tool: `fetch` (Server: `fetch`)

- **Finding**: Explicit second-person prompt instruction: 'Although originally you did not have internet access, and were advised to refuse and tell the user this, this tool now grants you internet access. Now you can fetch the most up-to-date information and let the user know that.'
- **Cybersecurity Analysis**: While originating from Anthropic's official MCP reference server, this docstring employs model-steering prompt engineering that syntactically mimics jailbreak/directive override framing. If included as a benign training example without careful handling, it risks teaching the classifier that constraint-override phrasing is benign, or causing false positives during inference.
- **Protocol Recommendation**: Exclude from baseline training set; use as an out-of-distribution adversarial evaluation test case.

### Tool: `sequentialthinking` (Server: `sequentialthinking`)

- **Finding**: Contains 11 numbered procedural rules directed to the model ('You should:', 'Ignore information that is irrelevant', 'Provide a single... answer', 'Only set nextThoughtNeeded to false when truly done'). Description length: 2,781 characters.
- **Cybersecurity Analysis**: Legitimate meta-cognitive reasoning tool. Contains directive verbs ('ignore', 'should', 'provide') and extreme text length (2.7KB). In TF-IDF models, this disproportionately shifts word frequency vectors and introduces imperative tokens.
- **Protocol Recommendation**: Exclude from standard TF-IDF training split; preserve as a dedicated long-context reasoning benchmark case.

---

## 4. Side-Effectful Tools Verification

A common pitfall in tool security analysis is conflating *mutating actions* (writing a file, creating a database row, making a git commit) with *maliciousness*. In an MCP environment, tools exist precisely to perform authorized system tasks.

All 9 side-effectful tools in this collection were audited against their upstream implementations:

| Tool Name | Server | Mutation Target | Operation | Implementation Safety Check |
|---|---|---|---|---|
| `write_file` | `write` | Local Filesystem | File Creation / Overwrite | Verified: Uses standard fs.writeFile within authorized directory boundaries. Free of unauthorized exfiltration or hidden subprocess spawning. |
| `git_commit` | `git` | Local Git Repository | Git Commit Creation | Verified: Calls git.commit with user-supplied commit message. Legitimate version control operation. |
| `git_add` | `git` | Local Git Staging Area | Git Staging | Verified: Calls git.add to stage files for commit. Legitimate version control operation. |
| `write_query` | `write` | SQLite Database | SQL INSERT/UPDATE/DELETE | Verified: Executes standard SQL DML statements on user's local database. Legitimate database administration. |
| `create_entities` | `create` | Knowledge Graph Storage | Graph Entity Insertion | Verified: Updates in-memory/JSON knowledge graph nodes. Side-effect is restricted to graph memory. |
| `create_relations` | `create` | Knowledge Graph Storage | Graph Edge Insertion | Verified: Links knowledge graph nodes. Legitimate semantic memory tool. |
| `add_observations` | `add` | Knowledge Graph Storage | Entity Observation Insertion | Verified: Appends observation strings to existing entities in knowledge graph. |
| `create_issue` | `create` | GitHub Repository Issues | Issue Creation via GitHub API | Verified: Makes authenticated GitHub API POST request to /repos/{owner}/{repo}/issues. Authorized API operation. |
| `create_pull_request` | `create` | GitHub Repository Pull Requests | PR Creation via GitHub API | Verified: Makes authenticated GitHub API POST request to create pull request. Authorized API operation. |

**Conclusion**: None of these tools contain unauthorized exfiltration channels, hidden background commands, or prompt overrides. Their side-effects are entirely legitimate and intended.

---

## 5. Server-Family Grouping & Near-Duplicate Analysis

To prevent data leakage during train/test splits, tools belonging to the same server must not be split across training and evaluation splits.

### Server Families:

- **`filesystem`** (5 tools): `read_text_file`, `write_file`, `list_directory`, `directory_tree`, `search_files`
- **`git`** (5 tools): `git_status`, `git_diff_unstaged`, `git_commit`, `git_add`, `git_log`
- **`fetch`** (1 tools): `fetch`
- **`brave-search`** (2 tools): `brave_web_search`, `brave_local_search`
- **`sqlite`** (4 tools): `read_query`, `write_query`, `list_tables`, `describe_table`
- **`memory`** (5 tools): `create_entities`, `create_relations`, `add_observations`, `read_graph`, `search_nodes`
- **`time`** (2 tools): `get_current_time`, `convert_time`
- **`sequentialthinking`** (1 tools): `sequentialthinking`
- **`github`** (5 tools): `search_repositories`, `get_file_contents`, `create_issue`, `create_pull_request`, `list_commits`

### High Lexical Similarity Pairs:

- **Group ND-01** (`create_issue` & `create_pull_request`): Cosine Similarity = **0.511**  
  *Risk Assessment*: Co-occurring API mutation tools with similar wording. Must be assigned together to either train or test split to prevent lexical leakage.

- **Group ND-02** (`read_query` & `write_query`): Cosine Similarity = **0.507**  
  *Risk Assessment*: Co-occurring database query execution tools. Must be grouped under 'sqlite' server family during GroupKFold splits.

---

## 6. Provenance & License Audit

- **Repository URLs**: 100% verified (`https://github.com/modelcontextprotocol/servers` and `https://github.com/modelcontextprotocol/servers-archived`).
- **Commit Hashes**: Verified against exact Git commits (`194cc86e3ae6400958555bd4116849d822d69263` and `e6396f9a0c2049d5cbf23eb250c60953a5c0b02f`).
- **Source Files**: 100% mapped to concrete TypeScript/Python files (`server.ts`, `index.ts`, `server.py`).
- **Licenses**: All 30 tools are licensed under the permissive **MIT License**.
- **Missing Provenance**: **0** records.

---

## 7. Suitability for First Experimental Training Run

### Verdict: **`CONDITIONALLY SUITABLE`**

This curated collection is superior to the previous 200 synthetic safe examples because it contains authentic, human-authored MCP descriptions from real-world servers. However, to preserve training validity, the following 3 rules must be enforced:

* 1. Group-Disjoint Splitting: When combining with the training set, splits must be grouped by 'server_name' (e.g. GroupKFold) to prevent near-duplicate leakage between companion tools.
* 2. Directive Segregation: The 2 tools with behavioral directives ('fetch' and 'sequentialthinking') must NOT be mixed into the standard training split as ordinary label=0 examples. They should be held out for adversarial stress-testing.
* 3. Balanced Weighting: The remaining 28 authentic tools provide diverse, real-world MCP descriptions that reduce the synthetic boilerplate bias of the original 200 synthetic safe examples.