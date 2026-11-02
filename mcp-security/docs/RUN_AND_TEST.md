# Complete Run and Testing Guide: MCP Security Gateway

This guide provides exact, verified PowerShell commands for running every component, testing suite, demonstration scenario, and research evaluation pipeline in the **MCP Security Gateway** project.

---

## 1. Directory & Terminal Conventions

Unless otherwise specified, all commands assume you are in the project root directory:

```powershell
Set-Location -Path "C:\Users\hp\OneDrive\Desktop\mdp-mcp\mcp-security"
```

If using a virtual environment:
```powershell
.\.venv\Scripts\Activate.ps1
```

---

## 2. Project Execution Workflows

### Architectural Note on Gateway Entry Points
The upstream MCP server has a direct CLI entry point ([`server/test_server.py`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/server/test_server.py)). The security gateway core ([`gateway/interceptor.py`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/gateway/interceptor.py)) is implemented as programmatic middleware classes ([`MCPGatewayProxy`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/gateway/interceptor.py#L42-L130), [`MCPGatewayProtocolServer`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/gateway/interceptor.py#L212-L280), and [`MCPGatewayInterceptor`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/gateway/interceptor.py#L65-L210)) rather than a standalone compiled daemon binary. 

To provide a beginner-friendly CLI experience, a dedicated, verified demonstration runner ([`scripts/demo_runner.py`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/scripts/demo_runner.py)) and PowerShell harness ([`scripts/run_demo.ps1`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/scripts/run_demo.ps1)) are provided to orchestrate the client, gateway, and upstream server across all operational lifecycle states.

---

### A. Starting the Upstream MCP Test Server

The upstream test server provides harmless tools with simulated descriptor mutation modes.

- **Folder**: `C:\Users\hp\OneDrive\Desktop\mdp-mcp\mcp-security`
- **Terminal**: Terminal 1
- **Command**:
  ```powershell
  python server/test_server.py --variant baseline --transport stdio
  ```
- **What it does**: Starts the FastMCP server with baseline tool descriptors (`calculate_total`, `search_products`, `get_weather`, `simple_division`) over stdio transport.
- **Expected Output**:
  ```text
  [test_server] Starting server variant 'baseline' via stdio transport...
  ```
- **How you know it succeeded**: The process remains running, waiting for JSON-RPC messages over stdin. Press `Ctrl + C` to stop.

*(To start via SSE transport on port 8765: `python server/test_server.py --variant baseline --transport sse --port 8765`)*

---

### B. Starting the MCP Security Gateway & Proxy

- **Command**:
  ```powershell
  python scripts/demo_runner.py --list-tools
  ```
- **What it does**: Initializes the ML detector, connects to the upstream server, registers baseline cryptographic hashes, inspects all tools, applies the policy engine, and filters the tools list.
- **Expected Output**:
  ```text
  Exposed Tools via Gateway Proxy:
   - search_products: Search product catalog for items matching query keyword...
   - calculate_total: Calculate total order price by summing item costs...
   - get_weather: Retrieve current weather observation data...
   - simple_division: Perform ordinary arithmetic division of number a by number b...
  ```
- **How you know it succeeded**: All 4 baseline tools are verified, approved, and listed. Exit code is 0.

---

### C. Calling an Approved Tool Through the Gateway

- **Command**:
  ```powershell
  python scripts/demo_runner.py --call-tool calculate_total --args '{\"subtotal\": 100.0, \"tax_rate\": 0.05}'
  ```
- **What it does**: Dispatches a `tools/call` request through the gateway. The gateway checks its active authorization table, verifies approval ($0.0007\text{ ms}$ lookup), and forwards the call upstream.
- **Expected Output**:
  ```text
  Calling tool 'calculate_total' with args {'subtotal': 100.0, 'tax_rate': 0.05}...
  Result: ([TextContent(type='text', text='105.0', annotations=None, meta=None)], {'result': 105.0})
  ```
- **How you know it succeeded**: The upstream server executes the arithmetic ($100.0 \times 1.05 = 105.0$) and returns the formatted response.

---

### D. Testing a Brand New (Unapproved) Tool

- **Command**:
  ```powershell
  python scripts/demo_runner.py --scenario 2
  ```
- **What it does**: Simulates an upstream server exposing a brand-new tool (`compute_blake3_hash`) that has never been vetted or approved by an administrator.
- **Expected Output**:
  ```text
  Target Tool: 'compute_blake3_hash' (Brand new, unapproved tool)
  -> Is 'compute_blake3_hash' exposed to client? False
  -> Gateway Decision: [QUARANTINE] (Reason: Description was modified or newly registered...)
  -> Gateway REJECTED execution: Tool execution denied for 'compute_blake3_hash' [QUARANTINE]
  -> Upstream execution count: 0 (Protected)
  RESULT: [QUARANTINE] - New tool safely isolated; never exposed to LLM client.
  ```
- **How you know it succeeded**: The tool is hidden from the client tool catalog, and direct invocation is rejected without reaching upstream.

---

### E. Testing a Modified Tool Description (Descriptor Drift)

- **Command**:
  ```powershell
  python scripts/demo_runner.py --scenario 3
  ```
- **What it does**: Upstream updates `simple_division` documentation to explain error handling. The gateway calculates the SHA-256 hash, detects a hash mismatch against the baseline, evaluates the ML model ($p \approx 0.36$), and quarantines the update.
- **Expected Output**:
  ```text
  -> ML Malicious Probability: 0.3614 (Benign wording)
  -> SHA-256 Hash Status: MISMATCH (Descriptor drift detected)
  -> Gateway Decision: [QUARANTINE]
  -> Gateway BLOCKED invocation: Tool execution denied for 'simple_division' [QUARANTINE]
  RESULT: [QUARANTINE] - Modified tool held for administrator review; not auto-trusted.
  ```
- **How you know it succeeded**: The tool is withheld from client exposure until audited.

---

### F. Testing a Malicious Tool Description (Prompt Injection)

- **Command**:
  ```powershell
  python scripts/demo_runner.py --scenario 4
  ```
- **What it does**: Upstream injects a system override directive into `search_products`. The gateway evaluates mandatory heuristic checks and ML detection ($p \approx 0.53$, flagged as injection).
- **Expected Output**:
  ```text
  -> ML Malicious Probability: 0.5335 (MEDIUM Risk)
  -> Gateway Decision: [BLOCK] (Reason: Mandatory security violation: Prompt injection...)
  RESULT: [BLOCK] - Malicious prompt injection stripped from tool list; LLM never sees injection.
  ```
- **How you know it succeeded**: `search_products` is completely stripped from `tools/list`; client cannot see or call the poisoned tool.

---

### G. Testing a Sensitive Data Exfiltration Attack (23.py)

- **Command**:
  ```powershell
  python scripts/demo_runner.py --scenario 5
  ```
- **What it does**: Simulates the classic MCPTox `23.py` attack where `simple_division` instructs the AI model to read `~/.ssh/id_rsa.pub` and `/etc/shadow`.
- **Expected Output**:
  ```text
  -> Detected Violations: ['Attempts to access or exfiltrate private/public SSH keys', 'Attempts to access system credential files']
  -> ML Malicious Probability: 0.8743
  -> Gateway Decision: [BLOCK]
  RESULT: [BLOCK] - High-severity sensitive file access strictly blocked by heuristic + ML.
  ```
- **How you know it succeeded**: Both heuristic invariants and the supervised ML classifier independently flag the description with $p > 0.85$, triggering an immediate hard block.

---

### H. Testing Direct-Call Bypass Prevention

- **Command**:
  ```powershell
  python scripts/demo_runner.py --scenario 7
  ```
- **What it does**: An attacker attempts to invoke `unregistered_admin_tool` by sending a `tools/call` message directly, intentionally skipping `tools/list`.
- **Expected Output**:
  ```text
  Attack Vector: Direct invocation of uninspected tool 'unregistered_admin_tool'
  Notice: The client intentionally skips tools/list and calls tools/call directly.
  -> Gateway Interceptor Caught Bypass Attempt: Tool execution denied for 'unregistered_admin_tool' [UNREGISTERED]: Tool 'unregistered_admin_tool' was not inspected or approved in tools/list.
  -> Status: REJECTED | Upstream calls: 0
  RESULT: [BLOCKED] - Protocol-level interception enforces fail-closed authorization.
  ```
- **How you know it succeeded**: The interceptor rejects the uninspected call immediately; upstream execution count remains exactly 0.

---

### I. Testing Quarantine & Human Approval Workflow

- **Command**:
  ```powershell
  python scripts/demo_runner.py --scenario 8
  ```
- **What it does**: Demonstrates how an administrator reviews a quarantined tool, approves it via `proxy.approve_tool(...)`, updates the cryptographic registry, and restores the tool to production.
- **Expected Output**:
  ```text
  1. Initial state: Modified simple_division description is quarantined...
     -> Status before approval: [QUARANTINE]
  2. Security Administrator audits tool code, verifies safety, and approves:
     -> Executing: proxy.approve_tool('simple_division', new_description)
  3. Client invokes tools/list again...
     -> 'simple_division' now visible? True
  4. Client executes simple_division...
     -> Execution SUCCESS! Output: 6.0
  RESULT: [TRUSTED] - Cryptographic baseline updated; tool safely restored to production.
  ```
- **How you know it succeeded**: The tool transitions from `QUARANTINE` to `ALLOW`, and subsequent client invocations succeed.

---

### J. Running the Markov Decision Process (MDP) Simulation

- **Command**:
  ```powershell
  python training/train_mdp.py
  ```
- **What it does**: Solves the Bellman optimality equations via Value Iteration, trains an MDP policy via Model-Free Q-Learning in a simulated environment, saves `models/mdp_policy.json`, and runs a 2,000-episode comparative evaluation.
- **Expected Output**:
  ```text
  Optimal Actions Learned per State:
    [0] LOW_RISK_APPROVED                -> Action: ALLOW      (V*=+10.0)
    [1] LOW_RISK_UNVERIFIED              -> Action: QUARANTINE (V*=+4.5)
    [2] MEDIUM_RISK_UNVERIFIED           -> Action: QUARANTINE (V*=+4.5)
    [3] HIGH_RISK_UNVERIFIED             -> Action: BLOCK      (V*=+8.5)
    [4] QUARANTINED_AWAITING_REVIEW      -> Action: QUARANTINE (V*=+6.8)
    [5] REVIEW_CONFIRMED_SAFE            -> Action: ALLOW      (V*=+8.9)
    [6] REVIEW_CONFIRMED_MALICIOUS       -> Action: BLOCK      (V*=+9.7)
  Simulation Comparison over 2000 Independent Episodes:
    MDP Policy Average Reward            : +7.22
    Static Threshold Average Reward      : +7.35
  ```
- **How you know it succeeded**: Value iteration converges in $< 100$ iterations, artifacts are saved to `models/mdp_policy.json`, and comparative rewards are printed.

---

### K. Running the Comparative Policy Evaluation

- **Command**:
  ```powershell
  python training/compare_gateway_policies.py
  ```
- **What it does**: Compares the Static Threshold Policy against the MDP Policy across $7$ gateway operational test cases.
- **Expected Output**: A concordance table displaying ML probabilities, risk categories, and decisions for both policies.

---

### L. Running the Complete Research Evaluation Pipeline

- **Command**:
  ```powershell
  python training/run_corrected_research_evaluation.py
  ```
- **What it does**: Executes the full publication-grade evaluation:
  1. Dataset integrity and leakage audit.
  2. 5-fold StratifiedGroupKFold cross-validation with cluster bootstrap ($1{,}000$ iterations) and Clopper-Pearson CIs.
  3. Independent held-out test evaluation ($N=133$).
  4. Out-of-Distribution evaluation ($N=4$).
  5. Granular latency microbenchmarks across $5$ distinct timing layers.
  6. Multi-seed MDP simulation ($2{,}500$ episodes).
  7. Component ablation matrix across $6$ configurations.
- **Expected Output**: Results written to `training/corrected_research_evaluation_results.json` and a terminal summary.
- **How you know it succeeded**: Exit code is 0; JSON report is refreshed.

---

## 3. Automated Testing Guide

The test suite contains **86 automated tests** providing complete coverage across the protocol, policy engine, ML detector, change detector, dataset integrity, and independent security validation.

### Run All 86 Tests
```powershell
python -m pytest -v
```
Expected output:
```text
============================= 86 passed in 12.06s =============================
```

---

### Run Individual Test Suites

#### 1. Real MCP Protocol End-to-End Tests
Tests actual MCP protocol client-to-gateway-to-server sessions over AnyIO memory streams:
```powershell
python -m pytest tests/test_real_mcp_e2e.py -v
```
*Expected: 2 passed.*

#### 2. Gateway Security Enforcement Scenarios
Tests all 14 gateway security scenarios (normal, drift, injection, exfiltration, direct bypass, fail-closed):
```powershell
python -m pytest tests/test_gateway_security_enforcement.py -v
```
*Expected: 14 passed.*

#### 3. Independent Security Validation
Tests protocol error forwarding, tool mutations, cross-server isolation, Unicode handling, and rollback:
```powershell
python -m pytest tests/test_independent_security_validation.py -v
```
*Expected: 18 passed.*

#### 4. Descriptor Change Detector Tests
Tests SHA-256 hash invariance, normalization, and drift detection:
```powershell
python -m pytest tests/test_change_detector.py -v
```
*Expected: 5 passed.*

#### 5. Machine Learning Detector Tests
Tests text cleaning, feature extraction, drift awareness, and unseen vocabulary handling:
```powershell
python -m pytest tests/test_detector.py -v
```
*Expected: 8 passed.*

#### 6. Policy Engine Tests
Tests ALLOW/QUARANTINE/BLOCK logic, mandatory rule overrides, and MDP dispositions:
```powershell
python -m pytest tests/test_policy.py -v
```
*Expected: 11 passed.*

#### 7. Dataset Validation Tests
Tests schema integrity, binary labels, class balance, and feature leakage prevention:
```powershell
python -m pytest tests/test_dataset.py -v
```
*Expected: 9 passed.*

#### 8. Markov Decision Process (MDP) Tests
Tests value iteration convergence, Q-learning policies, and simulation rewards:
```powershell
python -m pytest tests/test_mdp.py -v
```
*Expected: 6 passed.*

#### 9. Test Server Cases
Tests test server tool registration, side-effect freedom, and controlled variants:
```powershell
python -m pytest tests/test_server_cases.py -v
```
*Expected: 7 passed.*

---

### Run Specific Test Functions by Name

To run a single test function:
```powershell
# Test Scenario 1 (Normal Approved Tool)
python -m pytest tests/test_gateway_security_enforcement.py -k test_scenario_01_normal_approved_tool -v

# Test Scenario 10 (Direct-Call Bypass Attempt)
python -m pytest tests/test_gateway_security_enforcement.py -k test_scenario_10_direct_call_bypass_attempt -v

# Test Real MCP E2E Protocol Session
python -m pytest tests/test_real_mcp_e2e.py -k test_real_mcp_client_to_gateway_to_server_e2e -v
```
