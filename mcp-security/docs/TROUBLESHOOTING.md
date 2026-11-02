# Troubleshooting Guide: MCP Security Gateway

This guide provides troubleshooting solutions for common errors encountered when configuring, running, or testing the **MCP Security Gateway**.

---

## 1. Audit Logs & Inspecting Security Decisions

### Where are audit logs stored?
- In standard operations, the gateway's [`AuditLogger`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/gateway/audit_logger.py) writes structured JSON Lines to:
  ```text
  logs/gateway_audit.jsonl
  ```
  *(Or in a temporary directory during isolated test runs).*

### How to inspect recent security events:
Use PowerShell to inspect the last 5 security events:
```powershell
Get-Content logs\gateway_audit.jsonl -Tail 5 | ConvertFrom-Json | Format-Table timestamp, event_type, tool_name, decision, rule_triggered, malicious_probability
```

Sample log entry:
```json
{
  "timestamp": "2026-11-02T01:45:00.123456+00:00",
  "event_type": "TOOL_INSPECTION",
  "server_name": "ProductionServer",
  "tool_name": "search_products",
  "decision": "BLOCK",
  "reason": "Mandatory security violation: Prompt injection targeting AI instruction override",
  "rule_triggered": "RULE_MANDATORY_SECURITY_VIOLATION",
  "new_hash": "a1b2c3...",
  "old_hash": "122392...",
  "malicious_probability": 0.5335,
  "risk_level": "MEDIUM"
}
```

---

## 2. Common Errors and Resolutions

### A. Missing Model Artifacts Error
**Symptom**:
```text
FileNotFoundError: [Errno 2] No such file or directory: '.../models/expanded_detector_model.joblib'
```
**Cause**: The pre-trained model file or vectorizer is missing or was moved.
**Solution**:
1. Verify what files currently exist in `models/`:
   ```powershell
   Get-ChildItem models\
   ```
2. Confirm the presence of:
   - `models/expanded_detector_model.joblib`
   - `models/expanded_vectorizer.joblib`
3. If missing, restore them or verify repository checkout integrity. Never run model evaluation without the trained weights.

---

### B. Python Execution Policy / Script Error on Windows
**Symptom**:
```text
File ...\Activate.ps1 cannot be loaded because running scripts is disabled on this system.
```
**Cause**: Windows PowerShell script execution policy defaults to `Restricted`.
**Solution**:
Run the following in your current PowerShell window:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
Then reactivate:
```powershell
.\.venv\Scripts\Activate.ps1
```

---

### C. Import Error / ModuleNotFoundError: No module named 'gateway'
**Symptom**:
```text
ModuleNotFoundError: No module named 'gateway'
```
**Cause**: Python cannot locate the project root directory in `sys.path`.
**Solution**:
Set the `PYTHONPATH` environment variable in PowerShell:
```powershell
$env:PYTHONPATH = "C:\Users\hp\OneDrive\Desktop\mdp-mcp\mcp-security"
```
Or execute commands with Python module syntax:
```powershell
python -m pytest
```

---

### D. Port Conflict Error on SSE Transport (Port 8765)
**Symptom**:
```text
OSError: [Errno 10048] error while attempting to bind on address ('0.0.0.0', 8765): only one usage of each socket address is normally permitted
```
**Cause**: Another instance of `server/test_server.py` or another application is occupying port 8765.
**Solution**:
1. Identify the process holding port 8765:
   ```powershell
   Get-NetTCPConnection -LocalPort 8765 | Select-Object OwningProcess
   ```
2. Stop the conflicting process:
   ```powershell
   Stop-Process -Id <OwningProcessId> -Force
   ```
3. Or specify a different port when launching:
   ```powershell
   python server/test_server.py --variant baseline --transport sse --port 8790
   ```

---

### E. Distinguishing Gateway Security Denials from Upstream Connection Failures

When a tool call fails, it is critical to determine whether the gateway deliberately blocked it or if the upstream server crashed:

| Failure Mode | Exception Type | Log Message | Meaning |
|---|---|---|---|
| **Gateway Security Denial** | [`ToolExecutionDeniedError`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/gateway/interceptor.py#L27-L40) | `Tool execution denied for 'X' [BLOCK]: Mandatory security violation...` | **Working as intended**. Gateway detected an attack and intentionally prevented upstream execution. |
| **Quarantine Isolation** | [`ToolExecutionDeniedError`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/gateway/interceptor.py#L27-L40) | `Tool execution denied for 'X' [QUARANTINE]: Description was modified...` | **Working as intended**. Tool was newly added or modified and is awaiting review. |
| **Upstream Server Error** | `McpError` / `ToolError` | `subtotal: Field required [type=missing...]` | **Upstream issue**. Gateway allowed the call, but the tool code raised an exception during execution. |
| **Connection Teardown / Stream Failure** | `ClosedResourceError` / `BrokenResourceError` | `Stream has been closed` | **Transport issue**. Upstream process terminated unexpectedly or task group was cancelled. |

---

### F. How to Safely Reset Demo State

If you have approved tools during a demonstration and want to return the gateway to a clean baseline state:

**Safety Rule**: Do **NOT** delete files in `models/` or `data/`.

**Safe Reset Steps**:
1. The demonstration harness ([`scripts/demo_runner.py`](file:///C:/Users/hp/OneDrive/Desktop/mdp-mcp/mcp-security/scripts/demo_runner.py)) automatically uses an isolated temporary directory in memory for every run.
2. If you want to reset persistent test state:
   ```powershell
   # Remove temporary SQLite registry databases if created
   Get-ChildItem -Path . -Filter "*.db" -Recurse | Remove-Item -Force
   
   # Remove temporary test audit logs if created
   if (Test-Path "logs\gateway_audit.jsonl") {
       Remove-Item "logs\gateway_audit.jsonl" -Force
   }
   ```
3. Rerun baseline verification:
   ```powershell
   python scripts/demo_runner.py --scenario 1
   ```
