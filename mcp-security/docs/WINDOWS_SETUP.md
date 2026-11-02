# Windows 11 Setup Guide: MCP Security Gateway

This guide provides step-by-step instructions for setting up, configuring, and verifying the **MCP Security Gateway** project on Windows 11 using PowerShell.

---

## 1. Prerequisites and Required Software

Before starting, ensure the following software is installed on your Windows 11 PC:

| Software | Required Version | Purpose | How to Verify |
|---|---|---|---|
| **Windows OS** | Windows 11 (64-bit) | Operating Environment | Press `Win + R`, type `winver`, press Enter |
| **Python** | Python 3.14.8 (or 3.10+) | Runtime & ML Pipeline | `python --version` |
| **PowerShell** | Windows PowerShell 5.1 or PowerShell 7+ | Command Line Shell | `$PSVersionTable.PSVersion` |
| **VS Code** | Latest (Recommended) | Editor & IDE | `code --version` |

> [!NOTE]
> If `python` is not recognized, ensure that Python is added to your Windows PATH environment variable. In the Python Windows installer, check the box: **"Add python.exe to PATH"**.

---

## 2. Opening the Project Directory

Open Windows Terminal or PowerShell and navigate to the project directory:

```powershell
# Navigate to the project root directory
Set-Location -Path "C:\Users\hp\OneDrive\Desktop\mdp-mcp\mcp-security"

# Verify current directory
Get-Location
```

To open the project in Visual Studio Code:
```powershell
code .
```

---

## 3. Creating & Activating a Virtual Environment

It is recommended practice on Windows to run Python projects within an isolated virtual environment (`.venv`).

### Step 3.1: Enable Script Execution in PowerShell
By default, Windows PowerShell restricts running external scripts. Enable execution for the current terminal session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### Step 3.2: Create Virtual Environment
Create a virtual environment named `.venv` in the project root:

```powershell
python -m venv .venv
```

### Step 3.3: Activate the Virtual Environment
Activate the environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

Once activated, your terminal prompt will display `(.venv)` at the beginning:
```text
(.venv) PS C:\Users\hp\OneDrive\Desktop\mdp-mcp\mcp-security>
```

> [!TIP]
> To deactivate the virtual environment later, simply type:
> ```powershell
> deactivate
> ```

---

## 4. Installing Project Dependencies

With the virtual environment activated, install the required packages:

```powershell
# 1. Upgrade pip to the latest version
python -m pip install --upgrade pip

# 2. Install core project dependencies from requirements.txt
pip install -r requirements.txt

# 3. Ensure scipy is installed (required for exact Clopper-Pearson statistical intervals)
pip install scipy
```

---

## 5. Verifying Installation

Verify that all critical libraries import cleanly without DLL or path errors:

```powershell
python -c "import mcp, sklearn, pandas, numpy, scipy, joblib; print('SUCCESS: All core dependencies imported cleanly!')"
```

Expected output:
```text
SUCCESS: All core dependencies imported cleanly!
```

---

## 6. Verifying Model and Dataset Artifacts

The MCP Security Gateway relies on pre-trained supervised detection models and vetted datasets. Verify their presence using PowerShell:

```powershell
# Check presence of required model and dataset files
$artifacts = @(
    "models\expanded_detector_model.joblib",
    "models\expanded_vectorizer.joblib",
    "data\expanded_experimental_dataset.csv",
    "data\expanded_ood_dataset.json"
)

foreach ($file in $artifacts) {
    if (Test-Path $file) {
        Write-Host " [FOUND] $file" -ForegroundColor Green
    } else {
        Write-Host " [MISSING] $file" -ForegroundColor Red
    }
}
```

Expected output:
```text
 [FOUND] models\expanded_detector_model.joblib
 [FOUND] models\expanded_vectorizer.joblib
 [FOUND] data\expanded_experimental_dataset.csv
 [FOUND] data\expanded_ood_dataset.json
```

Verify that the trained ML detector can be loaded into memory:
```powershell
python -c "import joblib; model = joblib.load('models/expanded_detector_model.joblib'); vec = joblib.load('models/expanded_vectorizer.joblib'); print(f'Detector Ready: {model.__class__.__name__} with {vec.get_feature_names_out().shape[0]} features')"
```

Expected output:
```text
Detector Ready: LogisticRegression with 3000 features
```

---

## 7. Configuring Environment Variables (Optional)

The gateway operates with safe built-in defaults without mandatory environment variables. However, the following optional variables can be configured:

| Variable | Values | Purpose |
|---|---|---|
| `MCPSEC_TEST_VARIANT` | `baseline`, `legitimate_update`, `prompt_injection`, `data_exfiltration`, `suspicious_benign` | Sets default simulation variant for `server/test_server.py` |
| `PYTHONPATH` | `.` | Ensures root folder modules are discoverable |

To set in your current PowerShell session:
```powershell
$env:PYTHONPATH = "C:\Users\hp\OneDrive\Desktop\mdp-mcp\mcp-security"
```

---

## 8. Summary Checklist

You are fully set up when:
1. `python --version` reports Python 3.14.8 (or 3.10+).
2. Virtual environment is active: prompt shows `(.venv)`.
3. `pip list` shows `mcp`, `scikit-learn`, `pandas`, `numpy`, `scipy`, and `pytest`.
4. All $4$ core model and dataset artifacts are verified `[FOUND]`.
5. You can execute `pytest` and see passing tests.
