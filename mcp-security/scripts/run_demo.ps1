<#
.SYNOPSIS
    One-Command Safe Demonstration Runner for MCP Security Gateway.
.DESCRIPTION
    Verifies Python environment, checks required ML model and dataset artifacts,
    and executes all 9 security enforcement demonstration scenarios in an isolated,
    temporary test environment without altering production registry state.
.EXAMPLE
    .\scripts\run_demo.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $ProjectRoot

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "       MCP SECURITY GATEWAY - AUTOMATED DEMONSTRATION HARNESS          " -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "Project Root : $ProjectRoot"

# 1. Verify Python Installation
Write-Host "`n[1/4] Verifying Python Environment..." -ForegroundColor Yellow
try {
    $pythonVersion = & python --version 2>&1
    Write-Host "  -> Detected: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Error "Python executable not found in PATH. Please install Python 3.14+ and add it to PATH."
    exit 1
}

# Check for virtual environment activation if available
$venvActivate = Join-Path $ProjectRoot ".venv\Scripts\Activate.ps1"
if (Test-Path $venvActivate) {
    Write-Host "  -> Activating virtual environment: .venv" -ForegroundColor Green
    & $venvActivate
}

# 2. Verify Core Artifacts
Write-Host "`n[2/4] Verifying Trained Artifacts and Datasets..." -ForegroundColor Yellow
$RequiredArtifacts = @(
    "models\expanded_detector_model.joblib",
    "models\expanded_vectorizer.joblib",
    "data\expanded_experimental_dataset.csv"
)

$allPresent = $true
foreach ($artifact in $RequiredArtifacts) {
    $fullPath = Join-Path $ProjectRoot $artifact
    if (Test-Path $fullPath) {
        Write-Host "  [OK] $artifact" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] $artifact" -ForegroundColor Red
        $allPresent = $false
    }
}

if (-not $allPresent) {
    Write-Error "One or more required model artifacts are missing. Ensure models/ is intact."
    exit 1
}

# 3. Execute Demonstration Runner
Write-Host "`n[3/4] Running Security Enforcement Scenarios..." -ForegroundColor Yellow
$runnerScript = Join-Path $ProjectRoot "scripts\demo_runner.py"

try {
    & python $runnerScript --all
    $exitCode = $LASTEXITCODE
} catch {
    Write-Host "Error occurred while executing demonstration scenarios." -ForegroundColor Red
    $exitCode = 1
}

# 4. Result Summary and Exit
Write-Host "`n[4/4] Demonstration Summary:" -ForegroundColor Yellow
if ($exitCode -eq 0) {
    Write-Host "  -> ALL 9 SCENARIOS VERIFIED SUCCESSFULLY." -ForegroundColor Green
    Write-Host "  -> Policy Actions Demonstrated:" -ForegroundColor Cyan
    Write-Host "     * ALLOW       : Baseline matched, low ML risk" -ForegroundColor Green
    Write-Host "     * QUARANTINE  : Unverified drift or new tools isolated" -ForegroundColor Yellow
    Write-Host "     * BLOCK       : Prompt injection, credential exfiltration, direct bypass blocked" -ForegroundColor Red
    Write-Host "  -> Demonstration state was isolated; production registry was preserved."
    exit 0
} else {
    Write-Host "  -> DEMONSTRATION FAILED WITH EXIT CODE $exitCode." -ForegroundColor Red
    exit $exitCode
}
