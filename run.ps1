param(
  [int]$Port = 8000,
  [string]$OutputRoot = "",
  [string]$DataDir = "",
  [string]$ReportsDir = ""
)

$EnvFile = Join-Path $PSScriptRoot ".env"

if (Test-Path $EnvFile) {
  Get-Content $EnvFile | ForEach-Object {
    $line = $_.Trim()

    if ($line -eq "" -or $line.StartsWith("#")) {
      return
    }

    if ($line -match "^\s*([^=]+?)\s*=\s*(.*)\s*$") {
      $name = $matches[1].Trim()
      $value = $matches[2].Trim().Trim('"').Trim("'")
      [Environment]::SetEnvironmentVariable($name, $value, "Process")
    }
  }
}

$OutputRoot = $OutputRoot.Trim()
$DataDir = $DataDir.Trim()
$ReportsDir = $ReportsDir.Trim()
$HasOutputRootOverride = -not [string]::IsNullOrWhiteSpace($OutputRoot)
$HasDataDirOverride = -not [string]::IsNullOrWhiteSpace($DataDir)
$HasReportsDirOverride = -not [string]::IsNullOrWhiteSpace($ReportsDir)

if ($HasOutputRootOverride) {
  [Environment]::SetEnvironmentVariable("SECURE_REVIEW_OUTPUT_ROOT", $OutputRoot, "Process")
}
if ($HasDataDirOverride) {
  [Environment]::SetEnvironmentVariable("SECURE_REVIEW_DATA_DIR", $DataDir, "Process")
} elseif ($HasOutputRootOverride) {
  [Environment]::SetEnvironmentVariable("SECURE_REVIEW_DATA_DIR", (Join-Path $OutputRoot "data"), "Process")
}
if ($HasReportsDirOverride) {
  [Environment]::SetEnvironmentVariable("REPORT_BUNDLE_DIR", $ReportsDir, "Process")
} elseif ($HasOutputRootOverride) {
  [Environment]::SetEnvironmentVariable("REPORT_BUNDLE_DIR", (Join-Path $OutputRoot "reports"), "Process")
}

$DefaultOutputRoot = if (-not [string]::IsNullOrWhiteSpace($env:SECURE_REVIEW_OUTPUT_ROOT)) { $env:SECURE_REVIEW_OUTPUT_ROOT } else { "E:\secure-review" }
[Environment]::SetEnvironmentVariable("SECURE_REVIEW_OUTPUT_ROOT", $DefaultOutputRoot, "Process")
if ([string]::IsNullOrWhiteSpace($env:SECURE_REVIEW_DATA_DIR)) {
  [Environment]::SetEnvironmentVariable("SECURE_REVIEW_DATA_DIR", (Join-Path $DefaultOutputRoot "data"), "Process")
}
if ([string]::IsNullOrWhiteSpace($env:REPORT_BUNDLE_DIR)) {
  [Environment]::SetEnvironmentVariable("REPORT_BUNDLE_DIR", (Join-Path $DefaultOutputRoot "reports"), "Process")
}

& .\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port $Port
