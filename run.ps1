param([int]$Port = 8000)

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

$DefaultOutputRoot = if (-not [string]::IsNullOrWhiteSpace($env:SECURE_REVIEW_OUTPUT_ROOT)) { $env:SECURE_REVIEW_OUTPUT_ROOT } else { "E:\secure-review" }
[Environment]::SetEnvironmentVariable("SECURE_REVIEW_OUTPUT_ROOT", $DefaultOutputRoot, "Process")
if ([string]::IsNullOrWhiteSpace($env:SECURE_REVIEW_DATA_DIR)) {
  [Environment]::SetEnvironmentVariable("SECURE_REVIEW_DATA_DIR", (Join-Path $DefaultOutputRoot "data"), "Process")
}
if ([string]::IsNullOrWhiteSpace($env:REPORT_BUNDLE_DIR)) {
  [Environment]::SetEnvironmentVariable("REPORT_BUNDLE_DIR", (Join-Path $DefaultOutputRoot "reports"), "Process")
}

& .\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port $Port
