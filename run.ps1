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

& .\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port $Port
