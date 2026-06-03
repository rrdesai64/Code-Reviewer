param(
  [Parameter(Mandatory=$true)][string]$ScanId,
  [Parameter(Mandatory=$true)][string]$GitHubUrl,
  [string]$ApiBaseUrl = "http://127.0.0.1:8000",
  [string]$OutDir = "E:\secure-review\saved-scan-validation",
  [string]$BearerToken = "",
  [string]$RunId = "",
  [switch]$FailFast
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-FullPath {
  param([Parameter(Mandatory=$true)][string]$Path)
  return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function ConvertTo-SafeName {
  param([Parameter(Mandatory=$true)][string]$Value)

  $safe = $Value -replace '[^A-Za-z0-9._-]+', '_'
  $safe = $safe.Trim(' ', '.', '_', '-')
  if ([string]::IsNullOrWhiteSpace($safe)) {
    return "repository"
  }
  return $safe
}

function Get-RepoKey {
  param([Parameter(Mandatory=$true)][string]$Url)

  $trimmed = $Url.Trim().TrimEnd('/')
  $trimmed = $trimmed -replace '\.git$', ''
  if ($trimmed -match 'github\.com[:/](?<owner>[^/\s:]+)/(?<repo>[^/\s:]+)$') {
    return ConvertTo-SafeName "$($Matches.owner)__$($Matches.repo)"
  }
  return ConvertTo-SafeName $trimmed
}

function New-ApiHeaders {
  $headers = @{}
  if (-not [string]::IsNullOrWhiteSpace($BearerToken)) {
    $headers["Authorization"] = "Bearer $BearerToken"
  }
  return $headers
}

function New-ApiUri {
  param([Parameter(Mandatory=$true)][string]$Path)

  $base = $ApiBaseUrl.TrimEnd('/')
  return "$base$Path"
}

function Write-JsonFile {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)]$Value
  )

  $Value | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Invoke-JsonGet {
  param(
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$FileName
  )

  $uri = New-ApiUri $Path
  Write-Host "GET  $Path"
  try {
    $payload = Invoke-RestMethod -Method Get -Uri $uri -Headers (New-ApiHeaders)
    Write-JsonFile -Path (Join-Path $RunDir $FileName) -Value $payload
    return [pscustomobject]@{
      name = $Name
      method = "GET"
      path = $Path
      file = $FileName
      status = "passed"
      error = ""
    }
  } catch {
    $errorText = $_.Exception.Message
    Write-Warning "GET failed for ${Path}: $errorText"
    if ($FailFast) {
      throw
    }
    return [pscustomobject]@{
      name = $Name
      method = "GET"
      path = $Path
      file = $FileName
      status = "failed"
      error = $errorText
    }
  }
}

function Invoke-JsonPost {
  param(
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)]$Body,
    [Parameter(Mandatory=$true)][string]$FileName
  )

  $uri = New-ApiUri $Path
  $headers = New-ApiHeaders
  $headers["Content-Type"] = "application/json"
  Write-Host "POST $Path"
  try {
    $jsonBody = $Body | ConvertTo-Json -Depth 50
    $payload = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $jsonBody
    Write-JsonFile -Path (Join-Path $RunDir $FileName) -Value $payload
    return [pscustomobject]@{
      name = $Name
      method = "POST"
      path = $Path
      file = $FileName
      status = "passed"
      error = ""
    }
  } catch {
    $errorText = $_.Exception.Message
    Write-Warning "POST failed for ${Path}: $errorText"
    if ($FailFast) {
      throw
    }
    return [pscustomobject]@{
      name = $Name
      method = "POST"
      path = $Path
      file = $FileName
      status = "failed"
      error = $errorText
    }
  }
}

if ([string]::IsNullOrWhiteSpace($RunId)) {
  $RunId = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
}

$encodedScanId = [System.Uri]::EscapeDataString($ScanId)
$repoKey = Get-RepoKey $GitHubUrl
$safeScanId = ConvertTo-SafeName $ScanId
$root = Get-FullPath $OutDir
$RunDir = Join-Path (Join-Path $root $repoKey) "$safeScanId-$RunId"
New-Item -ItemType Directory -Force -Path $RunDir | Out-Null

$manifest = [pscustomobject]@{
  schema_version = 1
  generated_at = (Get-Date).ToUniversalTime().ToString("o")
  run_id = $RunId
  scan_id = $ScanId
  github_url = $GitHubUrl
  repo_key = $repoKey
  api_base_url = $ApiBaseUrl.TrimEnd('/')
  output_dir = $RunDir
  mode = "saved-scan-evidence-first"
  raw_repository_read = $false
  rescan_requested = $false
}
Write-JsonFile -Path (Join-Path $RunDir "manifest.json") -Value $manifest
Set-Content -LiteralPath (Join-Path $RunDir "scan-id.txt") -Value $ScanId -Encoding UTF8
Set-Content -LiteralPath (Join-Path $RunDir "github-url.txt") -Value $GitHubUrl -Encoding UTF8

$results = @()
$results += Invoke-JsonGet -Name "health" -Path "/api/health" -FileName "00-health.json"
$results += Invoke-JsonGet -Name "saved-scan" -Path "/api/scans/$encodedScanId" -FileName "01-scan.json"
$results += Invoke-JsonGet -Name "sanitized-report" -Path "/api/scans/$encodedScanId/sanitized-report?rebuild=true" -FileName "02-sanitized-report.json"
$results += Invoke-JsonGet -Name "rag-memory" -Path "/api/scans/$encodedScanId/rag-memory?rebuild=true" -FileName "03-rag-memory.json"
$results += Invoke-JsonGet -Name "hermes" -Path "/api/scans/$encodedScanId/hermes?persist=true" -FileName "04-hermes-orchestration.json"
$results += Invoke-JsonGet -Name "hermes-review-queue" -Path "/api/scans/$encodedScanId/hermes/review" -FileName "04b-hermes-review-queue.json"
$results += Invoke-JsonGet -Name "benchmark-gate" -Path "/api/scans/$encodedScanId/benchmark-gate" -FileName "05-benchmark-gate.json"
$results += Invoke-JsonGet -Name "messaging-gateway" -Path "/api/scans/$encodedScanId/messaging-gateway" -FileName "06-messaging-gateway.json"
$results += Invoke-JsonGet -Name "governance" -Path "/api/scans/$encodedScanId/governance" -FileName "07-governance-evidence.json"
$results += Invoke-JsonGet -Name "report-bundle" -Path "/api/scans/$encodedScanId/report-bundle?rebuild=true" -FileName "08-report-bundle.json"

$failed = @($results | Where-Object { $_.status -ne "passed" })
$summary = [pscustomobject]@{
  schema_version = 1
  generated_at = (Get-Date).ToUniversalTime().ToString("o")
  status = if ($failed.Count -eq 0) { "passed" } else { "failed" }
  run_id = $RunId
  scan_id = $ScanId
  github_url = $GitHubUrl
  output_dir = $RunDir
  total_checks = $results.Count
  passed_checks = ($results.Count - $failed.Count)
  failed_checks = $failed.Count
  checks = $results
}
Write-JsonFile -Path (Join-Path $RunDir "summary.json") -Value $summary

if ($failed.Count -gt 0) {
  Write-Host "Saved scan flow FAILED: $($failed.Count) of $($results.Count) checks failed."
  Write-Host "Output: $RunDir"
  exit 1
}

Write-Host "Saved scan flow passed: $($results.Count) checks."
Write-Host "Output: $RunDir"
