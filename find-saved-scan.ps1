param(
  [string]$GitHubUrl = "",
  [string]$RepoName = "",
  [string]$RepoPath = "",
  [string]$DataDir = "",
  [string]$ReportsDir = "",
  [int]$Limit = 20,
  [switch]$Json
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

function Get-OutputRoot {
  if (-not [string]::IsNullOrWhiteSpace($env:SECURE_REVIEW_OUTPUT_ROOT)) {
    return Get-FullPath $env:SECURE_REVIEW_OUTPUT_ROOT
  }
  return "E:\secure-review"
}

function Get-DefaultDataDir {
  if (-not [string]::IsNullOrWhiteSpace($DataDir)) {
    return Get-FullPath $DataDir
  }
  if (-not [string]::IsNullOrWhiteSpace($env:SECURE_REVIEW_DATA_DIR)) {
    return Get-FullPath $env:SECURE_REVIEW_DATA_DIR
  }
  $preferred = Join-Path (Get-OutputRoot) "data"
  if (Test-Path -LiteralPath (Join-Path $preferred "scans")) {
    return $preferred
  }
  foreach ($candidate in @("E:\secure-review\data", (Join-Path $PSScriptRoot "data"))) {
    if (Test-Path -LiteralPath (Join-Path $candidate "scans")) {
      return $candidate
    }
  }
  return $preferred
}

function Get-DefaultReportsDir {
  if (-not [string]::IsNullOrWhiteSpace($ReportsDir)) {
    return Get-FullPath $ReportsDir
  }
  if (-not [string]::IsNullOrWhiteSpace($env:REPORT_BUNDLE_DIR)) {
    return Get-FullPath $env:REPORT_BUNDLE_DIR
  }
  $preferred = Join-Path (Get-OutputRoot) "reports"
  if (Test-Path -LiteralPath $preferred) {
    return $preferred
  }
  foreach ($candidate in @("E:\secure-review\reports", (Join-Path $PSScriptRoot "reports"))) {
    if (Test-Path -LiteralPath $candidate) {
      return $candidate
    }
  }
  return $preferred
}

function Get-RepoKeyFromUrl {
  param([Parameter(Mandatory=$true)][string]$Url)

  $trimmed = $Url.Trim().TrimEnd('/')
  $trimmed = $trimmed -replace '\.git$', ''
  if ($trimmed -match 'github\.com[:/](?<owner>[^/\s:]+)/(?<repo>[^/\s:]+)$') {
    return ConvertTo-SafeName "$($Matches.owner)__$($Matches.repo)"
  }
  if ($trimmed -match '[:/](?<owner>[^/\s:]+)/(?<repo>[^/\s:]+)$') {
    return ConvertTo-SafeName "$($Matches.owner)__$($Matches.repo)"
  }
  return ConvertTo-SafeName ([System.IO.Path]::GetFileName($trimmed))
}

function Get-SearchTerms {
  $terms = @()
  if (-not [string]::IsNullOrWhiteSpace($GitHubUrl)) {
    $terms += $GitHubUrl.Trim()
    $terms += Get-RepoKeyFromUrl $GitHubUrl
    $terms += ($GitHubUrl.Trim().TrimEnd('/') -replace '\.git$', '' | Split-Path -Leaf)
  }
  if (-not [string]::IsNullOrWhiteSpace($RepoName)) {
    $terms += $RepoName.Trim()
  }
  if (-not [string]::IsNullOrWhiteSpace($RepoPath)) {
    $full = Get-FullPath $RepoPath
    $terms += $full
    $terms += Split-Path -Leaf $full
  }
  return @($terms | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
}

function Test-Match {
  param(
    [Parameter(Mandatory=$true)]$Scan,
    [string[]]$Terms = @()
  )

  if ($Terms.Count -eq 0) {
    return $true
  }

  $haystack = @(
    $Scan.scan_id
    $Scan.project_name
    $Scan.target_path
    ($Scan | ConvertTo-Json -Depth 12)
  ) -join "`n"

  foreach ($term in $Terms) {
    if ($haystack.IndexOf($term, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
      return $true
    }
  }
  return $false
}

function Find-ReportDir {
  param(
    [Parameter(Mandatory=$true)]$Scan,
    [Parameter(Mandatory=$true)][string]$ReportsRoot
  )

  $scanId = [string]$Scan.scan_id
  $project = ConvertTo-SafeName ([string]$Scan.project_name)
  $direct = Join-Path (Join-Path $ReportsRoot $project) $scanId
  if (Test-Path -LiteralPath $direct) {
    return $direct
  }

  $matches = Get-ChildItem -LiteralPath $ReportsRoot -Directory -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -eq $scanId } |
    Select-Object -First 1

  if ($matches) {
    return $matches.FullName
  }
  return ""
}

$scanRoot = Join-Path (Get-DefaultDataDir) "scans"
$reportsRoot = Get-DefaultReportsDir
$terms = @(Get-SearchTerms)

if (-not (Test-Path -LiteralPath $scanRoot)) {
  throw "Saved scans directory not found: $scanRoot"
}

$rows = @()
$files = Get-ChildItem -LiteralPath $scanRoot -Filter "*.json" -File | Sort-Object LastWriteTime -Descending
foreach ($file in $files) {
  try {
    $scan = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
  } catch {
    continue
  }

  if (-not (Test-Match -Scan $scan -Terms $terms)) {
    continue
  }

  $reportDir = ""
  if (Test-Path -LiteralPath $reportsRoot) {
    $reportDir = Find-ReportDir -Scan $scan -ReportsRoot $reportsRoot
  }

  $rows += [pscustomobject]@{
    scan_id = [string]$scan.scan_id
    project_name = [string]$scan.project_name
    created_at = [string]$scan.created_at
    target_path = [string]$scan.target_path
    findings = [int]$scan.summary.total_findings
    files_scanned = [int]$scan.summary.files_scanned
    tools = ($scan.summary.tools.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join "; "
    scan_file = $file.FullName
    report_dir = $reportDir
  }

  if ($rows.Count -ge [Math]::Max(1, $Limit)) {
    break
  }
}

if ($Json) {
  [pscustomobject]@{
    schema_version = 1
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    query = [pscustomobject]@{
      github_url = $GitHubUrl
      repo_name = $RepoName
      repo_path = $RepoPath
      terms = $terms
      data_dir = Get-DefaultDataDir
      reports_dir = $reportsRoot
    }
    count = $rows.Count
    scans = $rows
  } | ConvertTo-Json -Depth 20
  exit 0
}

if ($rows.Count -eq 0) {
  Write-Host "No matching saved scans found."
  Write-Host "Searched: $scanRoot"
  if ($terms.Count -gt 0) {
    Write-Host "Terms: $($terms -join ', ')"
  }
  exit 1
}

$rows | Format-Table scan_id, project_name, created_at, findings, files_scanned, report_dir -AutoSize
Write-Host ""
Write-Host "Use one scan_id with:"
Write-Host '.\test-saved-scan-flow.ps1 -ScanId "<scan-id>" -GitHubUrl "<github-url>"'
