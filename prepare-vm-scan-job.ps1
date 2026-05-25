param(
  [Parameter(Mandatory=$true)][string]$RepoPath,
  [string]$RepoUrl = "",
  [string]$ProjectName = "",
  [string]$SonarProjectKey = "",
  [string]$SonarBranchName = "",
  [string]$OutputRoot = "D:\secure-review",
  [string]$ReportsDir = ".\reports",
  [string]$RunId = "",
  [ValidateSet("windows-sandbox", "manual")][string]$Provider = "windows-sandbox",
  [ValidateSet("offline", "scanner-only", "full")][string]$NetworkPolicy = "scanner-only",
  [switch]$ApprovedQuarantine,
  [switch]$NoGitHistory,
  [string]$JobName = "",
  [string]$JsonOut = "",
  [switch]$Launch
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$argsList = @(
  '-B', '-m', 'app.vm_worker', 'prepare',
  '--repo-path', $RepoPath,
  '--output-root', $OutputRoot,
  '--reports-dir', $ReportsDir,
  '--provider', $Provider,
  '--network-policy', $NetworkPolicy
)

if (-not [string]::IsNullOrWhiteSpace($RepoUrl)) {
  $argsList += @('--repo-url', $RepoUrl)
}
if (-not [string]::IsNullOrWhiteSpace($ProjectName)) {
  $argsList += @('--project-name', $ProjectName)
}
if (-not [string]::IsNullOrWhiteSpace($SonarProjectKey)) {
  $argsList += @('--sonar-project-key', $SonarProjectKey)
}
if (-not [string]::IsNullOrWhiteSpace($SonarBranchName)) {
  $argsList += @('--sonar-branch-name', $SonarBranchName)
}
if (-not [string]::IsNullOrWhiteSpace($RunId)) {
  $argsList += @('--run-id', $RunId)
}
if ($ApprovedQuarantine) {
  $argsList += '--approved-quarantine'
}
if ($NoGitHistory) {
  $argsList += '--no-git-history'
}
if (-not [string]::IsNullOrWhiteSpace($JobName)) {
  $argsList += @('--job-name', $JobName)
}
if (-not [string]::IsNullOrWhiteSpace($JsonOut)) {
  $argsList += @('--json-out', $JsonOut)
}

$env:PYTHONDONTWRITEBYTECODE = "1"
& .\.venv\Scripts\python.exe @argsList
if ($LASTEXITCODE -ne 0) {
  exit $LASTEXITCODE
}

if ($Launch) {
  $jobPayload = if (-not [string]::IsNullOrWhiteSpace($JsonOut) -and (Test-Path -LiteralPath $JsonOut)) {
    Get-Content -LiteralPath $JsonOut -Raw | ConvertFrom-Json
  } else {
    throw "Use -JsonOut when combining -Launch with this helper."
  }
  & $jobPayload.files.launcher
}
