param(
  [Parameter(Mandatory=$true)][string]$List,
  [string[]]$ReposDir = @(".\scan-workspace\repos"),
  [string]$ReportsDir = ".\reports",
  [string]$OutputRoot = "",
  [string]$RunId = "",
  [switch]$DryRun,
  [switch]$FailFast,
  [int]$Limit = 0,
  [int]$HeartbeatSeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-FullPath {
  param([Parameter(Mandatory=$true)][string]$Path)
  return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function Get-OutputRoot {
  if (-not [string]::IsNullOrWhiteSpace($OutputRoot)) {
    return Get-FullPath $OutputRoot
  }
  if (-not [string]::IsNullOrWhiteSpace($env:SECURE_REVIEW_OUTPUT_ROOT)) {
    return Get-FullPath $env:SECURE_REVIEW_OUTPUT_ROOT
  }
  return "E:\secure-review"
}

function Test-AbsolutePath {
  param([Parameter(Mandatory=$true)][string]$Path)
  return $Path -match '^[A-Za-z]:' -or $Path.StartsWith('\\')
}

function Resolve-OutputPath {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [string]$KnownChild = ""
  )
  if (Test-AbsolutePath $Path) {
    return Get-FullPath $Path
  }
  $root = Get-OutputRoot
  if (-not [string]::IsNullOrWhiteSpace($KnownChild)) {
    return Join-Path $root $KnownChild
  }
  $relative = $Path -replace '^[.][\\/]', ''
  return Join-Path $root $relative
}

function Remove-InlineComment {
  param([Parameter(Mandatory=$true)][string]$Line)

  $hashIndex = $Line.IndexOf('#')
  if ($hashIndex -lt 0) {
    return $Line.Trim()
  }
  return $Line.Substring(0, $hashIndex).Trim()
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

function Get-RepoDirectoryName {
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

function Find-RepoPath {
  param(
    [Parameter(Mandatory=$true)][string[]]$RepositoryDirectories,
    [Parameter(Mandatory=$true)][string]$DirectoryName
  )

  foreach ($dir in $RepositoryDirectories) {
    $candidate = Join-Path $dir $DirectoryName
    if (Test-Path (Join-Path $candidate ".git")) {
      return $candidate
    }
  }
  return Join-Path $RepositoryDirectories[0] $DirectoryName
}

function ConvertFrom-RepoLine {
  param(
    [Parameter(Mandatory=$true)][string]$Line,
    [Parameter(Mandatory=$true)][int]$LineNumber
  )

  $clean = Remove-InlineComment $Line
  if ([string]::IsNullOrWhiteSpace($clean)) {
    return $null
  }

  if ($clean.Contains(',')) {
    $parts = $clean.Split(',') | ForEach-Object { $_.Trim() }
  } else {
    $parts = $clean -split '\s+', 3
  }

  $url = $parts[0].Trim()
  [pscustomobject]@{
    line = $LineNumber
    url = $url
    branch = if ($parts.Count -gt 1) { $parts[1].Trim() } else { "" }
    sonar_project_key = if ($parts.Count -gt 2) { $parts[2].Trim() } else { "" }
    directory_name = Get-RepoDirectoryName $url
  }
}

function ConvertTo-CommandLineArgument {
  param([Parameter(Mandatory=$true)][string]$Value)

  if ($Value -notmatch '[\s"]') {
    return $Value
  }
  return '"' + ($Value -replace '"', '\"') + '"'
}

function Get-PowerShellExecutable {
  try {
    $current = (Get-Process -Id $PID).Path
    if (-not [string]::IsNullOrWhiteSpace($current)) {
      return $current
    }
  } catch {
  }

  $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
  if ($pwsh) {
    return $pwsh.Source
  }

  return (Get-Command powershell -ErrorAction Stop).Source
}

function Invoke-ScanScript {
  param(
    [Parameter(Mandatory=$true)][string]$ScriptPath,
    [Parameter(Mandatory=$true)][string[]]$Arguments,
    [Parameter(Mandatory=$true)][int]$HeartbeatSeconds
  )

  $psExe = Get-PowerShellExecutable
  $processArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath) + $Arguments
  $argumentLine = ($processArgs | ForEach-Object { ConvertTo-CommandLineArgument $_ }) -join ' '
  $process = Start-Process -FilePath $psExe -ArgumentList $argumentLine -WorkingDirectory $PSScriptRoot -NoNewWindow -PassThru
  $started = Get-Date
  $waitMilliseconds = [Math]::Max(1, $HeartbeatSeconds) * 1000

  while (-not $process.HasExited) {
    if ($process.WaitForExit($waitMilliseconds)) {
      break
    }
    $elapsed = [int]((Get-Date) - $started).TotalSeconds
    Write-Host "  still scanning... elapsed ${elapsed}s"
  }

  $process.Refresh()
  return $process.ExitCode
}

function Add-ScanOutputArgs {
  param(
    [Parameter(Mandatory=$true)][string[]]$BaseArgs,
    [Parameter(Mandatory=$true)][string]$ReportDir
  )

  return $BaseArgs + @(
    '-JsonOut', (Join-Path $ReportDir 'scan.json'),
    '-SarifOut', (Join-Path $ReportDir 'secure-review.sarif'),
    '-ScannerMeshOut', (Join-Path $ReportDir 'scanner-mesh.json'),
    '-ConsolidatedFindingsOut', (Join-Path $ReportDir 'finding-consolidation.json'),
    '-ReachabilityContextOut', (Join-Path $ReportDir 'reachability-context.json'),
    '-DependencyReviewOut', (Join-Path $ReportDir 'dependency-review.json'),
    '-SonarQubeOut', (Join-Path $ReportDir 'sonarqube-quality-gate.json'),
    '-ScannerDepthOut', (Join-Path $ReportDir 'scanner-depth.json'),
    '-AdvancedAiOut', (Join-Path $ReportDir 'advanced-ai.json'),
    '-AiReviewOut', (Join-Path $ReportDir 'ai-review.json'),
    '-CycloneDxOut', (Join-Path $ReportDir 'cyclonedx-sbom.json'),
    '-SpdxOut', (Join-Path $ReportDir 'spdx-sbom.json'),
    '-SpdxComplianceOut', (Join-Path $ReportDir 'spdx-compliance.json'),
    '-SbomPolicyOut', (Join-Path $ReportDir 'sbom-policy.json'),
    '-SecretPolicyOut', (Join-Path $ReportDir 'secret-policy.json'),
    '-GitHubPrReviewOut', (Join-Path $ReportDir 'github-pr-review.json'),
    '-CodeHostReviewOut', (Join-Path $ReportDir 'code-host-review.json'),
    '-SbomCompareOut', (Join-Path $ReportDir 'sbom-compare.json'),
    '-ReportOut', (Join-Path $ReportDir 'secure-review.md'),
    '-PrCommentOut', (Join-Path $ReportDir 'pr-comment.md'),
    '-ComplianceOut', (Join-Path $ReportDir 'compliance.json'),
    '-FixProposalsOut', (Join-Path $ReportDir 'fix-proposals.json'),
    '-RemediationPlanOut', (Join-Path $ReportDir 'remediation-plan.json'),
    '-IssuePlanOut', (Join-Path $ReportDir 'issue-plan.json'),
    '-ChatNotificationOut', (Join-Path $ReportDir 'chat-notification.json'),
    '-TeamLearningOut', (Join-Path $ReportDir 'team-learning-dashboard.json'),
    '-RecursiveLearningOut', (Join-Path $ReportDir 'recursive-learning.json'),
    '-BenchmarkGateOut', (Join-Path $ReportDir 'benchmark-gate.json'),
    '-MessagingGatewayOut', (Join-Path $ReportDir 'messaging-gateway.json'),
    '-GovernanceOut', (Join-Path $ReportDir 'governance-evidence.json'),
    '-QuarantinePolicyOut', (Join-Path $ReportDir 'quarantine-policy.json'),
    '-SuppressionsOut', (Join-Path $ReportDir 'inline-suppressions.json'),
    '-SanitizedReportOut', (Join-Path $ReportDir 'sanitized-report.json'),
    '-RagMemoryOut', (Join-Path $ReportDir 'rag-memory.json'),
    '-HermesOut', (Join-Path $ReportDir 'hermes-orchestration.json'),
    '-FixBundleOut', (Join-Path $ReportDir 'fix-bundle.json'),
    '-FixApplyOut', (Join-Path $ReportDir 'fix-apply-dry-run.json'),
    '-VerifiedAutofixOut', (Join-Path $ReportDir 'verified-autofix-dry-run.json')
  )
}

$listPath = Get-FullPath $List
if (-not (Test-Path $listPath)) {
  throw "Repository list not found: $listPath"
}

$outputRootPath = Get-OutputRoot
$defaultRepoRoot = Join-Path $outputRootPath "repos"
$reposDirPaths = @()
$fallbackRepoDirPaths = @()
foreach ($dir in $ReposDir) {
  if (-not [string]::IsNullOrWhiteSpace($dir)) {
    if (Test-AbsolutePath $dir) {
      $resolvedDir = Get-FullPath $dir
    } else {
      $resolvedDir = $defaultRepoRoot
      $legacyDir = Get-FullPath $dir
      if ($legacyDir -ne $resolvedDir -and $fallbackRepoDirPaths -notcontains $legacyDir) {
        $fallbackRepoDirPaths += $legacyDir
      }
    }
    if ($reposDirPaths -notcontains $resolvedDir) {
      $reposDirPaths += $resolvedDir
    }
  }
}
if ($reposDirPaths.Count -eq 0) {
  $reposDirPaths += $defaultRepoRoot
}
if ($reposDirPaths -notcontains $defaultRepoRoot) {
  $reposDirPaths += $defaultRepoRoot
}
foreach ($fallbackDir in $fallbackRepoDirPaths) {
  if ($reposDirPaths -notcontains $fallbackDir) {
    $reposDirPaths += $fallbackDir
  }
}
$reportsDirPath = Resolve-OutputPath -Path $ReportsDir -KnownChild "reports"
if ([string]::IsNullOrWhiteSpace($RunId)) {
  $RunId = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
}

[Environment]::SetEnvironmentVariable("SECURE_REVIEW_OUTPUT_ROOT", $outputRootPath, "Process")
[Environment]::SetEnvironmentVariable("SECURE_REVIEW_DATA_DIR", (Join-Path $outputRootPath "data"), "Process")
[Environment]::SetEnvironmentVariable("REPORT_BUNDLE_DIR", (Join-Path $outputRootPath "reports"), "Process")

$lines = Get-Content $listPath
$repos = @()
for ($i = 0; $i -lt $lines.Count; $i++) {
  $repo = ConvertFrom-RepoLine -Line $lines[$i] -LineNumber ($i + 1)
  if ($null -ne $repo) {
    $repos += $repo
  }
}
if ($Limit -gt 0) {
  $repos = @($repos | Select-Object -First $Limit)
}

$scanScript = Join-Path $PSScriptRoot "scan.ps1"
$results = @()
$index = 0
foreach ($repo in $repos) {
  $index += 1
  $repoPath = Find-RepoPath -RepositoryDirectories $reposDirPaths -DirectoryName $repo.directory_name
  $reportDir = Join-Path (Join-Path $reportsDirPath $repo.directory_name) $RunId
  $record = [ordered]@{
    line = $repo.line
    url = $repo.url
    branch = $repo.branch
    sonar_project_key = $repo.sonar_project_key
    repository_directory = $repoPath
    report_directory = $reportDir
    success = $false
    exit_code = $null
    duration_seconds = 0
    message = ""
  }

  if (-not $DryRun) {
    Write-Host "[$index/$($repos.Count)] $($repo.url)"
    Write-Host "  repo: $repoPath"
    Write-Host "  reports: $reportDir"
    if (-not [string]::IsNullOrWhiteSpace($repo.sonar_project_key)) {
      Write-Host "  sonar: $($repo.sonar_project_key)"
    }
  }

  if (-not $DryRun -and -not (Test-Path (Join-Path $repoPath ".git"))) {
    $record.message = "Repository checkout not found. Run clone-repos.ps1 first."
    Write-Warning $record.message
    $results += [pscustomobject]$record
    if ($FailFast) {
      break
    }
    continue
  }

  $scanArgs = @('-Path', $repoPath)
  if (-not [string]::IsNullOrWhiteSpace($repo.sonar_project_key)) {
    $scanArgs += @('-SonarProjectKey', $repo.sonar_project_key)
  }
  if (-not [string]::IsNullOrWhiteSpace($repo.branch)) {
    $scanArgs += @('-SonarBranchName', $repo.branch)
  }
  $scanArgs = Add-ScanOutputArgs -BaseArgs $scanArgs -ReportDir $reportDir

  if ($DryRun) {
    $record.success = $true
    $record.exit_code = 0
    $record.message = "DRY RUN: $scanScript $($scanArgs -join ' ')"
    $results += [pscustomobject]$record
    continue
  }

  New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
  Write-Host "  started scan at $((Get-Date).ToString('s'))"
  $started = Get-Date
  $exitCode = Invoke-ScanScript -ScriptPath $scanScript -Arguments $scanArgs -HeartbeatSeconds $HeartbeatSeconds
  $duration = [int]((Get-Date) - $started).TotalSeconds
  $record.exit_code = $exitCode
  $record.duration_seconds = $duration
  $record.success = ($exitCode -eq 0)
  $record.message = if ($record.success) { "Scan completed." } else { "Scan failed." }
  if ($record.success) {
    Write-Host "  completed in ${duration}s"
  } else {
    Write-Warning "  failed in ${duration}s with exit code $exitCode"
  }
  $results += [pscustomobject]$record
  if ($FailFast -and -not $record.success) {
    break
  }
}

$summary = [ordered]@{
  generated_at = (Get-Date).ToUniversalTime().ToString("o")
  run_id = $RunId
  list = $listPath
  repositories_directories = $reposDirPaths
  reports_directory = $reportsDirPath
  dry_run = [bool]$DryRun
  total = $results.Count
  succeeded = @($results | Where-Object { $_.success }).Count
  failed = @($results | Where-Object { -not $_.success }).Count
  repositories = $results
}

$summaryJson = $summary | ConvertTo-Json -Depth 8
if ($DryRun) {
  $summaryJson
} else {
  New-Item -ItemType Directory -Force -Path $reportsDirPath | Out-Null
  $summaryPath = Join-Path $reportsDirPath "bulk-scan-summary-$RunId.json"
  $summaryJson | Set-Content -Path $summaryPath -Encoding UTF8
  Write-Host "Bulk scan summary: $summaryPath"
}

if ($summary.failed -gt 0) {
  exit 1
}
