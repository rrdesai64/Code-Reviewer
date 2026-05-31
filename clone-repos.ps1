param(
  [Parameter(Mandatory=$true)][string]$List,
  [string]$OutDir = ".\scan-workspace\repos",
  [string]$OutputRoot = "",
  [string]$Branch = "",
  [int]$Depth = 0,
  [string[]]$ResumeFromDir = @(),
  [switch]$UpdateExisting,
  [switch]$DryRun,
  [string]$SummaryOut = ""
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

  $repoUrl = $parts[0].Trim()
  $repoBranch = ""
  $sonarProjectKey = ""
  if ($parts.Count -gt 1) {
    $repoBranch = $parts[1].Trim()
  }
  if ($parts.Count -gt 2) {
    $sonarProjectKey = $parts[2].Trim()
  }
  if (-not [string]::IsNullOrWhiteSpace($Branch)) {
    $repoBranch = $Branch
  }

  [pscustomobject]@{
    line = $LineNumber
    url = $repoUrl
    branch = $repoBranch
    sonar_project_key = $sonarProjectKey
    directory_name = Get-RepoDirectoryName $repoUrl
  }
}

function Invoke-Git {
  param(
    [Parameter(Mandatory=$true)][string[]]$Arguments,
    [string]$WorkingDirectory = "",
    [switch]$Stream
  )

  if ($DryRun) {
    $prefix = "git"
    if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
      $prefix = "git -C `"$WorkingDirectory`""
    }
    return [pscustomobject]@{
      exit_code = 0
      output = "DRY RUN: $prefix $($Arguments -join ' ')"
    }
  }

  if ($Stream) {
    if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
      & git @Arguments
    } else {
      & git -C $WorkingDirectory @Arguments
    }
    return [pscustomobject]@{
      exit_code = $LASTEXITCODE
      output = ""
    }
  }

  if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
    $output = & git @Arguments 2>&1
  } else {
    $output = & git -C $WorkingDirectory @Arguments 2>&1
  }

  return [pscustomobject]@{
    exit_code = $LASTEXITCODE
    output = ($output | Out-String).Trim()
  }
}

function Get-CurrentCommit {
  param([Parameter(Mandatory=$true)][string]$RepoPath)

  if ($DryRun -or -not (Test-Path (Join-Path $RepoPath ".git"))) {
    return ""
  }

  $result = Invoke-Git -WorkingDirectory $RepoPath -Arguments @("rev-parse", "HEAD")
  if ($result.exit_code -eq 0) {
    return $result.output.Trim()
  }
  return ""
}

function Find-ExistingRepoPath {
  param(
    [Parameter(Mandatory=$true)][string]$DirectoryName,
    [Parameter(Mandatory=$true)][string]$TargetPath,
    [string[]]$ResumeDirectories = @()
  )

  $candidates = @($TargetPath)
  foreach ($dir in $ResumeDirectories) {
    $candidates += (Join-Path $dir $DirectoryName)
  }
  foreach ($candidate in $candidates) {
    if (Test-Path (Join-Path $candidate ".git")) {
      return $candidate
    }
  }
  return ""
}

$listPath = Get-FullPath $List
if (-not (Test-Path $listPath)) {
  throw "Repository list not found: $listPath"
}

$outDirPath = Resolve-OutputPath -Path $OutDir -KnownChild "repos"
$resumeDirPaths = @()
foreach ($dir in $ResumeFromDir) {
  if (-not [string]::IsNullOrWhiteSpace($dir)) {
    $resumeDirPaths += Get-FullPath $dir
  }
}
$legacyOutDirPath = Get-FullPath $OutDir
if ($legacyOutDirPath -ne $outDirPath -and (Test-Path $legacyOutDirPath) -and $resumeDirPaths -notcontains $legacyOutDirPath) {
  $resumeDirPaths += $legacyOutDirPath
}
if (-not $DryRun) {
  New-Item -ItemType Directory -Force -Path $outDirPath | Out-Null
}

$summaryPath = $SummaryOut
if ([string]::IsNullOrWhiteSpace($summaryPath)) {
  $summaryPath = Join-Path $outDirPath "clone-summary.json"
} else {
  $summaryPath = Resolve-OutputPath -Path $summaryPath
}

$lines = Get-Content $listPath
$repos = @()
for ($i = 0; $i -lt $lines.Count; $i++) {
  $repo = ConvertFrom-RepoLine -Line $lines[$i] -LineNumber ($i + 1)
  if ($null -ne $repo) {
    $repos += $repo
  }
}

$results = @()
$index = 0
foreach ($repo in $repos) {
  $index += 1
  $targetPath = Join-Path $outDirPath $repo.directory_name
  $existingRepoPath = Find-ExistingRepoPath -DirectoryName $repo.directory_name -TargetPath $targetPath -ResumeDirectories $resumeDirPaths
  if (-not $DryRun) {
    Write-Host "[$index/$($repos.Count)] $($repo.url)"
    Write-Host "  target: $targetPath"
    if (-not [string]::IsNullOrWhiteSpace($repo.sonar_project_key)) {
      Write-Host "  sonar: $($repo.sonar_project_key)"
    }
  }
  $record = [ordered]@{
    line = $repo.line
    url = $repo.url
    branch = $repo.branch
    sonar_project_key = $repo.sonar_project_key
    directory = $targetPath
    existing_directory = $existingRepoPath
    action = "none"
    success = $false
    commit = ""
    message = ""
  }

  try {
    if (-not [string]::IsNullOrWhiteSpace($existingRepoPath) -and (Resolve-Path -LiteralPath $existingRepoPath).Path -ne (Get-FullPath $targetPath)) {
      $record.action = "resumed"
      $record.success = $true
      $record.directory = $existingRepoPath
      $record.commit = Get-CurrentCommit $existingRepoPath
      $record.message = "Repository already exists in resume directory; leaving it in place."
      if (-not $DryRun) {
        Write-Host "  resumed: already cloned at $existingRepoPath"
      }
    } elseif (Test-Path $targetPath) {
      if (-not (Test-Path (Join-Path $targetPath ".git"))) {
        $record.action = "skipped"
        $record.message = "Target directory exists but is not a Git repository."
        if (-not $DryRun) {
          Write-Warning $record.message
        }
      } elseif ($UpdateExisting) {
        $record.action = "updated"
        $fetch = Invoke-Git -WorkingDirectory $targetPath -Arguments @("fetch", "--all", "--prune") -Stream
        if ($fetch.exit_code -ne 0) {
          throw "git fetch failed with exit code $($fetch.exit_code)"
        }
        if (-not [string]::IsNullOrWhiteSpace($repo.branch)) {
          $checkout = Invoke-Git -WorkingDirectory $targetPath -Arguments @("checkout", $repo.branch) -Stream
          if ($checkout.exit_code -ne 0) {
            throw "git checkout failed with exit code $($checkout.exit_code)"
          }
        }
        $pull = Invoke-Git -WorkingDirectory $targetPath -Arguments @("pull", "--ff-only") -Stream
        if ($pull.exit_code -ne 0) {
          throw "git pull failed with exit code $($pull.exit_code)"
        }
        $record.success = $true
        $record.commit = Get-CurrentCommit $targetPath
        $record.message = "Repository updated."
        if (-not $DryRun) {
          Write-Host "  updated"
        }
      } else {
        $record.action = "skipped"
        $record.success = $true
        $record.commit = Get-CurrentCommit $targetPath
        $record.message = "Repository already exists. Use -UpdateExisting to fetch and fast-forward."
        if (-not $DryRun) {
          Write-Host "  skipped: already exists"
        }
      }
    } else {
      $record.action = "cloned"
      $cloneArgs = @("clone")
      if ($Depth -gt 0) {
        $cloneArgs += @("--depth", [string]$Depth)
      }
      if (-not [string]::IsNullOrWhiteSpace($repo.branch)) {
        $cloneArgs += @("--branch", $repo.branch, "--single-branch")
      }
      $cloneArgs += @($repo.url, $targetPath)

      $clone = Invoke-Git -Arguments $cloneArgs -Stream
      if ($clone.exit_code -ne 0) {
        throw "git clone failed with exit code $($clone.exit_code)"
      }
      $record.success = $true
      $record.commit = Get-CurrentCommit $targetPath
      $record.message = "Repository cloned."
      if (-not $DryRun) {
        Write-Host "  cloned"
      }
    }
  } catch {
    $record.action = "failed"
    $record.success = $false
    $record.message = $_.Exception.Message
    if (-not $DryRun) {
      Write-Warning $record.message
    }
  }

  $results += [pscustomobject]$record
}

$summary = [ordered]@{
  generated_at = (Get-Date).ToUniversalTime().ToString("o")
  list = $listPath
  output_directory = $outDirPath
  resume_from_directories = $resumeDirPaths
  dry_run = [bool]$DryRun
  update_existing = [bool]$UpdateExisting
  depth = $Depth
  default_branch = $Branch
  total = $results.Count
  cloned = @($results | Where-Object { $_.action -eq "cloned" -and $_.success }).Count
  updated = @($results | Where-Object { $_.action -eq "updated" -and $_.success }).Count
  resumed = @($results | Where-Object { $_.action -eq "resumed" -and $_.success }).Count
  skipped = @($results | Where-Object { $_.action -eq "skipped" -and $_.success }).Count
  failed = @($results | Where-Object { -not $_.success }).Count
  repositories = $results
}

$summaryJson = $summary | ConvertTo-Json -Depth 6
if ($DryRun) {
  $summaryJson
} else {
  $summaryJson | Set-Content -Path $summaryPath -Encoding UTF8
  Write-Host "Clone summary: $summaryPath"
}

if ($summary.failed -gt 0) {
  exit 1
}
