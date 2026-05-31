param(
  [Parameter(Mandatory=$true)][string]$List,
  [string[]]$ReposDir = @(".\scan-workspace\repos"),
  [string]$OutDir = ".\scan-workspace\supply-chain-footprints",
  [string]$OutputRoot = "",
  [switch]$DryRun,
  [switch]$FailOnMissing
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$FootprintPatterns = @(
  "requirements*.txt",
  "constraints*.txt",
  "pyproject.toml",
  "poetry.lock",
  "Pipfile",
  "Pipfile.lock",
  "uv.lock",
  "setup.py",
  "setup.cfg",
  "environment.yml",
  "environment.yaml",
  "package.json",
  "package-lock.json",
  "npm-shrinkwrap.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lock",
  "bun.lockb",
  "go.mod",
  "go.sum",
  "go.work",
  "go.work.sum",
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "settings.gradle",
  "settings.gradle.kts",
  "gradle.lockfile",
  "Cargo.toml",
  "Cargo.lock",
  "composer.json",
  "composer.lock",
  "Gemfile",
  "Gemfile.lock",
  "packages.config",
  "*.csproj",
  "*.fsproj",
  "*.vbproj",
  "Directory.Packages.props",
  "Directory.Build.props",
  "global.json",
  "mix.exs",
  "mix.lock",
  "rebar.config",
  "rebar.lock",
  "pubspec.yaml",
  "pubspec.lock",
  "Package.swift",
  "Package.resolved",
  "Podfile",
  "Podfile.lock",
  "Cartfile",
  "Cartfile.resolved",
  "conanfile.txt",
  "conanfile.py",
  "vcpkg.json",
  "vcpkg-configuration.json",
  "deno.json",
  "deno.jsonc",
  "deno.lock",
  "deps.edn",
  "project.clj",
  "build.boot",
  "cpanfile",
  "cpanfile.snapshot",
  "renv.lock",
  "DESCRIPTION"
)

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

  [pscustomobject]@{
    line = $LineNumber
    url = $parts[0].Trim()
    branch = if ($parts.Count -gt 1) { $parts[1].Trim() } else { "" }
    sonar_project_key = if ($parts.Count -gt 2) { $parts[2].Trim() } else { "" }
    directory_name = Get-RepoDirectoryName $parts[0].Trim()
  }
}

function Test-FootprintName {
  param([Parameter(Mandatory=$true)][string]$Name)

  foreach ($pattern in $FootprintPatterns) {
    if ($Name -like $pattern) {
      return $true
    }
  }
  return $false
}

function Get-FootprintKind {
  param([Parameter(Mandatory=$true)][string]$Name)

  $lower = $Name.ToLowerInvariant()
  if ($lower -like "*lock*" -or $lower -in @("go.sum", "package.resolved", "cartfile.resolved", "cpanfile.snapshot", "gradle.lockfile")) {
    return "lock"
  }
  if ($lower -like "*.csproj" -or $lower -like "*.fsproj" -or $lower -like "*.vbproj") {
    return "manifest"
  }
  return "manifest"
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
$outDirPath = Resolve-OutputPath -Path $OutDir -KnownChild "supply-chain-footprints"
if (-not $DryRun) {
  New-Item -ItemType Directory -Force -Path $outDirPath | Out-Null
}

$lines = Get-Content $listPath
$repos = @()
for ($i = 0; $i -lt $lines.Count; $i++) {
  $repo = ConvertFrom-RepoLine -Line $lines[$i] -LineNumber ($i + 1)
  if ($null -ne $repo) {
    $repos += $repo
  }
}

$repoResults = @()
foreach ($repo in $repos) {
  $repoPath = Find-RepoPath -RepositoryDirectories $reposDirPaths -DirectoryName $repo.directory_name
  $repoOutDir = Join-Path $outDirPath $repo.directory_name
  $files = @()
  $missingReason = ""

  if (-not (Test-Path $repoPath)) {
    $missingReason = "Repository directory not found. Run clone-repos.ps1 first."
  } elseif (-not (Test-Path (Join-Path $repoPath ".git"))) {
    $missingReason = "Repository directory exists but is not a Git checkout."
  } else {
    $rootFiles = Get-ChildItem -LiteralPath $repoPath -File | Where-Object { Test-FootprintName $_.Name }
    if (-not $DryRun) {
      New-Item -ItemType Directory -Force -Path $repoOutDir | Out-Null
    }

    foreach ($file in $rootFiles) {
      $destination = Join-Path $repoOutDir $file.Name
      $hash = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256

      if (-not $DryRun) {
        Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
      }

      $files += [pscustomobject]@{
        name = $file.Name
        kind = Get-FootprintKind $file.Name
        source_path = $file.FullName
        copied_path = $destination
        size_bytes = $file.Length
        sha256 = $hash.Hash.ToLowerInvariant()
      }
    }
  }

  $repoResults += [pscustomobject]@{
    line = $repo.line
    url = $repo.url
    branch = $repo.branch
    sonar_project_key = $repo.sonar_project_key
    repository_directory = $repoPath
    evidence_directory = $repoOutDir
    found = $files.Count
    status = if ($missingReason) { "missing-repository" } elseif ($files.Count -eq 0) { "no-root-footprints" } else { "ok" }
    message = $missingReason
    files = $files
  }
}

$summary = [ordered]@{
  generated_at = (Get-Date).ToUniversalTime().ToString("o")
  list = $listPath
  repositories_directories = $reposDirPaths
  output_directory = $outDirPath
  dry_run = [bool]$DryRun
  root_only = $true
  patterns = $FootprintPatterns
  total_repositories = $repoResults.Count
  repositories_with_footprints = @($repoResults | Where-Object { $_.found -gt 0 }).Count
  repositories_without_footprints = @($repoResults | Where-Object { $_.status -eq "no-root-footprints" }).Count
  missing_repositories = @($repoResults | Where-Object { $_.status -eq "missing-repository" }).Count
  total_files = ($repoResults | ForEach-Object { $_.found } | Measure-Object -Sum).Sum
  repositories = $repoResults
}

$summaryJson = $summary | ConvertTo-Json -Depth 8
if ($DryRun) {
  $summaryJson
} else {
  $indexPath = Join-Path $outDirPath "footprint-index.json"
  $summaryJson | Set-Content -Path $indexPath -Encoding UTF8
  Write-Host "Supply-chain footprint index: $indexPath"
}

if ($FailOnMissing -and ($summary.repositories_without_footprints -gt 0 -or $summary.missing_repositories -gt 0)) {
  exit 1
}
