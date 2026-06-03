param(
  [string]$ScanId = "",
  [string]$GitHubUrl = "",
  [string]$RepoName = "",
  [string[]]$DataDir = @(),
  [string]$ApiBaseUrl = "http://127.0.0.1:8000",
  [string]$OutDir = "E:\secure-review\saved-scan-validation",
  [string]$BearerToken = "",
  [string]$RunId = "",
  [int]$Limit = 500,
  [switch]$Console,
  [switch]$ListOnly,
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

function ConvertFrom-RepoKeyToGitHubUrl {
  param([Parameter(Mandatory=$true)][string]$ProjectName)

  $parts = $ProjectName -split '__', 2
  if ($parts.Count -eq 2 -and -not [string]::IsNullOrWhiteSpace($parts[0]) -and -not [string]::IsNullOrWhiteSpace($parts[1])) {
    return "https://github.com/$($parts[0])/$($parts[1])"
  }
  return ""
}

function Get-CandidateDataDirs {
  $candidates = @()
  foreach ($dir in $DataDir) {
    if (-not [string]::IsNullOrWhiteSpace($dir)) {
      $candidates += Get-FullPath $dir
    }
  }
  if (-not [string]::IsNullOrWhiteSpace($env:SECURE_REVIEW_DATA_DIR)) {
    $candidates += Get-FullPath $env:SECURE_REVIEW_DATA_DIR
  }
  $candidates += @(
    "E:\secure-review\data",
    (Join-Path $PSScriptRoot "data")
  )

  return @(
    $candidates |
      Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
      Select-Object -Unique |
      Where-Object { Test-Path -LiteralPath (Join-Path $_ "scans") }
  )
}

function Get-SearchTerms {
  $terms = @()
  if (-not [string]::IsNullOrWhiteSpace($ScanId)) {
    $terms += $ScanId.Trim()
  }
  if (-not [string]::IsNullOrWhiteSpace($GitHubUrl)) {
    $terms += $GitHubUrl.Trim()
    $terms += Get-RepoKeyFromUrl $GitHubUrl
  }
  if (-not [string]::IsNullOrWhiteSpace($RepoName)) {
    $terms += $RepoName.Trim()
  }
  return @($terms | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
}

function Test-ScanMatch {
  param(
    [Parameter(Mandatory=$true)]$Row,
    [string[]]$Terms = @()
  )

  $termList = @($Terms | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  if ($termList.Count -eq 0) {
    return $true
  }
  $haystack = @(
    $Row.scan_id,
    $Row.project_name,
    $Row.github_url,
    $Row.target_path,
    $Row.scan_file
  ) -join "`n"
  foreach ($term in $termList) {
    if ($haystack.IndexOf($term, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
      return $true
    }
  }
  return $false
}

function Read-SavedScans {
  $dirs = @(Get-CandidateDataDirs)
  if ($dirs.Count -eq 0) {
    throw "No saved scan directories found. Checked E:\secure-review\data, project data, and SECURE_REVIEW_DATA_DIR."
  }

  $rows = @()
  foreach ($dir in $dirs) {
    $scanDir = Join-Path $dir "scans"
    $files = Get-ChildItem -LiteralPath $scanDir -Filter "*.json" -File -ErrorAction SilentlyContinue |
      Sort-Object LastWriteTime -Descending
    foreach ($file in $files) {
      try {
        $scan = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
      } catch {
        continue
      }
      $project = [string]$scan.project_name
      $derivedGitHubUrl = ConvertFrom-RepoKeyToGitHubUrl $project
      $rows += [pscustomobject]@{
        scan_id = [string]$scan.scan_id
        project_name = $project
        github_url = if (-not [string]::IsNullOrWhiteSpace($derivedGitHubUrl)) { $derivedGitHubUrl } else { $GitHubUrl }
        created_at = [string]$scan.created_at
        findings = [int]$scan.summary.total_findings
        files_scanned = [int]$scan.summary.files_scanned
        target_path = [string]$scan.target_path
        data_dir = $dir
        scan_file = $file.FullName
        display = "$project | $($scan.scan_id) | findings=$($scan.summary.total_findings) | files=$($scan.summary.files_scanned) | $($scan.created_at)"
      }
    }
  }

  $terms = @(Get-SearchTerms)
  $matched = @($rows | Where-Object { Test-ScanMatch -Row $_ -Terms $terms } | Select-Object -First ([Math]::Max(1, $Limit)))
  return $matched
}

function Show-ScanPickerGui {
  param([Parameter(Mandatory=$true)][object[]]$Rows)

  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing

  $form = New-Object System.Windows.Forms.Form
  $form.Text = "Select Saved Scan"
  $form.Size = New-Object System.Drawing.Size(1160, 650)
  $form.StartPosition = "CenterScreen"
  $form.TopMost = $true

  $label = New-Object System.Windows.Forms.Label
  $label.Text = "Select one saved scan, then click Run Saved Flow"
  $label.AutoSize = $true
  $label.Location = New-Object System.Drawing.Point(12, 12)
  $form.Controls.Add($label)

  $search = New-Object System.Windows.Forms.TextBox
  $search.Width = 760
  $search.Location = New-Object System.Drawing.Point(12, 38)
  $search.PlaceholderText = "Filter by repo name, scan id, GitHub URL, or path"
  $form.Controls.Add($search)

  $list = New-Object System.Windows.Forms.ListView
  $list.View = [System.Windows.Forms.View]::Details
  $list.FullRowSelect = $true
  $list.GridLines = $true
  $list.MultiSelect = $false
  $list.Location = New-Object System.Drawing.Point(12, 70)
  $list.Size = New-Object System.Drawing.Size(1120, 480)
  [void]$list.Columns.Add("Project", 220)
  [void]$list.Columns.Add("Scan ID", 120)
  [void]$list.Columns.Add("Created", 170)
  [void]$list.Columns.Add("Findings", 80)
  [void]$list.Columns.Add("Files", 80)
  [void]$list.Columns.Add("GitHub URL", 260)
  [void]$list.Columns.Add("Target Path", 520)
  $form.Controls.Add($list)

  function Add-RowsToList {
    param([object[]]$Items)
    $list.Items.Clear()
    foreach ($row in $Items) {
      $item = New-Object System.Windows.Forms.ListViewItem($row.project_name)
      [void]$item.SubItems.Add($row.scan_id)
      [void]$item.SubItems.Add($row.created_at)
      [void]$item.SubItems.Add([string]$row.findings)
      [void]$item.SubItems.Add([string]$row.files_scanned)
      [void]$item.SubItems.Add($row.github_url)
      [void]$item.SubItems.Add($row.target_path)
      $item.Tag = $row
      [void]$list.Items.Add($item)
    }
    if ($list.Items.Count -gt 0) {
      $list.Items[0].Selected = $true
    }
  }

  Add-RowsToList -Items $Rows

  $search.Add_TextChanged({
    $needle = $search.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($needle)) {
      Add-RowsToList -Items $Rows
      return
    }
    $filtered = @($Rows | Where-Object {
      $_.display.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
      $_.target_path.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
      $_.github_url.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
    })
    Add-RowsToList -Items $filtered
  })

  $ok = New-Object System.Windows.Forms.Button
  $ok.Text = "Run Saved Flow"
  $ok.Width = 140
  $ok.Location = New-Object System.Drawing.Point(840, 565)
  $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
  $form.AcceptButton = $ok
  $form.Controls.Add($ok)

  $cancel = New-Object System.Windows.Forms.Button
  $cancel.Text = "Cancel"
  $cancel.Width = 100
  $cancel.Location = New-Object System.Drawing.Point(1000, 565)
  $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
  $form.CancelButton = $cancel
  $form.Controls.Add($cancel)

  $list.Add_DoubleClick({ $form.DialogResult = [System.Windows.Forms.DialogResult]::OK; $form.Close() })

  $result = $form.ShowDialog()
  if ($result -ne [System.Windows.Forms.DialogResult]::OK -or $list.SelectedItems.Count -lt 1) {
    return $null
  }
  return $list.SelectedItems[0].Tag
}

function Show-ScanPickerConsole {
  param([Parameter(Mandatory=$true)][object[]]$Rows)

  $filtered = @($Rows)
  while ($true) {
    Write-Host ""
    Write-Host "Saved scans:"
    for ($index = 0; $index -lt [Math]::Min($filtered.Count, 50); $index++) {
      $row = $filtered[$index]
      "{0,3}. {1} | {2} | findings={3} | files={4}" -f ($index + 1), $row.project_name, $row.scan_id, $row.findings, $row.files_scanned | Write-Host
    }
    if ($filtered.Count -gt 50) {
      Write-Host "... showing first 50 of $($filtered.Count). Type a search term to narrow the list."
    }
    $choice = Read-Host "Enter number to run, search text to filter, or Q to quit"
    if ($choice -match '^[Qq]$') {
      return $null
    }
    if ($choice -match '^\d+$') {
      $selectedIndex = [int]$choice - 1
      if ($selectedIndex -ge 0 -and $selectedIndex -lt $filtered.Count) {
        return $filtered[$selectedIndex]
      }
      Write-Warning "Invalid selection."
      continue
    }
    $needle = $choice.Trim()
    $filtered = @($Rows | Where-Object {
      $_.display.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
      $_.target_path.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
      $_.github_url.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
    })
    if ($filtered.Count -eq 0) {
      Write-Warning "No matches. Resetting list."
      $filtered = @($Rows)
    }
  }
}

function Test-ScanAvailableInApi {
  param(
    [Parameter(Mandatory=$true)][string]$ApiBaseUrl,
    [Parameter(Mandatory=$true)][string]$ScanId
  )

  $encodedScanId = [System.Uri]::EscapeDataString($ScanId)
  $uri = "$($ApiBaseUrl.TrimEnd('/'))/api/scans/$encodedScanId"
  $headers = @{}
  if (-not [string]::IsNullOrWhiteSpace($BearerToken)) {
    $headers["Authorization"] = "Bearer $BearerToken"
  }

  try {
    Invoke-RestMethod -Method Get -Uri $uri -Headers $headers | Out-Null
    return $true
  } catch {
    return $false
  }
}

function Get-RunCommandHint {
  param([Parameter(Mandatory=$true)]$Selected)

  $dataRoot = Split-Path -Parent $Selected.data_dir
  if ([string]::IsNullOrWhiteSpace($dataRoot)) {
    $dataRoot = $Selected.data_dir
  }
  $reportsDir = Join-Path $dataRoot "reports"
  return ".\run.ps1 -DataDir `"$($Selected.data_dir)`" -ReportsDir `"$reportsDir`""
}

$rows = @(Read-SavedScans)
if ($rows.Count -eq 0) {
  throw "No matching saved scans found."
}

if ($ListOnly) {
  $rows | Select-Object project_name, scan_id, created_at, findings, files_scanned, github_url, target_path | Format-Table -AutoSize
  exit 0
}

$selected = $null
if (-not [string]::IsNullOrWhiteSpace($ScanId) -and $rows.Count -eq 1) {
  $selected = $rows[0]
} else {
  if (-not $Console) {
    try {
      $selected = Show-ScanPickerGui -Rows $rows
    } catch {
      Write-Warning "GUI picker unavailable: $($_.Exception.Message)"
    }
  }
  if (-not $selected) {
    $selected = Show-ScanPickerConsole -Rows $rows
  }
}

if (-not $selected) {
  Write-Host "No scan selected."
  exit 1
}

$resolvedGitHubUrl = $GitHubUrl
if ([string]::IsNullOrWhiteSpace($resolvedGitHubUrl)) {
  $resolvedGitHubUrl = $selected.github_url
}
if ([string]::IsNullOrWhiteSpace($resolvedGitHubUrl)) {
  $resolvedGitHubUrl = Read-Host "GitHub URL could not be derived. Enter GitHub URL for $($selected.project_name)"
}

$flowScript = Join-Path $PSScriptRoot "test-saved-scan-flow.ps1"
if (-not (Test-Path -LiteralPath $flowScript)) {
  throw "Saved scan flow script not found: $flowScript"
}

Write-Host ""
Write-Host "Selected:"
Write-Host "  Repo:      $($selected.project_name)"
Write-Host "  Scan ID:   $($selected.scan_id)"
Write-Host "  GitHub:    $resolvedGitHubUrl"
Write-Host "  Data dir:  $($selected.data_dir)"
Write-Host ""

if (-not (Test-ScanAvailableInApi -ApiBaseUrl $ApiBaseUrl -ScanId $selected.scan_id)) {
  Write-Warning "The running app cannot see scan '$($selected.scan_id)' in its configured data directory."
  Write-Host "Selected scan data dir: $($selected.data_dir)"
  Write-Host "Restart the app with this data directory, then rerun this script:"
  Write-Host "  $(Get-RunCommandHint -Selected $selected)"
  exit 1
}

$flowParams = @{
  ScanId = $selected.scan_id
  GitHubUrl = $resolvedGitHubUrl
  ApiBaseUrl = $ApiBaseUrl
  OutDir = $OutDir
}
if (-not [string]::IsNullOrWhiteSpace($BearerToken)) {
  $flowParams.BearerToken = $BearerToken
}
if (-not [string]::IsNullOrWhiteSpace($RunId)) {
  $flowParams.RunId = $RunId
}
if ($FailFast) {
  $flowParams.FailFast = $true
}

& $flowScript @flowParams
exit $LASTEXITCODE
