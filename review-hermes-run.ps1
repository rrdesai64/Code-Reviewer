param(
  [string]$ScanId = "",
  [string]$RunId = "",
  [string]$ApiBaseUrl = "http://127.0.0.1:8000",
  [string]$BearerToken = "",
  [string]$Reviewer = "",
  [string]$Decision = "",
  [string]$Note = "",
  [string[]]$ReviewItemId = @(),
  [int]$Limit = 50,
  [switch]$AllPending,
  [switch]$ListOnly,
  [string]$OutFile = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-ApiHeaders {
  $headers = @{}
  if (-not [string]::IsNullOrWhiteSpace($BearerToken)) {
    $headers["Authorization"] = "Bearer $BearerToken"
  }
  return $headers
}

function New-ApiUri {
  param([Parameter(Mandatory=$true)][string]$Path)
  return "$($ApiBaseUrl.TrimEnd('/'))$Path"
}

function Invoke-ApiGet {
  param([Parameter(Mandatory=$true)][string]$Path)
  Invoke-RestMethod -Method Get -Uri (New-ApiUri $Path) -Headers (New-ApiHeaders)
}

function Invoke-ApiPost {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)]$Body
  )
  $headers = New-ApiHeaders
  $headers["Content-Type"] = "application/json"
  Invoke-RestMethod -Method Post -Uri (New-ApiUri $Path) -Headers $headers -Body ($Body | ConvertTo-Json -Depth 20)
}

function ConvertTo-ShortText {
  param(
    [string]$Text,
    [int]$Length = 90
  )
  $clean = ($Text -replace '\s+', ' ').Trim()
  if ($clean.Length -le $Length) {
    return $clean
  }
  return $clean.Substring(0, [Math]::Max(0, $Length - 14)).TrimEnd() + "...[truncated]"
}

function Get-QueuePath {
  if (-not [string]::IsNullOrWhiteSpace($RunId)) {
    return "/api/hermes/runs/$([System.Uri]::EscapeDataString($RunId))/review?include_decided=true&limit=$Limit"
  }
  if (-not [string]::IsNullOrWhiteSpace($ScanId)) {
    return "/api/scans/$([System.Uri]::EscapeDataString($ScanId))/hermes/review?include_decided=false&limit=$Limit"
  }
  return "/api/hermes/review-queue?limit=$Limit"
}

function Show-Queue {
  param([Parameter(Mandatory=$true)]$Queue)

  $items = @($Queue.items)
  if ($items.Count -eq 0) {
    Write-Host "No Hermes review items found."
    return
  }

  Write-Host ""
  Write-Host "Hermes review queue: $($Queue.status), pending=$($Queue.pending_count), total=$($Queue.count)"
  Write-Host ""
  for ($i = 0; $i -lt $items.Count; $i++) {
    $item = $items[$i]
    $finding = ConvertTo-ShortText -Text (@($item.findings) -join " | ")
    "{0,3}. {1} | {2} | {3} | {4} | {5}" -f ($i + 1), $item.review_state, $item.status, $item.agent_id, $item.task_type, $finding | Write-Host
    Write-Host "     repo=$($item.project_name) scan=$($item.scan_id) run=$($item.run_id)"
    Write-Host "     review_item_id=$($item.review_item_id)"
  }
}

function Select-ReviewItems {
  param([Parameter(Mandatory=$true)]$Queue)

  $items = @($Queue.items | Where-Object { $_.review_state -eq "pending" })
  if ($items.Count -eq 0) {
    return @()
  }
  if ($AllPending) {
    return $items
  }
  if ($ReviewItemId.Count -gt 0) {
    $requested = @{}
    foreach ($id in $ReviewItemId) {
      if (-not [string]::IsNullOrWhiteSpace($id)) {
        $requested[$id] = $true
      }
    }
    return @($items | Where-Object { $requested.ContainsKey($_.review_item_id) })
  }

  $choice = Read-Host "Enter item numbers separated by comma, A for all pending, or Q to quit"
  if ($choice -match '^[Qq]$') {
    return @()
  }
  if ($choice -match '^[Aa]$') {
    return $items
  }

  $selected = @()
  foreach ($part in $choice.Split(',')) {
    $trimmed = $part.Trim()
    if ($trimmed -match '^\d+$') {
      $index = [int]$trimmed - 1
      if ($index -ge 0 -and $index -lt @($Queue.items).Count) {
        $item = @($Queue.items)[$index]
        if ($item.review_state -eq "pending") {
          $selected += $item
        }
      }
    }
  }
  return $selected
}

function Resolve-Decision {
  $allowed = @("needs_fix", "confirmed_true_positive", "accepted_risk", "false_positive", "needs_more_evidence", "acknowledged")
  if (-not [string]::IsNullOrWhiteSpace($Decision)) {
    if ($allowed -notcontains $Decision) {
      throw "Invalid decision '$Decision'. Allowed: $($allowed -join ', ')"
    }
    return $Decision
  }
  Write-Host ""
  Write-Host "Decision options:"
  for ($i = 0; $i -lt $allowed.Count; $i++) {
    "{0,3}. {1}" -f ($i + 1), $allowed[$i] | Write-Host
  }
  $choice = Read-Host "Choose decision number"
  if ($choice -notmatch '^\d+$') {
    throw "Decision selection cancelled."
  }
  $index = [int]$choice - 1
  if ($index -lt 0 -or $index -ge $allowed.Count) {
    throw "Invalid decision selection."
  }
  return $allowed[$index]
}

$queue = Invoke-ApiGet -Path (Get-QueuePath)
if (-not [string]::IsNullOrWhiteSpace($OutFile)) {
  $outPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
  $parent = Split-Path -Parent $outPath
  if (-not [string]::IsNullOrWhiteSpace($parent)) {
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
  }
  $queue | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $outPath -Encoding UTF8
  Write-Host "Hermes review queue saved: $outPath"
}

Show-Queue -Queue $queue
if ($ListOnly) {
  exit 0
}

$selectedItems = @(Select-ReviewItems -Queue $queue)
if ($selectedItems.Count -eq 0) {
  Write-Host "No Hermes review items selected."
  exit 0
}

$resolvedDecision = Resolve-Decision
$resolvedReviewer = $Reviewer
if ([string]::IsNullOrWhiteSpace($resolvedReviewer)) {
  $resolvedReviewer = $env:USERNAME
}
if ([string]::IsNullOrWhiteSpace($Note)) {
  $Note = Read-Host "Review note"
}

$byRun = $selectedItems | Group-Object run_id
$responses = @()
foreach ($group in $byRun) {
  $body = [pscustomobject]@{
    decision = $resolvedDecision
    reviewer = $resolvedReviewer
    note = $Note
    review_item_ids = @($group.Group | ForEach-Object { $_.review_item_id })
  }
  $responses += Invoke-ApiPost -Path "/api/hermes/runs/$([System.Uri]::EscapeDataString($group.Name))/review" -Body $body
}

Write-Host ""
foreach ($response in $responses) {
  Write-Host "Recorded review $($response.review.review_id): decision=$($response.review.decision), items=$($response.review.item_count), remaining=$($response.remaining_pending_count)"
}
