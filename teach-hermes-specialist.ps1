param(
  [string]$Language = "",
  [string]$AgentId = "",
  [string]$ScanId = "",
  [string]$RunId = "",
  [string]$ReviewItemId = "",
  [string]$ApiBaseUrl = "http://127.0.0.1:8000",
  [string]$BearerToken = "",
  [string]$LessonId = "",
  [string]$Category = "",
  [string]$Title = "",
  [string]$Source = "",
  [string]$RuleId = "",
  [string]$ProposedChange = "",
  [string]$Teacher = "",
  [string]$OutFile = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SupportedLanguages = @(
  "python",
  "javascript",
  "typescript",
  "go",
  "rust",
  "php",
  "java",
  "kotlin",
  "csharp",
  "iac-devops",
  "dependency-sbom",
  "secrets-malware-quarantine",
  "scanner-reliability"
)

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
  Invoke-RestMethod -Method Post -Uri (New-ApiUri $Path) -Headers $headers -Body ($Body | ConvertTo-Json -Depth 30)
}

function Get-ReviewQueuePath {
  if (-not [string]::IsNullOrWhiteSpace($RunId)) {
    return "/api/hermes/runs/$([System.Uri]::EscapeDataString($RunId))/review?include_decided=true&limit=100"
  }
  if (-not [string]::IsNullOrWhiteSpace($ScanId)) {
    return "/api/scans/$([System.Uri]::EscapeDataString($ScanId))/hermes/review?include_decided=false&limit=100"
  }
  return ""
}

function Select-ReviewItem {
  param($Queue)

  $items = @($Queue.items)
  if (-not [string]::IsNullOrWhiteSpace($AgentId)) {
    $items = @($items | Where-Object { $_.agent_id -eq $AgentId })
  }
  if ($items.Count -eq 0) {
    return $null
  }
  if (-not [string]::IsNullOrWhiteSpace($ReviewItemId)) {
    return @($items | Where-Object { $_.review_item_id -eq $ReviewItemId } | Select-Object -First 1)
  }
  Write-Host ""
  Write-Host "Hermes teacher candidates:"
  for ($i = 0; $i -lt $items.Count; $i++) {
    $item = $items[$i]
    $finding = ((@($item.findings) -join " | ") -replace '\s+', ' ').Trim()
    if ($finding.Length -gt 100) {
      $finding = $finding.Substring(0, 86).TrimEnd() + "...[truncated]"
    }
    "{0,3}. {1} | {2} | {3} | {4}" -f ($i + 1), $item.status, $item.agent_id, $item.task_type, $finding | Write-Host
  }
  $choice = Read-Host "Select item number to attach evidence, or press Enter to create lesson without item evidence"
  if ([string]::IsNullOrWhiteSpace($choice)) {
    return $null
  }
  if ($choice -notmatch '^\d+$') {
    throw "Invalid review item selection."
  }
  $index = [int]$choice - 1
  if ($index -lt 0 -or $index -ge $items.Count) {
    throw "Invalid review item selection."
  }
  return $items[$index]
}

function Resolve-Text {
  param(
    [string]$Value,
    [string]$Prompt
  )
  if (-not [string]::IsNullOrWhiteSpace($Value)) {
    return $Value
  }
  return Read-Host $Prompt
}

function Resolve-Language {
  param(
    [string]$RequestedLanguage,
    $ReviewItem
  )
  if (-not [string]::IsNullOrWhiteSpace($RequestedLanguage)) {
    return $RequestedLanguage.Trim().ToLowerInvariant()
  }
  if ($ReviewItem -and $ReviewItem.agent_id) {
    $id = [string]$ReviewItem.agent_id
    if ($id -match 'javascript-typescript') { return "javascript" }
    if ($id -match 'go-security') { return "go" }
    if ($id -match 'rust') { return "rust" }
    if ($id -match 'php') { return "php" }
    if ($id -match 'java-kotlin') { return "java" }
    if ($id -match 'dotnet-csharp') { return "csharp" }
    if ($id -match 'ruby') { return "ruby" }
    if ($id -match 'iac-devops') { return "iac-devops" }
    if ($id -match 'dependency-sbom') { return "dependency-sbom" }
    if ($id -match 'secrets-malware-quarantine') { return "secrets-malware-quarantine" }
    if ($id -match 'scanner-reliability') { return "scanner-reliability" }
    if ($id -match 'python') { return "python" }
  }
  return (Read-Host "Lesson language").Trim().ToLowerInvariant()
}

$reviewItem = $null
$queuePath = Get-ReviewQueuePath
if (-not [string]::IsNullOrWhiteSpace($queuePath)) {
  $queue = Invoke-ApiGet -Path $queuePath
  $reviewItem = Select-ReviewItem -Queue $queue
}

$resolvedLanguage = Resolve-Language -RequestedLanguage $Language -ReviewItem $reviewItem
if ($SupportedLanguages -notcontains $resolvedLanguage) {
  throw "Unsupported lesson language '$resolvedLanguage'. Supported: $($SupportedLanguages -join ', ')"
}
if ([string]::IsNullOrWhiteSpace($Category)) {
  $Category = "$resolvedLanguage-agent-feedback"
}

$resolvedTitle = Resolve-Text -Value $Title -Prompt "Teacher lesson title"
$resolvedChange = Resolve-Text -Value $ProposedChange -Prompt "Correction / proposed specialist-agent lesson"
if ([string]::IsNullOrWhiteSpace($resolvedTitle) -or [string]::IsNullOrWhiteSpace($resolvedChange)) {
  throw "Title and ProposedChange are required."
}

if ([string]::IsNullOrWhiteSpace($Teacher)) {
  $Teacher = $env:USERNAME
}
if ([string]::IsNullOrWhiteSpace($Teacher)) {
  $Teacher = "teacher"
}

$evidence = [ordered]@{
  teacher = $Teacher
  source = "teacher-feedback"
  created_from = "teach-hermes-specialist.ps1"
}
if (-not [string]::IsNullOrWhiteSpace($ScanId)) {
  $evidence.scan_id = $ScanId
}
if (-not [string]::IsNullOrWhiteSpace($RunId)) {
  $evidence.run_id = $RunId
}
if ($reviewItem) {
  $evidence.scan_id = $reviewItem.scan_id
  $evidence.run_id = $reviewItem.run_id
  $evidence.review_item_id = $reviewItem.review_item_id
  $evidence.agent_id = $reviewItem.agent_id
  $evidence.task_type = $reviewItem.task_type
  $evidence.agent_status = $reviewItem.status
  $evidence.findings = @($reviewItem.findings)
  $evidence.recommendations = @($reviewItem.recommendations)
  $evidence.evidence_refs = $reviewItem.evidence_refs
}

$body = [ordered]@{
  language = $resolvedLanguage
  category = $Category
  title = $resolvedTitle
  proposed_change = $resolvedChange
  evidence = $evidence
  delegated_actor = $Teacher
}
if (-not [string]::IsNullOrWhiteSpace($LessonId)) {
  $body.lesson_id = $LessonId
}
if (-not [string]::IsNullOrWhiteSpace($Source)) {
  $body.source = $Source
}
if (-not [string]::IsNullOrWhiteSpace($RuleId)) {
  $body.rule_id = $RuleId
}

$lesson = Invoke-ApiPost -Path "/api/benchmark-gate/lessons" -Body ([pscustomobject]$body)

if (-not [string]::IsNullOrWhiteSpace($OutFile)) {
  $outPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
  $parent = Split-Path -Parent $outPath
  if (-not [string]::IsNullOrWhiteSpace($parent)) {
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
  }
  $lesson | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $outPath -Encoding UTF8
  Write-Host "Teacher lesson saved: $outPath"
}

Write-Host ""
Write-Host "Teacher lesson proposed:"
Write-Host "  Lesson ID: $($lesson.lesson_id)"
Write-Host "  Language:  $resolvedLanguage"
Write-Host "  State:     $($lesson.promotion_state)"
Write-Host "  Active:    $($lesson.learning_influence_allowed)"
Write-Host ""
Write-Host "Next gate: reviewed -> benchmarked -> approved -> active"
