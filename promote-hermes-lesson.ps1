param(
  [Parameter(Mandatory=$true)][string]$LessonId,
  [string]$ApiBaseUrl = "http://127.0.0.1:8000",
  [string]$BearerToken = "",
  [string]$Actor = "Codex-teacher",
  [string]$ReviewNote = "Codex delegated teacher review accepted this lesson for benchmark evaluation.",
  [string]$ApprovalNote = "Codex delegated teacher approval recorded after benchmark evidence passed.",
  [string]$ActivationNote = "Activated by Codex delegated teacher after benchmark and approval gates.",
  [string]$BenchmarkEvidenceFile = "",
  [string]$BenchmarkEvidenceJson = "",
  [switch]$DryRun
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
  Invoke-RestMethod -Method Post -Uri (New-ApiUri $Path) -Headers $headers -Body ($Body | ConvertTo-Json -Depth 50)
}

function Read-BenchmarkEvidence {
  if (-not [string]::IsNullOrWhiteSpace($BenchmarkEvidenceJson)) {
    return $BenchmarkEvidenceJson | ConvertFrom-Json
  }
  if (-not [string]::IsNullOrWhiteSpace($BenchmarkEvidenceFile)) {
    $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BenchmarkEvidenceFile)
    return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
  }
  throw "Benchmark evidence is required. Pass -BenchmarkEvidenceFile or -BenchmarkEvidenceJson."
}

function ConvertTo-Hashtable {
  param($Value)

  if ($null -eq $Value) {
    return @{}
  }
  if ($Value -is [hashtable]) {
    return $Value
  }
  if ($Value -is [pscustomobject]) {
    $result = @{}
    foreach ($property in $Value.PSObject.Properties) {
      $result[$property.Name] = ConvertTo-Hashtable $property.Value
    }
    return $result
  }
  if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
    return @($Value | ForEach-Object { ConvertTo-Hashtable $_ })
  }
  return $Value
}

function Invoke-Transition {
  param(
    [Parameter(Mandatory=$true)][string]$TargetState,
    [string]$Note = "",
    $BenchmarkEvidence = $null
  )

  $body = [ordered]@{
    target_state = $TargetState
    note = $Note
    delegated_actor = $Actor
  }
  if ($null -ne $BenchmarkEvidence) {
    $body.benchmark_evidence = ConvertTo-Hashtable $BenchmarkEvidence
  }

  if ($DryRun) {
    Write-Host "DRY RUN: transition $LessonId -> $TargetState"
    return [pscustomobject]@{
      lesson_id = $LessonId
      promotion_state = $TargetState
      learning_influence_allowed = $false
      dry_run = $true
    }
  }

  Invoke-ApiPost -Path "/api/benchmark-gate/lessons/$([System.Uri]::EscapeDataString($LessonId))/transition" -Body ([pscustomobject]$body)
}

$lessonReport = Invoke-ApiGet -Path "/api/benchmark-gate/lessons"
$lesson = @($lessonReport.lessons | Where-Object { $_.lesson_id -eq $LessonId } | Select-Object -First 1)
if (-not $lesson) {
  throw "Benchmark lesson not found: $LessonId"
}

$evidence = Read-BenchmarkEvidence
$state = [string]$lesson.promotion_state

Write-Host "Promoting lesson: $LessonId"
Write-Host "Current state: $state"
Write-Host "Actor: $Actor"

if ($state -eq "proposed") {
  $lesson = Invoke-Transition -TargetState "reviewed" -Note $ReviewNote
  $state = [string]$lesson.promotion_state
  Write-Host "State: $state"
}
if ($state -eq "reviewed") {
  $lesson = Invoke-Transition -TargetState "benchmarked" -Note "Benchmark evidence supplied by $Actor." -BenchmarkEvidence $evidence
  $state = [string]$lesson.promotion_state
  Write-Host "State: $state"
}
if ($state -eq "benchmarked") {
  $lesson = Invoke-Transition -TargetState "approved" -Note $ApprovalNote
  $state = [string]$lesson.promotion_state
  Write-Host "State: $state"
}
if ($state -eq "approved") {
  $lesson = Invoke-Transition -TargetState "active" -Note $ActivationNote
  $state = [string]$lesson.promotion_state
  Write-Host "State: $state"
}

Write-Host ""
Write-Host "Final lesson state:"
Write-Host "  Lesson ID: $($lesson.lesson_id)"
Write-Host "  State:     $($lesson.promotion_state)"
Write-Host "  Active:    $($lesson.learning_influence_allowed)"
Write-Host ""
Write-Host "No scanner rules, parser code, suppressions, or repository files were modified."
