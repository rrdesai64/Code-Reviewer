param(
  [string]$ProjectKey = "",
  [string]$HostUrl = "",
  [string]$Organization = "",
  [string]$Token = "",
  [string]$BranchName = "",
  [string]$PullRequestKey = "",
  [string]$OutFile = "",
  [switch]$SkipHotspots
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Import-EnvFile {
  $envFile = Join-Path $PSScriptRoot ".env"
  if (-not (Test-Path -LiteralPath $envFile)) {
    return
  }

  Get-Content -LiteralPath $envFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -eq "" -or $line.StartsWith("#")) {
      return
    }
    if ($line -match "^\s*([^=]+?)\s*=\s*(.*)\s*$") {
      $name = $matches[1].Trim()
      $value = $matches[2].Trim().Trim('"').Trim("'")
      if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name, "Process"))) {
        [Environment]::SetEnvironmentVariable($name, $value, "Process")
      }
    }
  }
}

function Resolve-Setting {
  param(
    [string]$Value,
    [string]$EnvName,
    [string]$Default = ""
  )

  if (-not [string]::IsNullOrWhiteSpace($Value)) {
    return $Value.Trim()
  }
  $envValue = [Environment]::GetEnvironmentVariable($EnvName, "Process")
  if (-not [string]::IsNullOrWhiteSpace($envValue)) {
    return $envValue.Trim()
  }
  return $Default
}

function ConvertTo-QueryString {
  param([hashtable]$Params)

  $pairs = @()
  foreach ($entry in $Params.GetEnumerator() | Sort-Object Name) {
    if ([string]::IsNullOrWhiteSpace([string]$entry.Value)) {
      continue
    }
    $pairs += ([System.Uri]::EscapeDataString([string]$entry.Key) + "=" + [System.Uri]::EscapeDataString([string]$entry.Value))
  }
  return ($pairs -join "&")
}

function Add-SonarContextParams {
  param(
    [hashtable]$Params,
    [bool]$IncludePullRequest = $false
  )

  $copy = @{}
  foreach ($entry in $Params.GetEnumerator()) {
    $copy[$entry.Key] = $entry.Value
  }
  if (-not [string]::IsNullOrWhiteSpace($script:Organization)) {
    $copy["organization"] = $script:Organization
  }
  if ($IncludePullRequest -and -not [string]::IsNullOrWhiteSpace($script:PullRequestKey)) {
    $copy["pullRequest"] = $script:PullRequestKey
  } elseif (-not [string]::IsNullOrWhiteSpace($script:BranchName)) {
    $copy["branch"] = $script:BranchName
  }
  return $copy
}

function Remove-Secret {
  param([string]$Text)

  if ([string]::IsNullOrWhiteSpace($Text)) {
    return ""
  }
  if (-not [string]::IsNullOrWhiteSpace($script:Token)) {
    $Text = $Text.Replace($script:Token, "[REDACTED]")
  }
  return $Text
}

function New-SonarUri {
  param(
    [string]$Path,
    [hashtable]$Params
  )

  $query = ConvertTo-QueryString -Params $Params
  $base = $script:HostUrl.TrimEnd("/")
  if ([string]::IsNullOrWhiteSpace($query)) {
    return "$base$Path"
  }
  return "$base$Path`?$query"
}

function Read-ErrorBody {
  param($ErrorRecord)

  $body = ""
  try {
    if ($ErrorRecord.ErrorDetails -and -not [string]::IsNullOrWhiteSpace($ErrorRecord.ErrorDetails.Message)) {
      $body = $ErrorRecord.ErrorDetails.Message
    }
  } catch {
  }
  try {
    $response = $ErrorRecord.Exception.Response
    if ([string]::IsNullOrWhiteSpace($body) -and $response -and $response.GetResponseStream) {
      $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
      $body = $reader.ReadToEnd()
    }
  } catch {
  }
  return (Remove-Secret $body)
}

function Invoke-SonarGet {
  param(
    [string]$Name,
    [string]$Path,
    [hashtable]$Params,
    [bool]$Required = $true
  )

  $uri = New-SonarUri -Path $Path -Params $Params
  $headers = @{ Authorization = "Bearer $script:Token" }
  Write-Host "GET  $Path"

  try {
    $response = Invoke-WebRequest -Method Get -Uri $uri -Headers $headers -TimeoutSec 45 -ErrorAction Stop
    $payload = $null
    if (-not [string]::IsNullOrWhiteSpace($response.Content)) {
      try {
        $payload = $response.Content | ConvertFrom-Json
      } catch {
        $payload = $response.Content
      }
    }
    return [pscustomobject]@{
      name = $Name
      path = $Path
      uri = $uri
      required = $Required
      status = "passed"
      http_status = [int]$response.StatusCode
      error = ""
      error_body = ""
      summary = Get-ResponseSummary -Name $Name -Payload $payload
    }
  } catch {
    $statusCode = 0
    try {
      if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
        $statusCode = [int]$_.Exception.Response.StatusCode
      }
    } catch {
    }
    return [pscustomobject]@{
      name = $Name
      path = $Path
      uri = $uri
      required = $Required
      status = "failed"
      http_status = $statusCode
      error = Remove-Secret $_.Exception.Message
      error_body = Read-ErrorBody -ErrorRecord $_
      summary = ""
    }
  }
}

function Get-ResponseSummary {
  param(
    [string]$Name,
    $Payload
  )

  if ($null -eq $Payload) {
    return ""
  }
  if ($Name -eq "authentication") {
    return "valid=$($Payload.valid)"
  }
  if ($Name -eq "project") {
    return "project=$($Payload.component.key)"
  }
  if ($Name -eq "issues") {
    return "total=$($Payload.total), returned=$(@($Payload.issues).Count)"
  }
  if ($Name -eq "hotspots") {
    return "returned=$(@($Payload.hotspots).Count)"
  }
  if ($Name -eq "quality-gate") {
    return "status=$($Payload.projectStatus.status)"
  }
  return ""
}

Import-EnvFile

$script:ProjectKey = Resolve-Setting -Value $ProjectKey -EnvName "SONAR_PROJECT_KEY"
$script:HostUrl = Resolve-Setting -Value $HostUrl -EnvName "SONAR_HOST_URL" -Default "https://sonarcloud.io"
$script:Organization = Resolve-Setting -Value $Organization -EnvName "SONAR_ORGANIZATION"
$script:Token = Resolve-Setting -Value $Token -EnvName "SONAR_TOKEN"
$script:BranchName = Resolve-Setting -Value $BranchName -EnvName "SONAR_BRANCH_NAME"
$script:PullRequestKey = Resolve-Setting -Value $PullRequestKey -EnvName "SONAR_PULLREQUEST_KEY"

if ([string]::IsNullOrWhiteSpace($script:ProjectKey)) {
  throw "ProjectKey is required. Pass -ProjectKey or set SONAR_PROJECT_KEY."
}
if ([string]::IsNullOrWhiteSpace($script:Token)) {
  throw "SONAR_TOKEN is required. Set it in the environment or .env."
}
if ($script:HostUrl -match 'sonarcloud\.io' -and [string]::IsNullOrWhiteSpace($script:Organization)) {
  throw "Organization is required for SonarCloud. Pass -Organization or set SONAR_ORGANIZATION."
}

$checks = @()
$checks += Invoke-SonarGet -Name "authentication" -Path "/api/authentication/validate" -Params @{} -Required $true
$checks += Invoke-SonarGet -Name "project" -Path "/api/components/show" -Params (Add-SonarContextParams -Params @{ component = $script:ProjectKey }) -Required $true
$checks += Invoke-SonarGet -Name "issues" -Path "/api/issues/search" -Params (Add-SonarContextParams -Params @{ componentKeys = $script:ProjectKey; types = "VULNERABILITY,BUG,CODE_SMELL"; ps = "1" }) -Required $true
if (-not $SkipHotspots) {
  $checks += Invoke-SonarGet -Name "hotspots" -Path "/api/hotspots/search" -Params (Add-SonarContextParams -Params @{ projectKey = $script:ProjectKey; ps = "1" } -IncludePullRequest $true) -Required $true
}
$checks += Invoke-SonarGet -Name "quality-gate" -Path "/api/qualitygates/project_status" -Params (Add-SonarContextParams -Params @{ projectKey = $script:ProjectKey } -IncludePullRequest $true) -Required $true

$failed = @($checks | Where-Object { $_.required -and $_.status -ne "passed" })
$report = [pscustomobject]@{
  schema_version = 1
  generated_at = (Get-Date).ToUniversalTime().ToString("o")
  status = if ($failed.Count -eq 0) { "passed" } else { "failed" }
  host_url = $script:HostUrl
  project_key = $script:ProjectKey
  organization = $script:Organization
  branch = $script:BranchName
  pull_request = $script:PullRequestKey
  auth_scheme = "Bearer"
  token_present = $true
  checks = $checks
}

$checks | Select-Object name, status, http_status, summary, error | Format-Table -AutoSize

if (-not [string]::IsNullOrWhiteSpace($OutFile)) {
  $outPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
  $parent = Split-Path -Parent $outPath
  if (-not [string]::IsNullOrWhiteSpace($parent)) {
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
  }
  $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $outPath -Encoding UTF8
  Write-Host "Sonar diagnostic report: $outPath"
}

if ($failed.Count -gt 0) {
  Write-Warning "Sonar API diagnostic failed: $($failed.Count) required check(s) failed."
  foreach ($item in $failed) {
    Write-Warning "$($item.name): $($item.error)"
    if (-not [string]::IsNullOrWhiteSpace($item.error_body)) {
      Write-Warning "body: $($item.error_body)"
    }
  }
  exit 1
}

Write-Host "Sonar API diagnostic passed."
