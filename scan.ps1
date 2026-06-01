param(
  [Parameter(Mandatory=$true)][string]$Path,
  [string]$JsonOut = "scan.json",
  [string[]]$SarifIn = @(),
  [string[]]$CoverageIn = @(),
  [string]$SarifOut = "secure-review.sarif",
  [string]$ScannerMeshOut = "scanner-mesh.json",
  [string]$ConsolidatedFindingsOut = "finding-consolidation.json",
  [string]$PrioritizationOut = "prioritization.json",
  [string]$SoundnessOut = "soundness-verdict.json",
  [string]$RuntimePlanOut = "runtime-plan.json",
  [string]$RuntimeBuildRunPreviewOut = "runtime-build-run-worker.json",
  [string]$RuntimeSmokePostureOut = "runtime-smoke-posture.json",
  [string]$ReachabilityContextOut = "reachability-context.json",
  [string]$DependencyReviewOut = "dependency-review.json",
  [string]$SonarQubeOut = "sonarqube-quality-gate.json",
  [string]$ScannerDepthOut = "scanner-depth.json",
  [string]$CatalogCoverageOut = "catalog-coverage-map.json",
  [string]$AdvancedAiOut = "advanced-ai.json",
  [string]$AiReviewOut = "ai-review.json",
  [string]$CycloneDxOut = "cyclonedx-sbom.json",
  [string]$SpdxOut = "spdx-sbom.json",
  [string]$SpdxComplianceOut = "spdx-compliance.json",
  [string]$SbomPolicyOut = "sbom-policy.json",
  [string]$SecretPolicyOut = "secret-policy.json",
  [string]$GitHubPrReviewOut = "github-pr-review.json",
  [string]$CodeHostReviewOut = "code-host-review.json",
  [string]$SbomCompareOut = "sbom-compare.json",
  [string]$ReportOut = "secure-review.md",
  [string]$PrCommentOut = "pr-comment.md",
  [string]$ComplianceOut = "compliance.json",
  [string]$FixProposalsOut = "fix-proposals.json",
  [string]$RemediationPlanOut = "remediation-plan.json",
  [string]$IssuePlanOut = "issue-plan.json",
  [string]$ChatNotificationOut = "chat-notification.json",
  [string]$TeamLearningOut = "team-learning-dashboard.json",
  [string]$RecursiveLearningOut = "recursive-learning.json",
  [string]$BenchmarkGateOut = "benchmark-gate.json",
  [string]$MessagingGatewayOut = "messaging-gateway.json",
  [string]$GovernanceOut = "governance-evidence.json",
  [string]$QuarantinePolicyOut = "quarantine-policy.json",
  [string]$SuppressionsOut = "inline-suppressions.json",
  [string]$SanitizedReportOut = "sanitized-report.json",
  [string]$RagMemoryOut = "rag-memory.json",
  [string]$HermesOut = "hermes-orchestration.json",
  [string]$FixBundleOut = "fix-bundle.json",
  [string]$FixApplyOut = "fix-apply-dry-run.json",
  [string]$VerifiedAutofixOut = "verified-autofix-dry-run.json",
  [string]$InsideOutAutofixLoopOut = "inside-out-autofix-loop-dry-run.json",
  [string]$SonarProjectKey = "",
  [string]$SonarProjectName = "",
  [string]$SonarBranchName = ""
)

$EnvFile = Join-Path $PSScriptRoot ".env"

if (Test-Path $EnvFile) {
  Get-Content $EnvFile | ForEach-Object {
    $line = $_.Trim()

    if ($line -eq "" -or $line.StartsWith("#")) {
      return
    }

    if ($line -match "^\s*([^=]+?)\s*=\s*(.*)\s*$") {
      $name = $matches[1].Trim()
      $value = $matches[2].Trim().Trim('"').Trim("'")
      $currentValue = [Environment]::GetEnvironmentVariable($name, "Process")
      if ([string]::IsNullOrWhiteSpace($currentValue)) {
        [Environment]::SetEnvironmentVariable($name, $value, "Process")
      }
    }
  }
}

$DefaultOutputRoot = if (-not [string]::IsNullOrWhiteSpace($env:SECURE_REVIEW_OUTPUT_ROOT)) { $env:SECURE_REVIEW_OUTPUT_ROOT } else { "E:\secure-review" }
[Environment]::SetEnvironmentVariable("SECURE_REVIEW_OUTPUT_ROOT", $DefaultOutputRoot, "Process")
if ([string]::IsNullOrWhiteSpace($env:SECURE_REVIEW_DATA_DIR)) {
  [Environment]::SetEnvironmentVariable("SECURE_REVIEW_DATA_DIR", (Join-Path $DefaultOutputRoot "data"), "Process")
}
if ([string]::IsNullOrWhiteSpace($env:REPORT_BUNDLE_DIR)) {
  [Environment]::SetEnvironmentVariable("REPORT_BUNDLE_DIR", (Join-Path $DefaultOutputRoot "reports"), "Process")
}
[Environment]::SetEnvironmentVariable("PYTHONDONTWRITEBYTECODE", "1", "Process")

$CacheRoot = Join-Path $DefaultOutputRoot "cache"
$CachePaths = @{
  "SONAR_USER_HOME" = Join-Path $CacheRoot "sonar"
  "DOTNET_CLI_HOME" = Join-Path $CacheRoot "dotnet"
  "NUGET_PACKAGES" = Join-Path $CacheRoot "nuget-packages"
  "TEMP" = Join-Path $CacheRoot "temp"
  "TMP" = Join-Path $CacheRoot "temp"
}
foreach ($entry in $CachePaths.GetEnumerator()) {
  if ($entry.Key -in @("TEMP", "TMP", "SONAR_USER_HOME")) {
    [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, "Process")
  } elseif ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($entry.Key, "Process"))) {
    [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, "Process")
  }
  New-Item -ItemType Directory -Force -Path ([Environment]::GetEnvironmentVariable($entry.Key, "Process")) | Out-Null
}

if (-not [string]::IsNullOrWhiteSpace($SonarProjectKey)) {
  [Environment]::SetEnvironmentVariable("SONAR_PROJECT_KEY", $SonarProjectKey, "Process")
}
if (-not [string]::IsNullOrWhiteSpace($SonarProjectName)) {
  [Environment]::SetEnvironmentVariable("SONAR_PROJECT_NAME", $SonarProjectName, "Process")
}
if (-not [string]::IsNullOrWhiteSpace($SonarBranchName)) {
  [Environment]::SetEnvironmentVariable("SONAR_BRANCH_NAME", $SonarBranchName, "Process")
}

$argsList = @(
  '-m', 'app.cli',
  '--path', $Path,
  '--json-out', $JsonOut,
  '--sarif-out', $SarifOut,
  '--scanner-mesh-out', $ScannerMeshOut,
  '--consolidated-findings-out', $ConsolidatedFindingsOut,
  '--prioritization-out', $PrioritizationOut,
  '--soundness-out', $SoundnessOut,
  '--runtime-plan-out', $RuntimePlanOut,
  '--runtime-build-run-preview-out', $RuntimeBuildRunPreviewOut,
  '--runtime-smoke-preview-out', $RuntimeSmokePostureOut,
  '--reachability-context-out', $ReachabilityContextOut,
  '--dependency-review-out', $DependencyReviewOut,
  '--sonarqube-out', $SonarQubeOut,
  '--scanner-depth-out', $ScannerDepthOut,
  '--catalog-coverage-out', $CatalogCoverageOut,
  '--advanced-ai-out', $AdvancedAiOut,
  '--ai-review-out', $AiReviewOut,
  '--cyclonedx-out', $CycloneDxOut,
  '--spdx-out', $SpdxOut,
  '--spdx-compliance-out', $SpdxComplianceOut,
  '--sbom-policy-out', $SbomPolicyOut,
  '--secret-policy-out', $SecretPolicyOut,
  '--github-pr-review-out', $GitHubPrReviewOut,
  '--code-host-review-out', $CodeHostReviewOut,
  '--sbom-compare-out', $SbomCompareOut,
  '--report-out', $ReportOut,
  '--pr-comment-out', $PrCommentOut,
  '--compliance-out', $ComplianceOut,
  '--fix-proposals-out', $FixProposalsOut,
  '--remediation-plan-out', $RemediationPlanOut,
  '--issue-plan-out', $IssuePlanOut,
  '--chat-notification-out', $ChatNotificationOut,
  '--team-learning-out', $TeamLearningOut,
  '--recursive-learning-out', $RecursiveLearningOut,
  '--benchmark-gate-out', $BenchmarkGateOut,
  '--messaging-gateway-out', $MessagingGatewayOut,
  '--governance-out', $GovernanceOut,
  '--quarantine-policy-out', $QuarantinePolicyOut,
  '--suppressions-out', $SuppressionsOut,
  '--sanitized-report-out', $SanitizedReportOut,
  '--rag-memory-out', $RagMemoryOut,
  '--hermes-out', $HermesOut,
  '--fix-bundle-out', $FixBundleOut,
  '--fix-apply-out', $FixApplyOut,
  '--verified-autofix-out', $VerifiedAutofixOut,
  '--inside-out-autofix-loop-out', $InsideOutAutofixLoopOut
)

foreach ($item in $SarifIn) {
  $argsList += @('--sarif-in', $item)
}

foreach ($item in $CoverageIn) {
  $argsList += @('--coverage-in', $item)
}

& .\.venv\Scripts\python.exe @argsList
