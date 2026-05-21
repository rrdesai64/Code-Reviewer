param(
  [Parameter(Mandatory=$true)][string]$Path,
  [string[]]$SarifIn = @(),
  [string]$SarifOut = "secure-review.sarif",
  [string]$ScannerMeshOut = "scanner-mesh.json",
  [string]$DependencyReviewOut = "dependency-review.json",
  [string]$SonarQubeOut = "sonarqube-quality-gate.json",
  [string]$ScannerDepthOut = "scanner-depth.json",
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
  [string]$ComplianceOut = "compliance.json",
  [string]$FixProposalsOut = "fix-proposals.json",
  [string]$RemediationPlanOut = "remediation-plan.json",
  [string]$IssuePlanOut = "issue-plan.json",
  [string]$ChatNotificationOut = "chat-notification.json",
  [string]$TeamLearningOut = "team-learning-dashboard.json",
  [string]$FixBundleOut = "fix-bundle.json",
  [string]$FixApplyOut = "fix-apply-dry-run.json"
)

$argsList = @(
  '-m', 'app.cli',
  '--path', $Path,
  '--sarif-out', $SarifOut,
  '--scanner-mesh-out', $ScannerMeshOut,
  '--dependency-review-out', $DependencyReviewOut,
  '--sonarqube-out', $SonarQubeOut,
  '--scanner-depth-out', $ScannerDepthOut,
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
  '--pr-comment-out', 'pr-comment.md',
  '--compliance-out', $ComplianceOut,
  '--fix-proposals-out', $FixProposalsOut,
  '--remediation-plan-out', $RemediationPlanOut,
  '--issue-plan-out', $IssuePlanOut,
  '--chat-notification-out', $ChatNotificationOut,
  '--team-learning-out', $TeamLearningOut,
  '--fix-bundle-out', $FixBundleOut,
  '--fix-apply-out', $FixApplyOut
)

foreach ($item in $SarifIn) {
  $argsList += @('--sarif-in', $item)
}

& .\.venv\Scripts\python.exe @argsList
