param(
  [Parameter(Mandatory=$true)][string]$Path,
  [string]$SarifOut = "secure-review.sarif",
  [string]$AdvancedAiOut = "advanced-ai.json",
  [string]$CycloneDxOut = "cyclonedx-sbom.json",
  [string]$SpdxOut = "spdx-sbom.json",
  [string]$SpdxComplianceOut = "spdx-compliance.json",
  [string]$SbomPolicyOut = "sbom-policy.json",
  [string]$SecretPolicyOut = "secret-policy.json",
  [string]$GitHubPrReviewOut = "github-pr-review.json",
  [string]$SbomCompareOut = "sbom-compare.json",
  [string]$ReportOut = "secure-review.md",
  [string]$ComplianceOut = "compliance.json",
  [string]$FixProposalsOut = "fix-proposals.json",
  [string]$RemediationPlanOut = "remediation-plan.json"
)
& .\.venv\Scripts\python.exe -m app.cli --path $Path --sarif-out $SarifOut --advanced-ai-out $AdvancedAiOut --cyclonedx-out $CycloneDxOut --spdx-out $SpdxOut --spdx-compliance-out $SpdxComplianceOut --sbom-policy-out $SbomPolicyOut --secret-policy-out $SecretPolicyOut --github-pr-review-out $GitHubPrReviewOut --sbom-compare-out $SbomCompareOut --report-out $ReportOut --pr-comment-out pr-comment.md --compliance-out $ComplianceOut --fix-proposals-out $FixProposalsOut --remediation-plan-out $RemediationPlanOut
