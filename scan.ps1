param(
  [Parameter(Mandatory=$true)][string]$Path,
  [string]$SarifOut = "secure-review.sarif",
  [string]$ReportOut = "secure-review.md",
  [string]$ComplianceOut = "compliance.json",
  [string]$FixProposalsOut = "fix-proposals.json",
  [string]$RemediationPlanOut = "remediation-plan.json"
)
& .\.venv\Scripts\python.exe -m app.cli --path $Path --sarif-out $SarifOut --report-out $ReportOut --pr-comment-out pr-comment.md --compliance-out $ComplianceOut --fix-proposals-out $FixProposalsOut --remediation-plan-out $RemediationPlanOut
