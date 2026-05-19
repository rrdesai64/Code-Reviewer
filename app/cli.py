from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .models import FixApplyRequest

from .enterprise import audit, compliance_report
from .dependency_review import dependency_review_report
from .advanced_ai import build_embedding_index, fine_tune_dataset_jsonl, fine_tune_experiment_plan, phase_g_report, run_multi_agent_review, semantic_search
from .github_pr import GitHubIntegrationError, build_github_pr_review
from .fix_workflow import apply_fix_bundle, build_fix_bundle
from .ingestion import scanner_mesh_report
from .issue_planning import IssuePlanningError, build_issue_plan
from .memory import update_repository_memory
from .refactor import build_fix_proposal, build_remediation_plan
from .reporting import github_pr_comment, markdown_report
from .sarif import build_sarif
from .sbom import build_cyclonedx, build_spdx, compare_sboms, sbom_policy_report, spdx_compliance_report
from .scanner import SEVERITY_ORDER, run_scan
from .scanner_depth import scanner_depth_report
from .sonarqube import sonarqube_quality_report
from .secrets import secret_policy_report
from .storage import load_baseline, load_scan, save_baseline, save_scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Secure Code Review Assistant CLI')
    parser.add_argument('scan', nargs='?', help='run a repository scan')
    parser.add_argument('--path', required=True, help='repository path to scan')
    parser.add_argument('--project-name', default=None)
    parser.add_argument('--json-out')
    parser.add_argument('--sarif-out')
    parser.add_argument('--sarif-in', action='append', default=[], help='import an external SARIF file into the normalized scanner mesh')
    parser.add_argument('--scanner-mesh-out')
    parser.add_argument('--dependency-review-out')
    parser.add_argument('--sonarqube-out')
    parser.add_argument('--scanner-depth-out')
    parser.add_argument('--advanced-ai-out')
    parser.add_argument('--agent-review-out')
    parser.add_argument('--finetune-experiment-out')
    parser.add_argument('--finetune-dataset-out')
    parser.add_argument('--embedding-index-out')
    parser.add_argument('--semantic-search-out')
    parser.add_argument('--cyclonedx-out')
    parser.add_argument('--spdx-out')
    parser.add_argument('--spdx-compliance-out')
    parser.add_argument('--sbom-policy-out')
    parser.add_argument('--secret-policy-out')
    parser.add_argument('--sbom-compare-out')
    parser.add_argument('--sbom-compare-to', help='saved scan ID to compare SBOMs against; defaults to the saved baseline scan when available')
    parser.add_argument('--report-out')
    parser.add_argument('--pr-comment-out')
    parser.add_argument('--github-pr-review-out')
    parser.add_argument('--github-pr-repository')
    parser.add_argument('--github-pr-number', type=int)
    parser.add_argument('--github-pr-commit')
    parser.add_argument('--github-pr-diff', help='path to a unified GitHub PR diff for offline inline-comment mapping')
    parser.add_argument('--github-pr-event', help='COMMENT, REQUEST_CHANGES, APPROVE, or auto')
    parser.add_argument('--github-pr-max-inline', type=int)
    parser.add_argument('--github-pr-min-risk', type=int)
    parser.add_argument('--github-pr-publish', action='store_true', help='publish the prepared PR review to GitHub')
    parser.add_argument('--github-pr-publish-status', action='store_true', help='publish a commit status for the PR head commit')
    parser.add_argument('--compliance-out')
    parser.add_argument('--fix-proposals-out')
    parser.add_argument('--remediation-plan-out')
    parser.add_argument('--issue-plan-out')
    parser.add_argument('--issue-plan-provider', choices=['all', 'jira', 'linear'], default='all')
    parser.add_argument('--issue-plan-limit', type=int, default=25)
    parser.add_argument('--issue-plan-min-priority', choices=['P0', 'P1', 'P2', 'P3', 'P4'], default='P2')
    parser.add_argument('--issue-plan-publish', action='store_true', help='publish planned remediation issues when Jira/Linear credentials and dry-run gates allow it')
    parser.add_argument('--fail-on-issue-plan-publish-failure', action='store_true', help='exit with code 10 when issue planning publish fails')
    parser.add_argument('--fix-bundle-out')
    parser.add_argument('--fix-apply-out')
    parser.add_argument('--fix-bundle-limit', type=int, default=10)
    parser.add_argument('--fix-finding-id', action='append', default=[])
    parser.add_argument('--apply-fixes', action='store_true', help='apply eligible fixes when FIX_APPLY_ENABLED=true and --fix-apply-approved is set')
    parser.add_argument('--fix-apply-approved', action='store_true', help='confirm human approval for non-dry-run fix apply')
    parser.add_argument('--allow-placeholder-fixes', action='store_true', help='allow TODO/placeholder proposals in fix apply')
    parser.add_argument('--fix-provider', default='offline')
    parser.add_argument('--advanced-ai-provider', default='offline')
    parser.add_argument('--advanced-ai-model')
    parser.add_argument('--embedding-provider', default='local')
    parser.add_argument('--embedding-model')
    parser.add_argument('--semantic-query')
    parser.add_argument('--save-baseline', action='store_true')
    parser.add_argument('--fail-on', choices=['critical', 'high', 'medium', 'low', 'info'], default=None)
    parser.add_argument('--fail-on-sbom-policy', action='store_true', help='exit with code 3 when SBOM policy checks fail')
    parser.add_argument('--fail-on-dependency-policy', action='store_true', help='exit with code 7 when dependency reachability policy fails')
    parser.add_argument('--fail-on-sonarqube-gate', action='store_true', help='exit with code 9 when SonarQube quality gate fails')
    parser.add_argument('--fail-on-spdx-compliance', action='store_true', help='exit with code 4 when SPDX compliance is not procurement-ready')
    parser.add_argument('--fail-on-secrets', action='store_true', help='exit with code 5 when push protection blocks open secret findings')
    args = parser.parse_args(argv)

    scan = run_scan(Path(args.path), project_name=args.project_name, extra_sarif_paths=[Path(item) for item in args.sarif_in])
    save_scan(scan)
    update_repository_memory(scan)
    audit('cli', 'scan.created', scan.scan_id, {'project': scan.project_name})
    if args.save_baseline:
        save_baseline(scan)
    if args.json_out:
        Path(args.json_out).write_text(scan.model_dump_json(indent=2), encoding='utf-8')
    if args.sarif_out:
        Path(args.sarif_out).write_text(json.dumps(build_sarif(scan), indent=2), encoding='utf-8')
    if args.scanner_mesh_out:
        Path(args.scanner_mesh_out).write_text(json.dumps(scanner_mesh_report(scan), indent=2), encoding='utf-8')
    if args.dependency_review_out:
        Path(args.dependency_review_out).write_text(json.dumps(dependency_review_report(scan), indent=2), encoding='utf-8')
    if args.sonarqube_out:
        Path(args.sonarqube_out).write_text(json.dumps(sonarqube_quality_report(scan), indent=2), encoding='utf-8')
    if args.scanner_depth_out:
        Path(args.scanner_depth_out).write_text(json.dumps(scanner_depth_report(scan), indent=2), encoding='utf-8')
    if args.embedding_index_out:
        payload = build_embedding_index(provider=args.embedding_provider, model=args.embedding_model, force=True)
        Path(args.embedding_index_out).write_text(json.dumps({key: value for key, value in payload.items() if key != 'items'}, indent=2), encoding='utf-8')
    if args.semantic_search_out:
        query = args.semantic_query or f'{scan.project_name} secure code review risk remediation'
        Path(args.semantic_search_out).write_text(json.dumps(semantic_search(query, provider=args.embedding_provider, model=args.embedding_model), indent=2), encoding='utf-8')
    if args.advanced_ai_out:
        Path(args.advanced_ai_out).write_text(json.dumps(phase_g_report(scan, provider=args.advanced_ai_provider, model=args.advanced_ai_model, embedding_provider=args.embedding_provider), indent=2), encoding='utf-8')
    if args.agent_review_out:
        Path(args.agent_review_out).write_text(json.dumps(run_multi_agent_review(scan, provider=args.advanced_ai_provider, model=args.advanced_ai_model), indent=2), encoding='utf-8')
    if args.finetune_experiment_out:
        Path(args.finetune_experiment_out).write_text(json.dumps(fine_tune_experiment_plan(scan), indent=2), encoding='utf-8')
    if args.finetune_dataset_out:
        Path(args.finetune_dataset_out).write_text(fine_tune_dataset_jsonl(scan), encoding='utf-8')
    if args.cyclonedx_out:
        Path(args.cyclonedx_out).write_text(json.dumps(build_cyclonedx(scan), indent=2), encoding='utf-8')
    if args.spdx_out:
        Path(args.spdx_out).write_text(json.dumps(build_spdx(scan), indent=2), encoding='utf-8')
    if args.spdx_compliance_out:
        Path(args.spdx_compliance_out).write_text(json.dumps(spdx_compliance_report(scan), indent=2), encoding='utf-8')
    if args.sbom_policy_out:
        Path(args.sbom_policy_out).write_text(json.dumps(sbom_policy_report(scan), indent=2), encoding='utf-8')
    if args.secret_policy_out:
        Path(args.secret_policy_out).write_text(json.dumps(secret_policy_report(scan), indent=2), encoding='utf-8')
    if args.sbom_compare_out:
        baseline_scan = None
        baseline_scan_id = args.sbom_compare_to
        explicit_compare = bool(baseline_scan_id)
        if not baseline_scan_id:
            baseline = load_baseline()
            baseline_scan_id = baseline.get('scan_id') if baseline else None
        if baseline_scan_id:
            try:
                baseline_scan = load_scan(baseline_scan_id)
            except FileNotFoundError:
                if explicit_compare:
                    print(f'Baseline scan not found for SBOM comparison: {baseline_scan_id}', file=sys.stderr)
                    return 2
        Path(args.sbom_compare_out).write_text(json.dumps(compare_sboms(scan, baseline_scan), indent=2), encoding='utf-8')
    if args.report_out:
        Path(args.report_out).write_text(markdown_report(scan), encoding='utf-8')
    if args.pr_comment_out:
        Path(args.pr_comment_out).write_text(github_pr_comment(scan), encoding='utf-8')
    if args.github_pr_review_out or args.github_pr_publish or args.github_pr_publish_status:
        diff_text = Path(args.github_pr_diff).read_text(encoding='utf-8') if args.github_pr_diff else None
        try:
            github_review = build_github_pr_review(
                scan,
                repository=args.github_pr_repository,
                pr_number=args.github_pr_number,
                diff_text=diff_text,
                commit_sha=args.github_pr_commit,
                publish=args.github_pr_publish,
                publish_status=args.github_pr_publish_status,
                event=args.github_pr_event,
                max_inline_comments=args.github_pr_max_inline,
                min_inline_risk=args.github_pr_min_risk,
            )
        except GitHubIntegrationError as exc:
            print(f'GitHub PR review failed: {exc}', file=sys.stderr)
            return 6
        if args.github_pr_review_out:
            Path(args.github_pr_review_out).write_text(json.dumps(github_review, indent=2), encoding='utf-8')
    if args.compliance_out:
        Path(args.compliance_out).write_text(json.dumps(compliance_report(scan), indent=2), encoding='utf-8')
    if args.fix_proposals_out:
        proposals = [build_fix_proposal(scan, finding.id, provider=args.fix_provider).model_dump(mode='json') for finding in scan.findings if finding.severity in {'CRITICAL', 'HIGH', 'MEDIUM'}]
        Path(args.fix_proposals_out).write_text(json.dumps(proposals, indent=2), encoding='utf-8')
    if args.remediation_plan_out:
        Path(args.remediation_plan_out).write_text(json.dumps(build_remediation_plan(scan).model_dump(mode='json'), indent=2), encoding='utf-8')
    issue_plan = None
    if args.issue_plan_out or args.issue_plan_publish:
        try:
            issue_plan = build_issue_plan(
                scan,
                provider=args.issue_plan_provider,
                limit=args.issue_plan_limit,
                min_priority=args.issue_plan_min_priority,
                publish=args.issue_plan_publish,
            )
        except IssuePlanningError as exc:
            print(f'Issue planning failed: {exc}', file=sys.stderr)
            return 10
        if args.issue_plan_out:
            Path(args.issue_plan_out).write_text(json.dumps(issue_plan, indent=2), encoding='utf-8')
    if args.fix_bundle_out:
        Path(args.fix_bundle_out).write_text(json.dumps(build_fix_bundle(scan, finding_ids=args.fix_finding_id or None, limit=args.fix_bundle_limit, provider=args.fix_provider, allow_placeholders=args.allow_placeholder_fixes), indent=2), encoding='utf-8')
    if args.fix_apply_out or args.apply_fixes:
        apply_report = apply_fix_bundle(scan, FixApplyRequest(
            finding_ids=args.fix_finding_id or [],
            limit=args.fix_bundle_limit,
            provider=args.fix_provider,
            dry_run=not args.apply_fixes,
            approved=args.fix_apply_approved,
            allow_placeholders=args.allow_placeholder_fixes,
        ))
        if args.fix_apply_out:
            Path(args.fix_apply_out).write_text(json.dumps(apply_report, indent=2), encoding='utf-8')
        if args.apply_fixes and apply_report['status'] == 'blocked':
            print(f"Fix apply blocked: {', '.join(apply_report['blocked_reasons'])}", file=sys.stderr)
            return 8

    print(f'Scan {scan.scan_id}: {scan.summary.total_findings} findings across {scan.summary.files_scanned} files')
    print(f'Risk: max={scan.summary.max_risk_score}, avg={scan.summary.avg_risk_score}, priorities={scan.summary.priorities}')
    print(f"Tools: {', '.join(f'{k}={v}' for k, v in scan.summary.tools.items())}")
    secret_policy = secret_policy_report(scan)
    if secret_policy['total_secret_findings']:
        print(f"Push protection: {secret_policy['status']} ({secret_policy['blocking_findings']} blocking secrets)")
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on.upper()]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in scan.findings):
            return 2
    if args.fail_on_sbom_policy and sbom_policy_report(scan)['status'] == 'failed':
        return 3
    if args.fail_on_dependency_policy and dependency_review_report(scan)['status'] == 'failed':
        return 7
    if args.fail_on_sonarqube_gate and sonarqube_quality_report(scan)['status'] == 'failed':
        return 9
    if args.fail_on_spdx_compliance and spdx_compliance_report(scan)['status'] != 'ready':
        return 4
    if args.fail_on_secrets and secret_policy_report(scan)['status'] == 'blocked':
        return 5
    if args.fail_on_issue_plan_publish_failure and issue_plan and issue_plan['status'] in {'failed', 'partial'}:
        return 10
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
