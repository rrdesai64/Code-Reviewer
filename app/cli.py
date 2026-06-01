from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .models import DastScanRequest, FixApplyRequest, InsideOutAutofixLoopRequest, RuntimeBuildRunRequest, RuntimeSmokeCheckRequest, VerifiedAutofixRequest

from .enterprise import audit, compliance_report
from .autofix_loop import run_inside_out_autofix_loop
from .dependency_review import dependency_review_report
from .dast import dast_verification_report
from .chat_agents import ChatAgentError, build_chat_notification
from .code_hosts import CodeHostIntegrationError, build_code_host_review
from .consolidation import consolidated_findings_report
from .advanced_ai import build_embedding_index, fine_tune_dataset_jsonl, fine_tune_experiment_plan, phase_g_report, run_multi_agent_review, semantic_search
from .benchmark_gate import benchmark_gate_report_for_recommendations
from .catalog_coverage import catalog_coverage_map
from .github_pr import GitHubIntegrationError, build_github_pr_review
from .governance import compliance_evidence_export
from .hermes import run_hermes_on_memory
from .fix_workflow import apply_fix_bundle, build_fix_bundle
from .finding_ai import build_scan_ai_review
from .ingestion import scanner_mesh_report
from .issue_planning import IssuePlanningError, build_issue_plan
from .memory import update_repository_memory
from .messaging_gateway import GatewayError, build_scan_gateway_report
from .quarantine import blocks_host_scan, quarantine_policy, quarantine_policy_for_scan
from .priority import prioritization_report
from .reachability import reachability_context_report
from .rag_memory import save_rag_memory_for_report
from .refactor import build_fix_proposal, build_remediation_plan
from .recursive_learning import scan_recursive_learning_report
from .report_lake import save_sanitized_scan
from .reporting import github_pr_comment, markdown_report
from .runtime_plan import build_runtime_plan
from .runtime_smoke import run_runtime_smoke_checks, runtime_smoke_preview
from .runtime_worker import prepare_runtime_build_run_job, runtime_build_run_preview
from .sarif import build_sarif
from .sbom import build_cyclonedx, build_spdx, compare_sboms, sbom_policy_report, spdx_compliance_report
from .scanner import SEVERITY_ORDER, run_scan
from .scope import is_production_impacting
from .scanner_depth import scanner_depth_report
from .sonarqube import sonarqube_quality_report
from .secrets import secret_policy_report
from .soundness import soundness_verdict
from .storage import load_baseline, load_scan, save_baseline, save_scan
from .suppressions import inline_suppression_report, record_suppression_governance
from .team_learning import team_learning_dashboard
from .verified_autofix import run_verified_autofix


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Secure Code Review Assistant CLI')
    parser.add_argument('scan', nargs='?', help='run a repository scan')
    parser.add_argument('--path', required=True, help='repository path to scan')
    parser.add_argument('--project-name', default=None)
    parser.add_argument('--json-out')
    parser.add_argument('--sarif-out')
    parser.add_argument('--sarif-in', action='append', default=[], help='import an external SARIF file into the normalized scanner mesh')
    parser.add_argument('--coverage-in', action='append', default=[], help='coverage evidence file (Cobertura XML, Istanbul JSON, LCOV, or Go coverprofile) for priority context')
    parser.add_argument('--scanner-mesh-out')
    parser.add_argument('--consolidated-findings-out')
    parser.add_argument('--prioritization-out')
    parser.add_argument('--soundness-out')
    parser.add_argument('--runtime-plan-out')
    parser.add_argument('--runtime-build-run-preview-out')
    parser.add_argument('--runtime-build-run-job-out')
    parser.add_argument('--runtime-build-run-provider', choices=['container', 'windows-sandbox', 'manual'], default='container')
    parser.add_argument('--runtime-build-run-network-policy', choices=['offline', 'scanner-only', 'full'], default='offline')
    parser.add_argument('--runtime-build-run-profile-id')
    parser.add_argument('--runtime-build-run-container-image')
    parser.add_argument('--runtime-build-run-tests', action='store_true')
    parser.add_argument('--runtime-build-run-timeout', type=int, default=900)
    parser.add_argument('--runtime-build-run-start-timeout', type=int, default=60)
    parser.add_argument('--runtime-build-run-approved-quarantine', action='store_true')
    parser.add_argument('--runtime-build-run-job-name')
    parser.add_argument('--runtime-build-run-run-id')
    parser.add_argument('--runtime-smoke-preview-out')
    parser.add_argument('--runtime-smoke-check-out')
    parser.add_argument('--runtime-smoke-base-url')
    parser.add_argument('--runtime-smoke-network-probe', action='store_true')
    parser.add_argument('--runtime-smoke-allow-remote-base-url', action='store_true')
    parser.add_argument('--runtime-smoke-timeout', type=int, default=10)
    parser.add_argument('--runtime-smoke-probe-path', action='append', default=[])
    parser.add_argument('--runtime-smoke-allowed-port', action='append', type=int, default=[])
    parser.add_argument('--runtime-smoke-observed-port', action='append', type=int, default=[])
    parser.add_argument('--dast-out')
    parser.add_argument('--dast-in', action='append', default=[], help='ingest ZAP JSON, Nuclei JSONL/JSON, or DAST SARIF evidence')
    parser.add_argument('--dast-base-url')
    parser.add_argument('--dast-tool', choices=['auto', 'zap', 'nuclei'], default='auto')
    parser.add_argument('--dast-run-tools', action='store_true', help='run configured DAST tool(s) against an explicit Phase 3 loopback base URL')
    parser.add_argument('--dast-allow-remote-base-url', action='store_true')
    parser.add_argument('--dast-timeout', type=int, default=300)
    parser.add_argument('--dast-no-sandbox-required', action='store_true')
    parser.add_argument('--reachability-context-out')
    parser.add_argument('--dependency-review-out')
    parser.add_argument('--sonarqube-out')
    parser.add_argument('--scanner-depth-out')
    parser.add_argument('--catalog-coverage-out')
    parser.add_argument('--advanced-ai-out')
    parser.add_argument('--ai-review-out')
    parser.add_argument('--ai-review-limit', type=int, default=25)
    parser.add_argument('--ai-review-provider', default='offline')
    parser.add_argument('--ai-review-model')
    parser.add_argument('--ai-review-include-prompts', action='store_true')
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
    parser.add_argument('--code-host-review-out')
    parser.add_argument('--code-host-provider', choices=['all', 'gitlab', 'azure-devops', 'bitbucket'], default='all')
    parser.add_argument('--code-host-include-findings', type=int, default=25)
    parser.add_argument('--code-host-publish', action='store_true', help='publish the prepared review to GitLab, Azure DevOps, or Bitbucket')
    parser.add_argument('--code-host-publish-status', action='store_true', help='publish commit or pull-request status when supported and configured')
    parser.add_argument('--fail-on-code-host-publish-failure', action='store_true', help='exit with code 12 when code-host review publishing fails')
    parser.add_argument('--compliance-out')
    parser.add_argument('--fix-proposals-out')
    parser.add_argument('--remediation-plan-out')
    parser.add_argument('--issue-plan-out')
    parser.add_argument('--issue-plan-provider', choices=['all', 'jira', 'linear'], default='all')
    parser.add_argument('--issue-plan-limit', type=int, default=25)
    parser.add_argument('--issue-plan-min-priority', choices=['P0', 'P1', 'P2', 'P3', 'P4'], default='P2')
    parser.add_argument('--issue-plan-publish', action='store_true', help='publish planned remediation issues when Jira/Linear credentials and dry-run gates allow it')
    parser.add_argument('--chat-notification-out')
    parser.add_argument('--team-learning-out')
    parser.add_argument('--team-learning-limit', type=int, default=100)
    parser.add_argument('--recursive-learning-out')
    parser.add_argument('--recursive-learning-limit', type=int, default=100)
    parser.add_argument('--benchmark-gate-out')
    parser.add_argument('--messaging-gateway-out')
    parser.add_argument('--governance-out')
    parser.add_argument('--quarantine-policy-out')
    parser.add_argument('--suppressions-out')
    parser.add_argument('--sanitized-report-out')
    parser.add_argument('--rag-memory-out')
    parser.add_argument('--hermes-out')
    parser.add_argument('--chat-provider', choices=['all', 'slack', 'teams'], default='all')
    parser.add_argument('--chat-include-findings', type=int, default=10)
    parser.add_argument('--chat-publish', action='store_true', help='publish the prepared Slack/Teams notification when credentials and dry-run gates allow it')
    parser.add_argument('--fail-on-chat-publish-failure', action='store_true', help='exit with code 11 when Slack/Teams notification publishing fails')
    parser.add_argument('--gateway-channels', default='all', help='comma-separated gateway channels: all, slack, teams, email, telegram')
    parser.add_argument('--gateway-include-findings', type=int, default=10)
    parser.add_argument('--gateway-publish', action='store_true', help='publish through the Secure Review messaging gateway when credentials and dry-run gates allow it')
    parser.add_argument('--fail-on-gateway-publish-failure', action='store_true', help='exit with code 13 when gateway publishing fails')
    parser.add_argument('--fail-on-issue-plan-publish-failure', action='store_true', help='exit with code 10 when issue planning publish fails')
    parser.add_argument('--fix-bundle-out')
    parser.add_argument('--fix-apply-out')
    parser.add_argument('--verified-autofix-out')
    parser.add_argument('--inside-out-autofix-loop-out')
    parser.add_argument('--fix-bundle-limit', type=int, default=10)
    parser.add_argument('--fix-finding-id', action='append', default=[])
    parser.add_argument('--apply-fixes', action='store_true', help='apply eligible fixes when FIX_APPLY_ENABLED=true and --fix-apply-approved is set')
    parser.add_argument('--fix-apply-approved', action='store_true', help='confirm human approval for non-dry-run fix apply')
    parser.add_argument('--allow-placeholder-fixes', action='store_true', help='allow TODO/placeholder proposals in fix apply')
    parser.add_argument('--fix-provider', default='offline')
    parser.add_argument('--verified-autofix', action='store_true', help='create an autofix branch, apply eligible fixes, run tests, and optionally push/open a PR when green')
    parser.add_argument('--verified-autofix-approved', action='store_true', help='confirm human approval for non-dry-run verified autofix')
    parser.add_argument('--inside-out-autofix-loop', action='store_true', help='run the Phase 2C soundness-driven autofix loop with agent handoff, tests, and rescan verification')
    parser.add_argument('--inside-out-autofix-loop-approved', action='store_true', help='confirm approval for non-dry-run inside-out autofix loop')
    parser.add_argument('--inside-out-autofix-loop-max-iterations', type=int, default=1)
    parser.add_argument('--inside-out-autofix-loop-agent-id', default='verified-autofix')
    parser.add_argument('--inside-out-autofix-loop-issue-id', action='append', default=[])
    parser.add_argument('--inside-out-autofix-loop-no-regression-required', action='store_true', help='allow loop reports without target app test evidence')
    parser.add_argument('--inside-out-autofix-loop-allow-oscillation', action='store_true', help='continue until max iterations even when the same issue set repeats')
    parser.add_argument('--inside-out-autofix-loop-no-persist', action='store_true', help='write the loop report artifact without saving a durable loop run record')
    parser.add_argument('--verified-autofix-test-command', action='append', default=[], help='test command to run in the autofix worktree; repeat for multiple commands')
    parser.add_argument('--verified-autofix-timeout', type=int, default=900)
    parser.add_argument('--verified-autofix-branch')
    parser.add_argument('--verified-autofix-base-branch')
    parser.add_argument('--verified-autofix-push', action='store_true')
    parser.add_argument('--verified-autofix-publish-pr', action='store_true')
    parser.add_argument('--verified-autofix-pr-title')
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
    parser.add_argument('--fail-on-soundness-block', action='store_true', help='exit with code 15 when the machine soundness gate blocks')
    parser.add_argument('--fail-on-dast-gate', action='store_true', help='exit with code 18 when DAST verification blocks')
    args = parser.parse_args(argv)

    target = Path(args.path)
    if blocks_host_scan(str(target), project_name=args.project_name):
        policy = quarantine_policy(str(target), project_name=args.project_name)
        print('Scan blocked by quarantine policy: use a report-only or disposable-VM workflow.', file=sys.stderr)
        print(json.dumps(policy, indent=2), file=sys.stderr)
        return 13

    scan = run_scan(
        target,
        project_name=args.project_name,
        extra_sarif_paths=[Path(item) for item in args.sarif_in],
        coverage_paths=[Path(item) for item in args.coverage_in],
    )
    quarantine = quarantine_policy_for_scan(scan)
    save_scan(scan)
    sanitized = save_sanitized_scan(scan)
    rag_memory = save_rag_memory_for_report(sanitized)
    hermes_run = run_hermes_on_memory(rag_memory, requester='cli', persist=True)
    if quarantine['controls'].get('agent_learning', True):
        update_repository_memory(scan)
    else:
        audit('cli', 'memory.quarantine_skipped', scan.scan_id, {'project': scan.project_name, 'status': quarantine['status']})
    audit('cli', 'scan.created', scan.scan_id, {'project': scan.project_name})
    record_suppression_governance(scan, actor='cli')
    if args.save_baseline:
        save_baseline(scan)
    if args.json_out:
        Path(args.json_out).write_text(scan.model_dump_json(indent=2), encoding='utf-8')
    if args.sarif_out:
        Path(args.sarif_out).write_text(json.dumps(build_sarif(scan), indent=2), encoding='utf-8')
    if args.scanner_mesh_out:
        Path(args.scanner_mesh_out).write_text(json.dumps(scanner_mesh_report(scan), indent=2), encoding='utf-8')
    if args.consolidated_findings_out:
        Path(args.consolidated_findings_out).write_text(json.dumps(consolidated_findings_report(scan), indent=2), encoding='utf-8')
    if args.prioritization_out:
        Path(args.prioritization_out).write_text(json.dumps(prioritization_report(scan), indent=2), encoding='utf-8')
    soundness = soundness_verdict(scan)
    if args.soundness_out:
        Path(args.soundness_out).write_text(json.dumps(soundness, indent=2), encoding='utf-8')
    if args.runtime_plan_out:
        Path(args.runtime_plan_out).write_text(json.dumps(build_runtime_plan(scan), indent=2), encoding='utf-8')
    runtime_request = RuntimeBuildRunRequest(
        provider=args.runtime_build_run_provider,
        network_policy=args.runtime_build_run_network_policy,
        profile_id=args.runtime_build_run_profile_id,
        container_image=args.runtime_build_run_container_image,
        run_tests=args.runtime_build_run_tests,
        timeout_seconds=args.runtime_build_run_timeout,
        start_timeout_seconds=args.runtime_build_run_start_timeout,
        approved_quarantine=args.runtime_build_run_approved_quarantine,
        job_name=args.runtime_build_run_job_name,
        run_id=args.runtime_build_run_run_id,
        smoke_timeout_seconds=args.runtime_smoke_timeout,
        smoke_probe_paths=args.runtime_smoke_probe_path or [],
        smoke_allowed_ports=args.runtime_smoke_allowed_port or [],
    )
    if args.runtime_build_run_preview_out:
        Path(args.runtime_build_run_preview_out).write_text(json.dumps(runtime_build_run_preview(scan, runtime_request), indent=2), encoding='utf-8')
    if args.runtime_build_run_job_out:
        try:
            runtime_job = prepare_runtime_build_run_job(scan, runtime_request, actor='cli')
        except ValueError as exc:
            print(f'Runtime build/run job preparation failed: {exc}', file=sys.stderr)
            return 17
        Path(args.runtime_build_run_job_out).write_text(json.dumps(runtime_job, indent=2), encoding='utf-8')
    smoke_request = RuntimeSmokeCheckRequest(
        profile_id=args.runtime_build_run_profile_id,
        base_url=args.runtime_smoke_base_url,
        network_probe=args.runtime_smoke_network_probe,
        allow_remote_base_url=args.runtime_smoke_allow_remote_base_url,
        timeout_seconds=args.runtime_smoke_timeout,
        probe_paths=args.runtime_smoke_probe_path or [],
        allowed_ports=args.runtime_smoke_allowed_port or [],
        observed_ports=args.runtime_smoke_observed_port or [],
    )
    if args.runtime_smoke_preview_out:
        Path(args.runtime_smoke_preview_out).write_text(json.dumps(runtime_smoke_preview(scan, smoke_request), indent=2), encoding='utf-8')
    if args.runtime_smoke_check_out:
        Path(args.runtime_smoke_check_out).write_text(json.dumps(run_runtime_smoke_checks(scan, smoke_request), indent=2), encoding='utf-8')
    dast_report = None
    if args.dast_out or args.dast_in or args.dast_run_tools:
        dast_report = dast_verification_report(scan, DastScanRequest(
            report_paths=args.dast_in or [],
            base_url=args.dast_base_url,
            tool=args.dast_tool,
            run_tools=args.dast_run_tools,
            allow_remote_base_url=args.dast_allow_remote_base_url,
            timeout_seconds=args.dast_timeout,
            require_sandbox_running=not args.dast_no_sandbox_required,
        ))
        if args.dast_out:
            Path(args.dast_out).write_text(json.dumps(dast_report, indent=2), encoding='utf-8')
    if args.reachability_context_out:
        Path(args.reachability_context_out).write_text(json.dumps(reachability_context_report(scan), indent=2), encoding='utf-8')
    if args.dependency_review_out:
        Path(args.dependency_review_out).write_text(json.dumps(dependency_review_report(scan), indent=2), encoding='utf-8')
    if args.sonarqube_out:
        Path(args.sonarqube_out).write_text(json.dumps(sonarqube_quality_report(scan), indent=2), encoding='utf-8')
    if args.scanner_depth_out:
        Path(args.scanner_depth_out).write_text(json.dumps(scanner_depth_report(scan), indent=2), encoding='utf-8')
    if args.catalog_coverage_out:
        Path(args.catalog_coverage_out).write_text(json.dumps(catalog_coverage_map(), indent=2), encoding='utf-8')
    if args.embedding_index_out:
        payload = build_embedding_index(provider=args.embedding_provider, model=args.embedding_model, force=True)
        Path(args.embedding_index_out).write_text(json.dumps({key: value for key, value in payload.items() if key != 'items'}, indent=2), encoding='utf-8')
    if args.semantic_search_out:
        query = args.semantic_query or f'{scan.project_name} secure code review risk remediation'
        Path(args.semantic_search_out).write_text(json.dumps(semantic_search(query, provider=args.embedding_provider, model=args.embedding_model), indent=2), encoding='utf-8')
    if args.advanced_ai_out:
        Path(args.advanced_ai_out).write_text(json.dumps(phase_g_report(scan, provider=args.advanced_ai_provider, model=args.advanced_ai_model, embedding_provider=args.embedding_provider), indent=2), encoding='utf-8')
    if args.ai_review_out:
        Path(args.ai_review_out).write_text(json.dumps(build_scan_ai_review(scan, provider=args.ai_review_provider, model=args.ai_review_model, limit=args.ai_review_limit, include_prompts=args.ai_review_include_prompts), indent=2), encoding='utf-8')
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
    code_host_review = None
    if args.code_host_review_out or args.code_host_publish or args.code_host_publish_status:
        try:
            code_host_review = build_code_host_review(
                scan,
                provider=args.code_host_provider,
                include_findings=args.code_host_include_findings,
                publish=args.code_host_publish,
                publish_status=args.code_host_publish_status,
            )
        except CodeHostIntegrationError as exc:
            print(f'Code-host review failed: {exc}', file=sys.stderr)
            return 12
        if args.code_host_review_out:
            Path(args.code_host_review_out).write_text(json.dumps(code_host_review, indent=2), encoding='utf-8')
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
    if args.team_learning_out:
        Path(args.team_learning_out).write_text(
            json.dumps(team_learning_dashboard(limit=args.team_learning_limit), indent=2),
            encoding='utf-8',
        )
    if args.recursive_learning_out:
        Path(args.recursive_learning_out).write_text(
            json.dumps(scan_recursive_learning_report(scan, limit=args.recursive_learning_limit), indent=2),
            encoding='utf-8',
        )
    if args.benchmark_gate_out:
        learning = scan_recursive_learning_report(scan, limit=args.recursive_learning_limit)
        gate_report = benchmark_gate_report_for_recommendations(learning.get('scanner_improvement_recommendations', []))
        gate_report['scan_id'] = scan.scan_id
        gate_report['project_name'] = scan.project_name
        Path(args.benchmark_gate_out).write_text(json.dumps(gate_report, indent=2), encoding='utf-8')
    if args.governance_out:
        Path(args.governance_out).write_text(json.dumps(compliance_evidence_export(scan_id=scan.scan_id), indent=2), encoding='utf-8')
    if args.quarantine_policy_out:
        Path(args.quarantine_policy_out).write_text(json.dumps(quarantine, indent=2), encoding='utf-8')
    if args.suppressions_out:
        Path(args.suppressions_out).write_text(json.dumps(inline_suppression_report(scan), indent=2), encoding='utf-8')
    if args.sanitized_report_out:
        Path(args.sanitized_report_out).write_text(json.dumps(sanitized, indent=2), encoding='utf-8')
    if args.rag_memory_out:
        Path(args.rag_memory_out).write_text(json.dumps(rag_memory, indent=2), encoding='utf-8')
    if args.hermes_out:
        Path(args.hermes_out).write_text(json.dumps(hermes_run, indent=2), encoding='utf-8')
    gateway_report = None
    if args.messaging_gateway_out or args.gateway_publish:
        try:
            gateway_report = build_scan_gateway_report(
                scan,
                channels=args.gateway_channels,
                include_findings=args.gateway_include_findings,
                publish=args.gateway_publish,
                persist=args.gateway_publish,
                actor='cli',
            )
        except GatewayError as exc:
            print(f'Messaging gateway failed: {exc}', file=sys.stderr)
            return 13
        if args.messaging_gateway_out:
            Path(args.messaging_gateway_out).write_text(json.dumps(gateway_report, indent=2), encoding='utf-8')
    chat_notification = None
    if args.chat_notification_out or args.chat_publish:
        try:
            chat_notification = build_chat_notification(
                scan,
                provider=args.chat_provider,
                include_findings=args.chat_include_findings,
                publish=args.chat_publish,
            )
        except ChatAgentError as exc:
            print(f'Chat notification failed: {exc}', file=sys.stderr)
            return 11
        if args.chat_notification_out:
            Path(args.chat_notification_out).write_text(json.dumps(chat_notification, indent=2), encoding='utf-8')
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
    if args.verified_autofix_out or args.verified_autofix:
        autofix_report = run_verified_autofix(scan, VerifiedAutofixRequest(
            finding_ids=args.fix_finding_id or [],
            limit=args.fix_bundle_limit,
            provider=args.fix_provider,
            dry_run=not args.verified_autofix,
            approved=args.verified_autofix_approved,
            allow_placeholders=args.allow_placeholder_fixes,
            branch_name=args.verified_autofix_branch,
            base_branch=args.verified_autofix_base_branch,
            test_commands=args.verified_autofix_test_command or [],
            test_timeout_seconds=args.verified_autofix_timeout,
            push_branch=args.verified_autofix_push,
            publish_pr=args.verified_autofix_publish_pr,
            pr_title=args.verified_autofix_pr_title,
        ), actor='cli')
        if args.verified_autofix_out:
            Path(args.verified_autofix_out).write_text(json.dumps(autofix_report, indent=2), encoding='utf-8')
        if args.verified_autofix and autofix_report['status'] in {'blocked', 'failed', 'tests_failed', 'push_failed', 'pr_failed'}:
            print(f"Verified autofix failed: {autofix_report['status']} ({autofix_report['gate']})", file=sys.stderr)
            return 14
    if args.inside_out_autofix_loop_out or args.inside_out_autofix_loop:
        loop_report = run_inside_out_autofix_loop(scan, InsideOutAutofixLoopRequest(
            finding_ids=args.fix_finding_id or [],
            issue_ids=args.inside_out_autofix_loop_issue_id or [],
            limit=args.fix_bundle_limit,
            max_iterations=args.inside_out_autofix_loop_max_iterations,
            agent_id=args.inside_out_autofix_loop_agent_id,
            provider=args.fix_provider,
            dry_run=not args.inside_out_autofix_loop,
            approved=args.inside_out_autofix_loop_approved,
            allow_placeholders=args.allow_placeholder_fixes,
            branch_name=args.verified_autofix_branch,
            base_branch=args.verified_autofix_base_branch,
            test_commands=args.verified_autofix_test_command or [],
            test_timeout_seconds=args.verified_autofix_timeout,
            push_branch=args.verified_autofix_push,
            publish_pr=args.verified_autofix_publish_pr,
            pr_title=args.verified_autofix_pr_title,
            require_regression_tests=not args.inside_out_autofix_loop_no_regression_required,
            stop_on_oscillation=not args.inside_out_autofix_loop_allow_oscillation,
            persist=not args.inside_out_autofix_loop_no_persist,
        ), actor='cli')
        if args.inside_out_autofix_loop_out:
            Path(args.inside_out_autofix_loop_out).write_text(json.dumps(loop_report, indent=2), encoding='utf-8')
        if args.inside_out_autofix_loop and loop_report['gate'] != 'passed':
            print(f"Inside-out autofix loop failed: {loop_report['status']} ({loop_report['gate']})", file=sys.stderr)
            return 16

    print(f'Scan {scan.scan_id}: {scan.summary.total_findings} findings across {scan.summary.files_scanned} files')
    print(f'Production gate: findings={scan.summary.production_findings}, hygiene={scan.summary.hygiene_findings}, scopes={scan.summary.scope_counts}')
    print(f'Production risk: max={scan.summary.max_risk_score}, avg={scan.summary.avg_risk_score}, priorities={scan.summary.priorities}')
    print(f'Consolidated priorities: items={scan.summary.consolidated_findings}, cross-tool={scan.summary.cross_tool_clusters}, top_score={scan.summary.top_consolidated_priority_score}, priorities={scan.summary.consolidated_priorities}')
    print(f'Finding priorities: top_score={scan.summary.top_finding_priority_score}, active={scan.summary.active_prioritized_findings}, priorities={scan.summary.finding_priority_counts}')
    print(f"Soundness gate: {soundness['verdict']['status']} blocking={soundness['verdict']['blocking_issue_count']} confidence={soundness['verdict']['confidence']}")
    print(f'Reachability context: reachability={scan.summary.reachability_counts}, exploitability={scan.summary.exploitability_counts}, changed_files={scan.summary.changed_file_findings}, request_handlers={scan.summary.request_handler_findings}')
    print(f"Tools: {', '.join(f'{k}={v}' for k, v in scan.summary.tools.items())}")
    if quarantine.get('matched'):
        print(f"Quarantine: {quarantine['status']} (agent_learning={quarantine['controls'].get('agent_learning')}, report_only={quarantine['controls'].get('report_only')})")
    secret_policy = secret_policy_report(scan)
    if secret_policy['total_secret_findings']:
        print(f"Push protection: {secret_policy['status']} ({secret_policy['blocking_findings']} blocking secrets)")
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on.upper()]
        if any(is_production_impacting(f) and SEVERITY_ORDER[f.severity] >= threshold for f in scan.findings):
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
    if args.fail_on_soundness_block and soundness['verdict']['status'] == 'block':
        return 15
    if args.fail_on_dast_gate and dast_report and dast_report['gate']['status'] == 'block':
        return 18
    if args.fail_on_issue_plan_publish_failure and issue_plan and issue_plan['status'] in {'failed', 'partial'}:
        return 10
    if args.fail_on_chat_publish_failure and chat_notification and chat_notification['status'] in {'failed', 'partial'}:
        return 11
    if args.fail_on_code_host_publish_failure and code_host_review and code_host_review['status'] in {'failed', 'partial'}:
        return 12
    if args.fail_on_gateway_publish_failure and gateway_report and gateway_report['status'] in {'failed', 'partial'}:
        return 13
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
