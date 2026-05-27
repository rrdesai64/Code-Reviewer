from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

from fastapi import Body, Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .models import BenchmarkLessonRequest, BenchmarkTransitionRequest, ChatNotificationRequest, CodeHostReviewRequest, DecisionRequest, DisposableVmScanRequest, FixApplyRequest, GitHubPrReviewRequest, HermesReviewRequest, HermesRunRequest, IssuePlanRequest, LLMRequest, MemoryRollbackRequest, QuarantineEntryRequest, QuarantineLookupRequest, RagMemoryReindexRequest, ReportLakeReindexRequest, TeachingLoopSessionRequest, TeamCampaignRequest
from .advanced_ai import advanced_ai_status, build_embedding_index, fine_tune_dataset_jsonl, fine_tune_experiment_plan, gpu_profile, local_runtime_status, phase_g_report, run_multi_agent_review, semantic_search
from .benchmark_gate import benchmark_corpus_report, benchmark_gate_report_for_recommendations, benchmark_gate_status, list_benchmark_lessons, transition_benchmark_lesson, upsert_benchmark_lesson
from .chat_agents import ChatAgentError, build_chat_notification, chat_agent_status, handle_slack_command, handle_teams_command, verify_slack_signature, verify_teams_command_secret
from .code_hosts import CodeHostIntegrationError, build_code_host_review, code_host_status
from .compliance_api import compliance_activity_events, compliance_agent_actions, compliance_api_schema, compliance_api_status, compliance_approvals, compliance_evidence_bundle, compliance_memory_lineage, compliance_partner_manifest, compliance_quarantine_alerts, compliance_scan_inventory
from .auth import AuthEnforcementMiddleware, AuthUser, auth_config, auth_status, login_user, logout_user, make_oauth, make_saml_auth, normalize_user, require_permission, require_user, saml_metadata_response
from .enterprise import audit, audit_events, compliance_report, load_enterprise
from .finding_ai import build_finding_ai_review, build_scan_ai_review, finding_ai_status
from .dependency_review import dependency_review_report
from .llm import generate, provider_status
from .github_pr import GitHubIntegrationError, build_github_pr_review, github_integration_status, handle_github_webhook, verify_github_webhook_signature
from .governance import compliance_evidence_export, enterprise_governance_report, governance_events
from .hermes import create_hermes_run, hermes_report_for_scan, hermes_review_queue, hermes_run_review_report, hermes_status, list_hermes_runs, load_hermes_run, record_hermes_review
from .fix_workflow import apply_fix_bundle, build_fix_bundle
from .ingestion import scanner_mesh_report, scanner_mesh_status
from .issue_planning import IssuePlanningError, build_issue_plan, issue_planning_status
from .memory import load_memory, memory_summary, repository_memory, repository_memory_for_scan, update_repository_memory
from .rag import add_knowledge_document, build_index, finding_context, index_stats, retrieve_response
from .rag_memory import list_memory_versions, list_rag_memory_items, list_scan_rag_memory, query_rag_memory, rag_memory_for_scan, rag_memory_schema, rag_memory_status, reindex_rag_memory, rollback_rag_memory_version, save_rag_memory_for_report, scan_rag_memory_report
from .refactor import build_fix_proposal, build_remediation_plan
from .recursive_learning import recursive_learning_report, scan_recursive_learning_report
from .report_lake import list_sanitized_scans, load_sanitized_scan, reindex_report_lake, report_lake_index_record, report_lake_status, sanitized_scan_report, save_sanitized_scan
from .reporting import github_pr_comment, html_report, markdown_report
from .report_bundle import build_report_bundle, report_bundle_metadata
from .sarif import build_sarif
from .sbom import build_cyclonedx, build_spdx, compare_sboms, sbom_policy_report, spdx_compliance_report
from .scanner import ROOT, run_scan
from .scanner_depth import scanner_depth_report
from .secrets import secret_policy_report
from .paths import data_dir
from .quarantine import blocks_host_scan, quarantine_policy, quarantine_policy_for_scan, quarantine_registry_report, upsert_quarantine_entry
from .sonarqube import sonarqube_quality_report
from .storage import apply_decisions, load_baseline, load_scan, save_baseline, save_decision, save_scan, list_scans
from .team_learning import create_campaign, load_campaigns, scan_learning_brief_by_id, team_learning_dashboard
from .teaching_loop import create_teaching_session, list_teaching_sessions, load_teaching_session, teaching_loop_report_for_scan, teaching_loop_status
from .vm_worker import create_vm_scan_job, list_jobs as list_vm_jobs, load_job as load_vm_job, vm_worker_status

app = FastAPI(title='Secure Code Review Assistant', version='0.26.0')
oauth = make_oauth()
STATIC_DIR = ROOT / 'static'
UPLOAD_DIR = data_dir() / 'uploads'
cfg = auth_config()
app.add_middleware(AuthEnforcementMiddleware)
app.add_middleware(SessionMiddleware, secret_key=cfg.session_secret, https_only=cfg.cookie_secure, same_site=cfg.cookie_same_site)
app.mount('/static', StaticFiles(directory=STATIC_DIR), name='static')


@app.get('/', response_class=HTMLResponse)
def index(user: AuthUser = Depends(require_permission('scan:read'))) -> str:
    return (STATIC_DIR / 'index.html').read_text(encoding='utf-8')


@app.get('/api/health')
def health() -> dict:
    return {'ok': True, 'phase': 'phase-s', 'features': ['semgrep', 'bandit', 'python-ast', 'codeql-adapter', 'sonarqube-adapter', 'sonarqube-issue-ingestion', 'sonarqube-quality-gate', 'pip-audit', 'risk-scoring', 'sarif', 'baseline', 'pr-comments', 'rag', 'rag-expansion', 'memory', 'memory-trends', 'secure-refactoring', 'secure-refactoring-expansion', 'local-llm', 'cloud-llm', 'enterprise', 'sso-oidc', 'sso-saml', 'cyclonedx-sbom', 'spdx-sbom', 'sbom-policy', 'sbom-compare', 'spdx-compliance', 'advanced-ai', 'embeddings', 'semantic-rag', 'multi-agent-orchestration', 'fine-tune-experiments', 'local-runtime-discovery', 'gpu-optimization', 'secret-scanning', 'push-protection', 'gitleaks-adapter', 'trufflehog-adapter', 'local-gitleaks-tool', 'local-trufflehog-tool', 'github-pr-review', 'github-inline-comments', 'github-status-checks', 'github-webhooks', 'github-bot-commands', 'scanner-mesh', 'scanner-depth', 'expanded-semgrep-rules', 'semgrep-multi-config', 'codeql-query-depth', 'codeql-no-build-defaults', 'codeql-go-local-toolchain', 'sonarcloud-organization-config', 'dashboard-scan-state', 'unified-ingestion', 'sarif-ingestion', 'snyk-ready-ingestion', 'finding-enrichment', 'dependency-review', 'dependency-reachability', 'dependency-risk-scoring', 'go-module-dependency-review', 'govulncheck-adapter', 'secure-fix-bundles', 'controlled-fix-apply', 'fix-apply-dry-run', 'ide-cli-parity', 'vscode-extension-parity', 'ide-evidence-export', 'issue-planning', 'jira-planning', 'linear-planning', 'issue-plan-dry-run', 'slack-teams-agent', 'chat-notifications', 'slack-agent', 'teams-agent', 'chat-bot-commands', 'gitlab-review', 'azure-devops-review', 'bitbucket-review', 'multi-code-host-review', 'team-learning-dashboard', 'security-campaigns', 'learning-recommendations', 'risk-trend-dashboard', 'recursive-learning', 'scanner-improvement-recommendations', 'human-approved-tuning-workflow', 'benchmark-promotion-gates', 'benchmark-gate', 'language-benchmark-corpus', 'rule-regression-tests', 'false-positive-tests', 'fix-validation-tests', 'benchmark-lesson-promotion', 'approved-benchmarked-learning-only', 'quarantine-registry', 'host-scan-blocking', 'quarantined-learning-exclusion', 'disposable-vm-worker', 'windows-sandbox-job-export', 'vm-artifact-whitelist', 'sanitized-report-lake', 'report-lake-reindex', 'learning-eligibility-labels', 'rag-memory-schema', 'rag-memory-index', 'rag-memory-query', 'rag-memory-versioning', 'rag-memory-rollback', 'hermes-orchestrator', 'hermes-agent-registry', 'hermes-policy-gates', 'hermes-durable-runs', 'hermes-python-agent', 'python-specialist-review', 'python-dependency-agent', 'python-scanner-coverage-agent', 'enterprise-governance', 'governance-agent-audit-trail', 'governance-approval-lineage', 'governance-memory-version-lineage', 'governance-compliance-evidence-export', 'finding-ai-review', 'dynamic-prompt-templates', 'ai-vulnerability-explanations', 'ai-remediation-suggestions'], 'llm_providers': provider_status(), 'auth': auth_status()}



@app.get('/api/scanner-mesh/status')
def scanner_mesh_status_endpoint(user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    return scanner_mesh_status()


@app.get('/api/quarantine/registry')
def quarantine_registry(user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    report = quarantine_registry_report()
    audit(user.username, 'quarantine.registry_reported', 'quarantine-registry', {'entries': str(report['total_entries'])})
    return report


@app.post('/api/quarantine/lookup')
def quarantine_lookup(request: QuarantineLookupRequest, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    policy = quarantine_policy(request.repository, project_name=request.project_name)
    audit(user.username, 'quarantine.lookup', request.repository, {'matched': str(policy['matched']), 'status': policy['status']})
    return policy


@app.post('/api/quarantine/registry')
def quarantine_registry_upsert(request: QuarantineEntryRequest, user: AuthUser = Depends(require_permission('enterprise:write'))) -> dict:
    try:
        entry = upsert_quarantine_entry(request.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit(user.username, 'quarantine.entry_upserted', entry['key'], {'status': entry['status'], 'repository': entry['repository']})
    return entry


@app.get('/api/vm-worker/status')
def vm_worker_status_endpoint(user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    status = vm_worker_status()
    audit(user.username, 'vm_worker.status_reported', 'vm-worker', {'windows_sandbox': str(status['providers']['windows-sandbox']['available'])})
    return status


@app.get('/api/vm-worker/jobs')
def vm_worker_jobs(limit: int = 50, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    jobs = list_vm_jobs(limit=limit)
    return {'jobs': jobs, 'count': len(jobs)}


@app.get('/api/vm-worker/jobs/{job_id}')
def vm_worker_job(job_id: str, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    try:
        return load_vm_job(job_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='VM worker job not found')


@app.post('/api/vm-worker/jobs')
def vm_worker_prepare_job(request: DisposableVmScanRequest, user: AuthUser = Depends(require_permission('scan:run'))) -> dict:
    try:
        job = create_vm_scan_job(
            repository_path=request.repository_path,
            repository_url=request.repository_url,
            project_name=request.project_name,
            sonar_project_key=request.sonar_project_key,
            sonar_branch_name=request.sonar_branch_name,
            output_root_path=request.output_root,
            reports_dir=request.reports_dir,
            run_id=request.run_id,
            provider=request.provider,
            network_policy=request.network_policy,
            approved_quarantine=request.approved_quarantine,
            copy_git_history=request.copy_git_history,
            job_name=request.job_name,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit(user.username, 'vm_worker.job_prepared', job['job_id'], {'repo': job['repository']['path'], 'provider': job['provider'], 'network_policy': job['network_policy']})
    return job


@app.get('/api/report-lake/status')
def report_lake_status_endpoint(user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    status = report_lake_status()
    audit(user.username, 'report_lake.status_reported', 'report-lake', {'records': str(status['scan_record_count'])})
    return status


@app.get('/api/report-lake/scans')
def report_lake_scans(limit: int = 100, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    records = list_sanitized_scans(limit=limit)
    return {'records': records, 'count': len(records)}


@app.post('/api/report-lake/reindex')
def report_lake_reindex(request: ReportLakeReindexRequest | None = Body(None), user: AuthUser = Depends(require_permission('enterprise:write'))) -> dict:
    request = request or ReportLakeReindexRequest()
    report = reindex_report_lake(limit=request.limit, include_quarantined=request.include_quarantined)
    audit(user.username, 'report_lake.reindexed', 'report-lake', {'indexed': str(report['indexed']), 'include_quarantined': str(request.include_quarantined)})
    return report


@app.get('/api/report-lake/scans/{scan_id}')
def report_lake_scan(scan_id: str, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    try:
        return load_sanitized_scan(scan_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='sanitized report not found')


@app.get('/auth/me')
def auth_me(user: AuthUser = Depends(require_user)) -> dict:
    return user.model_dump()


@app.get('/auth/login/oidc')
async def oidc_login(request: Request):
    if not getattr(oauth, 'oidc', None):
        raise HTTPException(status_code=503, detail='OIDC is not configured')
    redirect_uri = f"{auth_config().public_base_url}/auth/callback/oidc"
    return await oauth.oidc.authorize_redirect(request, redirect_uri)


@app.get('/auth/callback/oidc')
async def oidc_callback(request: Request):
    if not getattr(oauth, 'oidc', None):
        raise HTTPException(status_code=503, detail='OIDC is not configured')
    token = await oauth.oidc.authorize_access_token(request)
    claims = dict(token.get('userinfo') or {})
    if not claims and token.get('id_token'):
        claims = dict(await oauth.oidc.parse_id_token(request, token))
    user = normalize_user(claims, 'oidc')
    login_user(request, user, id_token=token.get('id_token'))
    return RedirectResponse(url='/', status_code=303)


@app.get('/auth/login/saml')
async def saml_login(request: Request):
    auth = await make_saml_auth(request)
    return RedirectResponse(url=auth.login(), status_code=303)


@app.post('/auth/saml/acs')
async def saml_acs(request: Request):
    auth = await make_saml_auth(request)
    auth.process_response()
    errors = auth.get_errors()
    if errors or not auth.is_authenticated():
        raise HTTPException(status_code=401, detail={'errors': errors, 'reason': auth.get_last_error_reason()})
    claims = {key: value[0] if isinstance(value, list) and value else value for key, value in auth.get_attributes().items()}
    claims['NameID'] = auth.get_nameid()
    user = normalize_user(claims, 'saml')
    login_user(request, user)
    return RedirectResponse(url='/', status_code=303)


@app.get('/auth/saml/metadata')
def saml_metadata():
    return saml_metadata_response()


@app.api_route('/auth/saml/sls', methods=['GET', 'POST'])
async def saml_sls(request: Request):
    logout_user(request)
    return RedirectResponse(url='/', status_code=303)


@app.get('/auth/logout')
def logout(request: Request):
    logout_user(request)
    return RedirectResponse(url='/', status_code=303)


@app.get('/api/scans')
def scans(user: AuthUser = Depends(require_permission('scan:read'))) -> list[dict]:
    return [scan.model_dump(mode='json') for scan in list_scans()]


@app.post('/api/scans')
async def create_scan(project_name: str | None = Form(None), repo_path: str | None = Form(None), archive: UploadFile | None = File(None), user: AuthUser = Depends(require_permission('scan:run'))) -> dict:
    target = await resolve_target(repo_path, archive)
    if blocks_host_scan(str(target), project_name=project_name):
        policy = quarantine_policy(str(target), project_name=project_name)
        audit(user.username, 'quarantine.host_scan_blocked', str(target), {'status': policy['status'], 'project': project_name or ''})
        raise HTTPException(status_code=423, detail={'message': 'Repository is quarantined; use a report-only or disposable-VM workflow.', 'quarantine_policy': policy})
    scan = run_scan(target, project_name=project_name)
    policy = quarantine_policy_for_scan(scan)
    save_scan(scan)
    sanitized = save_sanitized_scan(scan)
    rag_memory = save_rag_memory_for_report(sanitized)
    hermes_run = create_hermes_run(scan_id=scan.scan_id, requester=user.username, persist=True)
    if policy['controls'].get('agent_learning', True):
        update_repository_memory(scan)
    else:
        audit(user.username, 'memory.quarantine_skipped', scan.scan_id, {'project': scan.project_name, 'status': policy['status']})
    report_bundle = build_report_bundle(scan)
    audit(user.username, 'scan.created', scan.scan_id, {'project': scan.project_name})
    audit(user.username, 'reports.bundle_created', scan.scan_id, {'path': report_bundle['bundle_dir'], 'artifacts': str(report_bundle['artifact_count']), 'errors': str(report_bundle['error_count'])})
    payload = scan.model_dump(mode='json')
    payload['quarantine_policy'] = policy
    payload['sanitized_report'] = report_lake_index_record(sanitized)
    payload['rag_memory'] = {
        'status': rag_memory.get('status'),
        'item_count': rag_memory.get('item_count', 0),
        'skipped_reason': rag_memory.get('skipped_reason', ''),
    }
    payload['hermes'] = {
        'run_id': hermes_run.get('run_id'),
        'status': hermes_run.get('status'),
        'task_count': hermes_run.get('plan', {}).get('task_count', 0),
        'summary': hermes_run.get('synthesis', {}).get('summary', ''),
    }
    payload['report_bundle'] = report_bundle
    return payload


@app.get('/api/scans/{scan_id}')
def get_scan(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    payload = scan.model_dump(mode='json')
    payload['quarantine_policy'] = quarantine_policy_for_scan(scan)
    try:
        payload['sanitized_report'] = report_lake_index_record(load_sanitized_scan(scan_id))
    except FileNotFoundError:
        payload['sanitized_report'] = report_lake_index_record(sanitized_scan_report(scan))
    try:
        rag_memory = scan_rag_memory_report(scan_id)
    except Exception:
        rag_memory = rag_memory_for_scan(scan)
    payload['rag_memory'] = {
        'status': rag_memory.get('status'),
        'item_count': rag_memory.get('item_count', 0),
        'skipped_reason': rag_memory.get('skipped_reason', ''),
    }
    payload['hermes'] = hermes_report_for_scan(scan)
    payload['report_bundle'] = report_bundle_metadata(scan)
    return payload


@app.get('/api/scans/{scan_id}/report-bundle')
def scan_report_bundle(scan_id: str, rebuild: bool = False, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    report = build_report_bundle(scan) if rebuild else report_bundle_metadata(scan)
    if not report.get('exists'):
        report = build_report_bundle(scan)
    audit(user.username, 'reports.bundle_reported', scan_id, {'path': report['bundle_dir'], 'artifacts': str(report.get('artifact_count', 0)), 'rebuilt': str(rebuild)})
    return report


@app.get('/api/scans/{scan_id}/scanner-mesh')
def scan_scanner_mesh(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    report = scanner_mesh_report(scan)
    audit(user.username, 'scanner_mesh.reported', scan_id, {'sources': str(len(report['sources'])), 'findings': str(report['findings'])})
    return report

@app.get('/api/scans/{scan_id}/sonarqube/report')
def scan_sonarqube_report(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    report = sonarqube_quality_report(scan)
    audit(user.username, 'sonarqube.reported', scan_id, {'status': report['status'], 'quality_gate': report['quality_gate']['status']})
    return report


@app.get('/api/scans/{scan_id}/scanner-depth')
def scan_scanner_depth(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    report = scanner_depth_report(scan)
    audit(user.username, 'scanner_depth.reported', scan_id, {'status': report['status'], 'gaps': str(len(report['coverage_gaps']))})
    return report


@app.get('/api/scans/{scan_id}/quarantine-policy')
def scan_quarantine_policy(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    policy = quarantine_policy_for_scan(scan)
    audit(user.username, 'quarantine.scan_policy_reported', scan_id, {'matched': str(policy['matched']), 'status': policy['status']})
    return policy


@app.get('/api/scans/{scan_id}/sanitized-report')
def scan_sanitized_report(scan_id: str, rebuild: bool = False, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    if not rebuild:
        try:
            report = load_sanitized_scan(scan_id)
            audit(user.username, 'report_lake.scan_reported', scan_id, {'source': 'lake'})
            return report
        except FileNotFoundError:
            pass
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    report = save_sanitized_scan(scan) if rebuild else sanitized_scan_report(scan)
    audit(user.username, 'report_lake.scan_reported', scan_id, {'source': 'rebuilt' if rebuild else 'generated'})
    return report


@app.get('/api/scans/{scan_id}/sarif')
def sarif(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> JSONResponse:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    return JSONResponse(build_sarif(scan), media_type='application/sarif+json')



@app.get('/api/scans/{scan_id}/dependencies/review')
def scan_dependency_review(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    report = dependency_review_report(scan)
    audit(user.username, 'dependencies.reviewed', scan_id, {'status': report['status'], 'components': str(report['counts']['components']), 'reachable_vulnerabilities': str(report['counts']['reachable_vulnerabilities'])})
    return report

@app.get('/api/scans/{scan_id}/sbom/cyclonedx')
def cyclonedx_sbom(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> JSONResponse:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    payload = build_cyclonedx(scan)
    audit(user.username, 'sbom.cyclonedx_exported', scan_id, {'components': str(len(payload.get('components', []))), 'vulnerabilities': str(len(payload.get('vulnerabilities', [])))})
    return JSONResponse(payload, media_type='application/vnd.cyclonedx+json')


@app.get('/api/scans/{scan_id}/sbom/spdx')
def spdx_sbom(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> JSONResponse:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    payload = build_spdx(scan)
    audit(user.username, 'sbom.spdx_exported', scan_id, {'packages': str(len(payload.get('packages', [])))})
    return JSONResponse(payload, media_type='application/spdx+json')


@app.get('/api/scans/{scan_id}/sbom/spdx/compliance')
def spdx_compliance(scan_id: str, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    report = spdx_compliance_report(scan)
    audit(user.username, 'sbom.spdx_compliance_reported', scan_id, {'status': report['status'], 'procurement_ready': str(report['procurement_ready'])})
    return report

@app.get('/api/scans/{scan_id}/sbom/policy')
def scan_sbom_policy(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    report = sbom_policy_report(scan)
    audit(user.username, 'sbom.policy_reported', scan_id, {'status': report['status']})
    return report


@app.get('/api/scans/{scan_id}/secrets/policy')
def scan_secret_policy(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    report = secret_policy_report(scan)
    audit(user.username, 'secrets.policy_reported', scan_id, {'status': report['status'], 'blocking': str(report['blocking_findings'])})
    return report


@app.get('/api/scans/{scan_id}/push-protection')
def scan_push_protection(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    report = secret_policy_report(scan)
    audit(user.username, 'secrets.push_protection_checked', scan_id, {'status': report['status'], 'blocking': str(report['blocking_findings'])})
    return report

@app.get('/api/scans/{scan_id}/sbom/compare')
def scan_sbom_compare(scan_id: str, baseline_scan_id: str | None = None, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    baseline_scan = None
    resolved_baseline_id = baseline_scan_id
    if not resolved_baseline_id:
        baseline = load_baseline()
        resolved_baseline_id = baseline.get('scan_id') if baseline else None
    if resolved_baseline_id:
        try:
            baseline_scan = apply_decisions(load_scan(resolved_baseline_id))
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail='baseline scan not found')
    report = compare_sboms(scan, baseline_scan)
    audit(user.username, 'sbom.compared', scan_id, {'baseline_scan_id': report.get('baseline_scan_id') or '', 'added': str(report['counts']['added']), 'removed': str(report['counts']['removed'])})
    return report

@app.get('/api/scans/{scan_id}/report.md', response_class=PlainTextResponse)
def report_markdown(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> str:
    try:
        return markdown_report(apply_decisions(load_scan(scan_id)))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')


@app.get('/api/scans/{scan_id}/report.html', response_class=HTMLResponse)
def report_html(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> str:
    try:
        return html_report(apply_decisions(load_scan(scan_id)))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')


@app.get('/api/scans/{scan_id}/github-pr-comment', response_class=PlainTextResponse)
def pr_comment(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> str:
    try:
        return github_pr_comment(apply_decisions(load_scan(scan_id)))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')

@app.get('/api/integrations/github/status')
def github_status(user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    return github_integration_status()

@app.get('/api/integrations/code-hosts/status')
def code_host_integration_status(user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    return code_host_status()


@app.get('/api/scans/{scan_id}/code-hosts/review')
def code_host_review_preview(scan_id: str, provider: str = 'all', include_findings: int = 25, publish_status: bool | None = None, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    try:
        report = build_code_host_review(scan, provider=provider, include_findings=include_findings, publish_status=publish_status, publish=False)
    except CodeHostIntegrationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit(user.username, 'code_hosts.review_previewed', scan_id, {'provider': provider, 'findings': str(include_findings), 'status': report['status']})
    return report


@app.post('/api/scans/{scan_id}/code-hosts/review')
def code_host_review_publish(scan_id: str, request: CodeHostReviewRequest, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    if request.publish and 'enterprise:write' not in user.permissions:
        raise HTTPException(status_code=403, detail='Missing permission: enterprise:write')
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    try:
        report = build_code_host_review(scan, provider=request.provider, include_findings=request.include_findings, publish_status=request.publish_status, publish=request.publish)
    except CodeHostIntegrationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit(user.username, 'code_hosts.review_published' if request.publish else 'code_hosts.review_prepared', scan_id, {'provider': request.provider, 'status': report['status'], 'published': str(request.publish)})
    return report
@app.get('/api/integrations/issues/status')
def issue_planning_integration_status(user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    return issue_planning_status()

@app.get('/api/integrations/chat/status')
def chat_agent_integration_status(user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    return chat_agent_status()


@app.get('/api/scans/{scan_id}/chat/notification')
def chat_notification_preview(scan_id: str, provider: str = 'all', include_findings: int = 10, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    try:
        report = build_chat_notification(scan, provider=provider, include_findings=include_findings, publish=False)
    except ChatAgentError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit(user.username, 'chat.notification_previewed', scan_id, {'provider': provider, 'findings': str(include_findings), 'status': report['status']})
    return report


@app.post('/api/scans/{scan_id}/chat/notification')
def chat_notification_publish(scan_id: str, request: ChatNotificationRequest, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    if request.publish and 'enterprise:write' not in user.permissions:
        raise HTTPException(status_code=403, detail='Missing permission: enterprise:write')
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    try:
        report = build_chat_notification(scan, provider=request.provider, include_findings=request.include_findings, publish=request.publish)
    except ChatAgentError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit(user.username, 'chat.notification_published' if request.publish else 'chat.notification_prepared', scan_id, {'provider': request.provider, 'status': report['status'], 'published': str(request.publish)})
    return report


@app.post('/api/integrations/slack/command')
async def slack_command(request: Request) -> dict:
    body = await request.body()
    verification = verify_slack_signature(body, request.headers.get('x-slack-request-timestamp'), request.headers.get('x-slack-signature'))
    if not verification['valid']:
        raise HTTPException(status_code=401, detail=verification['reason'])
    result = handle_slack_command(body)
    result['signature'] = {'configured': verification['configured'], 'valid': verification['valid']}
    audit('slack-command', 'chat.slack_command_received', result.get('command') or 'unknown', {'accepted': str(result.get('accepted', False)), 'action': result.get('action', ''), 'user': result.get('user', '')})
    return result


@app.post('/api/integrations/teams/command')
async def teams_command(request: Request) -> dict:
    verification = verify_teams_command_secret(request.headers.get('x-secure-review-teams-secret') or request.headers.get('x-teams-command-secret'))
    if not verification['valid']:
        raise HTTPException(status_code=401, detail=verification['reason'])
    body = await request.body()
    try:
        payload = json.loads(body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail='Invalid JSON Teams command payload')
    result = handle_teams_command(payload)
    result['signature'] = {'configured': verification['configured'], 'valid': verification['valid']}
    audit('teams-command', 'chat.teams_command_received', result.get('command') or 'unknown', {'accepted': str(result.get('accepted', False)), 'action': result.get('action', ''), 'user': result.get('user', '')})
    return result

@app.get('/api/scans/{scan_id}/issue-plan')
def issue_plan_preview(scan_id: str, provider: str = 'all', limit: int = 25, min_priority: str = 'P2', user: AuthUser = Depends(require_permission('fix:propose'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    try:
        report = build_issue_plan(scan, provider=provider, limit=limit, min_priority=min_priority, publish=False)
    except IssuePlanningError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit(user.username, 'issues.plan_previewed', scan_id, {'provider': provider, 'items': str(report['summary']['selected_findings']), 'min_priority': min_priority})
    return report


@app.post('/api/scans/{scan_id}/issue-plan')
def issue_plan_publish(scan_id: str, request: IssuePlanRequest, user: AuthUser = Depends(require_permission('fix:propose'))) -> dict:
    if request.publish and 'enterprise:write' not in user.permissions:
        raise HTTPException(status_code=403, detail='Missing permission: enterprise:write')
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    try:
        report = build_issue_plan(scan, provider=request.provider, limit=request.limit, min_priority=request.min_priority, publish=request.publish)
    except IssuePlanningError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit(user.username, 'issues.plan_published' if request.publish else 'issues.plan_prepared', scan_id, {'provider': request.provider, 'items': str(report['summary']['selected_findings']), 'status': report['status'], 'published': str(request.publish)})
    return report

@app.get('/api/scans/{scan_id}/github/pr-review')
def github_pr_review_preview(
    scan_id: str,
    repository: str | None = None,
    pr_number: int | None = None,
    commit_sha: str | None = None,
    event: str | None = None,
    max_inline_comments: int | None = None,
    min_inline_risk: int | None = None,
    user: AuthUser = Depends(require_permission('scan:read')),
) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    try:
        report = build_github_pr_review(
            scan,
            repository=repository,
            pr_number=pr_number,
            commit_sha=commit_sha,
            publish=False,
            event=event,
            max_inline_comments=max_inline_comments,
            min_inline_risk=min_inline_risk,
        )
    except GitHubIntegrationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit(user.username, 'github.pr_review_previewed', scan_id, {'repository': repository or '', 'pr_number': str(pr_number or ''), 'inline': str(report['review']['inline_comment_count'])})
    return report


@app.post('/api/scans/{scan_id}/github/pr-review')
def github_pr_review_publish(scan_id: str, request: GitHubPrReviewRequest, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    if request.publish and 'enterprise:write' not in user.permissions:
        raise HTTPException(status_code=403, detail='Missing permission: enterprise:write')
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    try:
        report = build_github_pr_review(
            scan,
            repository=request.repository,
            pr_number=request.pr_number,
            diff_text=request.diff_text,
            commit_sha=request.commit_sha,
            publish=request.publish,
            publish_status=request.publish_status,
            event=request.event,
            max_inline_comments=request.max_inline_comments,
            min_inline_risk=request.min_inline_risk,
        )
    except GitHubIntegrationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit(user.username, 'github.pr_review_published' if request.publish else 'github.pr_review_prepared', scan_id, {'repository': request.repository or '', 'pr_number': str(request.pr_number or ''), 'published': str(request.publish), 'inline': str(report['review']['inline_comment_count'])})
    return report


@app.post('/api/integrations/github/webhook')
async def github_webhook(request: Request) -> dict:
    body = await request.body()
    verification = verify_github_webhook_signature(body, request.headers.get('x-hub-signature-256'))
    if not verification['valid']:
        raise HTTPException(status_code=401, detail=verification['reason'])
    try:
        payload = json.loads(body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail='Invalid JSON webhook payload')
    event = request.headers.get('x-github-event', '')
    delivery = request.headers.get('x-github-delivery', '')
    result = handle_github_webhook(event, payload)
    result['delivery'] = delivery
    result['signature'] = {'configured': verification['configured'], 'valid': verification['valid']}
    audit('github-webhook', 'github.webhook_received', delivery or event or 'unknown', {'event': event, 'action': result.get('action', ''), 'accepted': str(result.get('accepted', False)), 'command': str(result.get('command') or '')})
    return result

@app.post('/api/scans/{scan_id}/baseline')
def baseline(scan_id: str, user: AuthUser = Depends(require_permission('baseline:write'))) -> dict:
    try:
        scan = load_scan(scan_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    save_baseline(scan)
    return {'saved': True, 'scan_id': scan_id, 'findings': len(scan.findings)}


@app.get('/api/baseline')
def current_baseline(user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    return load_baseline() or {'scan_id': None, 'fingerprints': []}


@app.post('/api/scans/{scan_id}/decisions')
def decision(scan_id: str, request: DecisionRequest, user: AuthUser = Depends(require_permission('decision:write'))) -> dict:
    try:
        scan = load_scan(scan_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    if request.finding_id not in {finding.id for finding in scan.findings}:
        raise HTTPException(status_code=404, detail='finding not found')
    save_decision(request.finding_id, request.state, request.reason)
    return {'saved': True, 'finding_id': request.finding_id, 'state': request.state}


@app.get('/api/rag/query')
def rag_query(q: str, limit: int = 5, tags: str | None = None, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    tag_list = [item.strip() for item in (tags or '').split(',') if item.strip()]
    return retrieve_response(q, limit=limit, tags=tag_list).model_dump(mode='json')


@app.get('/api/rag/stats')
def rag_stats(user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    return index_stats()

@app.get('/api/advanced-ai/status')
def advanced_ai_status_endpoint(user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    return advanced_ai_status()


@app.get('/api/advanced-ai/runtimes')
def advanced_ai_runtimes(user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    return {'runtimes': local_runtime_status()}


@app.get('/api/advanced-ai/gpu')
def advanced_ai_gpu(user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    return gpu_profile()


@app.post('/api/rag/embeddings/reindex')
def rag_embeddings_reindex(provider: str = 'local', model: str | None = None, force: bool = False, user: AuthUser = Depends(require_permission('enterprise:write'))) -> dict:
    payload = build_embedding_index(provider=provider, model=model, force=force)
    audit(user.username, 'advanced_ai.embeddings_reindexed', 'knowledge-base', {'provider': payload.get('provider', ''), 'chunks': str(payload.get('chunk_count', 0))})
    return {key: value for key, value in payload.items() if key != 'items'}


@app.get('/api/rag/semantic-query')
def rag_semantic_query(q: str, limit: int = 5, provider: str = 'local', model: str | None = None, hybrid: bool = True, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    return semantic_search(q, limit=limit, provider=provider, model=model, hybrid=hybrid)


@app.get('/api/scans/{scan_id}/findings/{finding_id}/rag-context')
def scan_finding_rag_context(scan_id: str, finding_id: str, limit: int = 5, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    try:
        return finding_context(scan, finding_id, limit=limit)
    except ValueError:
        raise HTTPException(status_code=404, detail='finding not found')


@app.post('/api/rag/reindex')
def rag_reindex(user: AuthUser = Depends(require_permission('enterprise:write'))) -> dict:
    chunks = build_index()
    audit(user.username, 'rag.reindexed', 'knowledge-base', {'chunks': str(len(chunks))})
    return {'chunks': len(chunks), 'stats': index_stats()}


@app.get('/api/rag-memory/schema')
def rag_memory_schema_endpoint(user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    return rag_memory_schema()


@app.get('/api/rag-memory/status')
def rag_memory_status_endpoint(user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    status = rag_memory_status()
    audit(user.username, 'rag_memory.status_reported', 'rag-memory', {'items': str(status['retrieval_item_count'])})
    return status


@app.get('/api/rag-memory/items')
def rag_memory_items(limit: int = 100, item_type: str | None = None, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    items = list_rag_memory_items(limit=limit, item_type=item_type)
    return {'items': items, 'count': len(items)}


@app.get('/api/rag-memory/scans')
def rag_memory_scans(limit: int = 100, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    records = list_scan_rag_memory(limit=limit)
    return {'records': records, 'count': len(records)}


@app.get('/api/rag-memory/query')
def rag_memory_query(q: str, limit: int = 5, tags: str | None = None, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    tag_list = [item.strip() for item in (tags or '').split(',') if item.strip()]
    return query_rag_memory(q, limit=limit, tags=tag_list)


@app.post('/api/rag-memory/reindex')
def rag_memory_reindex(request: RagMemoryReindexRequest | None = Body(None), user: AuthUser = Depends(require_permission('enterprise:write'))) -> dict:
    request = request or RagMemoryReindexRequest()
    report = reindex_rag_memory(limit=request.limit, include_ineligible=request.include_ineligible)
    audit(user.username, 'rag_memory.reindexed', 'rag-memory', {'items': str(report['retrieval_item_count']), 'include_ineligible': str(request.include_ineligible)})
    return report


@app.get('/api/rag-memory/versions')
def rag_memory_versions(scan_id: str | None = None, limit: int = 100, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    versions = list_memory_versions(scan_id=scan_id, limit=limit)
    audit(user.username, 'rag_memory.versions_reported', scan_id or 'all', {'count': str(len(versions))})
    return {'schema_version': 1, 'scan_id': scan_id, 'count': len(versions), 'versions': versions}


@app.post('/api/rag-memory/versions/{version_id}/rollback')
def rag_memory_version_rollback(version_id: str, request: MemoryRollbackRequest | None = Body(None), user: AuthUser = Depends(require_permission('enterprise:write'))) -> dict:
    request = request or MemoryRollbackRequest()
    try:
        report = rollback_rag_memory_version(version_id, actor=user.username, reason=request.reason)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='RAG memory version not found')
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit(user.username, 'rag_memory.version_rollback_requested', version_id, {'scan_id': report['scan_id'], 'reason': request.reason})
    return report


@app.get('/api/hermes/status')
def hermes_status_endpoint(user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    status = hermes_status()
    audit(user.username, 'hermes.status_reported', 'hermes', {'runs': str(status['run_count'])})
    return status


@app.get('/api/hermes/runs')
def hermes_runs(limit: int = 100, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    runs = list_hermes_runs(limit=limit)
    return {'runs': runs, 'count': len(runs)}


@app.get('/api/hermes/runs/{run_id}')
def hermes_run(run_id: str, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    try:
        return load_hermes_run(run_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='Hermes run not found')


@app.post('/api/hermes/runs')
def hermes_run_create(request: HermesRunRequest, user: AuthUser = Depends(require_permission('enterprise:write'))) -> dict:
    try:
        run = create_hermes_run(
            scan_id=request.scan_id,
            goal=request.goal,
            requester=user.username,
            allowed_agents=request.allowed_agents,
            limit=request.limit,
            include_ineligible=request.include_ineligible,
            persist=True,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit(user.username, 'hermes.run_created', run['run_id'], {'scan_id': request.scan_id, 'status': run['status'], 'goal': request.goal})
    return run


@app.get('/api/hermes/review-queue')
def hermes_review_queue_endpoint(
    scan_id: str | None = None,
    run_id: str | None = None,
    limit: int = 100,
    include_decided: bool = False,
    user: AuthUser = Depends(require_permission('enterprise:read')),
) -> dict:
    try:
        report = hermes_review_queue(scan_id=scan_id, run_id=run_id, limit=limit, include_decided=include_decided)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='Hermes run not found')
    audit(user.username, 'hermes.review_queue_reported', run_id or scan_id or 'all', {'pending': str(report['pending_count']), 'count': str(report['count'])})
    return report


@app.get('/api/hermes/runs/{run_id}/review')
def hermes_run_review(run_id: str, include_decided: bool = True, limit: int = 100, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    try:
        report = hermes_run_review_report(run_id, include_decided=include_decided, limit=limit)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='Hermes run not found')
    audit(user.username, 'hermes.run_review_reported', run_id, {'pending': str(report['pending_count']), 'count': str(report['count'])})
    return report


@app.post('/api/hermes/runs/{run_id}/review')
def hermes_run_review_record(run_id: str, request: HermesReviewRequest, user: AuthUser = Depends(require_permission('enterprise:write'))) -> dict:
    try:
        report = record_hermes_review(
            run_id,
            decision=request.decision,
            reviewer=request.reviewer or user.username,
            note=request.note,
            review_item_ids=request.review_item_ids,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='Hermes run not found')
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit(user.username, 'hermes.review_recorded', run_id, {'decision': request.decision, 'items': str(report['review']['item_count'])})
    return report


@app.get('/api/teaching-loop/status')
def teaching_loop_status_endpoint(user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    status = teaching_loop_status()
    audit(user.username, 'teaching_loop.status_reported', 'teaching-loop', {'sessions': str(status['session_count'])})
    return status


@app.get('/api/teaching-loop/sessions')
def teaching_loop_sessions(limit: int = 100, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    sessions = list_teaching_sessions(limit=limit)
    audit(user.username, 'teaching_loop.sessions_listed', 'teaching-loop', {'count': str(len(sessions))})
    return {'sessions': sessions}


@app.get('/api/teaching-loop/sessions/{session_id}')
def teaching_loop_session(session_id: str, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    try:
        session = load_teaching_session(session_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='Teaching loop session not found')
    audit(user.username, 'teaching_loop.session_reported', session_id, {'status': session.get('status', '')})
    return session


@app.post('/api/teaching-loop/sessions')
def teaching_loop_session_create(request: TeachingLoopSessionRequest, user: AuthUser = Depends(require_permission('enterprise:write'))) -> dict:
    try:
        session = create_teaching_session(
            scan_id=request.scan_id,
            requester=user.username,
            limit=request.limit,
            max_attempts=request.max_attempts,
            pass_score=request.pass_score,
            rebuild_memory=request.rebuild_memory,
            persist=True,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit(user.username, 'teaching_loop.session_created', session['session_id'], {'scan_id': request.scan_id, 'status': session['status']})
    return session


@app.get('/api/benchmark-gate/status')
def benchmark_gate_status_endpoint(user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    status = benchmark_gate_status()
    audit(user.username, 'benchmark_gate.status_reported', 'benchmark-gate', {'lessons': str(status['lesson_count']), 'active': str(status['active_influence_count'])})
    return status


@app.get('/api/benchmark-gate/corpus')
def benchmark_gate_corpus(language: str | None = None, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    report = benchmark_corpus_report(language=language)
    audit(user.username, 'benchmark_gate.corpus_reported', 'benchmark-gate', {'languages': str(report['language_count']), 'cases': str(report['case_count'])})
    return report


@app.get('/api/benchmark-gate/lessons')
def benchmark_gate_lessons(state: str | None = None, language: str | None = None, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    try:
        return list_benchmark_lessons(state=state, language=language)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post('/api/benchmark-gate/lessons')
def benchmark_gate_lesson_create(request: BenchmarkLessonRequest, user: AuthUser = Depends(require_permission('enterprise:write'))) -> dict:
    actor = request.delegated_actor or user.username
    try:
        lesson = upsert_benchmark_lesson(request.model_dump(exclude={'delegated_actor'}), actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit(user.username, 'benchmark_gate.lesson_proposed', lesson['lesson_id'], {'language': lesson['language'], 'category': lesson['category'], 'delegated_actor': actor})
    return lesson


@app.post('/api/benchmark-gate/lessons/{lesson_id}/transition')
def benchmark_gate_lesson_transition(lesson_id: str, request: BenchmarkTransitionRequest, user: AuthUser = Depends(require_permission('enterprise:write'))) -> dict:
    actor = request.delegated_actor or user.username
    try:
        lesson = transition_benchmark_lesson(
            lesson_id,
            request.target_state,
            actor=actor,
            note=request.note,
            benchmark_evidence=request.benchmark_evidence,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='benchmark lesson not found')
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit(user.username, 'benchmark_gate.lesson_transitioned', lesson_id, {'state': lesson['promotion_state'], 'influence_allowed': str(lesson['learning_influence_allowed']), 'delegated_actor': actor})
    return lesson


@app.get('/api/scans/{scan_id}/benchmark-gate')
def scan_benchmark_gate(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        learning = scan_recursive_learning_report(scan_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    report = benchmark_gate_report_for_recommendations(learning.get('scanner_improvement_recommendations', []))
    report['scan_id'] = scan_id
    report['project_name'] = learning.get('project_name')
    audit(user.username, 'benchmark_gate.scan_reported', scan_id, {'status': report['status'], 'influence_allowed': str(report['influence_allowed_count'])})
    return report


@app.post('/api/rag/documents')
def rag_document(title: str = Body(...), text: str = Body(...), user: AuthUser = Depends(require_permission('enterprise:write'))) -> dict:
    chunk = add_knowledge_document(title, text)
    audit(user.username, 'rag.document_added', chunk.id, {'title': title})
    return chunk.model_dump()


@app.get('/api/memory')
def memory(user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    return load_memory()


@app.get('/api/memory/summary')
def memory_summary_endpoint(user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    return memory_summary()


@app.get('/api/memory/repositories')
def memory_repositories(user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    return {'repositories': memory_summary().get('repositories', [])}


@app.get('/api/memory/repositories/{repo_key}')
def memory_repository(repo_key: str, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    try:
        return repository_memory(repo_key)
    except KeyError:
        raise HTTPException(status_code=404, detail='repository memory not found')


@app.get('/api/team-learning/dashboard')
def team_learning_dashboard_endpoint(limit: int = 100, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    report = team_learning_dashboard(limit=limit)
    audit(user.username, 'team_learning.dashboard_reported', 'team-learning', {'status': report['status'], 'scans': str(report['scan_count'])})
    return report


@app.get('/api/team-learning/campaigns')
def team_learning_campaigns(user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    return load_campaigns()


@app.post('/api/team-learning/campaigns')
def team_learning_campaign_create(request: TeamCampaignRequest, user: AuthUser = Depends(require_permission('enterprise:write'))) -> dict:
    campaign = create_campaign(
        title=request.title,
        focus_area=request.focus_area,
        owner=request.owner,
        due_date=request.due_date,
        description=request.description,
        status=request.status,
        scan_id=request.scan_id,
        rule_ids=request.rule_ids,
        repository_keys=request.repository_keys,
        target_reduction_percent=request.target_reduction_percent,
    )
    audit(user.username, 'team_learning.campaign_created', campaign['id'], {'focus_area': campaign['focus_area'], 'status': campaign['status']})
    return campaign


@app.get('/api/scans/{scan_id}/team-learning')
def scan_team_learning(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        report = scan_learning_brief_by_id(scan_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    audit(user.username, 'team_learning.scan_brief_reported', scan_id, {'status': report['status']})
    return report

@app.get('/api/recursive-learning/dashboard')
def recursive_learning_dashboard_endpoint(limit: int = 100, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    report = recursive_learning_report(limit=limit)
    audit(user.username, 'recursive_learning.dashboard_reported', 'recursive-learning', {'status': report['status'], 'scans': str(report['scan_count']), 'recommendations': str(len(report['scanner_improvement_recommendations']))})
    return report


@app.get('/api/scans/{scan_id}/recursive-learning')
def scan_recursive_learning(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        report = scan_recursive_learning_report(scan_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    audit(user.username, 'recursive_learning.scan_reported', scan_id, {'status': report['status'], 'recommendations': str(len(report['scanner_improvement_recommendations']))})
    return report

@app.get('/api/scans/{scan_id}/memory-context')
def scan_memory_context(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    policy = quarantine_policy_for_scan(scan)
    if not policy['controls'].get('agent_learning', True):
        audit(user.username, 'memory.quarantine_context_blocked', scan_id, {'project': scan.project_name, 'status': policy['status']})
        return {
            'repo_key': None,
            'project_name': scan.project_name,
            'last_scan_id': scan.scan_id,
            'quarantine_policy': policy,
            'recommendations': ['Repository memory is blocked by quarantine policy. Inspect sanitized reports only after explicit approval.'],
        }
    return repository_memory_for_scan(scan)


@app.get('/api/scans/{scan_id}/rag-memory')
def scan_rag_memory(scan_id: str, rebuild: bool = False, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    report = scan_rag_memory_report(scan_id, rebuild=rebuild)
    if report.get('status') == 'missing':
        raise HTTPException(status_code=404, detail=report.get('skipped_reason') or 'rag memory not found')
    audit(user.username, 'rag_memory.scan_reported', scan_id, {'status': report.get('status', ''), 'items': str(report.get('item_count', 0))})
    return report


@app.get('/api/scans/{scan_id}/hermes')
def scan_hermes(scan_id: str, goal: str = 'secure-review-triage', persist: bool = False, limit: int = 100, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        run = create_hermes_run(scan_id=scan_id, goal=goal, requester=user.username, limit=limit, persist=persist)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit(user.username, 'hermes.scan_reported', scan_id, {'status': run['status'], 'goal': run['goal'], 'persist': str(persist)})
    return run


@app.get('/api/scans/{scan_id}/hermes/review')
def scan_hermes_review(scan_id: str, limit: int = 100, include_decided: bool = False, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        report = hermes_review_queue(scan_id=scan_id, limit=limit, include_decided=include_decided)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='Hermes run not found')
    audit(user.username, 'hermes.scan_review_queue_reported', scan_id, {'pending': str(report['pending_count']), 'count': str(report['count'])})
    return report


@app.get('/api/scans/{scan_id}/teaching-loop')
def scan_teaching_loop(scan_id: str, persist: bool = False, limit: int = 50, max_attempts: int = 3, pass_score: int = 7, rebuild: bool = True, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        session = create_teaching_session(
            scan_id=scan_id,
            requester=user.username,
            limit=limit,
            max_attempts=max_attempts,
            pass_score=pass_score,
            rebuild_memory=rebuild,
            persist=persist,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit(user.username, 'teaching_loop.scan_reported', scan_id, {'status': session['status'], 'persist': str(persist), 'mastered': str((session.get('synthesis') or {}).get('mastered_count', 0))})
    return session


@app.get('/api/scans/{scan_id}/compliance/evidence')
def scan_compliance_evidence(scan_id: str, limit: int = 250, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    report = compliance_evidence_bundle(scan_id=scan_id, limit=limit)
    audit(user.username, 'compliance_api.scan_evidence_exported', scan_id, {'events': str(report['control_summary']['activity_events']), 'agent_actions': str(report['control_summary']['agent_actions'])})
    return report


@app.get('/api/llm/providers')
def llm_providers(user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    return provider_status()


@app.get('/api/finding-ai/status')
def finding_ai_status_endpoint(user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    return finding_ai_status()


@app.get('/api/scans/{scan_id}/ai-review')
def scan_ai_review(scan_id: str, provider: str = 'offline', model: str | None = None, limit: int = 25, include_prompts: bool = False, user: AuthUser = Depends(require_permission('fix:propose'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    report = build_scan_ai_review(scan, provider=provider, model=model, limit=limit, include_prompts=include_prompts)
    audit(user.username, 'finding_ai.scan_review', scan_id, {'provider': provider, 'count': str(report['review_count'])})
    return report


@app.get('/api/scans/{scan_id}/findings/{finding_id}/ai-review')
def finding_ai_review(scan_id: str, finding_id: str, provider: str = 'offline', model: str | None = None, include_prompts: bool = True, user: AuthUser = Depends(require_permission('fix:propose'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    try:
        review = build_finding_ai_review(scan, finding_id, provider=provider, model=model, include_prompts=include_prompts)
    except ValueError:
        raise HTTPException(status_code=404, detail='finding not found')
    audit(user.username, 'finding_ai.finding_review', finding_id, {'scan_id': scan_id, 'provider': provider})
    return review

@app.post('/api/llm/generate')
def llm_generate(request: LLMRequest, user: AuthUser = Depends(require_permission('fix:propose'))) -> dict:
    response = generate(request)
    audit(user.username, 'llm.generate', request.provider, {'fallback': str(response.used_fallback)})
    return response.model_dump()


@app.post('/api/scans/{scan_id}/findings/{finding_id}/fix-proposal')
def fix_proposal(scan_id: str, finding_id: str, provider: str = 'offline', model: str | None = None, user: AuthUser = Depends(require_permission('fix:propose'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    try:
        proposal = build_fix_proposal(scan, finding_id, provider=provider, model=model)
    except ValueError:
        raise HTTPException(status_code=404, detail='finding not found')
    audit(user.username, 'fix.proposed', finding_id, {'scan_id': scan_id, 'provider': provider, 'priority': proposal.priority})
    return proposal.model_dump(mode='json')


@app.get('/api/scans/{scan_id}/fixes/bundle')
def scan_fix_bundle(scan_id: str, limit: int = 10, finding_ids: str | None = None, provider: str = 'offline', model: str | None = None, allow_placeholders: bool = False, user: AuthUser = Depends(require_permission('fix:propose'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    ids = [item.strip() for item in (finding_ids or '').split(',') if item.strip()]
    report = build_fix_bundle(scan, finding_ids=ids or None, limit=limit, provider=provider, model=model, allow_placeholders=allow_placeholders)
    audit(user.username, 'fix.bundle_built', scan_id, {'selected': str(report['summary']['selected']), 'eligible': str(report['summary']['eligible'])})
    return report


@app.post('/api/scans/{scan_id}/fixes/apply')
def scan_fix_apply(scan_id: str, request: FixApplyRequest, user: AuthUser = Depends(require_permission('fix:apply'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    report = apply_fix_bundle(scan, request)
    audit(user.username, 'fix.apply_requested', scan_id, {'status': report['status'], 'dry_run': str(report['dry_run']), 'applied': str(len(report['applied']))})
    return report


@app.get('/api/scans/{scan_id}/advanced-ai/report')
def scan_advanced_ai_report(scan_id: str, provider: str = 'offline', model: str | None = None, embedding_provider: str = 'local', user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    report = phase_g_report(scan, provider=provider, model=model, embedding_provider=embedding_provider)
    audit(user.username, 'advanced_ai.reported', scan_id, {'provider': provider, 'status': report['multi_agent_review']['synthesis']['status']})
    return report


@app.get('/api/scans/{scan_id}/advanced-ai/review')
def scan_advanced_ai_review(scan_id: str, finding_id: str | None = None, provider: str = 'offline', model: str | None = None, limit: int = 5, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    try:
        report = run_multi_agent_review(scan, finding_id=finding_id, provider=provider, model=model, limit=limit)
    except ValueError:
        raise HTTPException(status_code=404, detail='finding not found')
    audit(user.username, 'advanced_ai.agent_reviewed', scan_id, {'provider': provider, 'findings': str(report['finding_count'])})
    return report


@app.get('/api/scans/{scan_id}/advanced-ai/finetune-experiment')
def scan_finetune_experiment(scan_id: str, limit: int = 50, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    report = fine_tune_experiment_plan(scan, limit=limit)
    audit(user.username, 'advanced_ai.finetune_experiment_reported', scan_id, {'examples': str(report['dataset']['example_count'])})
    return report


@app.get('/api/scans/{scan_id}/advanced-ai/finetune-dataset', response_class=PlainTextResponse)
def scan_finetune_dataset(scan_id: str, limit: int = 100, user: AuthUser = Depends(require_permission('enterprise:read'))) -> str:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    audit(user.username, 'advanced_ai.finetune_dataset_exported', scan_id, {'limit': str(limit)})
    return fine_tune_dataset_jsonl(scan, limit=limit)

@app.get('/api/scans/{scan_id}/remediation-plan')
def remediation_plan(scan_id: str, limit: int = 50, user: AuthUser = Depends(require_permission('fix:propose'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    plan = build_remediation_plan(scan, limit=limit)
    audit(user.username, 'fix.remediation_plan', scan_id, {'steps': str(plan.total_steps), 'p0': str(plan.p0_steps), 'p1': str(plan.p1_steps)})
    return plan.model_dump(mode='json')


@app.get('/api/scans/{scan_id}/compliance')
def scan_compliance(scan_id: str, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    report = compliance_report(scan)
    audit(user.username, 'enterprise.compliance_reported', scan_id, {'project': scan.project_name})
    return report


@app.get('/api/scans/{scan_id}/governance')
def scan_governance(scan_id: str, limit: int = 100, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    try:
        load_scan(scan_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    report = compliance_evidence_export(scan_id=scan_id, limit=limit)
    audit(user.username, 'enterprise.scan_governance_reported', scan_id, {'agent_actions': str(report['evidence']['agent_actions']['count'])})
    return report


@app.get('/api/enterprise')
def enterprise(user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    return load_enterprise()


@app.get('/api/compliance/status')
def secure_review_compliance_status(user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    report = compliance_api_status()
    audit(user.username, 'compliance_api.status_reported', 'compliance-api', {'sources': str(len(report['data_sources']))})
    return report


@app.get('/api/compliance/schema')
def secure_review_compliance_schema(user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    schema = compliance_api_schema()
    audit(user.username, 'compliance_api.schema_reported', 'compliance-api', {'data_products': str(len(schema['data_products']))})
    return schema


@app.get('/api/compliance/manifest')
def secure_review_compliance_manifest(user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    manifest = compliance_partner_manifest()
    audit(user.username, 'compliance_api.manifest_reported', 'compliance-api', {'endpoints': str(len(manifest['endpoints']))})
    return manifest


@app.get('/api/compliance/events')
def secure_review_compliance_events(category: str | None = None, scan_id: str | None = None, event_source: str | None = None, limit: int = 100, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    report = compliance_activity_events(limit=limit, category=category, scan_id=scan_id, event_source=event_source)
    audit(user.username, 'compliance_api.events_reported', scan_id or category or 'all', {'events': str(report['count']), 'source': event_source or 'all'})
    return report


@app.get('/api/compliance/agent-actions')
def secure_review_compliance_agent_actions(scan_id: str | None = None, limit: int = 100, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    report = compliance_agent_actions(limit=limit, scan_id=scan_id)
    audit(user.username, 'compliance_api.agent_actions_reported', scan_id or 'all', {'events': str(report['count'])})
    return report


@app.get('/api/compliance/approvals')
def secure_review_compliance_approvals(scan_id: str | None = None, limit: int = 100, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    report = compliance_approvals(limit=limit, scan_id=scan_id)
    audit(user.username, 'compliance_api.approvals_reported', scan_id or 'all', {'records': str(report['count'])})
    return report


@app.get('/api/compliance/memory-lineage')
def secure_review_compliance_memory_lineage(scan_id: str | None = None, limit: int = 100, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    report = compliance_memory_lineage(limit=limit, scan_id=scan_id)
    audit(user.username, 'compliance_api.memory_lineage_reported', scan_id or 'all', {'versions': str(report['count'])})
    return report


@app.get('/api/compliance/quarantine-alerts')
def secure_review_compliance_quarantine_alerts(limit: int = 100, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    report = compliance_quarantine_alerts(limit=limit)
    audit(user.username, 'compliance_api.quarantine_alerts_reported', 'quarantine', {'alerts': str(report['count'])})
    return report


@app.get('/api/compliance/scans')
def secure_review_compliance_scans(limit: int = 100, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    report = compliance_scan_inventory(limit=limit)
    audit(user.username, 'compliance_api.scans_reported', 'scan-inventory', {'records': str(report['count'])})
    return report


@app.get('/api/compliance/evidence')
def secure_review_compliance_evidence(scan_id: str | None = None, limit: int = 250, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    report = compliance_evidence_bundle(scan_id=scan_id, limit=limit)
    audit(user.username, 'compliance_api.evidence_exported', scan_id or 'all', {'events': str(report['control_summary']['activity_events']), 'agent_actions': str(report['control_summary']['agent_actions'])})
    return report


@app.get('/api/enterprise/governance')
def enterprise_governance(scan_id: str | None = None, limit: int = 100, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    report = enterprise_governance_report(scan_id=scan_id, limit=limit)
    audit(user.username, 'enterprise.governance_reported', scan_id or 'all', {'events': str(report['audit_trail']['event_count']), 'agent_actions': str(report['agent_actions']['count'])})
    return report


@app.get('/api/enterprise/governance/events')
def enterprise_governance_events(category: str | None = None, scan_id: str | None = None, limit: int = 100, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    events = governance_events(limit=limit, category=category, scan_id=scan_id)
    audit(user.username, 'enterprise.governance_events_reported', category or 'all', {'scan_id': scan_id or '', 'events': str(len(events))})
    return {'schema_version': 1, 'count': len(events), 'events': events}


@app.get('/api/enterprise/governance/evidence')
def enterprise_governance_evidence(scan_id: str | None = None, limit: int = 250, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    report = compliance_evidence_export(scan_id=scan_id, limit=limit)
    audit(user.username, 'enterprise.governance_evidence_exported', scan_id or 'all', {'agent_actions': str(report['evidence']['agent_actions']['count']), 'memory_versions': str(report['evidence']['memory_lineage']['version_count'])})
    return report


@app.get('/api/audit')
def audit_log(limit: int = 100, user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    return {'events': audit_events(limit=limit)}


async def resolve_target(repo_path: str | None, archive: UploadFile | None) -> Path:
    if archive and archive.filename:
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        scan_dir = UPLOAD_DIR / Path(archive.filename).stem.replace(' ', '_')
        if scan_dir.exists():
            shutil.rmtree(scan_dir)
        scan_dir.mkdir(parents=True)
        zip_path = UPLOAD_DIR / archive.filename
        zip_path.write_bytes(await archive.read())
        safe_extract_zip(zip_path, scan_dir)
        return scan_dir
    if repo_path:
        target = Path(repo_path).expanduser().resolve()
        if target.exists() and target.is_dir():
            return target
    raise HTTPException(status_code=400, detail='Provide a valid repo_path or ZIP archive')


def safe_extract_zip(zip_path: Path, destination: Path) -> None:
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            target = (destination / member.filename).resolve()
            if not str(target).startswith(str(destination.resolve())):
                raise HTTPException(status_code=400, detail='Unsafe ZIP path detected')
        zf.extractall(destination)
