from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

from fastapi import Body, Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .models import DecisionRequest, LLMRequest
from .advanced_ai import advanced_ai_status, build_embedding_index, fine_tune_dataset_jsonl, fine_tune_experiment_plan, gpu_profile, local_runtime_status, phase_g_report, run_multi_agent_review, semantic_search
from .auth import AuthEnforcementMiddleware, AuthUser, auth_config, auth_status, login_user, logout_user, make_oauth, make_saml_auth, normalize_user, require_permission, require_user, saml_metadata_response
from .enterprise import audit, audit_events, compliance_report, load_enterprise
from .llm import generate, provider_status
from .memory import load_memory, memory_summary, repository_memory, repository_memory_for_scan, update_repository_memory
from .rag import add_knowledge_document, build_index, finding_context, index_stats, retrieve_response
from .refactor import build_fix_proposal, build_remediation_plan
from .reporting import github_pr_comment, html_report, markdown_report
from .sarif import build_sarif
from .sbom import build_cyclonedx, build_spdx, compare_sboms, sbom_policy_report, spdx_compliance_report
from .scanner import ROOT, run_scan
from .secrets import secret_policy_report
from .storage import apply_decisions, load_baseline, load_scan, save_baseline, save_decision, save_scan, list_scans

app = FastAPI(title='Secure Code Review Assistant', version='0.15.0')
oauth = make_oauth()
STATIC_DIR = ROOT / 'static'
UPLOAD_DIR = ROOT / 'data' / 'uploads'
cfg = auth_config()
app.add_middleware(AuthEnforcementMiddleware)
app.add_middleware(SessionMiddleware, secret_key=cfg.session_secret, https_only=cfg.cookie_secure, same_site=cfg.cookie_same_site)
app.mount('/static', StaticFiles(directory=STATIC_DIR), name='static')


@app.get('/', response_class=HTMLResponse)
def index(user: AuthUser = Depends(require_permission('scan:read'))) -> str:
    return (STATIC_DIR / 'index.html').read_text(encoding='utf-8')


@app.get('/api/health')
def health() -> dict:
    return {'ok': True, 'phase': 'phase-h', 'features': ['semgrep', 'bandit', 'python-ast', 'codeql-adapter', 'sonarqube-adapter', 'pip-audit', 'risk-scoring', 'sarif', 'baseline', 'pr-comments', 'rag', 'rag-expansion', 'memory', 'memory-trends', 'secure-refactoring', 'secure-refactoring-expansion', 'local-llm', 'cloud-llm', 'enterprise', 'sso-oidc', 'sso-saml', 'cyclonedx-sbom', 'spdx-sbom', 'sbom-policy', 'sbom-compare', 'spdx-compliance', 'advanced-ai', 'embeddings', 'semantic-rag', 'multi-agent-orchestration', 'fine-tune-experiments', 'local-runtime-discovery', 'gpu-optimization', 'secret-scanning', 'push-protection', 'gitleaks-adapter', 'trufflehog-adapter'], 'llm_providers': provider_status(), 'auth': auth_status()}


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
    scan = run_scan(target, project_name=project_name)
    save_scan(scan)
    update_repository_memory(scan)
    audit(user.username, 'scan.created', scan.scan_id, {'project': scan.project_name})
    return scan.model_dump(mode='json')


@app.get('/api/scans/{scan_id}')
def get_scan(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    return scan.model_dump(mode='json')


@app.get('/api/scans/{scan_id}/sarif')
def sarif(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> JSONResponse:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    return JSONResponse(build_sarif(scan), media_type='application/sarif+json')


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


@app.get('/api/scans/{scan_id}/memory-context')
def scan_memory_context(scan_id: str, user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail='scan not found')
    return repository_memory_for_scan(scan)


@app.get('/api/llm/providers')
def llm_providers(user: AuthUser = Depends(require_permission('scan:read'))) -> dict:
    return provider_status()


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


@app.get('/api/enterprise')
def enterprise(user: AuthUser = Depends(require_permission('enterprise:read'))) -> dict:
    return load_enterprise()


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
