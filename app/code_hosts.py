from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .models import Finding, ScanResult
from .reporting import format_counts
from .secrets import secret_policy_report
from .scope import finding_scope, scope_sort_rank


class CodeHostIntegrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class GitLabConfig:
    enabled: str
    api_url: str
    token: str | None
    project_id: str | None
    merge_request_iid: int | None
    commit_sha: str | None
    dry_run: bool
    publish_status: bool
    status_context: str
    target_url: str | None

    @property
    def configured(self) -> bool:
        return bool(self.token and self.project_id and self.merge_request_iid)

    @property
    def active(self) -> bool:
        return self.enabled == 'true' or (self.enabled == 'auto' and self.configured)


@dataclass(frozen=True)
class AzureDevOpsConfig:
    enabled: str
    api_url: str
    organization: str | None
    project: str | None
    repository_id: str | None
    pull_request_id: int | None
    pat: str | None
    api_version: str
    commit_sha: str | None
    dry_run: bool
    publish_status: bool
    status_context: str
    target_url: str | None

    @property
    def configured(self) -> bool:
        return bool(self.organization and self.project and self.repository_id and self.pull_request_id and self.pat)

    @property
    def active(self) -> bool:
        return self.enabled == 'true' or (self.enabled == 'auto' and self.configured)


@dataclass(frozen=True)
class BitbucketConfig:
    enabled: str
    deployment: str
    api_url: str
    token: str | None
    username: str | None
    app_password: str | None
    workspace: str | None
    project_key: str | None
    repo_slug: str | None
    pull_request_id: int | None
    commit_sha: str | None
    dry_run: bool
    publish_status: bool
    status_key: str
    status_name: str
    target_url: str | None

    @property
    def has_auth(self) -> bool:
        return bool(self.token or (self.username and self.app_password))

    @property
    def configured(self) -> bool:
        if self.deployment == 'server':
            return bool(self.api_url and self.project_key and self.repo_slug and self.pull_request_id and self.has_auth)
        return bool(self.api_url and self.workspace and self.repo_slug and self.pull_request_id and self.has_auth)

    @property
    def active(self) -> bool:
        return self.enabled == 'true' or (self.enabled == 'auto' and self.configured)


def gitlab_config(publish_status: bool | None = None) -> GitLabConfig:
    return GitLabConfig(
        enabled=os.getenv('GITLAB_ENABLED', 'auto').lower(),
        api_url=os.getenv('GITLAB_API_URL', 'https://gitlab.com/api/v4').rstrip('/'),
        token=os.getenv('GITLAB_TOKEN') or None,
        project_id=os.getenv('GITLAB_PROJECT_ID') or None,
        merge_request_iid=int_or_none(os.getenv('GITLAB_MR_IID')),
        commit_sha=os.getenv('GITLAB_COMMIT_SHA') or None,
        dry_run=parse_bool(os.getenv('GITLAB_DRY_RUN'), True),
        publish_status=parse_bool(os.getenv('GITLAB_PUBLISH_STATUS'), False) if publish_status is None else publish_status,
        status_context=os.getenv('GITLAB_STATUS_CONTEXT', 'Secure Code Review'),
        target_url=os.getenv('GITLAB_STATUS_TARGET_URL') or public_scan_base_url(),
    )


def azure_devops_config(publish_status: bool | None = None) -> AzureDevOpsConfig:
    return AzureDevOpsConfig(
        enabled=os.getenv('AZURE_DEVOPS_ENABLED', 'auto').lower(),
        api_url=os.getenv('AZURE_DEVOPS_API_URL', 'https://dev.azure.com').rstrip('/'),
        organization=os.getenv('AZURE_DEVOPS_ORG') or os.getenv('AZURE_DEVOPS_ORGANIZATION') or None,
        project=os.getenv('AZURE_DEVOPS_PROJECT') or None,
        repository_id=os.getenv('AZURE_DEVOPS_REPOSITORY_ID') or os.getenv('AZURE_DEVOPS_REPO_ID') or None,
        pull_request_id=int_or_none(os.getenv('AZURE_DEVOPS_PR_ID')),
        pat=os.getenv('AZURE_DEVOPS_PAT') or None,
        api_version=os.getenv('AZURE_DEVOPS_API_VERSION', '7.1'),
        commit_sha=os.getenv('AZURE_DEVOPS_COMMIT_SHA') or None,
        dry_run=parse_bool(os.getenv('AZURE_DEVOPS_DRY_RUN'), True),
        publish_status=parse_bool(os.getenv('AZURE_DEVOPS_PUBLISH_STATUS'), False) if publish_status is None else publish_status,
        status_context=os.getenv('AZURE_DEVOPS_STATUS_CONTEXT', 'Secure Code Review'),
        target_url=os.getenv('AZURE_DEVOPS_STATUS_TARGET_URL') or public_scan_base_url(),
    )


def bitbucket_config(publish_status: bool | None = None) -> BitbucketConfig:
    deployment = os.getenv('BITBUCKET_DEPLOYMENT', 'cloud').lower()
    default_api_url = 'https://api.bitbucket.org/2.0' if deployment != 'server' else (os.getenv('BITBUCKET_SERVER_URL', '').rstrip('/') + '/rest/api/1.0')
    return BitbucketConfig(
        enabled=os.getenv('BITBUCKET_ENABLED', 'auto').lower(),
        deployment=deployment,
        api_url=os.getenv('BITBUCKET_API_URL', default_api_url).rstrip('/'),
        token=os.getenv('BITBUCKET_TOKEN') or None,
        username=os.getenv('BITBUCKET_USERNAME') or None,
        app_password=os.getenv('BITBUCKET_APP_PASSWORD') or None,
        workspace=os.getenv('BITBUCKET_WORKSPACE') or None,
        project_key=os.getenv('BITBUCKET_PROJECT_KEY') or None,
        repo_slug=os.getenv('BITBUCKET_REPO_SLUG') or None,
        pull_request_id=int_or_none(os.getenv('BITBUCKET_PR_ID')),
        commit_sha=os.getenv('BITBUCKET_COMMIT_SHA') or None,
        dry_run=parse_bool(os.getenv('BITBUCKET_DRY_RUN'), True),
        publish_status=parse_bool(os.getenv('BITBUCKET_PUBLISH_STATUS'), False) if publish_status is None else publish_status,
        status_key=os.getenv('BITBUCKET_STATUS_KEY', 'secure-review'),
        status_name=os.getenv('BITBUCKET_STATUS_NAME', 'Secure Code Review'),
        target_url=os.getenv('BITBUCKET_STATUS_TARGET_URL') or public_scan_base_url(),
    )


def code_host_status() -> dict[str, Any]:
    gitlab = gitlab_config()
    azure = azure_devops_config()
    bitbucket = bitbucket_config()
    return {
        'gitlab': {
            'enabled': gitlab.enabled,
            'active': gitlab.active,
            'configured': gitlab.configured,
            'api_url': gitlab.api_url,
            'token_configured': bool(gitlab.token),
            'project_id_configured': bool(gitlab.project_id),
            'merge_request_configured': bool(gitlab.merge_request_iid),
            'commit_configured': bool(gitlab.commit_sha),
            'dry_run_default': gitlab.dry_run,
            'publish_status_default': gitlab.publish_status,
        },
        'azure_devops': {
            'enabled': azure.enabled,
            'active': azure.active,
            'configured': azure.configured,
            'api_url': azure.api_url,
            'organization_configured': bool(azure.organization),
            'project_configured': bool(azure.project),
            'repository_configured': bool(azure.repository_id),
            'pull_request_configured': bool(azure.pull_request_id),
            'pat_configured': bool(azure.pat),
            'commit_configured': bool(azure.commit_sha),
            'dry_run_default': azure.dry_run,
            'publish_status_default': azure.publish_status,
        },
        'bitbucket': {
            'enabled': bitbucket.enabled,
            'active': bitbucket.active,
            'configured': bitbucket.configured,
            'deployment': bitbucket.deployment,
            'api_url': bitbucket.api_url,
            'token_configured': bool(bitbucket.token),
            'basic_auth_configured': bool(bitbucket.username and bitbucket.app_password),
            'workspace_configured': bool(bitbucket.workspace),
            'project_key_configured': bool(bitbucket.project_key),
            'repo_slug_configured': bool(bitbucket.repo_slug),
            'pull_request_configured': bool(bitbucket.pull_request_id),
            'commit_configured': bool(bitbucket.commit_sha),
            'dry_run_default': bitbucket.dry_run,
            'publish_status_default': bitbucket.publish_status,
        },
    }


def build_code_host_review(
    scan: ScanResult,
    provider: str = 'all',
    publish: bool = False,
    publish_status: bool | None = None,
    include_findings: int = 25,
) -> dict[str, Any]:
    selected = normalize_providers(provider)
    include_findings = max(1, min(include_findings, 50))
    status = review_status(scan)
    findings = top_findings(scan, include_findings)
    body = review_body(scan, status, findings)
    gitlab = gitlab_config(publish_status)
    azure = azure_devops_config(publish_status)
    bitbucket = bitbucket_config(publish_status)
    providers: dict[str, Any] = {}

    if 'gitlab' in selected:
        providers['gitlab'] = provider_artifact(
            provider='gitlab',
            configured=gitlab.configured,
            active=gitlab.active,
            dry_run=gitlab.dry_run,
            payload=gitlab_payload(scan, body, status, gitlab),
        )
    if 'azure-devops' in selected:
        providers['azure-devops'] = provider_artifact(
            provider='azure-devops',
            configured=azure.configured,
            active=azure.active,
            dry_run=azure.dry_run,
            payload=azure_devops_payload(scan, body, status, azure),
        )
    if 'bitbucket' in selected:
        providers['bitbucket'] = provider_artifact(
            provider='bitbucket',
            configured=bitbucket.configured,
            active=bitbucket.active,
            dry_run=bitbucket.dry_run,
            payload=bitbucket_payload(scan, body, status, bitbucket),
        )

    publish_summary = {'attempted': 0, 'published': 0, 'dry_run': 0, 'skipped': 0, 'failed': 0}
    if publish:
        publish_summary = publish_reviews(providers, gitlab, azure, bitbucket)

    return {
        'schema_version': 1,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'provider': provider,
        'publish_requested': publish,
        'status': resolve_status(publish, publish_summary),
        'review_status': status,
        'include_findings': include_findings,
        'configuration': code_host_status(),
        'summary': {
            'providers': selected,
            'publish': publish_summary,
            'top_findings': len(findings),
        },
        'review': {
            'body': body,
            'top_findings': findings,
        },
        'guardrails': [
            'Dry-run is the default for GitLab, Azure DevOps, and Bitbucket review publishing.',
            'Real publishing requires publish=true and the provider dry-run flag set to false.',
            'Commit status publishing is separate and requires a configured commit SHA.',
            'Inline changed-line comments are intentionally deferred until provider diff mapping is enabled.',
        ],
        'providers': providers,
    }


def gitlab_payload(scan: ScanResult, body: str, status: dict[str, Any], cfg: GitLabConfig) -> dict[str, Any]:
    project = url_quote(cfg.project_id or 'GITLAB_PROJECT_ID')
    mr = cfg.merge_request_iid or 0
    payload = {
        'note': {
            'method': 'POST',
            'path': f'/projects/{project}/merge_requests/{mr}/notes',
            'body': {'body': body},
        },
        'commit_status': None,
    }
    if cfg.publish_status:
        payload['commit_status'] = {
            'method': 'POST',
            'path': f'/projects/{project}/statuses/{cfg.commit_sha or "GITLAB_COMMIT_SHA"}',
            'body': {
                'state': gitlab_state(status),
                'name': cfg.status_context,
                'description': status['description'],
                'target_url': target_url(cfg.target_url, scan.scan_id),
            },
        }
    return payload


def azure_devops_payload(scan: ScanResult, body: str, status: dict[str, Any], cfg: AzureDevOpsConfig) -> dict[str, Any]:
    base = azure_path(cfg)
    payload = {
        'thread': {
            'method': 'POST',
            'path': f'{base}/pullRequests/{cfg.pull_request_id or 0}/threads?api-version={cfg.api_version}',
            'body': {
                'comments': [{'parentCommentId': 0, 'content': body, 'commentType': 'text'}],
                'status': 'active',
            },
        },
        'pull_request_status': None,
    }
    if cfg.publish_status:
        payload['pull_request_status'] = {
            'method': 'POST',
            'path': f'{base}/pullRequests/{cfg.pull_request_id or 0}/statuses?api-version={cfg.api_version}',
            'body': {
                'state': azure_state(status),
                'description': status['description'],
                'context': {'name': cfg.status_context, 'genre': 'secure-code-review'},
                'targetUrl': target_url(cfg.target_url, scan.scan_id),
            },
        }
    return payload


def bitbucket_payload(scan: ScanResult, body: str, status: dict[str, Any], cfg: BitbucketConfig) -> dict[str, Any]:
    if cfg.deployment == 'server':
        comment_path = f'/projects/{cfg.project_key or "PROJECT"}/repos/{cfg.repo_slug or "repo"}/pull-requests/{cfg.pull_request_id or 0}/comments'
        status_path = f'/commits/{cfg.commit_sha or "BITBUCKET_COMMIT_SHA"}/statuses/build'
        comment_body = {'text': body}
    else:
        comment_path = f'/repositories/{cfg.workspace or "workspace"}/{cfg.repo_slug or "repo"}/pullrequests/{cfg.pull_request_id or 0}/comments'
        status_path = f'/repositories/{cfg.workspace or "workspace"}/{cfg.repo_slug or "repo"}/commit/{cfg.commit_sha or "BITBUCKET_COMMIT_SHA"}/statuses/build'
        comment_body = {'content': {'raw': body}}
    payload = {
        'comment': {'method': 'POST', 'path': comment_path, 'body': comment_body},
        'commit_status': None,
    }
    if cfg.publish_status:
        payload['commit_status'] = {
            'method': 'POST',
            'path': status_path,
            'body': {
                'state': bitbucket_state(status),
                'key': cfg.status_key,
                'name': cfg.status_name,
                'url': target_url(cfg.target_url, scan.scan_id),
                'description': status['description'],
            },
        }
    return payload


def publish_reviews(providers: dict[str, Any], gitlab: GitLabConfig, azure: AzureDevOpsConfig, bitbucket: BitbucketConfig) -> dict[str, int]:
    summary = {'attempted': 0, 'published': 0, 'dry_run': 0, 'skipped': 0, 'failed': 0}
    if 'gitlab' in providers:
        publish_provider(providers['gitlab'], summary, lambda payload: publish_gitlab(payload, gitlab))
    if 'azure-devops' in providers:
        publish_provider(providers['azure-devops'], summary, lambda payload: publish_azure_devops(payload, azure))
    if 'bitbucket' in providers:
        publish_provider(providers['bitbucket'], summary, lambda payload: publish_bitbucket(payload, bitbucket))
    return summary


def publish_provider(artifact: dict[str, Any], summary: dict[str, int], publish_fn) -> None:
    if not artifact['active']:
        artifact['error'] = 'provider is disabled or not configured'
        summary['skipped'] += 1
        return
    if not artifact['configured']:
        artifact['error'] = 'provider credentials or repository settings are incomplete'
        summary['skipped'] += 1
        return
    if artifact['dry_run']:
        artifact['result'] = {'dry_run': True, 'message': 'provider dry-run is enabled'}
        summary['dry_run'] += 1
        return
    summary['attempted'] += 1
    artifact['publish_attempted'] = True
    try:
        artifact['result'] = publish_fn(artifact['payload'])
        summary['published'] += 1
    except CodeHostIntegrationError as exc:
        artifact['error'] = str(exc)
        summary['failed'] += 1


def publish_gitlab(payload: dict[str, Any], cfg: GitLabConfig) -> dict[str, Any]:
    headers = {'PRIVATE-TOKEN': cfg.token or ''}
    note = payload['note']
    result = {'note': request_json(f'{cfg.api_url}{note["path"]}', note['method'], note['body'], headers)}
    status_payload = payload.get('commit_status')
    if status_payload and cfg.commit_sha:
        result['commit_status'] = request_json(f'{cfg.api_url}{status_payload["path"]}', status_payload['method'], status_payload['body'], headers)
    elif status_payload:
        result['commit_status'] = {'skipped': True, 'reason': 'GITLAB_COMMIT_SHA is not configured'}
    return summarize_publish_result(result)


def publish_azure_devops(payload: dict[str, Any], cfg: AzureDevOpsConfig) -> dict[str, Any]:
    auth = base64.b64encode(f':{cfg.pat or ""}'.encode('utf-8')).decode('ascii')
    headers = {'Authorization': f'Basic {auth}'}
    thread = payload['thread']
    result = {'thread': request_json(f'{cfg.api_url}{thread["path"]}', thread['method'], thread['body'], headers)}
    status_payload = payload.get('pull_request_status')
    if status_payload:
        result['pull_request_status'] = request_json(f'{cfg.api_url}{status_payload["path"]}', status_payload['method'], status_payload['body'], headers)
    return summarize_publish_result(result)


def publish_bitbucket(payload: dict[str, Any], cfg: BitbucketConfig) -> dict[str, Any]:
    headers = bitbucket_auth_headers(cfg)
    comment = payload['comment']
    result = {'comment': request_json(f'{cfg.api_url}{comment["path"]}', comment['method'], comment['body'], headers)}
    status_payload = payload.get('commit_status')
    if status_payload and cfg.commit_sha:
        result['commit_status'] = request_json(f'{cfg.api_url}{status_payload["path"]}', status_payload['method'], status_payload['body'], headers)
    elif status_payload:
        result['commit_status'] = {'skipped': True, 'reason': 'BITBUCKET_COMMIT_SHA is not configured'}
    return summarize_publish_result(result)


def request_json(url: str, method: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode('utf-8'),
        method=method,
        headers={'Accept': 'application/json', 'Content-Type': 'application/json', 'User-Agent': 'secure-code-review-assistant', **headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            body = response.read().decode('utf-8', errors='replace')
            return {'status_code': response.status, 'body': json.loads(body) if body.strip() else {}}
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode('utf-8', errors='replace')
        raise CodeHostIntegrationError(f'{method} {url} failed with {exc.code}: {truncate(error_body, 500)}') from exc
    except urllib.error.URLError as exc:
        raise CodeHostIntegrationError(f'{method} {url} failed: {exc}') from exc


def provider_artifact(provider: str, configured: bool, active: bool, dry_run: bool, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        'provider': provider,
        'configured': configured,
        'active': active,
        'dry_run': dry_run,
        'publish_attempted': False,
        'payload': payload,
        'result': None,
        'error': None,
    }


def review_status(scan: ScanResult) -> dict[str, Any]:
    secret_policy = secret_policy_report(scan)
    blocking_secrets = int(secret_policy.get('blocking_findings', 0))
    p0 = scan.summary.priorities.get('P0', 0)
    p1 = scan.summary.priorities.get('P1', 0)
    if blocking_secrets or p0:
        state = 'fail'
        description = 'Release-blocking security findings require review.'
    elif p1 or scan.summary.max_risk_score >= 65:
        state = 'warn'
        description = 'High-risk findings require security review.'
    else:
        state = 'pass'
        description = 'No release-blocking security findings were detected.'
    return {
        'status': state,
        'description': description,
        'total_findings': scan.summary.total_findings,
        'production_findings': scan.summary.production_findings,
        'hygiene_findings': scan.summary.hygiene_findings,
        'scope_counts': dict(scan.summary.scope_counts),
        'max_risk_score': scan.summary.max_risk_score,
        'avg_risk_score': scan.summary.avg_risk_score,
        'priorities': dict(scan.summary.priorities),
        'risk_tiers': dict(scan.summary.risk_tiers),
        'blocking_secrets': blocking_secrets,
    }


def review_body(scan: ScanResult, status: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    lines = [
        '## Secure Code Review Summary',
        '',
        f'Project: **{scan.project_name}**',
        f'Scan ID: `{scan.scan_id}`',
        f'Status: **{status["status"]}** - {status["description"]}',
        f'Findings: **{status["total_findings"]}** across **{scan.summary.files_scanned}** files',
        f'Production/gate findings: **{status["production_findings"]}** | Hygiene findings: **{status["hygiene_findings"]}** | Scopes: **{format_counts(status["scope_counts"])}**',
        f'Production max risk: **{status["max_risk_score"]}** | Production average risk: **{status["avg_risk_score"]}**',
        f'Priorities: **{format_counts(status["priorities"])}**',
        f'Risk tiers: **{format_counts(status["risk_tiers"])}**',
        f'Blocking secrets: **{status["blocking_secrets"]}**',
        '',
        '| Risk | Scope | Severity | Source | Rule | Location | Finding |',
        '| --- | --- | --- | --- | --- | --- | --- |',
    ]
    for finding in findings:
        lines.append(
            f'| {finding["priority"]} {finding["risk_score"]} | {finding["scope"]} | {finding["severity"]} | '
            f'`{finding["source"]}` | `{finding["rule_id"]}` | `{finding["location"]}` | {escape_table(finding["title"])} |'
        )
    if len(scan.findings) > len(findings):
        lines.extend(['', f'Showing {len(findings)} of {len(scan.findings)} findings. See the full Secure Review artifact set for details.'])
    lines.extend(['', 'Generated by Secure Code Review Assistant.'])
    return '\n'.join(lines) + '\n'


def top_findings(scan: ScanResult, limit: int) -> list[dict[str, Any]]:
    sorted_findings = sorted(scan.findings, key=lambda item: (scope_sort_rank(item), item.risk.score, priority_rank(item)), reverse=True)
    return [finding_summary(finding) for finding in sorted_findings[:limit]]


def finding_summary(finding: Finding) -> dict[str, Any]:
    return {
        'id': finding.id,
        'priority': finding.risk.priority,
        'risk_score': finding.risk.score,
        'severity': finding.severity,
        'scope': finding_scope(finding),
        'source': finding.source,
        'rule_id': finding.rule_id,
        'location': f'{finding.location.path}:{finding.location.line}',
        'title': finding.title,
        'message': finding.message,
    }


def priority_rank(finding: Finding) -> int:
    return {'P0': 5, 'P1': 4, 'P2': 3, 'P3': 2, 'P4': 1}.get(finding.risk.priority, 0)


def normalize_providers(provider: str) -> list[str]:
    value = (provider or 'all').lower()
    if value == 'all':
        return ['gitlab', 'azure-devops', 'bitbucket']
    aliases = {'azure': 'azure-devops', 'azure_devops': 'azure-devops', 'ado': 'azure-devops'}
    value = aliases.get(value, value)
    if value in {'gitlab', 'azure-devops', 'bitbucket'}:
        return [value]
    raise CodeHostIntegrationError('provider must be all, gitlab, azure-devops, or bitbucket')


def resolve_status(publish: bool, publish_summary: dict[str, int]) -> str:
    if not publish:
        return 'dry_run'
    if publish_summary['failed'] and publish_summary['published']:
        return 'partial'
    if publish_summary['failed'] and not publish_summary['published']:
        return 'failed'
    if publish_summary['published']:
        return 'published'
    if publish_summary['dry_run']:
        return 'dry_run'
    return 'not_configured'


def gitlab_state(status: dict[str, Any]) -> str:
    return 'failed' if status['status'] == 'fail' else 'success'


def azure_state(status: dict[str, Any]) -> str:
    return 'failed' if status['status'] == 'fail' else 'succeeded'


def bitbucket_state(status: dict[str, Any]) -> str:
    return 'FAILED' if status['status'] == 'fail' else 'SUCCESSFUL'


def azure_path(cfg: AzureDevOpsConfig) -> str:
    org = url_quote(cfg.organization or 'organization')
    project = url_quote(cfg.project or 'project')
    repo = url_quote(cfg.repository_id or 'repository')
    return f'/{org}/{project}/_apis/git/repositories/{repo}'


def bitbucket_auth_headers(cfg: BitbucketConfig) -> dict[str, str]:
    if cfg.token:
        return {'Authorization': f'Bearer {cfg.token}'}
    raw = f'{cfg.username or ""}:{cfg.app_password or ""}'
    return {'Authorization': 'Basic ' + base64.b64encode(raw.encode('utf-8')).decode('ascii')}


def summarize_publish_result(result: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key, value in result.items():
        if isinstance(value, dict) and 'status_code' in value:
            body = value.get('body') if isinstance(value.get('body'), dict) else {}
            summary[key] = {
                'status_code': value.get('status_code'),
                'id': body.get('id') or body.get('key') or body.get('threadId') if isinstance(body, dict) else None,
                'url': response_url(body),
            }
        else:
            summary[key] = value
    return summary


def response_url(body: dict[str, Any]) -> str | None:
    if not isinstance(body, dict):
        return None
    links = body.get('links') if isinstance(body.get('links'), dict) else {}
    html = links.get('html') if isinstance(links.get('html'), dict) else {}
    return body.get('web_url') or body.get('url') or html.get('href')

def target_url(base_url: str | None, scan_id: str) -> str | None:
    if not base_url:
        return None
    if '{scan_id}' in base_url:
        return base_url.replace('{scan_id}', scan_id)
    return base_url


def public_scan_base_url() -> str | None:
    base_url = (os.getenv('CODE_HOST_PUBLIC_BASE_URL') or os.getenv('PUBLIC_BASE_URL') or '').rstrip('/')
    if not base_url:
        return None
    return f'{base_url}/api/scans/{{scan_id}}'


def url_quote(value: str) -> str:
    return urllib.parse.quote(str(value), safe='')


def escape_table(value: str) -> str:
    return str(value or '').replace('|', '\\|').replace('\n', ' ')[:240]


def truncate(value: str, limit: int = 500) -> str:
    text = ' '.join(str(value or '').split())
    return text if len(text) <= limit else text[: max(0, limit - 3)] + '...'


def int_or_none(value: str | None) -> int | None:
    try:
        return int(value) if value else None
    except ValueError:
        return None


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == '':
        return default
    return value.lower() in {'1', 'true', 'yes', 'on'}
