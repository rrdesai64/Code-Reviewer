from __future__ import annotations

import base64
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .models import Finding, Priority, RemediationStep, ScanResult
from .refactor import build_remediation_plan

PRIORITY_ORDER: dict[str, int] = {'P0': 0, 'P1': 1, 'P2': 2, 'P3': 3, 'P4': 4}
JIRA_PRIORITY_DEFAULTS = {'P0': 'Highest', 'P1': 'High', 'P2': 'Medium', 'P3': 'Low', 'P4': 'Lowest'}
LINEAR_PRIORITY_DEFAULTS = {'P0': 1, 'P1': 2, 'P2': 3, 'P3': 4, 'P4': 0}


class IssuePlanningError(RuntimeError):
    pass


@dataclass(frozen=True)
class JiraConfig:
    enabled: str
    base_url: str | None
    email: str | None
    token: str | None
    project_key: str | None
    issue_type: str
    labels: list[str]
    components: list[str]
    dry_run: bool

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.email and self.token and self.project_key)

    @property
    def active(self) -> bool:
        return self.enabled == 'true' or (self.enabled == 'auto' and self.configured)


@dataclass(frozen=True)
class LinearConfig:
    enabled: str
    api_url: str
    api_key: str | None
    team_id: str | None
    label_ids: list[str]
    project_id: str | None
    dry_run: bool

    @property
    def configured(self) -> bool:
        return bool(self.api_url and self.api_key and self.team_id)

    @property
    def active(self) -> bool:
        return self.enabled == 'true' or (self.enabled == 'auto' and self.configured)


def jira_config() -> JiraConfig:
    return JiraConfig(
        enabled=os.getenv('JIRA_ENABLED', 'auto').lower(),
        base_url=(os.getenv('JIRA_BASE_URL') or '').rstrip('/') or None,
        email=os.getenv('JIRA_EMAIL') or None,
        token=os.getenv('JIRA_API_TOKEN') or None,
        project_key=os.getenv('JIRA_PROJECT_KEY') or None,
        issue_type=os.getenv('JIRA_ISSUE_TYPE', 'Task'),
        labels=[sanitize_label(item) for item in csv_env('JIRA_LABELS', ['secure-review', 'security'])],
        components=csv_env('JIRA_COMPONENTS', []),
        dry_run=parse_bool(os.getenv('JIRA_DRY_RUN'), True),
    )


def linear_config() -> LinearConfig:
    return LinearConfig(
        enabled=os.getenv('LINEAR_ENABLED', 'auto').lower(),
        api_url=os.getenv('LINEAR_API_URL', 'https://api.linear.app/graphql'),
        api_key=os.getenv('LINEAR_API_KEY') or None,
        team_id=os.getenv('LINEAR_TEAM_ID') or None,
        label_ids=csv_env('LINEAR_LABEL_IDS', []),
        project_id=os.getenv('LINEAR_PROJECT_ID') or None,
        dry_run=parse_bool(os.getenv('LINEAR_DRY_RUN'), True),
    )


def issue_planning_status() -> dict[str, Any]:
    jira = jira_config()
    linear = linear_config()
    return {
        'jira': {
            'enabled': jira.enabled,
            'active': jira.active,
            'configured': jira.configured,
            'base_url_configured': bool(jira.base_url),
            'email_configured': bool(jira.email),
            'token_configured': bool(jira.token),
            'project_key_configured': bool(jira.project_key),
            'issue_type': jira.issue_type,
            'labels': jira.labels,
            'components': jira.components,
            'dry_run_default': jira.dry_run,
        },
        'linear': {
            'enabled': linear.enabled,
            'active': linear.active,
            'configured': linear.configured,
            'api_url': linear.api_url,
            'api_key_configured': bool(linear.api_key),
            'team_id_configured': bool(linear.team_id),
            'label_ids_configured': bool(linear.label_ids),
            'project_id_configured': bool(linear.project_id),
            'dry_run_default': linear.dry_run,
        },
    }


def build_issue_plan(scan: ScanResult, provider: str = 'all', limit: int = 25, min_priority: Priority = 'P2', publish: bool = False) -> dict[str, Any]:
    selected_providers = normalize_providers(provider)
    limit = max(1, min(limit, 100))
    if min_priority not in PRIORITY_ORDER:
        raise IssuePlanningError(f'Unsupported priority threshold: {min_priority}')

    remediation_plan = build_remediation_plan(scan, limit=max(limit * 2, limit))
    findings_by_id = {finding.id: finding for finding in scan.findings}
    steps = [
        step
        for step in remediation_plan.steps
        if PRIORITY_ORDER.get(step.priority, 99) <= PRIORITY_ORDER[min_priority]
    ][:limit]
    jira = jira_config()
    linear = linear_config()
    items = []
    for step in steps:
        finding = findings_by_id.get(step.finding_id)
        if not finding:
            continue
        item = build_issue_item(scan, step, finding)
        if 'jira' in selected_providers:
            item['providers']['jira'] = provider_artifact(
                provider='jira',
                configured=jira.configured,
                active=jira.active,
                dry_run=jira.dry_run,
                payload=build_jira_payload(item, jira),
            )
        if 'linear' in selected_providers:
            item['providers']['linear'] = provider_artifact(
                provider='linear',
                configured=linear.configured,
                active=linear.active,
                dry_run=linear.dry_run,
                payload=build_linear_payload(item, linear),
            )
        items.append(item)

    publish_summary = {'attempted': 0, 'created': 0, 'dry_run': 0, 'skipped': 0, 'failed': 0}
    if publish:
        publish_summary = publish_items(items, selected_providers, jira, linear)

    status = resolve_plan_status(publish, publish_summary)
    return {
        'schema_version': 1,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'provider': provider,
        'publish_requested': publish,
        'status': status,
        'min_priority': min_priority,
        'limit': limit,
        'configuration': issue_planning_status(),
        'summary': {
            'selected_findings': len(items),
            'available_findings': len(remediation_plan.steps),
            'providers': selected_providers,
            'publish': publish_summary,
        },
        'guardrails': [
            'Dry-run is the default for Jira and Linear issue planning.',
            'Real issue creation requires publish=true and the provider dry-run flag set to false.',
            'Issue bodies include validation commands and source context; review before assigning to teams.',
            'False-positive and risk-accepted findings are excluded through the remediation plan.',
        ],
        'items': items,
    }


def build_issue_item(scan: ScanResult, step: RemediationStep, finding: Finding) -> dict[str, Any]:
    labels = sorted(set([
        'secure-review',
        sanitize_label(f'priority-{step.priority.lower()}'),
        sanitize_label(f'source-{finding.source}'),
        sanitize_label(f'rule-{finding.rule_id}'),
    ]))
    title = truncate(f'[Secure Review][{step.priority}] {step.title}', 250)
    description = issue_description(scan, step, finding)
    return {
        'finding_id': finding.id,
        'scan_id': scan.scan_id,
        'title': title,
        'priority': step.priority,
        'risk_score': step.risk_score,
        'severity': finding.severity,
        'source': finding.source,
        'rule_id': finding.rule_id,
        'path': step.path,
        'line': step.line,
        'summary': step.summary,
        'dedupe_key': dedupe_key(scan, finding),
        'labels': labels,
        'validation_commands': step.validation_commands,
        'description_markdown': description,
        'providers': {},
    }


def issue_description(scan: ScanResult, step: RemediationStep, finding: Finding) -> str:
    cwe = ', '.join(finding.cwe) if finding.cwe else 'not mapped'
    owasp = ', '.join(finding.owasp) if finding.owasp else 'not mapped'
    validation = '\n'.join(f'- `{command}`' for command in step.validation_commands) or '- Rerun the secure review scan after remediation.'
    guidance = '\n'.join(f'- {item}' for item in finding.fix.guidance) or '- Review the finding and apply a human-approved fix.'
    factors = '\n'.join(f'- {factor.label}: {factor.detail}' for factor in finding.risk.factors) or '- No risk factors recorded.'
    return '\n'.join([
        f'Project: {scan.project_name}',
        f'Scan ID: {scan.scan_id}',
        f'Finding ID: {finding.id}',
        '',
        f'Priority: {step.priority}',
        f'Risk score: {step.risk_score}',
        f'Severity: {finding.severity}',
        f'Source: {finding.source}',
        f'Rule: {finding.rule_id}',
        f'Location: {step.path}:{step.line}',
        f'CWE: {cwe}',
        f'OWASP: {owasp}',
        '',
        'Summary:',
        step.summary,
        '',
        'Recommended remediation:',
        finding.fix.summary,
        guidance,
        '',
        'Risk factors:',
        factors,
        '',
        'Validation commands:',
        validation,
        '',
        'Guardrails:',
        '- Treat this as a planned remediation task, not an automatically approved code change.',
        '- Review the source diff and rerun scans before closing this issue.',
    ])


def build_jira_payload(item: dict[str, Any], cfg: JiraConfig) -> dict[str, Any]:
    labels = sorted(set(cfg.labels + item['labels']))
    fields: dict[str, Any] = {
        'project': {'key': cfg.project_key or 'PROJECT'},
        'summary': item['title'],
        'description': jira_adf(item['description_markdown']),
        'issuetype': {'name': cfg.issue_type},
        'labels': labels,
        'priority': {'name': jira_priority(item['priority'])},
    }
    if cfg.components:
        fields['components'] = [{'name': component} for component in cfg.components]
    return {'fields': fields}


def build_linear_payload(item: dict[str, Any], cfg: LinearConfig) -> dict[str, Any]:
    issue_input: dict[str, Any] = {
        'teamId': cfg.team_id or 'LINEAR_TEAM_ID',
        'title': item['title'],
        'description': item['description_markdown'],
        'priority': linear_priority(item['priority']),
    }
    if cfg.label_ids:
        issue_input['labelIds'] = cfg.label_ids
    if cfg.project_id:
        issue_input['projectId'] = cfg.project_id
    return {
        'query': (
            'mutation IssueCreate($input: IssueCreateInput!) { '
            'issueCreate(input: $input) { success issue { id identifier url title } } '
            '}'
        ),
        'variables': {'input': issue_input},
    }


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


def publish_items(items: list[dict[str, Any]], selected_providers: list[str], jira: JiraConfig, linear: LinearConfig) -> dict[str, int]:
    summary = {'attempted': 0, 'created': 0, 'dry_run': 0, 'skipped': 0, 'failed': 0}
    for item in items:
        if 'jira' in selected_providers:
            publish_provider_item(item['providers']['jira'], summary, lambda payload: create_jira_issue(payload, jira))
        if 'linear' in selected_providers:
            publish_provider_item(item['providers']['linear'], summary, lambda payload: create_linear_issue(payload, linear))
    return summary


def publish_provider_item(artifact: dict[str, Any], summary: dict[str, int], create_fn) -> None:
    if not artifact['active']:
        artifact['error'] = 'provider is disabled or not configured'
        summary['skipped'] += 1
        return
    if not artifact['configured']:
        artifact['error'] = 'provider credentials are incomplete'
        summary['skipped'] += 1
        return
    if artifact['dry_run']:
        artifact['result'] = {'dry_run': True, 'message': 'provider dry-run is enabled'}
        summary['dry_run'] += 1
        return
    summary['attempted'] += 1
    artifact['publish_attempted'] = True
    try:
        artifact['result'] = create_fn(artifact['payload'])
        summary['created'] += 1
    except IssuePlanningError as exc:
        artifact['error'] = str(exc)
        summary['failed'] += 1


def create_jira_issue(payload: dict[str, Any], cfg: JiraConfig) -> dict[str, Any]:
    if not cfg.configured:
        raise IssuePlanningError('Jira configuration is incomplete')
    auth = base64.b64encode(f'{cfg.email}:{cfg.token}'.encode('utf-8')).decode('ascii')
    response = json_request(
        f'{cfg.base_url}/rest/api/3/issue',
        method='POST',
        payload=payload,
        headers={
            'Authorization': f'Basic {auth}',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        },
    )
    body = response.get('body') if isinstance(response.get('body'), dict) else {}
    return {
        'status_code': response.get('status_code'),
        'id': body.get('id'),
        'key': body.get('key'),
        'url': body.get('self'),
        'browse_url': f'{cfg.base_url}/browse/{body.get("key")}' if body.get('key') else None,
    }


def create_linear_issue(payload: dict[str, Any], cfg: LinearConfig) -> dict[str, Any]:
    if not cfg.configured:
        raise IssuePlanningError('Linear configuration is incomplete')
    response = json_request(
        cfg.api_url,
        method='POST',
        payload=payload,
        headers={
            'Authorization': cfg.api_key or '',
            'Content-Type': 'application/json',
        },
    )
    body = response.get('body') if isinstance(response.get('body'), dict) else {}
    issue_create = ((body.get('data') or {}).get('issueCreate') or {}) if isinstance(body, dict) else {}
    issue = issue_create.get('issue') or {}
    if body.get('errors'):
        raise IssuePlanningError(f'Linear API returned errors: {truncate(json.dumps(body["errors"]), 500)}')
    return {
        'status_code': response.get('status_code'),
        'success': issue_create.get('success'),
        'id': issue.get('id'),
        'identifier': issue.get('identifier'),
        'url': issue.get('url'),
    }


def json_request(url: str, method: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode('utf-8'),
        method=method,
        headers={'User-Agent': 'secure-code-review-assistant', **headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            raw = response.read().decode('utf-8', errors='replace')
            return {
                'status_code': response.status,
                'headers': dict(response.headers.items()),
                'body': json.loads(raw) if raw.strip() else {},
            }
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode('utf-8', errors='replace')
        raise IssuePlanningError(f'{method} {url} failed with {exc.code}: {truncate(error_body, 500)}') from exc
    except urllib.error.URLError as exc:
        raise IssuePlanningError(f'{method} {url} failed: {exc}') from exc


def jira_adf(markdown: str) -> dict[str, Any]:
    content = []
    for line in markdown.splitlines():
        if not line.strip():
            content.append({'type': 'paragraph'})
            continue
        if line.startswith('- '):
            content.append({
                'type': 'bulletList',
                'content': [{
                    'type': 'listItem',
                    'content': [{'type': 'paragraph', 'content': [{'type': 'text', 'text': line[2:]}]}],
                }],
            })
            continue
        content.append({'type': 'paragraph', 'content': [{'type': 'text', 'text': line}]})
    return {'type': 'doc', 'version': 1, 'content': content or [{'type': 'paragraph'}]}


def normalize_providers(provider: str) -> list[str]:
    value = (provider or 'all').lower()
    if value == 'all':
        return ['jira', 'linear']
    if value in {'jira', 'linear'}:
        return [value]
    raise IssuePlanningError('provider must be all, jira, or linear')


def resolve_plan_status(publish: bool, publish_summary: dict[str, int]) -> str:
    if not publish:
        return 'dry_run'
    if publish_summary['failed'] and publish_summary['created']:
        return 'partial'
    if publish_summary['failed'] and not publish_summary['created']:
        return 'failed'
    if publish_summary['created']:
        return 'published'
    if publish_summary['dry_run']:
        return 'dry_run'
    return 'not_configured'


def jira_priority(priority: str) -> str:
    return os.getenv(f'JIRA_PRIORITY_{priority}', JIRA_PRIORITY_DEFAULTS.get(priority, 'Medium'))


def linear_priority(priority: str) -> int:
    value = os.getenv(f'LINEAR_PRIORITY_{priority}')
    if value and value.isdigit():
        return int(value)
    return LINEAR_PRIORITY_DEFAULTS.get(priority, 3)


def csv_env(name: str, default: list[str]) -> list[str]:
    raw = os.getenv(name)
    if raw is None or raw.strip() == '':
        return default
    return [item.strip() for item in re.split(r'[;,]', raw) if item.strip()]


def sanitize_label(value: str) -> str:
    text = re.sub(r'[^A-Za-z0-9_.-]+', '-', str(value or '').strip().lower())
    text = text.strip('-._')
    return text[:50] or 'secure-review'


def dedupe_key(scan: ScanResult, finding: Finding) -> str:
    return sanitize_label(f'{scan.project_name}-{finding.fingerprint or finding.id}')


def truncate(value: str, limit: int = 500) -> str:
    text = ' '.join(str(value or '').split())
    return text if len(text) <= limit else text[: max(0, limit - 3)] + '...'


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == '':
        return default
    return value.lower() in {'1', 'true', 'yes', 'on'}
