from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .consolidation import top_consolidated_findings
from .models import Finding, ScanResult
from .reporting import format_counts
from .scope import finding_scope, scope_sort_rank

SUPPORTED_CHAT_COMMANDS = {
    'help': 'Show supported Secure Review chat commands.',
    'status': 'Confirm the agent is reachable and configured.',
    'review': 'Request a secure review workflow for a scan or repository.',
    'plan': 'Request a remediation or issue-planning workflow for a scan.',
    'latest': 'Ask for the latest known scan context.',
}


class ChatAgentError(RuntimeError):
    pass


@dataclass(frozen=True)
class SlackConfig:
    enabled: str
    webhook_url: str | None
    signing_secret: str | None
    allow_unsigned: bool
    dry_run: bool
    channel: str | None
    username: str
    icon_emoji: str | None

    @property
    def configured(self) -> bool:
        return bool(self.webhook_url)

    @property
    def command_configured(self) -> bool:
        return bool(self.signing_secret)

    @property
    def active(self) -> bool:
        return self.enabled == 'true' or (self.enabled == 'auto' and self.configured)


@dataclass(frozen=True)
class TeamsConfig:
    enabled: str
    webhook_url: str | None
    command_secret: str | None
    allow_unsigned: bool
    dry_run: bool

    @property
    def configured(self) -> bool:
        return bool(self.webhook_url)

    @property
    def command_configured(self) -> bool:
        return bool(self.command_secret)

    @property
    def active(self) -> bool:
        return self.enabled == 'true' or (self.enabled == 'auto' and self.configured)


def slack_config() -> SlackConfig:
    return SlackConfig(
        enabled=os.getenv('SLACK_ENABLED', 'auto').lower(),
        webhook_url=os.getenv('SLACK_WEBHOOK_URL') or None,
        signing_secret=os.getenv('SLACK_SIGNING_SECRET') or None,
        allow_unsigned=parse_bool(os.getenv('SLACK_ALLOW_UNSIGNED'), False),
        dry_run=parse_bool(os.getenv('SLACK_DRY_RUN'), True),
        channel=os.getenv('SLACK_CHANNEL') or None,
        username=os.getenv('SLACK_USERNAME', 'Secure Review'),
        icon_emoji=os.getenv('SLACK_ICON_EMOJI') or ':shield:',
    )


def teams_config() -> TeamsConfig:
    return TeamsConfig(
        enabled=os.getenv('TEAMS_ENABLED', 'auto').lower(),
        webhook_url=os.getenv('TEAMS_WEBHOOK_URL') or None,
        command_secret=os.getenv('TEAMS_COMMAND_SECRET') or None,
        allow_unsigned=parse_bool(os.getenv('TEAMS_ALLOW_UNSIGNED'), False),
        dry_run=parse_bool(os.getenv('TEAMS_DRY_RUN'), True),
    )


def chat_agent_status() -> dict[str, Any]:
    slack = slack_config()
    teams = teams_config()
    return {
        'slack': {
            'enabled': slack.enabled,
            'active': slack.active,
            'configured': slack.configured,
            'webhook_configured': bool(slack.webhook_url),
            'signing_secret_configured': bool(slack.signing_secret),
            'allow_unsigned_commands': slack.allow_unsigned,
            'dry_run_default': slack.dry_run,
            'channel_configured': bool(slack.channel),
        },
        'teams': {
            'enabled': teams.enabled,
            'active': teams.active,
            'configured': teams.configured,
            'webhook_configured': bool(teams.webhook_url),
            'command_secret_configured': bool(teams.command_secret),
            'allow_unsigned_commands': teams.allow_unsigned,
            'dry_run_default': teams.dry_run,
        },
        'commands': chat_command_help(),
    }


def build_chat_notification(scan: ScanResult, provider: str = 'all', publish: bool = False, include_findings: int | None = None) -> dict[str, Any]:
    selected_providers = normalize_providers(provider)
    max_findings = max(1, min(include_findings or int(os.getenv('CHAT_MAX_FINDINGS', '10')), 25))
    slack = slack_config()
    teams = teams_config()
    summary = scan_summary(scan)
    findings = top_findings(scan, max_findings)
    providers: dict[str, Any] = {}
    if 'slack' in selected_providers:
        providers['slack'] = provider_artifact(
            provider='slack',
            configured=slack.configured,
            active=slack.active,
            dry_run=slack.dry_run,
            payload=build_slack_payload(scan, summary, findings, slack),
        )
    if 'teams' in selected_providers:
        providers['teams'] = provider_artifact(
            provider='teams',
            configured=teams.configured,
            active=teams.active,
            dry_run=teams.dry_run,
            payload=build_teams_payload(scan, summary, findings),
        )

    publish_summary = {'attempted': 0, 'sent': 0, 'dry_run': 0, 'skipped': 0, 'failed': 0}
    if publish:
        publish_summary = publish_notifications(providers, slack, teams)

    return {
        'schema_version': 1,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'provider': provider,
        'publish_requested': publish,
        'status': resolve_status(publish, publish_summary),
        'include_findings': max_findings,
        'configuration': chat_agent_status(),
        'summary': {
            **summary,
            'providers': selected_providers,
            'publish': publish_summary,
        },
        'top_findings': findings,
        'guardrails': [
            'Dry-run is the default for Slack and Teams notifications.',
            'Real chat publishing requires publish=true and the provider dry-run flag set to false.',
            'Inbound Slack commands require Slack signature verification unless explicitly allowed unsigned.',
            'Inbound Teams commands require a shared secret unless explicitly allowed unsigned.',
        ],
        'providers': providers,
    }


def build_slack_payload(scan: ScanResult, summary: dict[str, Any], findings: list[dict[str, Any]], cfg: SlackConfig) -> dict[str, Any]:
    status = chat_status_label(summary)
    fields = [
        {'type': 'mrkdwn', 'text': f'*Findings*\n{summary["total_findings"]}'},
        {'type': 'mrkdwn', 'text': f'*Production*\n{summary["production_findings"]}'},
        {'type': 'mrkdwn', 'text': f'*Production max risk*\n{summary["max_risk_score"]}'},
        {'type': 'mrkdwn', 'text': f'*Priorities*\n{slack_escape(summary["priorities"])}'},
        {'type': 'mrkdwn', 'text': f'*Push protection*\n{slack_escape(summary["push_protection"])}'},
    ]
    blocks: list[dict[str, Any]] = [
        {'type': 'header', 'text': {'type': 'plain_text', 'text': truncate(f'Secure Review: {scan.project_name}', 150)}},
        {'type': 'section', 'text': {'type': 'mrkdwn', 'text': f'*Status:* {slack_escape(status)}\n*Scan:* `{scan.scan_id}`'}},
        {'type': 'section', 'fields': fields},
    ]
    if findings:
        blocks.append({'type': 'divider'})
        blocks.append({'type': 'section', 'text': {'type': 'mrkdwn', 'text': '*Top findings*'}})
    for finding in findings:
        blocks.append({
            'type': 'section',
            'text': {
                'type': 'mrkdwn',
                'text': truncate(
                    f'*{slack_escape(finding["priority"])} {finding["risk_score"]}* '
                    f'{slack_escape(finding["title"])}\n'
                    f'`{slack_escape(finding["location"])}` `{slack_escape(finding["rule_id"])}`',
                    2900,
                ),
            },
        })
    public_url = public_scan_url(scan.scan_id)
    if public_url:
        blocks.append({'type': 'actions', 'elements': [{'type': 'button', 'text': {'type': 'plain_text', 'text': 'Open Scan'}, 'url': public_url}]})
    payload: dict[str, Any] = {
        'text': f'Secure Review {scan.project_name}: {status}',
        'blocks': blocks,
        'username': cfg.username,
    }
    if cfg.channel:
        payload['channel'] = cfg.channel
    if cfg.icon_emoji:
        payload['icon_emoji'] = cfg.icon_emoji
    return payload


def build_teams_payload(scan: ScanResult, summary: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    body: list[dict[str, Any]] = [
        {'type': 'TextBlock', 'text': f'Secure Review: {scan.project_name}', 'weight': 'Bolder', 'size': 'Large', 'wrap': True},
        {'type': 'TextBlock', 'text': f'Status: {chat_status_label(summary)}', 'wrap': True},
        {
            'type': 'FactSet',
            'facts': [
                {'title': 'Scan', 'value': scan.scan_id},
                {'title': 'Findings', 'value': str(summary['total_findings'])},
                {'title': 'Production/gate findings', 'value': str(summary['production_findings'])},
                {'title': 'Hygiene findings', 'value': str(summary['hygiene_findings'])},
                {'title': 'Production max risk', 'value': str(summary['max_risk_score'])},
                {'title': 'Priorities', 'value': summary['priorities']},
                {'title': 'Push protection', 'value': summary['push_protection']},
            ],
        },
    ]
    if findings:
        body.append({'type': 'TextBlock', 'text': 'Top findings', 'weight': 'Bolder', 'wrap': True})
    for finding in findings:
        body.append({
            'type': 'TextBlock',
            'text': f'{finding["priority"]} {finding["risk_score"]} - {finding["title"]}\n{finding["location"]} | {finding["rule_id"]}',
            'wrap': True,
            'spacing': 'Small',
        })
    actions = []
    public_url = public_scan_url(scan.scan_id)
    if public_url:
        actions.append({'type': 'Action.OpenUrl', 'title': 'Open Scan', 'url': public_url})
    return {
        'type': 'message',
        'attachments': [{
            'contentType': 'application/vnd.microsoft.card.adaptive',
            'contentUrl': None,
            'content': {
                '$schema': 'http://adaptivecards.io/schemas/adaptive-card.json',
                'type': 'AdaptiveCard',
                'version': '1.4',
                'body': body,
                'actions': actions,
            },
        }],
    }


def publish_notifications(providers: dict[str, Any], slack: SlackConfig, teams: TeamsConfig) -> dict[str, int]:
    summary = {'attempted': 0, 'sent': 0, 'dry_run': 0, 'skipped': 0, 'failed': 0}
    if 'slack' in providers:
        publish_provider(providers['slack'], summary, lambda payload: post_json(slack.webhook_url or '', payload))
    if 'teams' in providers:
        publish_provider(providers['teams'], summary, lambda payload: post_json(teams.webhook_url or '', payload))
    return summary


def publish_provider(artifact: dict[str, Any], summary: dict[str, int], post_fn) -> None:
    if not artifact['active']:
        artifact['error'] = 'provider is disabled or not configured'
        summary['skipped'] += 1
        return
    if not artifact['configured']:
        artifact['error'] = 'webhook URL is not configured'
        summary['skipped'] += 1
        return
    if artifact['dry_run']:
        artifact['result'] = {'dry_run': True, 'message': 'provider dry-run is enabled'}
        summary['dry_run'] += 1
        return
    summary['attempted'] += 1
    artifact['publish_attempted'] = True
    try:
        artifact['result'] = post_fn(artifact['payload'])
        summary['sent'] += 1
    except ChatAgentError as exc:
        artifact['error'] = str(exc)
        summary['failed'] += 1


def post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not url:
        raise ChatAgentError('webhook URL is not configured')
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode('utf-8'),
        method='POST',
        headers={'Content-Type': 'application/json', 'User-Agent': 'secure-code-review-assistant'},
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            body = response.read().decode('utf-8', errors='replace')
            return {'status_code': response.status, 'body': body[:500]}
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode('utf-8', errors='replace')
        raise ChatAgentError(f'chat webhook failed with {exc.code}: {truncate(error_body, 500)}') from exc
    except urllib.error.URLError as exc:
        raise ChatAgentError(f'chat webhook failed: {exc}') from exc


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


def verify_slack_signature(body: bytes, timestamp: str | None, signature: str | None, secret: str | None = None) -> dict[str, Any]:
    cfg = slack_config()
    signing_secret = secret if secret is not None else cfg.signing_secret
    if not signing_secret:
        return {'valid': cfg.allow_unsigned, 'configured': False, 'reason': 'unsigned Slack command allowed' if cfg.allow_unsigned else 'SLACK_SIGNING_SECRET is not configured'}
    if not timestamp or not signature or not signature.startswith('v0='):
        return {'valid': False, 'configured': True, 'reason': 'missing or unsupported Slack signature headers'}
    try:
        request_time = int(timestamp)
    except ValueError:
        return {'valid': False, 'configured': True, 'reason': 'invalid Slack timestamp'}
    if abs(int(time.time()) - request_time) > 300:
        return {'valid': False, 'configured': True, 'reason': 'Slack timestamp is outside the allowed window'}
    base = b'v0:' + timestamp.encode('utf-8') + b':' + body
    digest = hmac.new(signing_secret.encode('utf-8'), base, hashlib.sha256).hexdigest()
    expected = f'v0={digest}'
    return {'valid': hmac.compare_digest(expected, signature), 'configured': True, 'reason': 'signature verified' if hmac.compare_digest(expected, signature) else 'signature mismatch'}


def verify_teams_command_secret(secret_header: str | None, secret: str | None = None) -> dict[str, Any]:
    cfg = teams_config()
    command_secret = secret if secret is not None else cfg.command_secret
    if not command_secret:
        return {'valid': cfg.allow_unsigned, 'configured': False, 'reason': 'unsigned Teams command allowed' if cfg.allow_unsigned else 'TEAMS_COMMAND_SECRET is not configured'}
    if not secret_header:
        return {'valid': False, 'configured': True, 'reason': 'missing Teams command secret header'}
    valid = hmac.compare_digest(command_secret, secret_header)
    return {'valid': valid, 'configured': True, 'reason': 'secret verified' if valid else 'secret mismatch'}


def handle_slack_command(body: bytes) -> dict[str, Any]:
    params = urllib.parse.parse_qs(body.decode('utf-8', errors='replace'))
    text = first_value(params, 'text')
    return handle_chat_command(
        platform='slack',
        text=text,
        user=first_value(params, 'user_name') or first_value(params, 'user_id'),
        channel=first_value(params, 'channel_name') or first_value(params, 'channel_id'),
        team=first_value(params, 'team_domain') or first_value(params, 'team_id'),
    )


def handle_teams_command(payload: dict[str, Any]) -> dict[str, Any]:
    text = str(payload.get('text') or payload.get('command') or '')
    sender = payload.get('from') if isinstance(payload.get('from'), dict) else {}
    channel = payload.get('channelData') if isinstance(payload.get('channelData'), dict) else {}
    return handle_chat_command(
        platform='teams',
        text=text,
        user=str(sender.get('name') or sender.get('id') or payload.get('user') or ''),
        channel=str(channel.get('channel', {}).get('name') if isinstance(channel.get('channel'), dict) else payload.get('channel') or ''),
        team=str(channel.get('team', {}).get('name') if isinstance(channel.get('team'), dict) else payload.get('team') or ''),
    )


def handle_chat_command(platform: str, text: str, user: str | None = None, channel: str | None = None, team: str | None = None) -> dict[str, Any]:
    command, args = parse_chat_command(text)
    accepted = command in SUPPORTED_CHAT_COMMANDS
    if not accepted:
        command = 'help'
        args = ''
    action = {
        'help': 'show_help',
        'status': 'show_status',
        'latest': 'latest_scan_requested',
        'review': 'review_requested',
        'plan': 'plan_requested',
    }.get(command, 'show_help')
    response_text = command_response_text(command, args)
    return {
        'accepted': accepted,
        'platform': platform,
        'command': command,
        'args': args,
        'action': action,
        'user': user or '',
        'channel': channel or '',
        'team': team or '',
        'response_type': 'ephemeral',
        'text': response_text,
    }


def parse_chat_command(text: str) -> tuple[str, str]:
    line = (text or '').strip()
    if not line:
        return 'help', ''
    if line.startswith('/'):
        _, _, line = line.partition(' ')
        line = line.strip()
    first, _, rest = line.partition(' ')
    command = first.lower() if first else 'help'
    return command, rest.strip()


def command_response_text(command: str, args: str) -> str:
    if command == 'help':
        commands = ', '.join(f'`{name}`' for name in SUPPORTED_CHAT_COMMANDS)
        return f'Secure Review commands: {commands}. Use `review <scan_id>` or `plan <scan_id>` from an authenticated workflow.'
    if command == 'status':
        status = chat_agent_status()
        return f'Secure Review chat agent is reachable. Slack configured={status["slack"]["configured"]}, Teams configured={status["teams"]["configured"]}.'
    if command == 'latest':
        return 'Latest scan lookup is accepted. Use the web app or API to select the scan; chat does not expose scan data without an authenticated workflow.'
    if command == 'review':
        return f'Review request accepted for `{args or "current context"}`. Run or publish review artifacts from the API, CLI, or CI workflow.'
    if command == 'plan':
        return f'Planning request accepted for `{args or "current context"}`. Generate remediation, Jira/Linear, or chat artifacts from the API, CLI, or CI workflow.'
    return command_response_text('help', '')


def chat_command_help() -> list[dict[str, str]]:
    return [{'command': name, 'description': description} for name, description in SUPPORTED_CHAT_COMMANDS.items()]


def scan_summary(scan: ScanResult) -> dict[str, Any]:
    secret_status = scan.summary.tools.get('secret-scan', 'not run')
    return {
        'total_findings': scan.summary.total_findings,
        'files_scanned': scan.summary.files_scanned,
        'production_findings': scan.summary.production_findings,
        'hygiene_findings': scan.summary.hygiene_findings,
        'scope_counts': format_counts(scan.summary.scope_counts),
        'max_risk_score': scan.summary.max_risk_score,
        'avg_risk_score': scan.summary.avg_risk_score,
        'priorities': format_counts(scan.summary.priorities),
        'risk_tiers': format_counts(scan.summary.risk_tiers),
        'new_findings': len(scan.new_findings),
        'resolved_findings': len(scan.resolved_findings),
        'push_protection': secret_status,
    }


def top_findings(scan: ScanResult, limit: int) -> list[dict[str, Any]]:
    consolidated = top_consolidated_findings(scan, limit)
    if consolidated:
        return [consolidated_finding_summary(item) for item in consolidated]
    sorted_findings = sorted(scan.findings, key=lambda item: (scope_sort_rank(item), item.risk.score, priority_rank(item)), reverse=True)
    return [finding_summary(finding) for finding in sorted_findings[:limit]]


def consolidated_finding_summary(item: Any) -> dict[str, Any]:
    line_range = str(item.line_start) if item.line_start == item.line_end else f'{item.line_start}-{item.line_end}'
    return {
        'id': item.cluster_id,
        'priority': item.priority,
        'risk_score': item.priority_score,
        'severity': item.severity,
        'scope': 'consolidated',
        'title': item.title,
        'source': ','.join(item.sources),
        'rule_id': ','.join(item.cwe or item.rules[:2]) or item.semantic_key,
        'location': f'{item.path}:{line_range}',
        'message': f'{item.agreement_count} tool(s) agree; {item.raw_count} raw finding(s).',
    }


def finding_summary(finding: Finding) -> dict[str, Any]:
    return {
        'id': finding.id,
        'priority': finding.risk.priority,
        'risk_score': finding.risk.score,
        'severity': finding.severity,
        'scope': finding_scope(finding),
        'title': finding.title,
        'source': finding.source,
        'rule_id': finding.rule_id,
        'location': f'{finding.location.path}:{finding.location.line}',
        'message': finding.message,
    }


def chat_status_label(summary: dict[str, Any]) -> str:
    if summary['max_risk_score'] >= 85:
        return 'action required'
    if summary['max_risk_score'] >= 65:
        return 'security review required'
    if summary['production_findings'] or summary['hygiene_findings']:
        return 'review recommended'
    return 'no findings'


def priority_rank(finding: Finding) -> int:
    ranks = {'P0': 5, 'P1': 4, 'P2': 3, 'P3': 2, 'P4': 1}
    return ranks.get(finding.risk.priority, 0)


def normalize_providers(provider: str) -> list[str]:
    value = (provider or 'all').lower()
    if value == 'all':
        return ['slack', 'teams']
    if value in {'slack', 'teams'}:
        return [value]
    raise ChatAgentError('provider must be all, slack, or teams')


def resolve_status(publish: bool, publish_summary: dict[str, int]) -> str:
    if not publish:
        return 'dry_run'
    if publish_summary['failed'] and publish_summary['sent']:
        return 'partial'
    if publish_summary['failed'] and not publish_summary['sent']:
        return 'failed'
    if publish_summary['sent']:
        return 'published'
    if publish_summary['dry_run']:
        return 'dry_run'
    return 'not_configured'


def public_scan_url(scan_id: str) -> str | None:
    base_url = (os.getenv('CHAT_PUBLIC_BASE_URL') or os.getenv('PUBLIC_BASE_URL') or '').rstrip('/')
    if not base_url:
        return None
    return f'{base_url}/api/scans/{scan_id}'


def first_value(params: dict[str, list[str]], key: str) -> str:
    values = params.get(key) or []
    return values[0] if values else ''


def slack_escape(value: Any) -> str:
    return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def truncate(value: str, limit: int = 500) -> str:
    text = str(value or '')
    return text if len(text) <= limit else text[: max(0, limit - 3)] + '...'


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == '':
        return default
    return value.lower() in {'1', 'true', 'yes', 'on'}
