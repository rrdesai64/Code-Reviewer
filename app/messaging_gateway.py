from __future__ import annotations

import hashlib
import hmac
import json
import os
import smtplib
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any

from .chat_agents import build_slack_payload, build_teams_payload, chat_status_label, post_json, scan_summary, top_findings, truncate
from .models import ScanResult
from .paths import data_dir
from .storage import apply_decisions, list_scans, load_scan

SCHEMA_VERSION = 1
SUPPORTED_GATEWAY_CHANNELS = (
    'slack',
    'teams',
    'email',
    'telegram',
    'discord',
    'google-chat',
    'whatsapp',
    'signal',
    'home-assistant',
    'twitch',
    'macos',
    'ios',
    'android',
    'ubuntu',
)
WEBHOOK_RELAY_CHANNELS = {'discord', 'google-chat', 'macos', 'ios', 'android', 'ubuntu'}
GENERIC_INBOUND_CHANNELS = {'discord', 'google-chat', 'signal', 'home-assistant', 'twitch', 'macos', 'ios', 'android', 'ubuntu'}
SUPPORTED_GATEWAY_COMMANDS = {
    'help': 'Show supported Secure Review gateway commands.',
    'status': 'Show gateway status.',
    'latest': 'Show the latest saved scan summary.',
    'scan': 'Show a saved scan summary by scan ID.',
    'explain': 'Show a sanitized finding summary by scan ID and finding ID.',
}


class GatewayError(RuntimeError):
    pass


@dataclass(frozen=True)
class GatewayChannelConfig:
    name: str
    enabled: str
    configured: bool
    active: bool
    dry_run: bool
    outbound: bool
    inbound: bool
    required_env: list[str]
    missing_env: list[str]
    target: str
    allow_all_users: bool
    allowed_user_count: int


def gateway_status() -> dict[str, Any]:
    channels = gateway_channels()['channels']
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'service': 'secure-review-messaging-gateway',
        'enabled': gateway_enabled(),
        'dry_run_default': parse_bool(os.getenv('GATEWAY_DRY_RUN'), True),
        'supported_channels': list(SUPPORTED_GATEWAY_CHANNELS),
        'active_channels': [name for name, channel in channels.items() if channel['active']],
        'configured_channels': [name for name, channel in channels.items() if channel['configured']],
        'event_count': len(read_gateway_events(limit=10000)),
        'channels': channels,
        'commands': gateway_command_help(),
        'guardrails': gateway_guardrails(),
    }


def gateway_channels() -> dict[str, Any]:
    configs = {name: channel_config(name) for name in SUPPORTED_GATEWAY_CHANNELS}
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'channels': {name: channel_config_public(config) for name, config in configs.items()},
    }


def gateway_events(limit: int = 100, channel: str | None = None, scan_id: str | None = None) -> dict[str, Any]:
    events = read_gateway_events(limit=max(limit, 1000), channel=channel, scan_id=scan_id)[: max(1, min(limit, 1000))]
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'count': len(events),
        'events': events,
    }


def build_scan_gateway_report(
    scan: ScanResult,
    channels: list[str] | str | None = None,
    publish: bool = False,
    include_findings: int = 10,
    persist: bool = False,
    actor: str = 'system',
) -> dict[str, Any]:
    summary = scan_summary(scan)
    severity = severity_from_summary(summary)
    return send_gateway_message(
        {
            'channels': normalize_channels(channels),
            'title': f'Secure Review scan complete: {scan.project_name}',
            'message': scan_message(scan, summary),
            'severity': severity,
            'scan_id': scan.scan_id,
            'source': 'scan-report',
            'publish': publish,
            'include_findings': include_findings,
            'metadata': {
                'project_name': scan.project_name,
                'total_findings': str(summary['total_findings']),
                'production_findings': str(summary['production_findings']),
                'max_risk_score': str(summary['max_risk_score']),
            },
        },
        actor=actor,
        scan=scan,
        persist=persist,
    )


def send_gateway_message(
    request: dict[str, Any],
    actor: str = 'system',
    scan: ScanResult | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    selected_channels = normalize_channels(request.get('channels'))
    publish = bool(request.get('publish'))
    scan_id = safe_text(request.get('scan_id'), 120)
    if scan is None and scan_id:
        scan = apply_decisions(load_scan(scan_id))
    include_findings = max(1, min(int(request.get('include_findings') or 10), 25))
    event = gateway_event_from_request(request, actor=actor, scan=scan)
    artifacts = build_delivery_artifacts(event, selected_channels, scan=scan, include_findings=include_findings)
    publish_summary = publish_gateway_artifacts(artifacts) if publish else delivery_summary()
    status = resolve_gateway_status(publish, publish_summary, artifacts)
    event_record = {
        **event,
        'status': status,
        'publish_requested': publish,
        'channels': selected_channels,
        'delivery': publish_summary,
    }
    if persist or publish:
        record_gateway_event(event_record)
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'status': status,
        'publish_requested': publish,
        'event': event,
        'channels': selected_channels,
        'delivery': publish_summary,
        'artifacts': artifacts,
        'configuration': gateway_channels(),
        'guardrails': gateway_guardrails(),
    }


def handle_gateway_webhook(channel: str, raw_body: bytes, headers: dict[str, str], actor: str = 'gateway-webhook') -> dict[str, Any]:
    normalized = normalize_channel(channel)
    if normalized not in SUPPORTED_GATEWAY_CHANNELS:
        raise GatewayError(f'Unsupported gateway channel: {channel}')
    message = normalize_inbound_message(normalized, raw_body, headers)
    authorized = inbound_authorized(normalized, message['user_id'] or message['user'])
    result = handle_gateway_command(normalized, message, authorized)
    record_gateway_event({
        'event_id': event_id(f'inbound:{normalized}:{message.get("user_id")}:{message.get("text")}'),
        'created_at': now_iso(),
        'actor': actor,
        'source': 'inbound-webhook',
        'direction': 'inbound',
        'severity': 'info',
        'title': f'Inbound {normalized} command',
        'message': safe_text(message.get('text'), 500),
        'scan_id': result.get('scan_id') or '',
        'channels': [normalized],
        'status': result['status'],
        'metadata': {
            'channel': normalized,
            'user': safe_text(message.get('user'), 120),
            'user_id': safe_text(message.get('user_id'), 120),
            'command': result.get('command', ''),
            'accepted': str(result.get('accepted', False)),
        },
    })
    return result


def handle_gateway_command(channel: str, message: dict[str, Any], authorized: dict[str, Any]) -> dict[str, Any]:
    command, args = parse_gateway_command(message.get('text', ''))
    if not authorized['allowed']:
        return {
            'schema_version': SCHEMA_VERSION,
            'accepted': False,
            'status': 'blocked',
            'channel': channel,
            'command': command,
            'reason': authorized['reason'],
            'response_text': 'Blocked: this sender is not allowed to use the Secure Review gateway.',
        }
    if command not in SUPPORTED_GATEWAY_COMMANDS:
        command, args = 'help', ''
    response = gateway_command_response(command, args)
    return {
        'schema_version': SCHEMA_VERSION,
        'accepted': True,
        'status': 'accepted',
        'channel': channel,
        'command': command,
        'args': args,
        'scan_id': response.get('scan_id', ''),
        'response_text': response['text'],
        'payload': response.get('payload', {}),
    }


def gateway_command_response(command: str, args: str) -> dict[str, Any]:
    if command == 'help':
        commands = ', '.join(SUPPORTED_GATEWAY_COMMANDS)
        return {'text': f'Secure Review gateway commands: {commands}. No command mutates scanner rules or repository files.'}
    if command == 'status':
        status = gateway_status()
        active = ', '.join(status['active_channels']) or 'none'
        return {'text': f'Secure Review gateway is reachable. Active channels: {active}. Dry-run default={status["dry_run_default"]}.'}
    if command == 'latest':
        scans = list_scans()
        if not scans:
            return {'text': 'No saved scans were found.'}
        return scan_command_response(scans[0])
    if command == 'scan':
        scan_id = args.strip()
        if not scan_id:
            return {'text': 'Use: scan <scan_id>.'}
        try:
            return scan_command_response(apply_decisions(load_scan(scan_id)))
        except FileNotFoundError:
            return {'text': f'Scan not found: {scan_id}.', 'scan_id': scan_id}
    if command == 'explain':
        parts = args.split()
        if len(parts) < 2:
            return {'text': 'Use: explain <scan_id> <finding_id>.'}
        return explain_command_response(parts[0], parts[1])
    return gateway_command_response('help', '')


def scan_command_response(scan: ScanResult) -> dict[str, Any]:
    summary = scan_summary(scan)
    text = (
        f'Scan {scan.scan_id} for {scan.project_name}: '
        f'{summary["total_findings"]} findings, {summary["production_findings"]} production, '
        f'max risk {summary["max_risk_score"]}, priorities {summary["priorities"]}.'
    )
    return {'text': text, 'scan_id': scan.scan_id, 'payload': {'summary': summary}}


def explain_command_response(scan_id: str, finding_id: str) -> dict[str, Any]:
    try:
        scan = apply_decisions(load_scan(scan_id))
    except FileNotFoundError:
        return {'text': f'Scan not found: {scan_id}.', 'scan_id': scan_id}
    finding = next((item for item in scan.findings if item.id == finding_id), None)
    if finding is None:
        return {'text': f'Finding not found: {finding_id}.', 'scan_id': scan_id}
    text = (
        f'{finding.risk.priority} {finding.severity} finding {finding.id}: {finding.title}. '
        f'{truncate(finding.message, 300)} Recommended action: {truncate(finding.risk.recommended_action, 240)}'
    )
    return {
        'text': text,
        'scan_id': scan_id,
        'payload': {
            'finding_id': finding.id,
            'title': finding.title,
            'severity': finding.severity,
            'priority': finding.risk.priority,
            'risk_score': finding.risk.score,
            'source': finding.source,
            'rule_id': finding.rule_id,
        },
    }


def build_delivery_artifacts(event: dict[str, Any], channels: list[str], scan: ScanResult | None = None, include_findings: int = 10) -> dict[str, Any]:
    configs = {name: channel_config(name) for name in channels}
    summary = scan_summary(scan) if scan else None
    findings = top_findings(scan, include_findings) if scan else []
    return {
        name: provider_artifact(config, build_channel_payload(name, config, event, scan, summary, findings))
        for name, config in configs.items()
    }


def build_channel_payload(
    channel: str,
    config: GatewayChannelConfig,
    event: dict[str, Any],
    scan: ScanResult | None,
    summary: dict[str, Any] | None,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    if channel == 'slack':
        if scan and summary is not None:
            return build_slack_payload(scan, summary, findings, slack_payload_config())
        return slack_text_payload(event)
    if channel == 'teams':
        if scan and summary is not None:
            return build_teams_payload(scan, summary, findings)
        return teams_text_payload(event)
    if channel == 'email':
        return email_payload(event, scan=scan, summary=summary, findings=findings)
    if channel == 'telegram':
        return telegram_payload(event, scan=scan, summary=summary, findings=findings)
    if channel == 'discord':
        return discord_payload(event, scan=scan, summary=summary, findings=findings)
    if channel == 'google-chat':
        return google_chat_payload(event, scan=scan, summary=summary, findings=findings)
    if channel == 'whatsapp':
        return whatsapp_payload(event, scan=scan, summary=summary, findings=findings)
    if channel == 'signal':
        return signal_payload(event, scan=scan, summary=summary, findings=findings)
    if channel == 'home-assistant':
        return home_assistant_payload(event, scan=scan, summary=summary, findings=findings)
    if channel == 'twitch':
        return twitch_payload(event, scan=scan, summary=summary, findings=findings)
    if channel in {'macos', 'ios', 'android', 'ubuntu'}:
        return device_payload(channel, event, scan=scan, summary=summary, findings=findings)
    raise GatewayError(f'Unsupported gateway channel: {channel}')


def publish_gateway_artifacts(artifacts: dict[str, Any]) -> dict[str, int]:
    summary = delivery_summary()
    for channel, artifact in artifacts.items():
        publish_artifact(channel, artifact, summary)
    return summary


def publish_artifact(channel: str, artifact: dict[str, Any], summary: dict[str, int]) -> None:
    if not artifact['active']:
        artifact['error'] = 'channel is disabled or not configured'
        summary['skipped'] += 1
        return
    if not artifact['configured']:
        artifact['error'] = 'channel credentials or target are not configured'
        summary['skipped'] += 1
        return
    if artifact['dry_run']:
        artifact['result'] = {'dry_run': True, 'message': 'gateway dry-run is enabled'}
        summary['dry_run'] += 1
        return
    summary['attempted'] += 1
    artifact['publish_attempted'] = True
    try:
        if channel == 'slack':
            artifact['result'] = post_json(env_first('GATEWAY_SLACK_WEBHOOK_URL', 'SLACK_WEBHOOK_URL') or '', artifact['payload'])
        elif channel == 'teams':
            artifact['result'] = post_json(env_first('GATEWAY_TEAMS_WEBHOOK_URL', 'TEAMS_WEBHOOK_URL') or '', artifact['payload'])
        elif channel == 'telegram':
            artifact['result'] = send_telegram_message(artifact['payload'])
        elif channel == 'email':
            artifact['result'] = send_email_message(artifact['payload'])
        elif channel == 'discord':
            artifact['result'] = post_json(env_first('GATEWAY_DISCORD_WEBHOOK_URL', 'DISCORD_WEBHOOK_URL') or '', artifact['payload'])
        elif channel == 'google-chat':
            artifact['result'] = post_json(env_first('GATEWAY_GOOGLE_CHAT_WEBHOOK_URL', 'GOOGLE_CHAT_WEBHOOK_URL') or '', artifact['payload'])
        elif channel == 'whatsapp':
            artifact['result'] = send_whatsapp_message(artifact['payload'])
        elif channel == 'signal':
            artifact['result'] = send_signal_message(artifact['payload'])
        elif channel == 'home-assistant':
            artifact['result'] = send_home_assistant_notification(artifact['payload'])
        elif channel == 'twitch':
            artifact['result'] = send_twitch_message(artifact['payload'])
        elif channel in {'macos', 'ios', 'android', 'ubuntu'}:
            artifact['result'] = post_json(env_first(f'GATEWAY_{channel_env_name(channel)}_WEBHOOK_URL') or '', artifact['payload'])
        else:
            raise GatewayError(f'Unsupported gateway channel: {channel}')
        summary['sent'] += 1
    except Exception as exc:
        artifact['error'] = truncate(str(exc), 500)
        summary['failed'] += 1


def send_telegram_message(payload: dict[str, Any]) -> dict[str, Any]:
    token = env_first('GATEWAY_TELEGRAM_BOT_TOKEN', 'TELEGRAM_BOT_TOKEN')
    if not token:
        raise GatewayError('Telegram bot token is not configured')
    req = urllib.request.Request(
        f'https://api.telegram.org/bot{token}/sendMessage',
        data=json.dumps(payload).encode('utf-8'),
        method='POST',
        headers={'Content-Type': 'application/json', 'User-Agent': 'secure-review-messaging-gateway'},
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            body = response.read().decode('utf-8', errors='replace')
            return {'status_code': response.status, 'body': body[:500]}
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode('utf-8', errors='replace')
        raise GatewayError(f'Telegram API failed with {exc.code}: {truncate(error_body, 500)}') from exc
    except urllib.error.URLError as exc:
        raise GatewayError(f'Telegram API failed: {exc}') from exc


def send_whatsapp_message(payload: dict[str, Any]) -> dict[str, Any]:
    token = env_first('GATEWAY_WHATSAPP_ACCESS_TOKEN', 'WHATSAPP_ACCESS_TOKEN')
    phone_number_id = env_first('GATEWAY_WHATSAPP_PHONE_NUMBER_ID', 'WHATSAPP_PHONE_NUMBER_ID')
    if not token or not phone_number_id:
        raise GatewayError('WhatsApp Cloud API token or phone number ID is not configured')
    version = env_first('GATEWAY_WHATSAPP_GRAPH_VERSION', 'WHATSAPP_GRAPH_VERSION') or 'v20.0'
    req = urllib.request.Request(
        f'https://graph.facebook.com/{version}/{phone_number_id}/messages',
        data=json.dumps(payload).encode('utf-8'),
        method='POST',
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}',
            'User-Agent': 'secure-review-messaging-gateway',
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            body = response.read().decode('utf-8', errors='replace')
            return {'status_code': response.status, 'body': body[:500]}
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode('utf-8', errors='replace')
        raise GatewayError(f'WhatsApp API failed with {exc.code}: {truncate(error_body, 500)}') from exc
    except urllib.error.URLError as exc:
        raise GatewayError(f'WhatsApp API failed: {exc}') from exc


def send_signal_message(payload: dict[str, Any]) -> dict[str, Any]:
    base_url = (env_first('GATEWAY_SIGNAL_REST_URL', 'SIGNAL_REST_URL') or '').rstrip('/')
    if not base_url:
        raise GatewayError('Signal REST bridge URL is not configured')
    return post_json(f'{base_url}/v2/send', payload)


def send_home_assistant_notification(payload: dict[str, Any]) -> dict[str, Any]:
    base_url = (env_first('GATEWAY_HOME_ASSISTANT_URL', 'HOME_ASSISTANT_URL') or '').rstrip('/')
    token = env_first('GATEWAY_HOME_ASSISTANT_TOKEN', 'HOME_ASSISTANT_TOKEN')
    service = env_first('GATEWAY_HOME_ASSISTANT_NOTIFY_SERVICE', 'HOME_ASSISTANT_NOTIFY_SERVICE') or 'notify.persistent_notification'
    if not base_url or not token:
        raise GatewayError('Home Assistant URL or token is not configured')
    domain, _, service_name = service.partition('.')
    if not domain or not service_name:
        raise GatewayError('Home Assistant notify service must use domain.service format')
    req = urllib.request.Request(
        f'{base_url}/api/services/{domain}/{service_name}',
        data=json.dumps(payload).encode('utf-8'),
        method='POST',
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}',
            'User-Agent': 'secure-review-messaging-gateway',
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            body = response.read().decode('utf-8', errors='replace')
            return {'status_code': response.status, 'body': body[:500]}
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode('utf-8', errors='replace')
        raise GatewayError(f'Home Assistant API failed with {exc.code}: {truncate(error_body, 500)}') from exc
    except urllib.error.URLError as exc:
        raise GatewayError(f'Home Assistant API failed: {exc}') from exc


def send_twitch_message(payload: dict[str, Any]) -> dict[str, Any]:
    token = env_first('GATEWAY_TWITCH_ACCESS_TOKEN', 'TWITCH_ACCESS_TOKEN')
    client_id = env_first('GATEWAY_TWITCH_CLIENT_ID', 'TWITCH_CLIENT_ID')
    if not token or not client_id:
        raise GatewayError('Twitch access token or client ID is not configured')
    req = urllib.request.Request(
        'https://api.twitch.tv/helix/chat/messages',
        data=json.dumps(payload).encode('utf-8'),
        method='POST',
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}',
            'Client-Id': client_id,
            'User-Agent': 'secure-review-messaging-gateway',
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            body = response.read().decode('utf-8', errors='replace')
            return {'status_code': response.status, 'body': body[:500]}
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode('utf-8', errors='replace')
        raise GatewayError(f'Twitch API failed with {exc.code}: {truncate(error_body, 500)}') from exc
    except urllib.error.URLError as exc:
        raise GatewayError(f'Twitch API failed: {exc}') from exc


def send_email_message(payload: dict[str, Any]) -> dict[str, Any]:
    host = env_first('GATEWAY_SMTP_HOST', 'SMTP_HOST')
    if not host:
        raise GatewayError('SMTP host is not configured')
    port = int(env_first('GATEWAY_SMTP_PORT', 'SMTP_PORT') or ('465' if email_ssl_enabled() else '587'))
    username = env_first('GATEWAY_SMTP_USERNAME', 'SMTP_USERNAME')
    password = env_first('GATEWAY_SMTP_PASSWORD', 'SMTP_PASSWORD')
    message = EmailMessage()
    message['Subject'] = payload['subject']
    message['From'] = payload['from']
    message['To'] = ', '.join(payload['to'])
    message.set_content(payload['body'])
    if email_ssl_enabled():
        with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=45) as smtp:
            if username:
                smtp.login(username, password or '')
            smtp.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=45) as smtp:
            if parse_bool(env_first('GATEWAY_SMTP_TLS', 'SMTP_TLS'), True):
                smtp.starttls(context=ssl.create_default_context())
            if username:
                smtp.login(username, password or '')
            smtp.send_message(message)
    return {'sent': True, 'to_count': len(payload['to']), 'smtp_host': host}


def normalize_inbound_message(channel: str, raw_body: bytes, headers: dict[str, str]) -> dict[str, Any]:
    if channel == 'slack':
        verification = verify_slack_gateway_signature(raw_body, headers)
        if not verification['valid']:
            raise GatewayError(f'Slack signature rejected: {verification["reason"]}')
        params = urllib.parse.parse_qs(raw_body.decode('utf-8', errors='replace'))
        return {
            'channel': channel,
            'text': first_value(params, 'text') or first_value(params, 'command'),
            'user': first_value(params, 'user_name') or first_value(params, 'user_id'),
            'user_id': first_value(params, 'user_id') or first_value(params, 'user_name'),
            'conversation_id': first_value(params, 'channel_id') or first_value(params, 'channel_name'),
        }
    if channel == 'teams':
        verify_shared_secret(channel, headers, env_first('GATEWAY_TEAMS_COMMAND_SECRET', 'TEAMS_COMMAND_SECRET'))
        payload = load_json_body(raw_body)
        sender = payload.get('from') if isinstance(payload.get('from'), dict) else {}
        channel_data = payload.get('channelData') if isinstance(payload.get('channelData'), dict) else {}
        tenant = channel_data.get('tenant') if isinstance(channel_data.get('tenant'), dict) else {}
        return {
            'channel': channel,
            'text': safe_text(payload.get('text') or payload.get('command'), 1000),
            'user': safe_text(sender.get('name') or payload.get('user'), 120),
            'user_id': safe_text(sender.get('id') or payload.get('user_id') or payload.get('user'), 120),
            'conversation_id': safe_text(payload.get('conversation_id') or tenant.get('id'), 120),
        }
    if channel == 'telegram':
        secret = env_first('GATEWAY_TELEGRAM_WEBHOOK_SECRET', 'TELEGRAM_WEBHOOK_SECRET')
        if secret:
            verify_shared_secret(channel, headers, secret, header_names=('x-telegram-bot-api-secret-token', 'x-secure-review-gateway-secret'))
        payload = load_json_body(raw_body)
        message = payload.get('message') if isinstance(payload.get('message'), dict) else payload
        sender = message.get('from') if isinstance(message.get('from'), dict) else {}
        chat = message.get('chat') if isinstance(message.get('chat'), dict) else {}
        return {
            'channel': channel,
            'text': safe_text(message.get('text') or message.get('caption'), 1000),
            'user': safe_text(sender.get('username') or sender.get('first_name') or sender.get('id'), 120),
            'user_id': safe_text(sender.get('id') or sender.get('username'), 120),
            'conversation_id': safe_text(chat.get('id'), 120),
        }
    if channel == 'whatsapp':
        verify_meta_signature_or_shared_secret(channel, raw_body, headers)
        payload = load_json_body(raw_body)
        value = first_whatsapp_value(payload)
        message = first_list_item(value.get('messages'))
        sender = first_list_item(value.get('contacts'))
        profile = sender.get('profile') if isinstance(sender.get('profile'), dict) else {}
        return {
            'channel': channel,
            'text': safe_text((message.get('text') or {}).get('body') if isinstance(message.get('text'), dict) else message.get('body'), 1000),
            'user': safe_text(profile.get('name') or sender.get('wa_id') or message.get('from'), 120),
            'user_id': safe_text(sender.get('wa_id') or message.get('from'), 120),
            'conversation_id': safe_text(message.get('from') or sender.get('wa_id'), 120),
        }
    if channel == 'email':
        secret = env_first('GATEWAY_EMAIL_WEBHOOK_SECRET', 'EMAIL_WEBHOOK_SECRET')
        if secret:
            verify_shared_secret(channel, headers, secret)
        payload = load_json_body(raw_body)
        return {
            'channel': channel,
            'text': safe_text(payload.get('text') or payload.get('subject') or payload.get('body'), 1000),
            'user': safe_text(payload.get('from') or payload.get('sender'), 120),
            'user_id': safe_text(payload.get('from') or payload.get('sender'), 120),
            'conversation_id': safe_text(payload.get('thread_id') or payload.get('message_id'), 120),
        }
    if channel in GENERIC_INBOUND_CHANNELS:
        secret = env_first(f'GATEWAY_{channel_env_name(channel)}_WEBHOOK_SECRET')
        verify_shared_secret(channel, headers, secret)
        payload = load_json_body(raw_body)
        sender = payload.get('from') if isinstance(payload.get('from'), dict) else {}
        return {
            'channel': channel,
            'text': safe_text(payload.get('text') or payload.get('message') or payload.get('body') or payload.get('content'), 1000),
            'user': safe_text(payload.get('user') or payload.get('username') or sender.get('name') or sender.get('id'), 120),
            'user_id': safe_text(payload.get('user_id') or payload.get('sender_id') or sender.get('id') or payload.get('user'), 120),
            'conversation_id': safe_text(payload.get('channel_id') or payload.get('conversation_id') or payload.get('thread_id'), 120),
        }
    raise GatewayError(f'Unsupported gateway channel: {channel}')


def verify_slack_gateway_signature(body: bytes, headers: dict[str, str]) -> dict[str, Any]:
    secret = env_first('GATEWAY_SLACK_SIGNING_SECRET', 'SLACK_SIGNING_SECRET')
    allow_unsigned = parse_bool(env_first('GATEWAY_SLACK_ALLOW_UNSIGNED', 'SLACK_ALLOW_UNSIGNED'), False)
    if not secret:
        return {'valid': allow_unsigned, 'reason': 'unsigned Slack webhook allowed' if allow_unsigned else 'Slack signing secret is not configured'}
    timestamp = headers.get('x-slack-request-timestamp')
    signature = headers.get('x-slack-signature')
    if not timestamp or not signature or not signature.startswith('v0='):
        return {'valid': False, 'reason': 'missing Slack signature headers'}
    try:
        request_time = int(timestamp)
    except ValueError:
        return {'valid': False, 'reason': 'invalid Slack timestamp'}
    if abs(int(time.time()) - request_time) > 300:
        return {'valid': False, 'reason': 'Slack timestamp outside allowed window'}
    base = b'v0:' + timestamp.encode('utf-8') + b':' + body
    digest = hmac.new(secret.encode('utf-8'), base, hashlib.sha256).hexdigest()
    expected = f'v0={digest}'
    return {'valid': hmac.compare_digest(expected, signature), 'reason': 'signature verified' if hmac.compare_digest(expected, signature) else 'signature mismatch'}


def verify_shared_secret(channel: str, headers: dict[str, str], expected: str | None, header_names: tuple[str, ...] = ('x-secure-review-gateway-secret', 'x-secure-review-teams-secret')) -> None:
    allow_unsigned = parse_bool(os.getenv(f'GATEWAY_{channel_env_name(channel)}_ALLOW_UNSIGNED'), False)
    if not expected:
        if allow_unsigned:
            return
        raise GatewayError(f'{channel} webhook secret is not configured')
    provided = next((headers.get(name) for name in header_names if headers.get(name)), '')
    if not provided or not hmac.compare_digest(str(expected), str(provided)):
        raise GatewayError(f'{channel} webhook secret rejected')


def verify_meta_signature_or_shared_secret(channel: str, body: bytes, headers: dict[str, str]) -> None:
    app_secret = env_first('GATEWAY_WHATSAPP_APP_SECRET', 'WHATSAPP_APP_SECRET')
    signature = headers.get('x-hub-signature-256') or headers.get('x-whatsapp-signature')
    if app_secret and signature and signature.startswith('sha256='):
        digest = hmac.new(app_secret.encode('utf-8'), body, hashlib.sha256).hexdigest()
        if hmac.compare_digest(f'sha256={digest}', signature):
            return
        raise GatewayError('whatsapp webhook signature mismatch')
    secret = env_first('GATEWAY_WHATSAPP_WEBHOOK_SECRET', 'WHATSAPP_WEBHOOK_SECRET')
    verify_shared_secret(channel, headers, secret)


def inbound_authorized(channel: str, user: str | None) -> dict[str, Any]:
    config = channel_config(channel)
    if config.allow_all_users:
        return {'allowed': True, 'reason': 'channel allows all users'}
    allowed = allowed_users(channel)
    if not allowed:
        return {'allowed': False, 'reason': 'no gateway allowlist configured'}
    if safe_text(user, 200) in allowed:
        return {'allowed': True, 'reason': 'sender is allowlisted'}
    return {'allowed': False, 'reason': 'sender is not allowlisted'}


def channel_config(name: str) -> GatewayChannelConfig:
    channel = normalize_channel(name)
    global_enabled = gateway_enabled()
    prefix = channel_env_name(channel)
    enabled = (os.getenv(f'GATEWAY_{prefix}_ENABLED') or 'auto').lower()
    dry_run = parse_bool(os.getenv(f'GATEWAY_{prefix}_DRY_RUN'), parse_bool(os.getenv('GATEWAY_DRY_RUN'), True))
    required = channel_required_env(channel)
    missing = [key for key in required if not env_first(key)]
    configured = not missing
    active = global_enabled != 'false' and (enabled == 'true' or (enabled == 'auto' and configured))
    if enabled == 'false':
        active = False
    return GatewayChannelConfig(
        name=channel,
        enabled=enabled,
        configured=configured,
        active=active,
        dry_run=dry_run,
        outbound=True,
        inbound=True,
        required_env=required,
        missing_env=missing,
        target=channel_target(channel),
        allow_all_users=parse_bool(os.getenv(f'GATEWAY_{prefix}_ALLOW_ALL_USERS'), parse_bool(os.getenv('GATEWAY_ALLOW_ALL_USERS'), False)),
        allowed_user_count=len(allowed_users(channel)),
    )


def channel_required_env(channel: str) -> list[str]:
    if channel == 'slack':
        return ['GATEWAY_SLACK_WEBHOOK_URL|SLACK_WEBHOOK_URL']
    if channel == 'teams':
        return ['GATEWAY_TEAMS_WEBHOOK_URL|TEAMS_WEBHOOK_URL']
    if channel == 'email':
        return ['GATEWAY_SMTP_HOST|SMTP_HOST', 'GATEWAY_EMAIL_FROM|EMAIL_FROM', 'GATEWAY_EMAIL_TO|EMAIL_TO']
    if channel == 'telegram':
        return ['GATEWAY_TELEGRAM_BOT_TOKEN|TELEGRAM_BOT_TOKEN', 'GATEWAY_TELEGRAM_CHAT_ID|TELEGRAM_CHAT_ID']
    if channel == 'discord':
        return ['GATEWAY_DISCORD_WEBHOOK_URL|DISCORD_WEBHOOK_URL']
    if channel == 'google-chat':
        return ['GATEWAY_GOOGLE_CHAT_WEBHOOK_URL|GOOGLE_CHAT_WEBHOOK_URL']
    if channel == 'whatsapp':
        return ['GATEWAY_WHATSAPP_ACCESS_TOKEN|WHATSAPP_ACCESS_TOKEN', 'GATEWAY_WHATSAPP_PHONE_NUMBER_ID|WHATSAPP_PHONE_NUMBER_ID', 'GATEWAY_WHATSAPP_TO|WHATSAPP_TO']
    if channel == 'signal':
        return ['GATEWAY_SIGNAL_REST_URL|SIGNAL_REST_URL', 'GATEWAY_SIGNAL_ACCOUNT|SIGNAL_ACCOUNT', 'GATEWAY_SIGNAL_RECIPIENTS|SIGNAL_RECIPIENTS']
    if channel == 'home-assistant':
        return ['GATEWAY_HOME_ASSISTANT_URL|HOME_ASSISTANT_URL', 'GATEWAY_HOME_ASSISTANT_TOKEN|HOME_ASSISTANT_TOKEN']
    if channel == 'twitch':
        return ['GATEWAY_TWITCH_ACCESS_TOKEN|TWITCH_ACCESS_TOKEN', 'GATEWAY_TWITCH_CLIENT_ID|TWITCH_CLIENT_ID', 'GATEWAY_TWITCH_BROADCASTER_ID|TWITCH_BROADCASTER_ID', 'GATEWAY_TWITCH_SENDER_ID|TWITCH_SENDER_ID']
    if channel in {'macos', 'ios', 'android', 'ubuntu'}:
        return [f'GATEWAY_{channel_env_name(channel)}_WEBHOOK_URL']
    raise GatewayError(f'Unsupported gateway channel: {channel}')


def channel_target(channel: str) -> str:
    if channel == 'slack':
        return safe_text(env_first('GATEWAY_SLACK_CHANNEL', 'SLACK_CHANNEL') or 'webhook-default', 120)
    if channel == 'teams':
        return 'incoming-webhook'
    if channel == 'email':
        return ','.join(redact_email(item) for item in csv_env(env_first('GATEWAY_EMAIL_TO', 'EMAIL_TO')))
    if channel == 'telegram':
        return redact_middle(env_first('GATEWAY_TELEGRAM_CHAT_ID', 'TELEGRAM_CHAT_ID') or '')
    if channel == 'discord':
        return 'discord-webhook'
    if channel == 'google-chat':
        return 'google-chat-webhook'
    if channel == 'whatsapp':
        return redact_middle(env_first('GATEWAY_WHATSAPP_TO', 'WHATSAPP_TO') or '')
    if channel == 'signal':
        return ','.join(redact_middle(item) for item in csv_env(env_first('GATEWAY_SIGNAL_RECIPIENTS', 'SIGNAL_RECIPIENTS')))
    if channel == 'home-assistant':
        return safe_text(env_first('GATEWAY_HOME_ASSISTANT_NOTIFY_SERVICE', 'HOME_ASSISTANT_NOTIFY_SERVICE') or 'notify.persistent_notification', 120)
    if channel == 'twitch':
        return redact_middle(env_first('GATEWAY_TWITCH_BROADCASTER_ID', 'TWITCH_BROADCASTER_ID') or '')
    if channel in {'macos', 'ios', 'android', 'ubuntu'}:
        return f'{channel}-notification-relay'
    return ''


def env_first(*names: str) -> str | None:
    for name in names:
        if '|' in name:
            value = env_first(*name.split('|'))
            if value:
                return value
            continue
        value = os.getenv(name)
        if value:
            return value
    return None


def channel_env_name(channel: str) -> str:
    return normalize_channel(channel).upper().replace('-', '_')


def gateway_enabled() -> str:
    return (os.getenv('GATEWAY_ENABLED') or 'auto').lower()


def channel_config_public(config: GatewayChannelConfig) -> dict[str, Any]:
    return {
        'name': config.name,
        'enabled': config.enabled,
        'configured': config.configured,
        'active': config.active,
        'dry_run': config.dry_run,
        'outbound': config.outbound,
        'inbound': config.inbound,
        'target': config.target,
        'missing_env': config.missing_env,
        'allow_all_users': config.allow_all_users,
        'allowed_user_count': config.allowed_user_count,
    }


def provider_artifact(config: GatewayChannelConfig, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        'channel': config.name,
        'configured': config.configured,
        'active': config.active,
        'dry_run': config.dry_run,
        'publish_attempted': False,
        'target': config.target,
        'payload': payload,
        'result': None,
        'error': None,
    }


def gateway_event_from_request(request: dict[str, Any], actor: str, scan: ScanResult | None = None) -> dict[str, Any]:
    title = safe_text(request.get('title') or 'Secure Review update', 180)
    message = safe_text(request.get('message') or '', 2000)
    if not message and scan:
        message = scan_message(scan, scan_summary(scan))
    metadata = sanitize_metadata(request.get('metadata') if isinstance(request.get('metadata'), dict) else {})
    if scan:
        metadata.setdefault('project_name', scan.project_name)
    scan_id = safe_text(request.get('scan_id') or (scan.scan_id if scan else ''), 120)
    return {
        'event_id': event_id(f'{title}:{message}:{scan_id}:{actor}:{now_iso()}'),
        'created_at': now_iso(),
        'actor': safe_text(actor, 120),
        'source': safe_text(request.get('source') or 'api', 120),
        'direction': 'outbound',
        'severity': normalize_severity(request.get('severity')),
        'title': title,
        'message': message,
        'scan_id': scan_id,
        'metadata': metadata,
    }


def record_gateway_event(event: dict[str, Any]) -> dict[str, Any]:
    ensure_gateway_dir()
    safe_event = sanitize_jsonable(event)
    with gateway_events_path().open('a', encoding='utf-8') as handle:
        handle.write(json.dumps(safe_event, sort_keys=True) + '\n')
    try:
        from .governance import record_governance_event

        record_governance_event(
            category='messaging-gateway',
            action='gateway.event_recorded',
            actor=safe_event.get('actor', 'gateway'),
            resource=safe_event.get('scan_id') or safe_event.get('event_id', 'gateway'),
            scan_id=safe_event.get('scan_id') or None,
            metadata={
                'event_id': safe_text(safe_event.get('event_id'), 120),
                'status': safe_text(safe_event.get('status'), 80),
                'channels': ','.join(safe_event.get('channels') or []),
            },
        )
    except Exception:
        pass
    return safe_event


def read_gateway_events(limit: int = 100, channel: str | None = None, scan_id: str | None = None) -> list[dict[str, Any]]:
    path = gateway_events_path()
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if channel and channel not in (event.get('channels') or [event.get('channel')]):
            continue
        if scan_id and event.get('scan_id') != scan_id:
            continue
        events.append(event)
    return list(reversed(events))[: max(1, min(limit, 10000))]


def slack_payload_config():
    class Config:
        channel = env_first('GATEWAY_SLACK_CHANNEL', 'SLACK_CHANNEL')
        username = env_first('GATEWAY_SLACK_USERNAME', 'SLACK_USERNAME') or 'Secure Review'
        icon_emoji = env_first('GATEWAY_SLACK_ICON_EMOJI', 'SLACK_ICON_EMOJI') or ':shield:'

    return Config()


def slack_text_payload(event: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {
        'text': f'{event["title"]}: {event["message"]}',
        'username': env_first('GATEWAY_SLACK_USERNAME', 'SLACK_USERNAME') or 'Secure Review',
        'blocks': [
            {'type': 'header', 'text': {'type': 'plain_text', 'text': truncate(event['title'], 150)}},
            {'type': 'section', 'text': {'type': 'mrkdwn', 'text': slack_escape(event['message'])}},
        ],
    }
    channel = env_first('GATEWAY_SLACK_CHANNEL', 'SLACK_CHANNEL')
    if channel:
        payload['channel'] = channel
    return payload


def teams_text_payload(event: dict[str, Any]) -> dict[str, Any]:
    return {
        'type': 'message',
        'attachments': [{
            'contentType': 'application/vnd.microsoft.card.adaptive',
            'content': {
                '$schema': 'http://adaptivecards.io/schemas/adaptive-card.json',
                'type': 'AdaptiveCard',
                'version': '1.4',
                'body': [
                    {'type': 'TextBlock', 'text': event['title'], 'weight': 'Bolder', 'size': 'Large', 'wrap': True},
                    {'type': 'TextBlock', 'text': event['message'], 'wrap': True},
                ],
            },
        }],
    }


def email_payload(event: dict[str, Any], scan: ScanResult | None, summary: dict[str, Any] | None, findings: list[dict[str, Any]]) -> dict[str, Any]:
    subject_prefix = env_first('GATEWAY_EMAIL_SUBJECT_PREFIX', 'EMAIL_SUBJECT_PREFIX') or '[Secure Review]'
    lines = [
        event['title'],
        '',
        event['message'],
        '',
        f'Severity: {event["severity"]}',
        f'Scan ID: {event.get("scan_id") or "n/a"}',
    ]
    if scan and summary:
        lines.extend([
            '',
            f'Project: {scan.project_name}',
            f'Findings: {summary["total_findings"]}',
            f'Production findings: {summary["production_findings"]}',
            f'Max risk: {summary["max_risk_score"]}',
            f'Status: {chat_status_label(summary)}',
        ])
    if findings:
        lines.append('')
        lines.append('Top findings:')
        for finding in findings:
            lines.append(f'- {finding["priority"]} {finding["risk_score"]}: {finding["title"]} ({finding["rule_id"]})')
    return {
        'subject': truncate(f'{subject_prefix} {event["title"]}', 180),
        'from': env_first('GATEWAY_EMAIL_FROM', 'EMAIL_FROM') or '',
        'to': csv_env(env_first('GATEWAY_EMAIL_TO', 'EMAIL_TO')),
        'body': '\n'.join(lines),
    }


def telegram_payload(event: dict[str, Any], scan: ScanResult | None, summary: dict[str, Any] | None, findings: list[dict[str, Any]]) -> dict[str, Any]:
    lines = [event['title'], '', event['message']]
    if scan and summary:
        lines.extend([
            '',
            f'Scan: {scan.scan_id}',
            f'Project: {scan.project_name}',
            f'Findings: {summary["total_findings"]}',
            f'Production: {summary["production_findings"]}',
            f'Max risk: {summary["max_risk_score"]}',
        ])
    if findings:
        lines.append('')
        lines.append('Top findings:')
        for finding in findings[:5]:
            lines.append(f'- {finding["priority"]} {finding["risk_score"]}: {finding["title"]}')
    return {
        'chat_id': env_first('GATEWAY_TELEGRAM_CHAT_ID', 'TELEGRAM_CHAT_ID') or '',
        'text': truncate('\n'.join(lines), 3900),
        'disable_web_page_preview': True,
    }


def discord_payload(event: dict[str, Any], scan: ScanResult | None, summary: dict[str, Any] | None, findings: list[dict[str, Any]]) -> dict[str, Any]:
    fields = event_fields(scan, summary)
    embed: dict[str, Any] = {
        'title': truncate(event['title'], 256),
        'description': truncate(event['message'], 3900),
        'color': severity_color(event['severity']),
        'fields': fields[:10],
    }
    if findings:
        embed['fields'].append({'name': 'Top findings', 'value': truncate('\n'.join(f'- {item["priority"]} {item["risk_score"]}: {item["title"]}' for item in findings[:5]), 1000), 'inline': False})
    return {
        'username': env_first('GATEWAY_DISCORD_USERNAME', 'DISCORD_USERNAME') or 'Secure Review',
        'content': truncate(event['title'], 1900),
        'embeds': [embed],
    }


def google_chat_payload(event: dict[str, Any], scan: ScanResult | None, summary: dict[str, Any] | None, findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {'text': truncate(compact_text(event, scan, summary, findings), 3900)}


def whatsapp_payload(event: dict[str, Any], scan: ScanResult | None, summary: dict[str, Any] | None, findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        'messaging_product': 'whatsapp',
        'to': env_first('GATEWAY_WHATSAPP_TO', 'WHATSAPP_TO') or '',
        'type': 'text',
        'text': {'preview_url': False, 'body': truncate(compact_text(event, scan, summary, findings), 3900)},
    }


def signal_payload(event: dict[str, Any], scan: ScanResult | None, summary: dict[str, Any] | None, findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        'number': env_first('GATEWAY_SIGNAL_ACCOUNT', 'SIGNAL_ACCOUNT') or '',
        'recipients': csv_env(env_first('GATEWAY_SIGNAL_RECIPIENTS', 'SIGNAL_RECIPIENTS')),
        'message': truncate(compact_text(event, scan, summary, findings), 3900),
    }


def home_assistant_payload(event: dict[str, Any], scan: ScanResult | None, summary: dict[str, Any] | None, findings: list[dict[str, Any]]) -> dict[str, Any]:
    payload = {
        'title': event['title'],
        'message': truncate(compact_text(event, scan, summary, findings), 2000),
    }
    target = env_first('GATEWAY_HOME_ASSISTANT_TARGET', 'HOME_ASSISTANT_TARGET')
    if target:
        payload['target'] = csv_env(target)
    return payload


def twitch_payload(event: dict[str, Any], scan: ScanResult | None, summary: dict[str, Any] | None, findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        'broadcaster_id': env_first('GATEWAY_TWITCH_BROADCASTER_ID', 'TWITCH_BROADCASTER_ID') or '',
        'sender_id': env_first('GATEWAY_TWITCH_SENDER_ID', 'TWITCH_SENDER_ID') or '',
        'message': truncate(compact_text(event, scan, summary, findings).replace('\n', ' | '), 450),
    }


def device_payload(channel: str, event: dict[str, Any], scan: ScanResult | None, summary: dict[str, Any] | None, findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        'channel': channel,
        'title': event['title'],
        'message': truncate(compact_text(event, scan, summary, findings), 2000),
        'severity': event['severity'],
        'scan_id': event.get('scan_id') or '',
        'metadata': event.get('metadata') or {},
    }


def compact_text(event: dict[str, Any], scan: ScanResult | None, summary: dict[str, Any] | None, findings: list[dict[str, Any]]) -> str:
    lines = [event['title'], '', event['message']]
    if scan and summary:
        lines.extend([
            '',
            f'Scan: {scan.scan_id}',
            f'Project: {scan.project_name}',
            f'Findings: {summary["total_findings"]}',
            f'Production: {summary["production_findings"]}',
            f'Max risk: {summary["max_risk_score"]}',
        ])
    if findings:
        lines.append('')
        lines.append('Top findings:')
        for finding in findings[:5]:
            lines.append(f'- {finding["priority"]} {finding["risk_score"]}: {finding["title"]}')
    return '\n'.join(lines)


def event_fields(scan: ScanResult | None, summary: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not scan or not summary:
        return []
    return [
        {'name': 'Scan', 'value': scan.scan_id, 'inline': True},
        {'name': 'Findings', 'value': str(summary['total_findings']), 'inline': True},
        {'name': 'Production', 'value': str(summary['production_findings']), 'inline': True},
        {'name': 'Max risk', 'value': str(summary['max_risk_score']), 'inline': True},
        {'name': 'Status', 'value': chat_status_label(summary), 'inline': True},
    ]


def severity_color(severity: str) -> int:
    return {'critical': 0xB00020, 'warning': 0xF59E0B, 'info': 0x2563EB}.get(severity, 0x2563EB)


def normalize_channels(channels: list[str] | str | None) -> list[str]:
    if channels is None or channels == '' or channels == 'all':
        return list(SUPPORTED_GATEWAY_CHANNELS)
    if isinstance(channels, str):
        values = [item.strip() for item in channels.split(',') if item.strip()]
    else:
        values = [str(item).strip() for item in channels if str(item).strip()]
    if not values or 'all' in {item.lower() for item in values}:
        return list(SUPPORTED_GATEWAY_CHANNELS)
    normalized = []
    for value in values:
        channel = normalize_channel(value)
        if channel not in SUPPORTED_GATEWAY_CHANNELS:
            raise GatewayError(f'Unsupported gateway channel: {value}')
        if channel not in normalized:
            normalized.append(channel)
    return normalized


def normalize_channel(channel: str) -> str:
    value = str(channel or '').strip().lower().replace('_', '-')
    aliases = {
        'googlechat': 'google-chat',
        'gchat': 'google-chat',
        'homeassistant': 'home-assistant',
        'home-assistant-notify': 'home-assistant',
        'mac': 'macos',
        'mac-os': 'macos',
        'iphone': 'ios',
        'ipad': 'ios',
        'linux': 'ubuntu',
    }
    return aliases.get(value, value)


def parse_gateway_command(text: str) -> tuple[str, str]:
    line = (text or '').strip()
    if not line:
        return 'help', ''
    if line.startswith('/'):
        line = line[1:]
    first, _, rest = line.partition(' ')
    return (first or 'help').lower(), rest.strip()


def gateway_command_help() -> list[dict[str, str]]:
    return [{'command': name, 'description': description} for name, description in SUPPORTED_GATEWAY_COMMANDS.items()]


def scan_message(scan: ScanResult, summary: dict[str, Any]) -> str:
    return (
        f'{scan.project_name} scan {scan.scan_id} completed with '
        f'{summary["total_findings"]} findings, {summary["production_findings"]} production findings, '
        f'and max risk {summary["max_risk_score"]}.'
    )


def severity_from_summary(summary: dict[str, Any]) -> str:
    if int(summary.get('max_risk_score') or 0) >= 85:
        return 'critical'
    if int(summary.get('max_risk_score') or 0) >= 65:
        return 'warning'
    return 'info'


def normalize_severity(value: Any) -> str:
    severity = str(value or 'info').lower()
    return severity if severity in {'info', 'warning', 'critical'} else 'info'


def resolve_gateway_status(publish: bool, summary: dict[str, int], artifacts: dict[str, Any]) -> str:
    if not publish:
        return 'prepared'
    if summary['failed'] and summary['sent']:
        return 'partial'
    if summary['failed'] and not summary['sent']:
        return 'failed'
    if summary['sent']:
        return 'published'
    if summary['dry_run']:
        return 'dry_run'
    if all(not item['configured'] or not item['active'] for item in artifacts.values()):
        return 'not_configured'
    return 'skipped'


def delivery_summary() -> dict[str, int]:
    return {'attempted': 0, 'sent': 0, 'dry_run': 0, 'skipped': 0, 'failed': 0}


def gateway_guardrails() -> list[str]:
    return [
        'The Secure Review messaging gateway is first-party code and does not import external gateway frameworks.',
        'Dry-run is enabled by default; real publishing requires publish=true and channel dry-run disabled.',
        'Inbound commands require signed webhooks, shared secrets, or explicit allowlists.',
        'Gateway commands can read saved scan metadata and sanitized finding summaries, but cannot mutate scanner rules, suppressions, parser code, or repository files.',
        'Gateway events are written to the local gateway event log and mirrored into governance evidence.',
    ]


def allowed_users(channel: str) -> set[str]:
    values = set(csv_env(os.getenv('GATEWAY_ALLOWED_USERS')))
    values.update(csv_env(os.getenv(f'GATEWAY_{channel_env_name(channel)}_ALLOWED_USERS')))
    return {safe_text(value, 200) for value in values if value}


def csv_env(value: str | None) -> list[str]:
    return [item.strip() for item in str(value or '').split(',') if item.strip()]


def email_ssl_enabled() -> bool:
    return parse_bool(env_first('GATEWAY_SMTP_SSL', 'SMTP_SSL'), False)


def load_json_body(raw_body: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(raw_body.decode('utf-8', errors='replace') or '{}')
    except json.JSONDecodeError as exc:
        raise GatewayError('Invalid gateway webhook JSON payload') from exc
    if not isinstance(payload, dict):
        raise GatewayError('Gateway webhook payload must be a JSON object')
    return payload


def first_whatsapp_value(payload: dict[str, Any]) -> dict[str, Any]:
    entry = first_list_item(payload.get('entry'))
    changes = first_list_item(entry.get('changes'))
    value = changes.get('value') if isinstance(changes.get('value'), dict) else payload.get('value')
    return value if isinstance(value, dict) else payload


def first_list_item(value: Any) -> dict[str, Any]:
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return value[0]
    return value if isinstance(value, dict) else {}


def first_value(params: dict[str, list[str]], key: str) -> str:
    values = params.get(key) or []
    return values[0] if values else ''


def gateway_dir():
    return data_dir() / 'messaging-gateway'


def gateway_events_path():
    return gateway_dir() / 'events.jsonl'


def ensure_gateway_dir() -> None:
    gateway_dir().mkdir(parents=True, exist_ok=True)


def event_id(seed: str) -> str:
    digest = hashlib.sha256(seed.encode('utf-8')).hexdigest()[:16]
    return f'gw-{digest}'


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == '':
        return default
    return value.lower() in {'1', 'true', 'yes', 'on'}


def safe_text(value: Any, limit: int) -> str:
    text = str(value or '').replace('\x00', '').strip()
    return text if len(text) <= limit else text[: max(0, limit - 3)] + '...'


def sanitize_metadata(payload: dict[str, Any]) -> dict[str, str]:
    return {safe_text(key, 80): safe_text(value, 500) for key, value in payload.items() if key}


def sanitize_jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {safe_text(key, 120): sanitize_jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_jsonable(item) for item in value[:200]]
    if isinstance(value, str):
        return safe_text(value, 4000)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return safe_text(value, 500)


def slack_escape(value: Any) -> str:
    return str(value or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def redact_email(value: str) -> str:
    if '@' not in value:
        return redact_middle(value)
    name, domain = value.split('@', 1)
    return f'{redact_middle(name)}@{domain}'


def redact_middle(value: str) -> str:
    text = str(value or '')
    if len(text) <= 6:
        return 'configured' if text else ''
    return f'{text[:3]}...{text[-3:]}'
