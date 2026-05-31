from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .consolidation import ensure_consolidated_scan
from .models import ConsolidatedFinding, Finding, ScanResult
from .reporting import format_counts
from .secrets import secret_policy_report
from .scope import finding_scope, is_blocking_secret, is_production_impacting

SEVERITY_ORDER = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
SUPPORTED_REVIEW_EVENTS = {'COMMENT', 'REQUEST_CHANGES', 'APPROVE'}
SUPPORTED_BOT_COMMANDS = {
    '/review': 'review',
    '/full-review': 'full_review',
    '/fix-plan': 'fix_plan',
}


class GitHubIntegrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class GitHubConfig:
    api_url: str
    api_version: str
    repository: str | None
    token: str | None
    pr_number: int | None
    dry_run: bool
    publish_status: bool
    max_inline_comments: int
    min_inline_risk: int
    inline_context_lines: bool
    review_event: str
    status_context: str
    warn_as_failure: bool
    target_url: str | None


def github_config(
    repository: str | None = None,
    pr_number: int | None = None,
    dry_run: bool | None = None,
    publish_status: bool | None = None,
    event: str | None = None,
    max_inline_comments: int | None = None,
    min_inline_risk: int | None = None,
    commit_sha: str | None = None,
) -> GitHubConfig:
    del commit_sha
    return GitHubConfig(
        api_url=os.getenv('GITHUB_API_URL', 'https://api.github.com').rstrip('/'),
        api_version=os.getenv('GITHUB_API_VERSION', '2026-03-10'),
        repository=repository or os.getenv('GITHUB_REPOSITORY') or None,
        token=os.getenv('GITHUB_TOKEN') or os.getenv('GH_TOKEN') or None,
        pr_number=pr_number or int_or_none(os.getenv('GITHUB_PR_NUMBER')),
        dry_run=parse_bool(os.getenv('GITHUB_DRY_RUN'), True) if dry_run is None else dry_run,
        publish_status=parse_bool(os.getenv('GITHUB_PUBLISH_STATUS'), False) if publish_status is None else publish_status,
        max_inline_comments=max_inline_comments or int(os.getenv('GITHUB_MAX_INLINE_COMMENTS', '25')),
        min_inline_risk=min_inline_risk or int(os.getenv('GITHUB_MIN_INLINE_RISK', '40')),
        inline_context_lines=parse_bool(os.getenv('GITHUB_INLINE_CONTEXT_LINES'), False),
        review_event=(event or os.getenv('GITHUB_REVIEW_EVENT', 'COMMENT')).upper(),
        status_context=os.getenv('GITHUB_STATUS_CONTEXT', 'Secure Code Review'),
        warn_as_failure=parse_bool(os.getenv('GITHUB_WARN_AS_FAILURE'), False),
        target_url=os.getenv('GITHUB_STATUS_TARGET_URL') or None,
    )


def github_integration_status() -> dict[str, Any]:
    cfg = github_config()
    return {
        'configured': bool(cfg.repository and cfg.pr_number),
        'repository_configured': bool(cfg.repository),
        'pr_number_configured': bool(cfg.pr_number),
        'token_configured': bool(cfg.token),
        'api_url': cfg.api_url,
        'dry_run_default': cfg.dry_run,
        'fetch_pr_diff_default': parse_bool(os.getenv('GITHUB_FETCH_PR_DIFF'), False),
        'publish_status_default': cfg.publish_status,
        'max_inline_comments': cfg.max_inline_comments,
        'min_inline_risk': cfg.min_inline_risk,
        'review_event': cfg.review_event,
        'webhook_secret_configured': bool(os.getenv('GITHUB_WEBHOOK_SECRET')),
        'webhook_unsigned_allowed': parse_bool(os.getenv('GITHUB_WEBHOOK_ALLOW_UNSIGNED'), False),
        'bot_commands': sorted(SUPPORTED_BOT_COMMANDS),
    }


def build_github_pr_review(
    scan: ScanResult,
    repository: str | None = None,
    pr_number: int | None = None,
    diff_text: str | None = None,
    commit_sha: str | None = None,
    publish: bool = False,
    publish_status: bool | None = None,
    event: str | None = None,
    max_inline_comments: int | None = None,
    min_inline_risk: int | None = None,
) -> dict[str, Any]:
    cfg = github_config(
        repository=repository,
        pr_number=pr_number,
        dry_run=not publish,
        publish_status=publish_status,
        event=event,
        max_inline_comments=max_inline_comments,
        min_inline_risk=min_inline_risk,
        commit_sha=commit_sha,
    )
    validate_repository(cfg.repository)

    fetched_pr: dict[str, Any] | None = None
    should_fetch_diff = publish or parse_bool(os.getenv('GITHUB_FETCH_PR_DIFF'), False)
    if cfg.repository and cfg.pr_number and cfg.token and not diff_text and should_fetch_diff:
        fetched_pr = fetch_pull_request_context(cfg)
        diff_text = fetched_pr.get('diff_text') or None
        commit_sha = commit_sha or fetched_pr.get('head_sha')

    scan = ensure_consolidated_scan(scan)
    diff_map = parse_unified_diff(diff_text or '')
    status = review_status(scan)
    inline_comments, summary_only = build_inline_comments(scan, diff_map, cfg)
    requested_event = resolve_review_event(cfg.review_event, status['status'])
    body = build_review_body(scan, status, inline_comments, summary_only)
    review_payload = {
        'body': body,
        'event': requested_event,
        'comments': [comment['github'] for comment in inline_comments],
    }
    status_payload = build_status_payload(scan, status, commit_sha, cfg)
    artifact = {
        'schema_version': 1,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'repository': cfg.repository,
        'pull_request': cfg.pr_number,
        'head_sha': commit_sha,
        'dry_run': not publish,
        'publish_status_requested': bool(cfg.publish_status if publish_status is None else publish_status),
        'status': status,
        'diff': {
            'provided': bool(diff_text),
            'files': sorted({key[0] for key in diff_map}),
            'mapped_lines': len(diff_map),
            'changed_lines': sum(1 for value in diff_map.values() if value.get('changed')),
            'inline_context_lines': cfg.inline_context_lines,
            'inline_policy': 'changed PR lines only; finding fingerprint must be new since baseline',
        },
        'review': {
            'event': requested_event,
            'body': body,
            'inline_comment_count': len(inline_comments),
            'summary_only_count': len(summary_only),
            'suppressed_count': scan.summary.suppressed_findings,
            'max_inline_comments': cfg.max_inline_comments,
            'min_inline_risk': cfg.min_inline_risk,
            'inline_comments': [comment_without_payload(comment) for comment in inline_comments],
            'summary_only_findings': [finding_summary(finding, reason) for finding, reason in summary_only[:50]],
            'payload': review_payload,
        },
        'commit_status': status_payload,
        'bot_commands': bot_command_help(),
        'publish': {'attempted': False, 'review': None, 'commit_status': None},
    }

    if publish:
        artifact['publish'] = publish_review_and_status(cfg, artifact, status_payload)
    return artifact


def publish_review_and_status(cfg: GitHubConfig, artifact: dict[str, Any], status_payload: dict[str, Any] | None) -> dict[str, Any]:
    if not cfg.repository or not cfg.pr_number:
        raise GitHubIntegrationError('GITHUB_REPOSITORY and GITHUB_PR_NUMBER are required to publish a PR review')
    if not cfg.token:
        raise GitHubIntegrationError('GITHUB_TOKEN or GH_TOKEN is required to publish a PR review')
    publish_result: dict[str, Any] = {'attempted': True, 'review': None, 'commit_status': None}
    review_response = github_api_request(
        cfg,
        'POST',
        f'/repos/{cfg.repository}/pulls/{cfg.pr_number}/reviews',
        payload=artifact['review']['payload'],
    )
    publish_result['review'] = response_summary(review_response)
    if cfg.publish_status and status_payload and artifact.get('head_sha'):
        status_response = github_api_request(
            cfg,
            'POST',
            f'/repos/{cfg.repository}/statuses/{artifact["head_sha"]}',
            payload=status_payload,
        )
        publish_result['commit_status'] = response_summary(status_response)
    return publish_result


def fetch_pull_request_context(cfg: GitHubConfig) -> dict[str, Any]:
    if not cfg.repository or not cfg.pr_number or not cfg.token:
        return {}
    pr_response = github_api_request(cfg, 'GET', f'/repos/{cfg.repository}/pulls/{cfg.pr_number}')
    pr = pr_response.get('body') or {}
    diff_response = github_api_request(
        cfg,
        'GET',
        f'/repos/{cfg.repository}/pulls/{cfg.pr_number}',
        accept='application/vnd.github.v3.diff',
        raw=True,
    )
    head = pr.get('head', {}) if isinstance(pr, dict) else {}
    return {
        'head_sha': head.get('sha'),
        'html_url': pr.get('html_url') if isinstance(pr, dict) else None,
        'diff_text': diff_response.get('body') or '',
    }


def github_api_request(
    cfg: GitHubConfig,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    accept: str = 'application/vnd.github+json',
    raw: bool = False,
) -> dict[str, Any]:
    if not cfg.token:
        raise GitHubIntegrationError('GitHub token is required for API requests')
    url = f'{cfg.api_url}{path}'
    body = json.dumps(payload).encode('utf-8') if payload is not None else None
    headers = {
        'Accept': accept,
        'Authorization': f'Bearer {cfg.token}',
        'User-Agent': 'secure-code-review-assistant',
        'X-GitHub-Api-Version': cfg.api_version,
    }
    if payload is not None:
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            raw_body = response.read().decode('utf-8', errors='replace')
            return {
                'status_code': response.status,
                'headers': dict(response.headers.items()),
                'body': raw_body if raw else json.loads(raw_body) if raw_body.strip() else {},
            }
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode('utf-8', errors='replace')
        raise GitHubIntegrationError(f'GitHub API {method} {path} failed with {exc.code}: {truncate(error_body, 500)}') from exc
    except urllib.error.URLError as exc:
        raise GitHubIntegrationError(f'GitHub API {method} {path} failed: {exc}') from exc


def parse_unified_diff(diff_text: str) -> dict[tuple[str, int], dict[str, Any]]:
    mapping: dict[tuple[str, int], dict[str, Any]] = {}
    current_file: str | None = None
    new_line = 0
    position = 0
    in_hunk = False
    for line in diff_text.splitlines():
        if line.startswith('diff --git '):
            current_file = None
            new_line = 0
            position = 0
            in_hunk = False
            continue
        if line.startswith('+++ '):
            current_file = normalize_diff_path(line[4:].strip())
            continue
        if line.startswith('@@'):
            match = re.search(r'\+(\d+)(?:,(\d+))?', line)
            if not match:
                in_hunk = False
                continue
            new_line = int(match.group(1))
            in_hunk = True
            continue
        if not current_file or not in_hunk:
            continue
        position += 1
        if line.startswith('+') and not line.startswith('+++'):
            mapping[(current_file, new_line)] = {'position': position, 'side': 'RIGHT', 'changed': True}
            new_line += 1
        elif line.startswith(' ') or line == '':
            mapping[(current_file, new_line)] = {'position': position, 'side': 'RIGHT', 'changed': False}
            new_line += 1
        elif line.startswith('-') and not line.startswith('---'):
            continue
        elif line.startswith('\\ No newline at end of file'):
            continue

    return mapping


def build_inline_comments(scan: ScanResult, diff_map: dict[tuple[str, int], dict[str, Any]], cfg: GitHubConfig) -> tuple[list[dict[str, Any]], list[tuple[Finding, str]]]:
    scan = ensure_consolidated_scan(scan)
    inline: list[dict[str, Any]] = []
    summary_only: list[tuple[Finding, str]] = []
    used_locations: set[tuple[str, int]] = set()
    finding_by_id = {finding.id: finding for finding in scan.findings}
    if scan.consolidated_findings:
        for cluster in scan.consolidated_findings:
            finding, comment, reason = select_inline_finding_for_cluster(scan, cluster, finding_by_id, diff_map, cfg, used_locations)
            if comment:
                inline.append(comment)
                used_locations.add((comment['path'], comment['line']))
                continue
            if finding and should_include_summary_only(scan, finding, reason or ''):
                summary_only.append((finding, reason or 'not eligible for diff-scoped inline comment'))
        return inline, summary_only

    for finding in scan.findings:
        reason = inline_rejection_reason(scan, finding, diff_map, cfg, used_locations, finding.risk.score)
        if reason:
            if should_include_summary_only(scan, finding, reason):
                summary_only.append((finding, reason))
            continue
        path = normalize_repo_path(finding.location.path)
        line = int(finding.location.line or 1)
        diff_line = diff_map.get((path, line))
        github_payload = {
            'path': path,
            'position': diff_line['position'],
            'body': inline_comment_body(scan, finding),
        }
        inline.append({'finding': finding, 'line': line, 'path': path, 'position': diff_line['position'], 'changed': diff_line.get('changed', False), 'github': github_payload})
        used_locations.add((path, line))
    return inline, summary_only


def select_inline_finding_for_cluster(
    scan: ScanResult,
    cluster: ConsolidatedFinding,
    finding_by_id: dict[str, Finding],
    diff_map: dict[tuple[str, int], dict[str, Any]],
    cfg: GitHubConfig,
    used_locations: set[tuple[str, int]],
) -> tuple[Finding | None, dict[str, Any] | None, str]:
    representative = finding_by_id.get(cluster.representative_finding_id)
    candidates = [finding_by_id[item] for item in cluster.finding_ids if item in finding_by_id]
    candidates = sorted(candidates, key=lambda item: candidate_sort_key(item, diff_map), reverse=True)
    rejections: list[tuple[Finding, str]] = []
    for finding in candidates:
        risk_score = max(finding.risk.score, cluster.priority_score)
        reason = inline_rejection_reason(scan, finding, diff_map, cfg, used_locations, risk_score)
        if reason:
            rejections.append((finding, reason))
            continue
        path = normalize_repo_path(finding.location.path)
        line = int(finding.location.line or 1)
        diff_line = diff_map[(path, line)]
        github_payload = {
            'path': path,
            'position': diff_line['position'],
            'body': inline_comment_body(scan, finding, cluster=cluster),
        }
        comment = {
            'finding': finding,
            'cluster': cluster,
            'line': line,
            'path': path,
            'position': diff_line['position'],
            'changed': diff_line.get('changed', False),
            'github': github_payload,
        }
        return finding, comment, ''
    for finding, reason in rejections:
        if should_include_summary_only(scan, finding, reason):
            return finding, None, reason
    return representative or (candidates[0] if candidates else None), None, summarize_reasons([reason for _, reason in rejections])


def inline_rejection_reason(
    scan: ScanResult,
    finding: Finding,
    diff_map: dict[tuple[str, int], dict[str, Any]],
    cfg: GitHubConfig,
    used_locations: set[tuple[str, int]],
    risk_score: int,
) -> str:
    if finding.decision == 'suppressed':
        return 'suppressed by in-code annotation'
    if finding.decision != 'open':
        return 'non-open decision'
    if finding.fingerprint not in set(scan.new_findings):
        return 'not marked new since baseline'
    if risk_score < cfg.min_inline_risk:
        return 'below inline risk threshold'
    path = normalize_repo_path(finding.location.path)
    line = int(finding.location.line or 1)
    diff_line = diff_map.get((path, line))
    if not diff_line:
        return 'line not present in PR diff'
    if not cfg.inline_context_lines and not diff_line.get('changed'):
        return 'line is context, not an added PR line'
    if (path, line) in used_locations:
        return 'line already has an inline comment'
    if len(used_locations) >= cfg.max_inline_comments:
        return 'inline comment limit reached'
    return ''


def should_include_summary_only(scan: ScanResult, finding: Finding, reason: str) -> bool:
    del reason
    return finding.fingerprint in set(scan.new_findings)


def candidate_sort_key(finding: Finding, diff_map: dict[tuple[str, int], dict[str, Any]]) -> tuple[int, int, int, int]:
    path = normalize_repo_path(finding.location.path)
    line = int(finding.location.line or 1)
    diff_line = diff_map.get((path, line)) or {}
    return (
        1 if diff_line.get('changed') else 0,
        1 if diff_line else 0,
        finding.risk.score,
        -line,
    )


def summarize_reasons(reasons: list[str]) -> str:
    if not reasons:
        return 'no eligible evidence finding'
    counts: dict[str, int] = {}
    for reason in reasons:
        counts[reason] = counts.get(reason, 0) + 1
    return ', '.join(f'{reason} ({count})' if count > 1 else reason for reason, count in sorted(counts.items()))


def review_status(scan: ScanResult) -> dict[str, Any]:
    secrets = secret_policy_report(scan)
    new_fingerprints = set(scan.new_findings)
    open_findings = [
        finding
        for finding in scan.findings
        if finding.decision == 'open' and finding.fingerprint in new_fingerprints and is_production_impacting(finding)
    ]
    blocking_secrets = [finding for finding in open_findings if is_blocking_secret(finding)]
    p0 = [finding for finding in open_findings if finding.risk.priority == 'P0']
    p1 = [finding for finding in open_findings if finding.risk.priority == 'P1']
    critical = [finding for finding in open_findings if finding.severity == 'CRITICAL']
    high = [finding for finding in open_findings if finding.severity == 'HIGH']
    if blocking_secrets or p0 or critical:
        status = 'fail'
        gate = 'blocked'
        reason = 'Blocking secret, P0, or critical findings require changes before merge.'
    elif p1 or high:
        status = 'warn'
        gate = 'attention_required'
        reason = 'High/P1 findings should be reviewed before merge.'
    else:
        status = 'pass'
        gate = 'passed'
        reason = 'No blocking security findings were detected.'
    return {
        'status': status,
        'gate': gate,
        'reason': reason,
        'open_findings': len(open_findings),
        'total_findings': scan.summary.total_findings,
        'production_findings': scan.summary.production_findings,
        'hygiene_findings': scan.summary.hygiene_findings,
        'scope_counts': dict(scan.summary.scope_counts),
        'p0': len(p0),
        'p1': len(p1),
        'critical': len(critical),
        'high': len(high),
        'secret_policy_status': 'blocked' if blocking_secrets else secrets['status'],
        'blocking_secret_findings': len(blocking_secrets),
        'new_finding_scope': True,
    }


def build_review_body(scan: ScanResult, status: dict[str, Any], inline: list[dict[str, Any]], summary_only: list[tuple[Finding, str]]) -> str:
    lines = [
        '## Secure Code Review PR Review',
        '',
        f"Gate: **{status['gate']}** ({status['status']})",
        f"Reason: {status['reason']}",
        '',
        f'Findings: **{scan.summary.total_findings}** across **{scan.summary.files_scanned} files**.',
        f'Production/gate findings: **{scan.summary.production_findings}** | Hygiene findings: **{scan.summary.hygiene_findings}** | Scopes: **{format_counts(scan.summary.scope_counts)}**',
        f'Production max risk: **{scan.summary.max_risk_score}** | Production average risk: **{scan.summary.avg_risk_score}** | Production priorities: **{format_counts(scan.summary.priorities)}**',
        f'Inline comments prepared: **{len(inline)}** | Summary-only findings: **{len(summary_only)}** | In-code suppressions: **{scan.summary.suppressed_findings}**',
        'Inline scope: **new findings on added PR lines only**.',
        '',
    ]
    append_diff_scoped_review(lines, inline, summary_only)
    return '\n'.join(lines).strip() + '\n'


def append_diff_scoped_review(lines: list[str], inline: list[dict[str, Any]], summary_only: list[tuple[Finding, str]]) -> None:
    lines.extend([
        '### Inline Comments',
        '',
    ])
    if not inline:
        lines.append('No inline comments were prepared for added PR lines.')
    else:
        lines.extend(['| Priority | Rule | Location | Finding |', '| --- | --- | --- | --- |'])
        for item in inline:
            finding = item['finding']
            cluster = item.get('cluster')
            cluster_note = f' / {cluster.cluster_id}' if cluster else ''
            location = f'{item["path"]}:{item["line"]}'
            title = truncate(finding.title, 160).replace('|', '\\|')
            lines.append(f'| {finding.risk.priority} {finding.risk.score}{cluster_note} | `{finding.rule_id}` | `{location}` | {title} |')
    reason_counts: dict[str, int] = {}
    for _, reason in summary_only:
        reason_counts[reason] = reason_counts.get(reason, 0) + 1
    if reason_counts:
        lines.extend(['', '### Summary-Only Reasons', ''])
        for reason, count in sorted(reason_counts.items()):
            lines.append(f'- {reason}: {count}')


def inline_comment_body(scan: ScanResult, finding: Finding, cluster: ConsolidatedFinding | None = None) -> str:
    cwe = ', '.join(finding.cwe) if finding.cwe else 'n/a'
    owasp = ', '.join(finding.owasp) if finding.owasp else 'n/a'
    guidance = finding.fix.guidance[:3]
    lines = [
        f'**[{finding.risk.priority} / {finding.risk.score}] {finding.title}**',
        '',
        f'- Scan: `{scan.scan_id}`',
        f'- Source: `{finding.source}` / `{finding.rule_id}`',
        f'- Scope: `{finding_scope(finding)}`',
        f'- Severity: `{finding.severity}` | Confidence: `{finding.confidence}`',
        f'- CWE: {cwe}',
        f'- OWASP: {owasp}',
    ]
    if cluster:
        lines.extend([
            f'- Consolidated priority: `{cluster.priority}` / `{cluster.priority_score}`',
            f'- Tool agreement: `{cluster.agreement_count}` source(s), `{cluster.raw_count}` raw finding(s)',
            f'- Cluster: `{cluster.cluster_id}`',
        ])
    lines.extend([
        '',
        truncate(finding.message, 500),
        '',
        f'**Suggested fix:** {truncate(finding.fix.summary, 500)}',
    ])
    for item in guidance:
        lines.append(f'- {truncate(item, 220)}')
    return '\n'.join(lines).strip()


def build_status_payload(scan: ScanResult, status: dict[str, Any], commit_sha: str | None, cfg: GitHubConfig) -> dict[str, Any] | None:
    if not commit_sha:
        return None
    state = 'success'
    if status['status'] == 'fail' or (status['status'] == 'warn' and cfg.warn_as_failure):
        state = 'failure'
    description = truncate(f"{status['gate']}: {status['reason']}", 140)
    payload = {'state': state, 'context': cfg.status_context, 'description': description}
    target_url = cfg.target_url or scan_target_url(scan)
    if target_url:
        payload['target_url'] = target_url
    return payload


def scan_target_url(scan: ScanResult) -> str | None:
    base = os.getenv('PUBLIC_BASE_URL', '').rstrip('/')
    if not base:
        return None
    return f'{base}/api/scans/{scan.scan_id}'


def resolve_review_event(configured: str, status: str) -> str:
    event = configured.upper()
    if event == 'AUTO':
        return 'REQUEST_CHANGES' if status == 'fail' else 'COMMENT'
    if event in SUPPORTED_REVIEW_EVENTS:
        return event
    return 'COMMENT'


def verify_github_webhook_signature(body: bytes, signature_header: str | None, secret: str | None = None) -> dict[str, Any]:
    configured_secret = secret if secret is not None else os.getenv('GITHUB_WEBHOOK_SECRET', '')
    allow_unsigned = parse_bool(os.getenv('GITHUB_WEBHOOK_ALLOW_UNSIGNED'), False)
    if not configured_secret:
        return {'valid': allow_unsigned, 'configured': False, 'reason': 'unsigned webhook allowed' if allow_unsigned else 'GITHUB_WEBHOOK_SECRET is not configured'}
    if not signature_header or not signature_header.startswith('sha256='):
        return {'valid': False, 'configured': True, 'reason': 'missing or unsupported signature header'}
    digest = hmac.new(configured_secret.encode('utf-8'), body, hashlib.sha256).hexdigest()
    expected = f'sha256={digest}'
    return {'valid': hmac.compare_digest(expected, signature_header), 'configured': True, 'reason': 'signature verified' if hmac.compare_digest(expected, signature_header) else 'signature mismatch'}


def handle_github_webhook(event: str, payload: dict[str, Any]) -> dict[str, Any]:
    action = str(payload.get('action') or '')
    repository = payload.get('repository', {}) if isinstance(payload.get('repository'), dict) else {}
    repo_full_name = repository.get('full_name')
    result: dict[str, Any] = {
        'event': event,
        'action': action,
        'repository': repo_full_name,
        'accepted': False,
        'command': None,
        'pull_request': None,
        'reason': 'event ignored',
    }
    if event == 'pull_request' and action in {'opened', 'reopened', 'synchronize', 'ready_for_review'}:
        pr = payload.get('pull_request', {}) if isinstance(payload.get('pull_request'), dict) else {}
        result.update({'accepted': True, 'command': 'review', 'pull_request': pr.get('number'), 'reason': 'pull request event accepted for review'})
        return result
    if event in {'issue_comment', 'pull_request_review_comment'} and action == 'created':
        body = comment_body(payload)
        command = parse_bot_command(body)
        if command:
            pr_number = pull_request_number_from_payload(payload)
            result.update({'accepted': True, 'command': command['command'], 'pull_request': pr_number, 'reason': command['reason'], 'args': command.get('args', '')})
            return result
        result['reason'] = 'no supported bot command found'
        return result
    return result


def parse_bot_command(text: str) -> dict[str, str] | None:
    for raw_line in (text or '').splitlines():
        line = raw_line.strip()
        if not line:
            continue
        first, _, rest = line.partition(' ')
        command = SUPPORTED_BOT_COMMANDS.get(first)
        if command:
            return {'command': command, 'args': rest.strip(), 'reason': f'{first} command accepted'}
        return None
    return None


def bot_command_help() -> list[dict[str, str]]:
    return [
        {'command': '/review', 'description': 'Run or publish a standard changed-lines security review.'},
        {'command': '/full-review', 'description': 'Request a full repository security review for this PR branch.'},
        {'command': '/fix-plan', 'description': 'Generate a remediation plan without applying patches.'},
    ]


def comment_body(payload: dict[str, Any]) -> str:
    comment = payload.get('comment', {}) if isinstance(payload.get('comment'), dict) else {}
    return str(comment.get('body') or payload.get('body') or '')


def pull_request_number_from_payload(payload: dict[str, Any]) -> int | None:
    pr = payload.get('pull_request') if isinstance(payload.get('pull_request'), dict) else None
    if pr and pr.get('number'):
        return int(pr['number'])
    issue = payload.get('issue') if isinstance(payload.get('issue'), dict) else None
    if issue and 'pull_request' in issue and issue.get('number'):
        return int(issue['number'])
    return None


def finding_summary(finding: Finding, reason: str) -> dict[str, Any]:
    return {
        'id': finding.id,
        'reason': reason,
        'source': finding.source,
        'rule_id': finding.rule_id,
        'title': finding.title,
        'severity': finding.severity,
        'risk_score': finding.risk.score,
        'priority': finding.risk.priority,
        'scope': finding_scope(finding),
        'location': {'path': finding.location.path, 'line': finding.location.line},
        'message': finding.message,
    }


def comment_without_payload(comment: dict[str, Any]) -> dict[str, Any]:
    finding = comment['finding']
    return {
        'finding_id': finding.id,
        'source': finding.source,
        'rule_id': finding.rule_id,
        'title': finding.title,
        'severity': finding.severity,
        'risk_score': finding.risk.score,
        'priority': finding.risk.priority,
        'scope': finding_scope(finding),
        'path': comment['path'],
        'line': comment['line'],
        'position': comment['position'],
        'changed': comment['changed'],
        'cluster_id': comment.get('cluster').cluster_id if comment.get('cluster') else '',
    }


def response_summary(response: dict[str, Any]) -> dict[str, Any]:
    body = response.get('body')
    return {
        'status_code': response.get('status_code'),
        'id': body.get('id') if isinstance(body, dict) else None,
        'html_url': body.get('html_url') if isinstance(body, dict) else None,
        'url': body.get('url') if isinstance(body, dict) else None,
    }


def validate_repository(repository: str | None) -> None:
    if repository is None:
        return
    if not re.match(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$', repository):
        raise GitHubIntegrationError('GitHub repository must use owner/repo format')


def normalize_diff_path(path: str) -> str | None:
    if path == '/dev/null':
        return None
    if path.startswith('b/') or path.startswith('a/'):
        path = path[2:]
    return normalize_repo_path(path)


def normalize_repo_path(path: str) -> str:
    value = str(path or '').replace('\\', '/').strip()
    if value.startswith('./'):
        value = value[2:]
    return value


def truncate(value: str, limit: int) -> str:
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
