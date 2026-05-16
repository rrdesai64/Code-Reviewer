from __future__ import annotations

import html
from .models import ScanResult


def markdown_report(scan: ScanResult) -> str:
    lines = [
        f'# Secure Code Review Report: {scan.project_name}', '',
        f'- Scan ID: `{scan.scan_id}`', f'- Target: `{scan.target_path}`',
        f'- Files scanned: {scan.summary.files_scanned}',
        f'- Findings: {scan.summary.total_findings} total, {scan.summary.high} high, {scan.summary.medium} medium, {scan.summary.low} low',
        f'- New since baseline: {len(scan.new_findings)}', f'- Resolved since baseline: {len(scan.resolved_findings)}', '', '## Findings',
    ]
    if not scan.findings:
        lines.append('No findings were reported by the configured scanners.')
    for finding in scan.findings:
        lines.extend(['', f'### [{finding.severity}] {finding.title}', f'- ID: `{finding.id}`',
            f'- Tool: `{finding.source}` / `{finding.rule_id}`', f'- Location: `{finding.location.path}:{finding.location.line}`',
            f'- Confidence: {finding.confidence}', f'- CWE: {", ".join(finding.cwe) if finding.cwe else "n/a"}',
            f'- OWASP: {", ".join(finding.owasp) if finding.owasp else "n/a"}', f'- Decision: {finding.decision}', '',
            finding.message, '', '**Explanation**', '', finding.explanation, '', '**Suggested fix**', '', finding.fix.summary])
        for item in finding.fix.guidance:
            lines.append(f'- {item}')
    return '\n'.join(lines) + '\n'


def html_report(scan: ScanResult) -> str:
    escaped = html.escape(markdown_report(scan))
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Secure Code Review Report</title><style>body{font-family:Inter,Segoe UI,Arial,sans-serif;margin:40px;color:#18202a}pre{white-space:pre-wrap;line-height:1.55}</style></head><body><pre>' + escaped + '</pre></body></html>'


def github_pr_comment(scan: ScanResult) -> str:
    lines = ['## Secure Code Review Summary', '', f'**{scan.summary.total_findings} findings** across **{scan.summary.files_scanned} files**.',
        f'New: **{len(scan.new_findings)}** | Resolved: **{len(scan.resolved_findings)}** | Unchanged: **{len(scan.unchanged_findings)}**', '',
        '| Severity | Rule | Location | Message |', '| --- | --- | --- | --- |']
    for finding in scan.findings[:25]:
        location = f'{finding.location.path}:{finding.location.line}'
        message = finding.message.replace('|', '\|')[:180]
        lines.append(f'| {finding.severity} | `{finding.rule_id}` | `{location}` | {message} |')
    if len(scan.findings) > 25:
        lines.append(f'\nShowing 25 of {len(scan.findings)} findings. See SARIF/report artifact for the full result.')
    return '\n'.join(lines) + '\n'
