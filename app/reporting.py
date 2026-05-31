from __future__ import annotations

import html
from .consolidation import ensure_consolidated_scan, top_consolidated_findings
from .models import ConsolidatedFinding, Finding, ScanResult
from .scope import finding_scope, hygiene_findings, production_gate_findings


def markdown_report(scan: ScanResult) -> str:
    scan = ensure_consolidated_scan(scan)
    production = production_gate_findings(scan.findings)
    hygiene = hygiene_findings(scan.findings)
    lines = [
        f'# Secure Code Review Report: {scan.project_name}', '',
        f'- Scan ID: `{scan.scan_id}`', f'- Target: `{scan.target_path}`',
        f'- Files scanned: {scan.summary.files_scanned}',
        f'- Findings: {scan.summary.total_findings} total, {scan.summary.high} high, {scan.summary.medium} medium, {scan.summary.low} low',
        f'- Production/gate findings: {scan.summary.production_findings}',
        f'- Test/docs/example hygiene findings: {scan.summary.hygiene_findings}',
        f'- Scope counts: {format_counts(scan.summary.scope_counts)}',
        f'- Production max risk score: {scan.summary.max_risk_score}',
        f'- Production average risk score: {scan.summary.avg_risk_score}',
        f'- Production risk tiers: {format_counts(scan.summary.risk_tiers)}',
        f'- Production priorities: {format_counts(scan.summary.priorities)}',
        f'- Consolidated priority items: {scan.summary.consolidated_findings}',
        f'- Cross-tool agreement clusters: {scan.summary.cross_tool_clusters}',
        f'- Consolidated priorities: {format_counts(scan.summary.consolidated_priorities)}',
        f'- All-findings max risk score: {scan.summary.all_max_risk_score}',
        f'- All-findings priorities: {format_counts(scan.summary.all_priorities)}',
        f'- New since baseline: {len(scan.new_findings)}', f'- Resolved since baseline: {len(scan.resolved_findings)}',
        '', '## Top Consolidated Priorities',
    ]
    consolidated = top_consolidated_findings(scan, limit=10)
    if not consolidated:
        lines.append('No consolidated priority items were generated.')
    for item in consolidated:
        append_consolidated_finding(lines, item)
    lines.extend([
        '',
        '## Production / Gate Findings',
    ])
    if not production:
        lines.append('No production-impacting findings were reported by the configured scanners.')
    for finding in production:
        append_finding(lines, finding)
    lines.append('')
    lines.append('## Test / Docs / Example Hygiene Findings')
    if not hygiene:
        lines.append('No non-production hygiene findings were reported.')
    else:
        lines.append('These findings are scanned and retained, but they do not drive the production score or blocking gate unless they are high-confidence secrets.')
    for finding in hygiene:
        append_finding(lines, finding)
    return '\n'.join(lines).rstrip() + '\n'


def append_consolidated_finding(lines: list[str], item: ConsolidatedFinding) -> None:
    factors = ', '.join(f'{factor.label} {format_points(factor.points)}' for factor in item.factors) or 'n/a'
    line_range = str(item.line_start) if item.line_start == item.line_end else f'{item.line_start}-{item.line_end}'
    tools = ', '.join(item.sources) or 'n/a'
    rules = ', '.join(item.rules[:6]) or 'n/a'
    if len(item.rules) > 6:
        rules += f', +{len(item.rules) - 6} more'
    lines.extend([
        '',
        f'### [{item.priority} / {item.priority_score}] {item.title}',
        f'- Cluster ID: `{item.cluster_id}`',
        f'- Representative finding: `{item.representative_finding_id}`',
        f'- Location: `{item.path}:{line_range}`',
        f'- Agreement: {item.agreement_count} tool(s), {item.raw_count} raw finding(s)',
        f'- Tools: {tools}',
        f'- Rules: {rules}',
        f'- Severity: {item.severity}',
        f'- Confidence: {item.confidence}',
        f'- CWE: {", ".join(item.cwe) if item.cwe else "n/a"}',
        f'- Sink: {item.sink or "n/a"}',
        f'- Recommended action: {item.recommended_action}',
        f'- Priority factors: {factors}',
    ])


def append_finding(lines: list[str], finding: Finding) -> None:
    factors = ', '.join(f'{factor.label} {format_points(factor.points)}' for factor in finding.risk.factors) or 'n/a'
    lines.extend([
        '', f'### [{finding.risk.priority} / {finding.risk.score}] {finding.title}', f'- ID: `{finding.id}`',
        f'- Tool: `{finding.source}` / `{finding.rule_id}`', f'- Location: `{finding.location.path}:{finding.location.line}`',
        f'- Scope: {finding_scope(finding)}', f'- Severity: {finding.severity}', f'- Risk tier: {finding.risk.tier}',
        f'- Recommended action: {finding.risk.recommended_action}', f'- Risk factors: {factors}', f'- Confidence: {finding.confidence}',
        f'- CWE: {", ".join(finding.cwe) if finding.cwe else "n/a"}', f'- OWASP: {", ".join(finding.owasp) if finding.owasp else "n/a"}',
        f'- Decision: {finding.decision}', '', finding.message, '', '**Explanation**', '', finding.explanation, '', '**Suggested fix**', '', finding.fix.summary,
    ])
    for item in finding.fix.guidance:
        lines.append(f'- {item}')


def html_report(scan: ScanResult) -> str:
    escaped = html.escape(markdown_report(scan))
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Secure Code Review Report</title><style>body{font-family:Inter,Segoe UI,Arial,sans-serif;margin:40px;color:#18202a}pre{white-space:pre-wrap;line-height:1.55}</style></head><body><pre>' + escaped + '</pre></body></html>'


def github_pr_comment(scan: ScanResult) -> str:
    scan = ensure_consolidated_scan(scan)
    lines = ['## Secure Code Review Summary', '', f'**{scan.summary.total_findings} findings** across **{scan.summary.files_scanned} files**.',
        f'Production/gate findings: **{scan.summary.production_findings}** | Hygiene findings: **{scan.summary.hygiene_findings}** | Scopes: **{format_counts(scan.summary.scope_counts)}**',
        f'Production max risk: **{scan.summary.max_risk_score}** | Production average risk: **{scan.summary.avg_risk_score}** | Production priorities: **{format_counts(scan.summary.priorities)}**',
        f'Consolidated priorities: **{scan.summary.consolidated_findings}** | Cross-tool agreement clusters: **{scan.summary.cross_tool_clusters}** | Priority mix: **{format_counts(scan.summary.consolidated_priorities)}**',
        f'All-findings max risk: **{scan.summary.all_max_risk_score}** | All priorities: **{format_counts(scan.summary.all_priorities)}**',
        f'New: **{len(scan.new_findings)}** | Resolved: **{len(scan.resolved_findings)}** | Unchanged: **{len(scan.unchanged_findings)}**', '',
        '| Priority | Agreement | Severity | Tools | Rule/CWE | Location | Finding |', '| --- | --- | --- | --- | --- | --- | --- |']
    rows = top_consolidated_findings(scan, limit=25)
    for item in rows:
        line_range = str(item.line_start) if item.line_start == item.line_end else f'{item.line_start}-{item.line_end}'
        location = f'{item.path}:{line_range}'
        rule = ', '.join(item.cwe or item.rules[:2]) or item.semantic_key
        tools = ', '.join(item.sources)
        title = item.title.replace('|', r'\|')[:180]
        lines.append(f'| {item.priority} {item.priority_score} | {item.agreement_count} tool(s) / {item.raw_count} raw | {item.severity} | {tools} | `{rule}` | `{location}` | {title} |')
    if len(scan.consolidated_findings) > 25:
        lines.append(f'\nShowing 25 of {len(scan.consolidated_findings)} consolidated priorities. Raw findings remain in SARIF/report artifacts.')
    return '\n'.join(lines) + '\n'


def format_points(points: int) -> str:
    return f'+{points}' if points > 0 else str(points)


def format_counts(values: dict[str, int]) -> str:
    return ', '.join(f'{key}={value}' for key, value in values.items()) if values else 'none'
