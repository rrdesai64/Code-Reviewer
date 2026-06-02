from __future__ import annotations

import hashlib
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from .models import ConsolidatedFinding, ConsolidatedFindingEvidence, Finding, RiskFactor, ScanResult
from .risk import CONFIDENCE_POINTS, SENSITIVE_CWES, SEVERITY_POINTS, action_for_tier, priority_for_score, tier_for_score
from .scope import apply_finding_scope, is_production_impacting, normalize_path

SCHEMA_VERSION = 'finding-consolidation-v1'
LINE_WINDOW = 3
MAX_CLUSTER_LINE_SPAN = 12
SEVERITY_ORDER = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
CONFIDENCE_ORDER = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
PRIORITY_ORDER = {'P0': 4, 'P1': 3, 'P2': 2, 'P3': 1, 'P4': 0}
PRIORITY_SCORE_FLOORS = {'P0': 100, 'P1': 65, 'P2': 40, 'P3': 15, 'P4': 0}

CWE_SINKS = {
    'CWE-22': 'path-traversal',
    'CWE-78': 'command-injection',
    'CWE-79': 'xss',
    'CWE-89': 'sql-injection',
    'CWE-94': 'code-injection',
    'CWE-120': 'memory-corruption',
    'CWE-200': 'information-disclosure',
    'CWE-287': 'authentication',
    'CWE-295': 'tls-validation',
    'CWE-306': 'missing-authentication',
    'CWE-319': 'cleartext-transport',
    'CWE-326': 'weak-crypto',
    'CWE-327': 'weak-crypto',
    'CWE-352': 'csrf',
    'CWE-434': 'unrestricted-file-upload',
    'CWE-502': 'deserialization',
    'CWE-522': 'credential-storage',
    'CWE-798': 'hardcoded-secret',
    'CWE-918': 'ssrf',
}
SINK_CWES = {sink: cwe for cwe, sink in CWE_SINKS.items()}
SINK_PATTERNS = (
    ('sql-injection', re.compile(r'\b(sql injection|sqli|tainted sql|raw sql|execute a sql|dynamic sql|sql query)\b', re.I)),
    ('command-injection', re.compile(r'\b(command injection|shell injection|os command|subprocess|shell=true)\b', re.I)),
    ('xss', re.compile(r'\b(xss|cross-site scripting|unescaped html|html injection)\b', re.I)),
    ('path-traversal', re.compile(r'\b(path traversal|directory traversal|zip slip)\b', re.I)),
    ('deserialization', re.compile(r'\b(deserialization|pickle|yaml\.load|object injection)\b', re.I)),
    ('ssrf', re.compile(r'\b(ssrf|server-side request forgery)\b', re.I)),
    ('hardcoded-secret', re.compile(r'\b(hardcoded secret|hardcoded password|api[_ -]?key|private key|credential|token)\b', re.I)),
    ('weak-crypto', re.compile(r'\b(weak crypto|md5|sha1|insecure random|broken cryptographic)\b', re.I)),
    ('cleartext-transport', re.compile(r'\b(cleartext|plaintext|http url|insecure transport)\b', re.I)),
    ('csrf', re.compile(r'\b(csrf|cross-site request forgery)\b', re.I)),
    ('unrestricted-file-upload', re.compile(r'\b(unrestricted file upload|file upload)\b', re.I)),
)


def ensure_consolidated_scan(scan: ScanResult) -> ScanResult:
    if not scan.consolidated_findings and scan.findings:
        return consolidate_scan(scan)
    if scan.consolidated_findings:
        if consolidated_finding_ids(scan) != current_finding_ids(scan):
            return consolidate_scan(scan)
        update_summary(scan)
    return scan


def consolidate_scan(scan: ScanResult) -> ScanResult:
    scan.findings = [apply_finding_scope(finding) for finding in scan.findings]
    clusters: list[_Cluster] = []
    for finding in sorted(scan.findings, key=finding_sort_key):
        item = finding_item(finding)
        match = next((cluster for cluster in clusters if cluster_accepts(cluster, item)), None)
        if match is None:
            clusters.append(_Cluster(items=[item]))
        else:
            match.items.append(item)

    scan.consolidated_findings = sorted(
        [build_consolidated_finding(cluster) for cluster in clusters],
        key=lambda item: (-item.priority_score, -item.agreement_count, -SEVERITY_ORDER.get(item.severity, 0), item.path, item.line_start, item.semantic_key),
    )
    update_summary(scan)
    return scan


def consolidated_findings_report(scan: ScanResult, limit: int | None = None) -> dict[str, Any]:
    scan = ensure_consolidated_scan(scan)
    clusters = scan.consolidated_findings
    if limit is not None:
        clusters = clusters[: max(0, limit)]
    cross_tool = [cluster for cluster in scan.consolidated_findings if cluster.agreement_count > 1]
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'raw_findings': len(scan.findings),
        'consolidated_findings': len(scan.consolidated_findings),
        'duplicate_reduction': max(0, len(scan.findings) - len(scan.consolidated_findings)),
        'cross_tool_clusters': len(cross_tool),
        'top_priority_score': scan.summary.top_consolidated_priority_score,
        'priority_counts': dict(scan.summary.consolidated_priorities),
        'scoring': {
            'severity': 'highest normalized scanner/catalog severity in the cluster',
            'confidence': 'highest normalized tool confidence in the cluster',
            'tool_agreement': f'distinct scanner sources add up to 24 points using a {LINE_WINDOW}-line semantic match window',
            'raw_risk_floor': 'cluster score never drops below the highest underlying finding risk score',
            'guardrail': 'raw findings remain stored as evidence; consolidation is presentation and prioritization only',
        },
        'clusters': [cluster.model_dump(mode='json') for cluster in clusters],
    }


def update_summary(scan: ScanResult) -> None:
    priorities = Counter(cluster.priority for cluster in scan.consolidated_findings)
    scan.summary.consolidated_findings = len(scan.consolidated_findings)
    scan.summary.cross_tool_clusters = sum(1 for cluster in scan.consolidated_findings if cluster.agreement_count > 1)
    scan.summary.consolidated_priorities = dict(sorted(priorities.items()))
    scan.summary.top_consolidated_priority_score = max((cluster.priority_score for cluster in scan.consolidated_findings), default=0)
    scan.summary.suppressed_findings = sum(1 for finding in scan.findings if finding.decision == 'suppressed')
    scan.summary.invalid_suppression_annotations = len(scan.invalid_suppressions)


def current_finding_ids(scan: ScanResult) -> set[str]:
    return {finding.id for finding in scan.findings}


def consolidated_finding_ids(scan: ScanResult) -> set[str]:
    return {finding_id for cluster in scan.consolidated_findings for finding_id in cluster.finding_ids}


def top_consolidated_findings(scan: ScanResult, limit: int = 10) -> list[ConsolidatedFinding]:
    scan = ensure_consolidated_scan(scan)
    return scan.consolidated_findings[: max(0, limit)]


class _Cluster:
    def __init__(self, items: list[dict[str, Any]]) -> None:
        self.items = items

    @property
    def path_key(self) -> str:
        return self.items[0]['path_key']

    @property
    def line_start(self) -> int:
        return min(item['line_start'] for item in self.items)

    @property
    def line_end(self) -> int:
        return max(item['line_end'] for item in self.items)

    @property
    def tokens(self) -> set[str]:
        return set().union(*(item['tokens'] for item in self.items))

    @property
    def has_parser_error(self) -> bool:
        return any(item['parser_error'] for item in self.items)


def finding_sort_key(finding: Finding) -> tuple[str, int, int, str, str]:
    start, end = finding_lines(finding)
    return (path_key(finding.location.path), start, end, semantic_key_for_finding(finding), finding.id)


def finding_item(finding: Finding) -> dict[str, Any]:
    start, end = finding_lines(finding)
    sink = infer_sink(finding)
    cwe = normalize_cwes(finding.cwe)
    tokens = semantic_tokens(cwe, sink, finding)
    return {
        'finding': finding,
        'path_key': path_key(finding.location.path),
        'path': normalize_path(finding.location.path),
        'line_start': start,
        'line_end': end,
        'sink': sink,
        'cwe': cwe,
        'tokens': tokens,
        'parser_error': is_parser_error_finding(finding),
        'semantic_key': semantic_key(cwe, sink, finding),
    }


def cluster_accepts(cluster: _Cluster, item: dict[str, Any]) -> bool:
    if cluster.path_key != item['path_key']:
        return False
    if cluster.has_parser_error != item['parser_error']:
        return False
    if item['path_key'] in {'', 'unknown'} and any(existing['finding'].source != item['finding'].source for existing in cluster.items):
        return False
    if not semantic_overlap(cluster.tokens, item['tokens']):
        return False
    start = min(cluster.line_start, item['line_start'])
    end = max(cluster.line_end, item['line_end'])
    if end - start > MAX_CLUSTER_LINE_SPAN:
        return False
    return line_ranges_close(cluster.line_start, cluster.line_end, item['line_start'], item['line_end'])


def semantic_overlap(left: set[str], right: set[str]) -> bool:
    return bool(left and right and left.intersection(right))


def line_ranges_close(left_start: int, left_end: int, right_start: int, right_end: int) -> bool:
    if left_start <= right_end and right_start <= left_end:
        return True
    return min(abs(right_start - left_end), abs(left_start - right_end)) <= LINE_WINDOW


def build_consolidated_finding(cluster: _Cluster) -> ConsolidatedFinding:
    findings = [item['finding'] for item in cluster.items]
    representative = max(findings, key=lambda item: (item.risk.score, SEVERITY_ORDER.get(item.severity, 0), CONFIDENCE_ORDER.get(confidence(item), 0)))
    sources = sorted({finding.source for finding in findings})
    rules = sorted({finding.rule_id for finding in findings})
    cwes = sorted(set().union(*(set(item['cwe']) for item in cluster.items)))
    sink = primary_sink(cluster.items, cwes)
    severity = max((finding.severity for finding in findings), key=lambda value: SEVERITY_ORDER.get(value, 0))
    consolidated_confidence = max((confidence(finding) for finding in findings), key=lambda value: CONFIDENCE_ORDER.get(value, 0))
    semantic = semantic_key(cwes, sink, representative)
    factors = score_factors(findings, severity, consolidated_confidence, len(sources), cwes, sink)
    effective_priority = effective_cluster_priority(findings)
    priority_score = max(
        max((finding.risk.score for finding in findings), default=0),
        clamp_score(sum(factor.points for factor in factors)),
        PRIORITY_SCORE_FLOORS.get(effective_priority, 0),
    )
    risk_tier = tier_for_score(priority_score)
    return ConsolidatedFinding(
        cluster_id=cluster_id(cluster.path_key, cluster.line_start, cluster.line_end, semantic),
        title=representative.title,
        path=representative.location.path,
        line_start=cluster.line_start,
        line_end=cluster.line_end,
        semantic_key=semantic,
        cwe=cwes,
        sink=sink,
        severity=severity,
        confidence=consolidated_confidence,
        priority_score=priority_score,
        priority=effective_priority if priority_rank(effective_priority) > priority_rank(priority_for_score(priority_score)) else priority_for_score(priority_score),
        risk_tier=risk_tier,
        recommended_action=action_for_tier(risk_tier) if any(is_production_impacting(finding) for finding in findings) else 'Track as hygiene unless review confirms production exposure or a real secret.',
        agreement_count=len(sources),
        tool_agreement_score=tool_agreement_score(len(sources)),
        raw_count=len(findings),
        sources=sources,
        rules=rules,
        finding_ids=[finding.id for finding in findings],
        representative_finding_id=representative.id,
        evidence=[evidence_for(item, sink) for item in cluster.items],
        factors=factors,
    )


def score_factors(findings: list[Finding], severity: str, consolidated_confidence: str, agreement_count: int, cwes: list[str], sink: str) -> list[RiskFactor]:
    factors = [
        RiskFactor(name='severity', label='Cluster severity', points=SEVERITY_POINTS.get(severity, 4), detail=severity),
        RiskFactor(name='confidence', label='Tool confidence', points=CONFIDENCE_POINTS.get(consolidated_confidence, 3), detail=consolidated_confidence),
    ]
    agreement_points = min(24, max(0, agreement_count - 1) * 8)
    if agreement_points:
        factors.append(RiskFactor(name='tool-agreement', label='Independent tool agreement', points=agreement_points, detail=f'{agreement_count} scanner sources reported this same semantic issue.'))
    if any(cwe.upper() in SENSITIVE_CWES for cwe in cwes):
        factors.append(RiskFactor(name='weakness', label='High-impact CWE', points=10, detail=', '.join(cwes)))
    if any((finding.scanner_metadata or {}).get('catalog_rule_id') for finding in findings):
        factors.append(RiskFactor(name='catalog', label='Catalog-mapped rule', points=6, detail='At least one scanner finding maps to the Secure Review catalog.'))
    if sink:
        factors.append(RiskFactor(name='sink', label='Shared vulnerability sink', points=4, detail=sink))
    if any((finding.scanner_metadata or {}).get('source_reachability_context') == 'untrusted-entrypoint' for finding in findings):
        factors.append(RiskFactor(name='reachability', label='Untrusted entrypoint context', points=14, detail='At least one evidence finding is near an HTTP/request entrypoint and untrusted input signal.'))
    elif any((finding.scanner_metadata or {}).get('request_handler_context') == 'true' for finding in findings):
        factors.append(RiskFactor(name='reachability', label='Request handler context', points=8, detail='At least one evidence finding is in or near request handling code.'))
    if any((finding.scanner_metadata or {}).get('changed_file_context') == 'true' for finding in findings):
        factors.append(RiskFactor(name='change-context', label='Changed file context', points=4, detail='At least one evidence finding is new or in a changed file.'))
    if any(finding.dataflow.confirmed_exploitable for finding in findings):
        factors.append(RiskFactor(name='confirmed-exploitable', label='Confirmed dynamic exploitability', points=100, detail='At least one evidence finding was dynamically confirmed exploitable.'))
    if not any(is_production_impacting(finding) for finding in findings):
        factors.append(RiskFactor(name='scope', label='Non-production scope', points=-45, detail='All evidence in this cluster is non-production hygiene.'))
    return factors


def effective_cluster_priority(findings: list[Finding]) -> str:
    priorities = [member_priority(finding) for finding in findings]
    if any(finding.dataflow.confirmed_exploitable for finding in findings):
        priorities.append('P0')
    return max(priorities or ['P4'], key=priority_rank)


def member_priority(finding: Finding) -> str:
    if finding.priority and finding.priority.tier:
        return finding.priority.tier
    return finding.risk.priority or 'P4'


def priority_rank(priority: str) -> int:
    return PRIORITY_ORDER.get(str(priority or 'P4'), 0)


def evidence_for(item: dict[str, Any], sink: str) -> ConsolidatedFindingEvidence:
    finding: Finding = item['finding']
    return ConsolidatedFindingEvidence(
        finding_id=finding.id,
        source=finding.source,
        rule_id=finding.rule_id,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        path=finding.location.path,
        line=item['line_start'],
        end_line=finding.location.end_line,
        cwe=item['cwe'],
        sink=item['sink'] or sink,
        message=finding.message,
        decision=finding.decision,
    )


def infer_sink(finding: Finding) -> str:
    cwes = normalize_cwes(finding.cwe)
    for cwe in cwes:
        if cwe in CWE_SINKS:
            return CWE_SINKS[cwe]
    metadata = finding.scanner_metadata or {}
    metadata_values = ' '.join(str(value) for value in metadata.values())
    text = ' '.join([finding.source, finding.rule_id, finding.title, finding.message, finding.explanation, metadata_values])
    for sink, pattern in SINK_PATTERNS:
        if pattern.search(text):
            return sink
    catalog_rule = metadata.get('catalog_rule_id', '')
    if catalog_rule:
        return f'catalog-{catalog_rule.lower()}'
    return ''


def is_parser_error_finding(finding: Finding) -> bool:
    if finding.source.startswith('dast:') or finding.dynamic:
        return False
    metadata = finding.scanner_metadata or {}
    if metadata.get('parser_error') == 'true':
        return True
    text = ' '.join([finding.source, finding.rule_id, finding.title, finding.message]).lower()
    return any(token in text for token in ('syntax error', 'syntax-error', 'parse error', 'parse-error', 'parser error', 'parser-error'))


def semantic_tokens(cwes: list[str], sink: str, finding: Finding) -> set[str]:
    tokens = {cwe.upper() for cwe in cwes if cwe}
    if sink:
        tokens.add(f'sink:{sink}')
        mapped = SINK_CWES.get(sink)
        if mapped:
            tokens.add(mapped)
    if not tokens:
        catalog_rule = (finding.scanner_metadata or {}).get('catalog_rule_id', '')
        if catalog_rule:
            tokens.add(f'catalog:{catalog_rule.lower()}')
    if not tokens:
        tokens.add(f'rule:{normalize_rule_family(finding.rule_id)}')
    return tokens


def semantic_key(cwes: list[str], sink: str, finding: Finding) -> str:
    if cwes:
        return cwes[0].upper()
    if sink:
        return f'sink:{sink}'
    catalog_rule = (finding.scanner_metadata or {}).get('catalog_rule_id', '')
    if catalog_rule:
        return f'catalog:{catalog_rule.lower()}'
    return f'rule:{normalize_rule_family(finding.rule_id)}'


def semantic_key_for_finding(finding: Finding) -> str:
    return semantic_key(normalize_cwes(finding.cwe), infer_sink(finding), finding)


def primary_sink(items: list[dict[str, Any]], cwes: list[str]) -> str:
    for cwe in cwes:
        if cwe in CWE_SINKS:
            return CWE_SINKS[cwe]
    counts = Counter(item['sink'] for item in items if item['sink'])
    return counts.most_common(1)[0][0] if counts else ''


def normalize_cwes(cwes: list[str]) -> list[str]:
    normalized = []
    for item in cwes or []:
        text = str(item).strip().upper().replace('_', '-')
        if re.match(r'^CWE\d+$', text):
            text = text.replace('CWE', 'CWE-')
        if text.isdigit():
            text = f'CWE-{text}'
        if text.startswith('CWE-'):
            normalized.append(text)
    return sorted(set(normalized))


def normalize_rule_family(rule_id: str) -> str:
    value = str(rule_id or 'unknown').lower()
    value = re.sub(r'^(python|javascript|typescript|java|go|ruby|php|csharp|cs|security)[.:-]+', '', value)
    value = re.sub(r'[^a-z0-9]+', '-', value).strip('-')
    return value or 'unknown'


def finding_lines(finding: Finding) -> tuple[int, int]:
    start = max(1, int(finding.location.line or 1))
    end = max(start, int(finding.location.end_line or start))
    return start, end


def path_key(path: str) -> str:
    return normalize_path(path).lower()


def confidence(finding: Finding) -> str:
    value = str(finding.confidence or 'MEDIUM').upper()
    return value if value in CONFIDENCE_ORDER else 'MEDIUM'


def tool_agreement_score(agreement_count: int) -> int:
    return min(100, 40 + max(0, agreement_count - 1) * 20)


def cluster_id(path: str, line_start: int, line_end: int, semantic: str) -> str:
    digest = hashlib.sha256(f'{path}|{line_start}|{line_end}|{semantic}'.encode('utf-8')).hexdigest()[:16]
    return f'cf-{digest}'


def clamp_score(score: int) -> int:
    return max(0, min(100, int(score)))
