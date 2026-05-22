from __future__ import annotations

import re
from collections import Counter

from .models import Finding, RiskFactor, RiskScore, ScanResult
from .scope import finding_scope, is_blocking_secret, is_production_impacting, is_secret_like, production_gate_findings, scope_counts

SEVERITY_POINTS = {'CRITICAL': 72, 'HIGH': 56, 'MEDIUM': 34, 'LOW': 16, 'INFO': 4}
CONFIDENCE_POINTS = {'HIGH': 10, 'MEDIUM': 5, 'LOW': 1}

SENSITIVE_CWES = {
    'CWE-22', 'CWE-78', 'CWE-79', 'CWE-89', 'CWE-94', 'CWE-120', 'CWE-200', 'CWE-287',
    'CWE-295', 'CWE-306', 'CWE-319', 'CWE-326', 'CWE-327', 'CWE-352', 'CWE-434', 'CWE-502',
    'CWE-522', 'CWE-798', 'CWE-918',
}
HIGH_RISK_OWASP = ('A01', 'A02', 'A03', 'A05', 'A06', 'A07', 'A10')
EXPLOITABLE_KEYWORDS = (
    'command injection', 'sql injection', 'xss', 'path traversal', 'deserialization', 'ssrf',
    'hardcoded password', 'hardcoded secret', 'private key', 'token', 'credential', 'subprocess',
    'shell=true', 'eval', 'exec', 'insecure random', 'verify=false', 'known vulnerability',
)
DEPENDENCY_SOURCES = {'pip-audit', 'dependency-manifest', 'snyk'}
RUNTIME_DEPENDENCY_REACHABILITY = {'reachable-source-import', 'direct-manifest'}
LOWER_RISK_DEPENDENCY_REACHABILITY = {'dev-or-optional', 'transitive-unknown', 'reachable-test-import'}
EXPOSURE_PATTERNS = (
    re.compile(r'(^|/)(api|routes|controllers|views|handlers|auth|login|admin)(/|\.|$)', re.I),
    re.compile(r'(^|/)(Dockerfile|docker-compose\.ya?ml|kubernetes|helm|terraform|\.github/workflows)(/|$)', re.I),
    re.compile(r'(^|/)(config|settings|\.env|secrets?|credentials?)(\.|/|$)', re.I),
)


def score_scan(scan: ScanResult) -> ScanResult:
    new_fingerprints = set(scan.new_findings)
    for finding in scan.findings:
        finding.risk = score_finding(finding, is_new=finding.fingerprint in new_fingerprints)
    production_findings = production_gate_findings(scan.findings)
    scan.summary.max_risk_score = max((finding.risk.score for finding in production_findings), default=0)
    scan.summary.avg_risk_score = round(sum(finding.risk.score for finding in production_findings) / len(production_findings), 1) if production_findings else 0
    scan.summary.risk_tiers = dict(sorted(Counter(finding.risk.tier for finding in production_findings).items()))
    scan.summary.priorities = dict(sorted(Counter(finding.risk.priority for finding in production_findings).items()))
    scan.summary.scope_counts = scope_counts(scan.findings)
    scan.summary.production_findings = len(production_findings)
    scan.summary.hygiene_findings = len(scan.findings) - len(production_findings)
    scan.summary.all_max_risk_score = max((finding.risk.score for finding in scan.findings), default=0)
    scan.summary.all_avg_risk_score = round(sum(finding.risk.score for finding in scan.findings) / len(scan.findings), 1) if scan.findings else 0
    scan.summary.all_risk_tiers = dict(sorted(Counter(finding.risk.tier for finding in scan.findings).items()))
    scan.summary.all_priorities = dict(sorted(Counter(finding.risk.priority for finding in scan.findings).items()))
    return scan


def score_finding(finding: Finding, is_new: bool = False) -> RiskScore:
    factors: list[RiskFactor] = []
    add_factor(factors, 'severity', 'Scanner severity', SEVERITY_POINTS.get(finding.severity, 4), finding.severity)

    confidence = str(finding.confidence or 'MEDIUM').upper()
    add_factor(factors, 'confidence', 'Scanner confidence', CONFIDENCE_POINTS.get(confidence, 3), confidence)

    if is_new:
        add_factor(factors, 'baseline', 'New since baseline', 8, 'New findings are prioritized for review gates.')

    if any(cwe.upper() in SENSITIVE_CWES for cwe in finding.cwe):
        add_factor(factors, 'weakness', 'High-impact CWE', 10, ', '.join(finding.cwe))

    if any(any(tag.upper().startswith(prefix) for prefix in HIGH_RISK_OWASP) for tag in finding.owasp):
        add_factor(factors, 'owasp', 'High-impact OWASP category', 6, ', '.join(finding.owasp))

    text = ' '.join([finding.title, finding.rule_id, finding.message, finding.explanation]).lower()
    if any(keyword in text for keyword in EXPLOITABLE_KEYWORDS):
        add_factor(factors, 'exploitability', 'Exploitability signal', 8, 'Finding text contains a known exploitability indicator.')

    if finding.source in {'pip-audit', 'codeql', 'sonarqube', 'secret-scan', 'gitleaks', 'trufflehog'}:
        add_factor(factors, 'source', 'High-value scanner source', 5, finding.source)

    if is_secret_like(finding) and not is_blocking_secret(finding):
        add_factor(factors, 'secret-confidence', 'Unverified secret heuristic', -25, 'Not a high-confidence or critical secret pattern; review before blocking.')

    metadata = finding.scanner_metadata or {}
    if metadata.get('sonar_kind') == 'quality_gate':
        add_factor(factors, 'quality-gate', 'SonarQube quality gate failure', 15, metadata.get('quality_gate_status', 'quality gate failed'))

    if finding.source in DEPENDENCY_SOURCES:
        add_dependency_factors(finding, factors)

    path = finding.location.path.replace('\\', '/')
    if any(pattern.search(path) for pattern in EXPOSURE_PATTERNS):
        add_factor(factors, 'exposure', 'Sensitive or exposed file path', 7, path)

    scope = finding_scope(finding)
    if not is_production_impacting(finding):
        discount = -45 if scope in {'test', 'docs', 'example'} else -30
        add_factor(factors, 'scope', 'Non-production scope', discount, f'{scope} findings are tracked as hygiene and excluded from production gates.')
        if scope == 'test' and finding.rule_id in {'B101', 'B105', 'B113', 'B301', 'B403'}:
            add_factor(factors, 'test-noise', 'Common test-only scanner pattern', -10, finding.rule_id)

    raw_score = sum(factor.points for factor in factors)
    score = max(0, min(100, raw_score))
    tier = tier_for_score(score)
    action = action_for_tier(tier)
    if not is_production_impacting(finding):
        action = 'Track as test/docs/example hygiene unless review confirms production exposure or a real secret.'
    return RiskScore(score=score, tier=tier, priority=priority_for_score(score), recommended_action=action, factors=factors)


def add_dependency_factors(finding: Finding, factors: list[RiskFactor]) -> None:
    metadata = finding.scanner_metadata or {}
    reachability = metadata.get('dependency_reachability') or finding.reachability
    scope = metadata.get('dependency_scope', '')
    dep_type = metadata.get('dependency_type', '')
    fix_versions = metadata.get('fix_versions', '')
    if reachability == 'reachable-source-import':
        add_factor(factors, 'dependency-reachability', 'Reachable dependency usage', 12, metadata.get('dependency_evidence') or reachability)
    elif reachability == 'direct-manifest':
        add_factor(factors, 'dependency-reachability', 'Direct runtime dependency', 7, 'Declared directly in a runtime dependency manifest.')
    elif reachability in LOWER_RISK_DEPENDENCY_REACHABILITY:
        add_factor(factors, 'dependency-reachability', 'Lower reachability signal', -8, reachability)
    elif reachability in {'manifest-only', 'package-level', 'unknown'}:
        add_factor(factors, 'dependency-reachability', 'Unproven dependency reachability', -4, reachability)
    if scope == 'optional':
        add_factor(factors, 'dependency-scope', 'Dev or optional dependency scope', -6, 'Dependency is marked optional/dev in the manifest.')
    elif scope == 'required':
        add_factor(factors, 'dependency-scope', 'Runtime dependency scope', 4, 'Dependency is required at runtime.')
    if dep_type == 'direct':
        add_factor(factors, 'dependency-type', 'Direct dependency', 4, metadata.get('dependency_name', 'direct manifest dependency'))
    elif dep_type == 'lockfile':
        add_factor(factors, 'dependency-type', 'Lockfile or transitive dependency', -5, metadata.get('dependency_name', 'lockfile dependency'))
    if finding.source in {'pip-audit', 'snyk'} and not fix_versions:
        add_factor(factors, 'dependency-fix', 'No fixed version in scanner output', 5, 'Manual remediation or parent upgrade may be required.')


def add_factor(factors: list[RiskFactor], name: str, label: str, points: int, detail: str) -> None:
    if points != 0:
        factors.append(RiskFactor(name=name, label=label, points=points, detail=detail))


def tier_for_score(score: int) -> str:
    if score >= 85:
        return 'CRITICAL'
    if score >= 65:
        return 'HIGH'
    if score >= 40:
        return 'MEDIUM'
    if score >= 15:
        return 'LOW'
    return 'INFO'


def priority_for_score(score: int) -> str:
    if score >= 85:
        return 'P0'
    if score >= 65:
        return 'P1'
    if score >= 40:
        return 'P2'
    if score >= 15:
        return 'P3'
    return 'P4'


def action_for_tier(tier: str) -> str:
    return {
        'CRITICAL': 'Block release until reviewed and remediated or formally risk-accepted.',
        'HIGH': 'Require security review before merge or deployment.',
        'MEDIUM': 'Plan remediation in the current sprint and verify the fix.',
        'LOW': 'Track and remediate as maintenance work.',
        'INFO': 'Review when touching related code.',
    }.get(tier, 'Review and triage.')
