from __future__ import annotations

import re
from collections import Counter

from .models import Finding, RiskFactor, RiskScore, ScanResult

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
EXPOSURE_PATTERNS = (
    re.compile(r'(^|/)(api|routes|controllers|views|handlers|auth|login|admin)(/|\.|$)', re.I),
    re.compile(r'(^|/)(Dockerfile|docker-compose\.ya?ml|kubernetes|helm|terraform|\.github/workflows)(/|$)', re.I),
    re.compile(r'(^|/)(config|settings|\.env|secrets?|credentials?)(\.|/|$)', re.I),
)


def score_scan(scan: ScanResult) -> ScanResult:
    new_fingerprints = set(scan.new_findings)
    for finding in scan.findings:
        finding.risk = score_finding(finding, is_new=finding.fingerprint in new_fingerprints)
    scan.summary.max_risk_score = max((finding.risk.score for finding in scan.findings), default=0)
    scan.summary.avg_risk_score = round(sum(finding.risk.score for finding in scan.findings) / len(scan.findings), 1) if scan.findings else 0
    scan.summary.risk_tiers = dict(sorted(Counter(finding.risk.tier for finding in scan.findings).items()))
    scan.summary.priorities = dict(sorted(Counter(finding.risk.priority for finding in scan.findings).items()))
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

    if finding.source in {'pip-audit', 'codeql', 'sonarqube'}:
        add_factor(factors, 'source', 'High-value scanner source', 5, finding.source)

    path = finding.location.path.replace('\\', '/')
    if any(pattern.search(path) for pattern in EXPOSURE_PATTERNS):
        add_factor(factors, 'exposure', 'Sensitive or exposed file path', 7, path)

    raw_score = sum(factor.points for factor in factors)
    score = max(0, min(100, raw_score))
    tier = tier_for_score(score)
    return RiskScore(score=score, tier=tier, priority=priority_for_score(score), recommended_action=action_for_tier(tier), factors=factors)


def add_factor(factors: list[RiskFactor], name: str, label: str, points: int, detail: str) -> None:
    if points > 0:
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
