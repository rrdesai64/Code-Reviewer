from __future__ import annotations

from .models import Finding, ScanResult
from .scope import finding_scope, is_production_impacting


def build_sarif(scan: ScanResult) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for finding in scan.findings:
        rules.setdefault(finding.rule_id, rule_from_finding(finding))
        results.append({
            'ruleId': finding.rule_id,
            'level': sarif_level(finding.risk.tier),
            'message': {'text': finding.message},
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {'uri': finding.location.path},
                    'region': {'startLine': finding.location.line, 'startColumn': finding.location.column},
                }
            }],
            'partialFingerprints': {'secureReviewFingerprint': finding.fingerprint},
            'properties': {
                'source': finding.source,
                'severity': finding.severity,
                'confidence': finding.confidence,
                'scope': finding_scope(finding),
                'production_impacting': is_production_impacting(finding),
                'risk_score': finding.risk.score,
                'risk_tier': finding.risk.tier,
                'priority': finding.risk.priority,
                'recommended_action': finding.risk.recommended_action,
                'risk_factors': [factor.model_dump() for factor in finding.risk.factors],
                'cwe': finding.cwe,
                'owasp': finding.owasp,
                'decision': finding.decision,
            },
        })
    return {
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {'driver': {'name': 'Secure Code Review Assistant', 'informationUri': 'https://owasp.org/www-project-code-review-guide/', 'rules': list(rules.values())}},
            'results': results,
            'properties': {
                'max_risk_score': scan.summary.max_risk_score,
                'avg_risk_score': scan.summary.avg_risk_score,
                'risk_tiers': scan.summary.risk_tiers,
                'priorities': scan.summary.priorities,
                'scope_counts': scan.summary.scope_counts,
                'production_findings': scan.summary.production_findings,
                'hygiene_findings': scan.summary.hygiene_findings,
                'all_max_risk_score': scan.summary.all_max_risk_score,
                'all_priorities': scan.summary.all_priorities,
            },
        }],
    }


def rule_from_finding(finding: Finding) -> dict:
    return {
        'id': finding.rule_id,
        'name': finding.title,
        'shortDescription': {'text': finding.title},
        'fullDescription': {'text': finding.explanation},
        'help': {'text': '\n'.join([finding.explanation, '', 'Fix: ' + finding.fix.summary])},
        'properties': {'tags': finding.cwe + finding.owasp, 'precision': finding.confidence.lower()},
    }


def sarif_level(severity: str) -> str:
    return {'CRITICAL': 'error', 'HIGH': 'error', 'MEDIUM': 'warning', 'LOW': 'note', 'INFO': 'note'}.get(severity, 'warning')
