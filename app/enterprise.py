from __future__ import annotations

import json
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .models import AuditEvent, Role, ScanResult, UserAccount

ROOT = Path(__file__).resolve().parents[1]
ENTERPRISE_PATH = ROOT / 'data' / 'enterprise.json'
AUDIT_PATH = ROOT / 'data' / 'audit.log'

DEFAULT_ROLES = [
    Role(name='admin', permissions=['scan:run', 'scan:read', 'baseline:write', 'decision:write', 'enterprise:read', 'enterprise:write', 'fix:propose', 'fix:apply']),
    Role(name='security_reviewer', permissions=['scan:run', 'scan:read', 'baseline:write', 'decision:write', 'enterprise:read', 'fix:propose', 'fix:apply']),
    Role(name='developer', permissions=['scan:run', 'scan:read', 'decision:write', 'fix:propose']),
    Role(name='auditor', permissions=['scan:read', 'enterprise:read']),
]
DEFAULT_USERS = [UserAccount(username='local-admin', display_name='Local Admin', roles=['admin'])]


def load_enterprise() -> dict:
    if not ENTERPRISE_PATH.exists():
        data = {'roles': [role.model_dump() for role in DEFAULT_ROLES], 'users': [user.model_dump() for user in DEFAULT_USERS], 'sso': {'enabled': False, 'provider': None}, 'policies': default_policies()}
        save_enterprise(data)
        return data
    data = json.loads(ENTERPRISE_PATH.read_text(encoding='utf-8'))
    policy_ids = {policy.get('id') for policy in data.get('policies', [])}
    changed = False
    for policy in default_policies():
        if policy['id'] not in policy_ids:
            data.setdefault('policies', []).append(policy)
            changed = True
    default_role_permissions = {role.name: set(role.permissions) for role in DEFAULT_ROLES}
    for role in data.get('roles', []):
        name = role.get('name')
        if name in default_role_permissions:
            current = set(role.get('permissions', []))
            missing = default_role_permissions[name] - current
            if missing:
                role['permissions'] = sorted(current | missing)
                changed = True
    if changed:
        save_enterprise(data)
    return data


def save_enterprise(data: dict) -> None:
    ENTERPRISE_PATH.parent.mkdir(parents=True, exist_ok=True)
    ENTERPRISE_PATH.write_text(json.dumps(data, indent=2), encoding='utf-8')


def default_policies() -> list[dict]:
    return [
        {'id': 'block-high-new-findings', 'description': 'High or critical new findings require review before merge.', 'severity': ['HIGH', 'CRITICAL'], 'action': 'review_required'},
        {'id': 'block-p0-risk', 'description': 'P0 risk findings require release blocking review.', 'priority': ['P0'], 'action': 'block_release'},
        {'id': 'require-dependency-audit', 'description': 'Dependency audit must run for repositories with requirements files.', 'tool': 'pip-audit', 'action': 'audit_required'},
        {'id': 'require-human-fix-approval', 'description': 'Generated secure refactoring patches require human approval.', 'action': 'approval_required'},
        {'id': 'require-controlled-fix-apply', 'description': 'One-click fixes require dry-run, explicit approval, audit logging, and runtime apply enablement.', 'action': 'approval_required'},
    ]


def audit(actor: str, action: str, resource: str, metadata: dict[str, str] | None = None) -> AuditEvent:
    event = AuditEvent(event_id=uuid.uuid4().hex[:16], actor=actor, action=action, resource=resource, metadata=metadata or {})
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_PATH.open('a', encoding='utf-8') as handle:
        handle.write(event.model_dump_json() + '\n')
    return event


def audit_events(limit: int = 100) -> list[dict]:
    if not AUDIT_PATH.exists():
        return []
    lines = AUDIT_PATH.read_text(encoding='utf-8').splitlines()[-limit:]
    return [json.loads(line) for line in lines if line.strip()]


def compliance_report(scan: ScanResult) -> dict:
    by_owasp = Counter(tag for finding in scan.findings for tag in finding.owasp)
    by_cwe = Counter(tag for finding in scan.findings for tag in finding.cwe)
    by_priority = Counter(finding.risk.priority for finding in scan.findings)
    policy_results = []
    for policy in load_enterprise().get('policies', []):
        if policy.get('id') == 'block-high-new-findings':
            high_new = [finding for finding in scan.findings if finding.fingerprint in scan.new_findings and finding.severity in {'HIGH', 'CRITICAL'}]
            policy_results.append({'policy_id': policy['id'], 'status': 'attention_required' if high_new else 'passed', 'count': len(high_new)})
        elif policy.get('id') == 'block-p0-risk':
            p0_open = [finding for finding in scan.findings if finding.risk.priority == 'P0' and finding.decision not in {'false_positive', 'risk_accepted'}]
            policy_results.append({'policy_id': policy['id'], 'status': 'attention_required' if p0_open else 'passed', 'count': len(p0_open)})
        elif policy.get('id') == 'require-dependency-audit':
            status = scan.summary.tools.get('pip-audit', 'missing')
            policy_results.append({'policy_id': policy['id'], 'status': 'passed' if status == 'ok' or status.startswith('skipped') else 'attention_required', 'detail': status})
        else:
            policy_results.append({'policy_id': policy['id'], 'status': 'configured'})
    return {
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'summary': scan.summary.model_dump(),
        'risk_summary': {
            'max_risk_score': scan.summary.max_risk_score,
            'avg_risk_score': scan.summary.avg_risk_score,
            'risk_tiers': scan.summary.risk_tiers,
            'priorities': dict(by_priority),
        },
        'owasp_coverage': dict(by_owasp),
        'cwe_coverage': dict(by_cwe),
        'policy_results': policy_results,
        'audit_events_recorded': len(audit_events(limit=1000)),
    }
