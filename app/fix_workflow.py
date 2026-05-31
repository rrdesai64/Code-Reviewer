from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Finding, FixApplyRequest, FixProposal, ScanResult
from .refactor import build_fix_proposal, deterministic_patch, has_blocking_check, make_diff, read_lines

TRUTHY = {'1', 'true', 'yes', 'on'}
PLACEHOLDER_MARKERS = ('TODO', 'REPLACE_WITH_SECRET_NAME')


def fix_apply_enabled() -> bool:
    return os.getenv('FIX_APPLY_ENABLED', 'false').strip().lower() in TRUTHY


def build_fix_bundle(
    scan: ScanResult,
    finding_ids: list[str] | None = None,
    limit: int = 10,
    provider: str = 'offline',
    model: str | None = None,
    allow_placeholders: bool = False,
) -> dict[str, Any]:
    findings = select_findings(scan, finding_ids=finding_ids, limit=limit)
    proposals: list[dict[str, Any]] = []
    combined_patches: list[str] = []
    seen_patches: set[str] = set()
    counts = {'selected': len(findings), 'eligible': 0, 'manual_review': 0, 'blocked': 0}

    for finding in findings:
        try:
            proposal = build_fix_proposal(scan, finding.id, provider=provider, model=model)
            workflow = classify_proposal(proposal, finding, allow_placeholders=allow_placeholders)
            payload = proposal.model_dump(mode='json')
        except Exception as exc:  # defensive: bundle generation should report, not abort, a single bad proposal
            workflow = {
                'status': 'blocked',
                'blockers': ['proposal-generation-failed'],
                'warnings': [str(exc)[:500]],
                'requires_human_approval': True,
                'dry_run_available': False,
                'apply_available': False,
            }
            payload = {
                'finding_id': finding.id,
                'scan_id': scan.scan_id,
                'title': f'Secure refactor for {finding.title}',
                'summary': 'Proposal generation failed.',
                'patch': '',
                'safety_notes': [],
                'priority': finding.risk.priority,
                'risk_score': finding.risk.score,
                'effort': 'manual-review',
                'confidence': 'blocked',
                'validation_checks': [],
                'validation_commands': [],
                'context_summary': {},
            }

        payload['workflow'] = workflow
        payload['apply_endpoint'] = f'/api/scans/{scan.scan_id}/fixes/apply'
        proposals.append(payload)
        if workflow['status'] == 'eligible':
            counts['eligible'] += 1
            patch_text = str(payload.get('patch') or '').strip()
            if patch_text and patch_text not in seen_patches:
                seen_patches.add(patch_text)
                combined_patches.append(patch_text)
        elif workflow['status'] == 'blocked':
            counts['blocked'] += 1
        else:
            counts['manual_review'] += 1

    return {
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'workflow': 'secure-one-click-fixes',
        'mode': 'dry-run-first',
        'summary': counts,
        'configuration': {
            'provider': provider,
            'model': model or '',
            'limit': limit,
            'finding_ids': finding_ids or [],
            'allow_placeholders': allow_placeholders,
            'fix_apply_enabled': fix_apply_enabled(),
        },
        'guardrails': [
            'Generated fixes are reviewed as patch bundles before source files are changed.',
            'Real apply requires approved=true, dry_run=false, and FIX_APPLY_ENABLED=true.',
            'Manual/TODO/placeholder proposals are excluded from apply unless explicitly allowed.',
            'Only one eligible fix per file is applied in a bundle to avoid overlapping edits.',
            'Backups are written before source changes when create_backups=true.',
        ],
        'combined_patch': '\n\n'.join(patch for patch in combined_patches if patch),
        'proposals': proposals,
    }


def apply_fix_bundle(scan: ScanResult, request: FixApplyRequest) -> dict[str, Any]:
    bundle = build_fix_bundle(
        scan,
        finding_ids=request.finding_ids,
        limit=request.limit,
        provider=request.provider,
        model=request.model,
        allow_placeholders=request.allow_placeholders,
    )
    dry_run = request.dry_run
    blocked_reasons: list[str] = []
    if not dry_run and not request.approved:
        blocked_reasons.append('approved=true is required for non-dry-run apply')
    if not dry_run and not fix_apply_enabled():
        blocked_reasons.append('FIX_APPLY_ENABLED=true is required for non-dry-run apply')
    if blocked_reasons:
        return {
            'scan_id': scan.scan_id,
            'project_name': scan.project_name,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'status': 'blocked',
            'dry_run': dry_run,
            'blocked_reasons': blocked_reasons,
            'applied': [],
            'skipped': bundle_skip_items(bundle, 'apply-gate-blocked'),
            'bundle': bundle,
        }

    target = Path(scan.target_path).resolve()
    touched_files: set[Path] = set()
    applied: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    finding_lookup = {finding.id: finding for finding in scan.findings}

    for item in bundle['proposals']:
        finding_id = str(item.get('finding_id', ''))
        workflow = item.get('workflow', {})
        if workflow.get('status') != 'eligible':
            skipped.append(skip_item(item, 'not-eligible'))
            continue
        finding = finding_lookup.get(finding_id)
        if not finding:
            skipped.append(skip_item(item, 'finding-not-found'))
            continue
        source_path, error = safe_source_path(target, finding)
        if error:
            skipped.append(skip_item(item, error))
            continue
        if source_path in touched_files:
            skipped.append(skip_item(item, 'same-file-overlap'))
            continue
        original = read_lines(source_path)
        if not original:
            skipped.append(skip_item(item, 'empty-or-missing-file'))
            continue
        patched, _summary, _notes = deterministic_patch(original, finding)
        patch = make_diff(finding.location.path, original, patched)
        if not patch.strip():
            skipped.append(skip_item(item, 'no-mechanical-diff'))
            continue
        if patch.strip() != str(item.get('patch', '')).strip():
            skipped.append(skip_item(item, 'proposal-changed-before-apply'))
            continue

        before_text = ''.join(original)
        after_text = ''.join(patched)
        record = {
            'finding_id': finding.id,
            'title': finding.title,
            'path': finding.location.path,
            'line': finding.location.line,
            'before_sha256': sha256_text(before_text),
            'after_sha256': sha256_text(after_text),
            'changed_lines': changed_line_count(patch),
            'action': 'would_apply' if dry_run else 'applied',
        }
        if not dry_run:
            if request.create_backups:
                backup_path = backup_file(target, source_path, finding.location.path, before_text, scan.scan_id)
                record['backup_path'] = str(backup_path)
            source_path.write_text(after_text, encoding='utf-8')
        touched_files.add(source_path)
        applied.append(record)

    status = 'dry_run' if dry_run else 'applied'
    if not applied and skipped:
        status = 'no_eligible_fixes' if dry_run else 'nothing_applied'
    return {
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'status': status,
        'dry_run': dry_run,
        'approved': request.approved,
        'fix_apply_enabled': fix_apply_enabled(),
        'counts': {'applied': len(applied), 'skipped': len(skipped), 'selected': bundle['summary']['selected']},
        'applied': applied,
        'skipped': skipped,
        'bundle': bundle,
    }


def select_findings(scan: ScanResult, finding_ids: list[str] | None, limit: int) -> list[Finding]:
    lookup = {finding.id: finding for finding in scan.findings}
    if finding_ids:
        return [lookup[item] for item in finding_ids if item in lookup]
    candidates = [finding for finding in scan.findings if finding.decision not in {'false_positive', 'risk_accepted'}]
    candidates.sort(key=lambda item: (-item.risk.score, item.location.path, item.location.line, item.id))
    return candidates[:max(1, limit)]


def classify_proposal(proposal: FixProposal, finding: Finding, allow_placeholders: bool = False) -> dict[str, Any]:
    blockers: list[str] = []
    warnings: list[str] = []
    patch = proposal.patch or ''
    if proposal.confidence != 'mechanical':
        blockers.append('manual-review-confidence')
    if has_blocking_check(proposal.validation_checks):
        blockers.append('blocked-validation-check')
    if not patch.strip():
        blockers.append('empty-patch')
    if patch.lstrip().startswith(('# Manual fix proposal', '// Manual fix proposal')):
        blockers.append('manual-guidance-only')
    if any(marker in patch for marker in PLACEHOLDER_MARKERS):
        if allow_placeholders:
            warnings.append('placeholder-or-todo-present')
        else:
            blockers.append('placeholder-or-todo-present')
    if finding.source in {'secret-scan', 'gitleaks', 'trufflehog'}:
        warnings.append('secret-rotation-still-required')
    status = 'eligible' if not blockers else 'manual-review'
    return {
        'status': status,
        'blockers': blockers,
        'warnings': warnings,
        'requires_human_approval': True,
        'dry_run_available': status == 'eligible',
        'apply_available': status == 'eligible' and fix_apply_enabled(),
    }


def safe_source_path(target: Path, finding: Finding) -> tuple[Path | None, str | None]:
    try:
        source_path = (target / finding.location.path).resolve()
        source_path.relative_to(target)
    except Exception:
        return None, 'path-outside-target'
    if not source_path.exists() or not source_path.is_file():
        return None, 'target-file-missing'
    return source_path, None


def backup_file(target: Path, source_path: Path, relative_path: str, before_text: str, scan_id: str) -> Path:
    backup_path = target / '.secure-review-backups' / scan_id / relative_path
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path.write_text(before_text, encoding='utf-8')
    return backup_path


def skip_item(item: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        'finding_id': item.get('finding_id'),
        'title': item.get('title'),
        'reason': reason,
        'workflow': item.get('workflow', {}),
    }


def bundle_skip_items(bundle: dict[str, Any], reason: str) -> list[dict[str, Any]]:
    return [skip_item(item, reason) for item in bundle.get('proposals', [])]


def changed_line_count(patch: str) -> int:
    return sum(1 for line in patch.splitlines() if line.startswith(('+', '-')) and not line.startswith(('+++', '---')))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()