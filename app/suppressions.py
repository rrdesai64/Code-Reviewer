from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .models import Finding, InvalidSuppressionAnnotation, ScanResult, SuppressionRecord
from .scope import apply_finding_scope, finding_scope, normalize_path

SUPPRESSION_LOOKBACK_LINES = 2
MAX_SUPPRESSION_FILE_BYTES = 1_000_000
ANNOTATION_PATTERN = re.compile(r'secure-review:\s*ignore\s+(?P<body>.+)$', re.IGNORECASE)
REASON_SPLIT_PATTERN = re.compile(r'\s+(?:--?|\u2013|\u2014)\s+', re.IGNORECASE)


def apply_inline_suppressions(target: Path, scan: ScanResult) -> ScanResult:
    finding_paths = {normalize_path(finding.location.path) for finding in scan.findings if finding.location.path}
    index = load_suppression_index(target, finding_paths)
    records: list[SuppressionRecord] = []
    for finding in scan.findings:
        apply_finding_scope(finding)
        match = match_suppression(finding, index.get(normalize_path(finding.location.path), []))
        if match is None:
            continue
        finding.decision = 'suppressed'
        finding.decision_reason = match.reason
        metadata = dict(finding.scanner_metadata or {})
        metadata.update({
            'suppression_kind': 'inline-annotation',
            'suppression_reason': match.reason,
            'suppression_annotation_line': str(match.line),
            'suppression_matched_rule': match.matched_rule,
        })
        finding.scanner_metadata = metadata
        records.append(SuppressionRecord(
            finding_id=finding.id,
            fingerprint=finding.fingerprint,
            rule_id=finding.rule_id,
            source=finding.source,
            path=finding.location.path,
            line=int(finding.location.line or 1),
            annotation_line=match.line,
            reason=match.reason,
            annotation=match.annotation,
            matched_rule=match.matched_rule,
            scope=finding_scope(finding),
        ))
    scan.suppressions = records
    scan.invalid_suppressions = invalid_annotations(index)
    update_suppression_summary(scan)
    return scan


def inline_suppression_report(scan: ScanResult) -> dict[str, Any]:
    update_suppression_summary(scan)
    return {
        'schema_version': 1,
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'suppressed_findings': len(scan.suppressions),
        'invalid_annotations': len(scan.invalid_suppressions),
        'records': [record.model_dump(mode='json') for record in scan.suppressions],
        'invalid_records': [record.model_dump(mode='json') for record in scan.invalid_suppressions],
        'policy': {
            'required_format': 'secure-review: ignore <rule-id|*> - <reason>',
            'reason_required': True,
            'match_window': f'same line or previous {SUPPRESSION_LOOKBACK_LINES} line(s)',
            'raw_code_included': False,
        },
    }


def record_suppression_governance(scan: ScanResult, actor: str = 'system') -> list[dict[str, Any]]:
    if not scan.suppressions and not scan.invalid_suppressions:
        return []
    try:
        from .governance import record_governance_event
    except Exception:
        return []
    events = []
    for record in scan.suppressions:
        events.append(record_governance_event(
            actor=actor,
            action='finding.suppressed_by_annotation',
            category='suppression',
            resource=record.finding_id,
            scan_id=scan.scan_id,
            reason=record.reason,
            metadata={
                'rule_id': record.rule_id,
                'source': record.source,
                'path': record.path,
                'line': str(record.line),
                'annotation_line': str(record.annotation_line),
                'matched_rule': record.matched_rule,
            },
            evidence_refs={
                'fingerprint': record.fingerprint,
                'annotation': record.annotation,
            },
        ))
    for record in scan.invalid_suppressions:
        events.append(record_governance_event(
            actor=actor,
            action='finding.invalid_suppression_annotation',
            category='suppression',
            resource=f'{record.path}:{record.line}',
            scan_id=scan.scan_id,
            reason=record.reason,
            metadata={'path': record.path, 'line': str(record.line)},
            evidence_refs={'annotation': record.annotation},
        ))
    return events


def update_suppression_summary(scan: ScanResult) -> None:
    scan.summary.suppressed_findings = len(scan.suppressions)
    scan.summary.invalid_suppression_annotations = len(scan.invalid_suppressions)


class _Annotation:
    def __init__(self, path: str, line: int, annotation: str, rules: list[str], reason: str, valid: bool, invalid_reason: str = '') -> None:
        self.path = path
        self.line = line
        self.annotation = annotation
        self.rules = rules
        self.reason = reason
        self.valid = valid
        self.invalid_reason = invalid_reason
        self.matched_rule = ''


def load_suppression_index(target: Path, finding_paths: set[str]) -> dict[str, list[_Annotation]]:
    index: dict[str, list[_Annotation]] = {}
    if not target.exists() or not finding_paths:
        return index
    root = target.resolve()
    for rel in sorted(finding_paths):
        try:
            path = (root / rel).resolve()
            path.relative_to(root)
        except Exception:
            continue
        if not path.is_file() or skip_path(path):
            continue
        try:
            if path.stat().st_size > MAX_SUPPRESSION_FILE_BYTES:
                continue
            annotations = annotations_from_text(rel, path.read_text(encoding='utf-8', errors='ignore'))
        except OSError:
            continue
        if annotations:
            index[rel] = annotations
    return index


def annotations_from_text(path: str, text: str) -> list[_Annotation]:
    annotations: list[_Annotation] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        marker_index = line.lower().find('secure-review:')
        if marker_index < 0:
            continue
        annotation = line[marker_index:].strip()
        match = ANNOTATION_PATTERN.search(annotation)
        if not match:
            annotations.append(_Annotation(path, line_number, annotation, [], '', False, 'annotation must use: secure-review: ignore <rule-id|*> - <reason>'))
            continue
        rules_text, reason_text = split_annotation_body(match.group('body') or '')
        reason = clean_reason(reason_text)
        rules = normalize_rules(rules_text)
        if not reason:
            annotations.append(_Annotation(path, line_number, annotation, rules, '', False, 'suppression reason is required'))
            continue
        if not rules:
            annotations.append(_Annotation(path, line_number, annotation, [], reason, False, 'suppression rule id is required'))
            continue
        annotations.append(_Annotation(path, line_number, annotation, rules, reason, True))
    return annotations


def match_suppression(finding: Finding, annotations: list[_Annotation]) -> _Annotation | None:
    line = int(finding.location.line or 1)
    rule_tokens = finding_rule_tokens(finding)
    for annotation in annotations:
        if not annotation.valid:
            continue
        if line < annotation.line or line > annotation.line + SUPPRESSION_LOOKBACK_LINES:
            continue
        matched = next((rule for rule in annotation.rules if rule == '*' or rule in rule_tokens), '')
        if not matched:
            continue
        annotation.matched_rule = matched
        return annotation
    return None


def invalid_annotations(index: dict[str, list[_Annotation]]) -> list[InvalidSuppressionAnnotation]:
    records: list[InvalidSuppressionAnnotation] = []
    for file_annotations in index.values():
        for annotation in file_annotations:
            if annotation.valid:
                continue
            records.append(InvalidSuppressionAnnotation(
                path=annotation.path,
                line=annotation.line,
                annotation=annotation.annotation,
                reason=annotation.invalid_reason,
            ))
    return records


def finding_rule_tokens(finding: Finding) -> set[str]:
    values = {finding.rule_id, finding.id}
    values.update(finding.cwe or [])
    metadata = finding.scanner_metadata or {}
    for key in ('catalog_rule_id', 'raw_ruleId', 'raw_check_id', 'raw_test_id'):
        if metadata.get(key):
            values.add(metadata[key])
    return {normalize_rule(value) for value in values if value}


def normalize_rules(value: str) -> list[str]:
    values = re.split(r'[,\s]+', str(value or '').strip())
    return [normalize_rule(item) for item in values if normalize_rule(item)]


def split_annotation_body(body: str) -> tuple[str, str]:
    parts = REASON_SPLIT_PATTERN.split(str(body or '').strip(), maxsplit=1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return str(body or '').strip(), ''


def normalize_rule(value: str) -> str:
    text = str(value or '').strip().lower()
    text = text.strip('`\'"[](){}')
    return text


def clean_reason(value: str) -> str:
    return ' '.join(str(value or '').strip().split())[:500]


def skip_path(path: Path) -> bool:
    ignored = {'.git', '.venv', 'venv', 'node_modules', 'dist', 'build', '__pycache__', '.mypy_cache', '.pytest_cache', 'data'}
    return any(part in ignored for part in path.parts)


def relpath(path: Path, target: Path) -> str:
    try:
        return str(path.resolve().relative_to(target.resolve())).replace('\\', '/')
    except Exception:
        return normalize_path(str(path))
