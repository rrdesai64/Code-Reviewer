from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .paths import data_dir
from .rag import tokenize
from .report_lake import list_sanitized_scans, load_sanitized_scan, sanitized_scan_report

SCHEMA_VERSION = 1
MAX_FINDING_ITEMS_PER_SCAN = 1000
MAX_RULE_ITEMS_PER_SCAN = 100
MAX_DEPENDENCY_ITEMS_PER_SCAN = 250
MAX_TEXT_LENGTH = 1400

MEMORY_ITEM_TYPES = {
    'scan-summary': 'Repository scan summary suitable for retrieval and trend context.',
    'finding-pattern': 'Sanitized finding pattern with taxonomy, rule, risk, and remediation labels.',
    'rule-pattern': 'Rule-level aggregate for repeated findings in one sanitized scan.',
    'dependency-signal': 'Supply-chain or dependency-specific finding signal.',
    'scanner-status': 'Scanner coverage and tool status evidence.',
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def rag_memory_dir() -> Path:
    return data_dir() / 'rag-memory'


def rag_memory_scans_dir() -> Path:
    return rag_memory_dir() / 'scans'


def rag_memory_index_path() -> Path:
    return rag_memory_dir() / 'index.json'


def rag_memory_versions_dir() -> Path:
    return rag_memory_dir() / 'versions'


def rag_memory_versions_path() -> Path:
    return rag_memory_dir() / 'versions.json'


def ensure_rag_memory_dirs() -> None:
    rag_memory_scans_dir().mkdir(parents=True, exist_ok=True)
    rag_memory_versions_dir().mkdir(parents=True, exist_ok=True)


def rag_memory_schema() -> dict[str, Any]:
    return {
        'schema_version': SCHEMA_VERSION,
        'name': 'secure-review-rag-memory',
        'source_contract': {
            'accepted_source': 'sanitized-report-lake',
            'raw_repository_reads_allowed': False,
            'raw_report_file_reads_allowed': False,
            'requires_learning_eligibility': True,
        },
        'memory_item_required_fields': [
            'item_id',
            'item_type',
            'title',
            'text',
            'tags',
            'metadata',
            'source',
            'eligibility',
            'safety',
        ],
        'item_types': MEMORY_ITEM_TYPES,
        'eligibility_contract': {
            'retrieval_allowed': 'true only when sanitized report learning_eligibility.rag_ingest_allowed is true',
            'agent_learning_allowed': 'copied from sanitized report learning_eligibility.agent_learning_allowed',
            'fine_tuning_allowed': 'always false until a future human approval and benchmark gate is implemented',
            'requires_human_review': True,
            'requires_benchmark_gate': True,
        },
        'safety_contract': {
            'raw_code_included': False,
            'patches_included': False,
            'full_local_paths_included': False,
            'secret_redaction_required': True,
        },
        'guardrails': [
            'Only sanitized report lake records may be converted into RAG memory.',
            'Quarantined, blocked, or watch-policy records are skipped for retrieval by default.',
            'RAG memory is for explanation and planning context only; it must not promote scanner/rule changes without human approval and benchmark evidence.',
            'Fine-tuning export remains disabled at this layer.',
        ],
    }


def rag_memory_for_scan(scan: Any) -> dict[str, Any]:
    return rag_memory_from_report(sanitized_scan_report(scan))


def rag_memory_from_report(report: dict[str, Any], include_ineligible: bool = False) -> dict[str, Any]:
    eligibility = dict(report.get('learning_eligibility') or {})
    allowed = bool(eligibility.get('rag_ingest_allowed'))
    source = source_from_report(report)
    if not allowed and not include_ineligible:
        return scan_memory_report(
            source=source,
            eligibility=eligibility,
            status='skipped',
            items=[],
            skipped_reason=eligibility.get('blocked_reason') or 'rag ingest is not allowed by sanitized report policy',
        )

    items = build_memory_items(report, retrieval_allowed=allowed)
    return scan_memory_report(
        source=source,
        eligibility=eligibility,
        status='indexed' if allowed else 'audit-only',
        items=items,
        skipped_reason='' if allowed else 'stored as audit-only because rag ingest is not allowed',
    )


def save_rag_memory_for_report(report: dict[str, Any], include_ineligible: bool = False) -> dict[str, Any]:
    ensure_rag_memory_dirs()
    memory = rag_memory_from_report(report, include_ineligible=include_ineligible)
    previous_version_id = latest_memory_version_for_scan(str(memory.get('source', {}).get('scan_id') or ''))
    memory = attach_memory_version(memory, previous_version_id=previous_version_id)
    scan_id = safe_scan_filename(str(memory['source']['scan_id']))
    scan_path = rag_memory_scans_dir() / f'{scan_id}.json'
    scan_path.write_text(json.dumps(memory, indent=2), encoding='utf-8')
    register_memory_version(memory, previous_version_id=previous_version_id)
    update_global_index(memory)
    try:
        from .governance import record_memory_version_event

        record_memory_version_event(memory, previous_version_id=previous_version_id, actor='rag-memory')
    except Exception:
        pass
    return memory


def load_scan_rag_memory(scan_id: str) -> dict[str, Any]:
    path = rag_memory_scans_dir() / f'{safe_scan_filename(scan_id)}.json'
    if not path.exists():
        raise FileNotFoundError(scan_id)
    return json.loads(path.read_text(encoding='utf-8'))


def scan_rag_memory_report(scan_id: str, rebuild: bool = False) -> dict[str, Any]:
    if not rebuild:
        try:
            return load_scan_rag_memory(scan_id)
        except FileNotFoundError:
            pass
    try:
        report = load_sanitized_scan(scan_id)
    except FileNotFoundError:
        if rebuild:
            try:
                from .report_lake import save_sanitized_scan
                from .storage import apply_decisions, load_scan

                report = save_sanitized_scan(apply_decisions(load_scan(scan_id)))
            except FileNotFoundError:
                return {
                    'schema_version': SCHEMA_VERSION,
                    'generated_at': now_iso(),
                    'status': 'missing',
                    'scan_id': scan_id,
                    'items': [],
                    'skipped_reason': 'saved scan and sanitized report lake record not found',
                    'guardrails': rag_memory_schema()['guardrails'],
                }
        else:
            return {
                'schema_version': SCHEMA_VERSION,
                'generated_at': now_iso(),
                'status': 'missing',
                'scan_id': scan_id,
                'items': [],
                'skipped_reason': 'sanitized report lake record not found',
                'guardrails': rag_memory_schema()['guardrails'],
            }
    return save_rag_memory_for_report(report) if rebuild else rag_memory_from_report(report)


def reindex_rag_memory(limit: int = 100, include_ineligible: bool = False) -> dict[str, Any]:
    ensure_rag_memory_dirs()
    reset_rag_memory_index()
    records = list_sanitized_scans(limit=limit)
    indexed_reports: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for record in records:
        scan_id = str(record.get('scan_id') or '')
        if not scan_id:
            continue
        try:
            report = load_sanitized_scan(scan_id)
        except FileNotFoundError:
            skipped.append({'scan_id': scan_id, 'reason': 'sanitized report disappeared during reindex'})
            continue
        memory = save_rag_memory_for_report(report, include_ineligible=include_ineligible)
        indexed_reports.append(scan_index_record(memory))
        if memory.get('status') == 'skipped':
            skipped.append({'scan_id': scan_id, 'reason': memory.get('skipped_reason', 'skipped')})
    index = load_rag_memory_index()
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'status': 'completed',
        'scan_reports_processed': len(indexed_reports),
        'retrieval_item_count': len(index.get('items', [])),
        'skipped': skipped,
        'records': indexed_reports,
        'include_ineligible': include_ineligible,
        'guardrails': rag_memory_schema()['guardrails'],
    }


def rag_memory_status() -> dict[str, Any]:
    ensure_rag_memory_dirs()
    index = load_rag_memory_index()
    scan_files = list(rag_memory_scans_dir().glob('*.json'))
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'memory_dir': str(rag_memory_dir()),
        'index_path': str(rag_memory_index_path()),
        'scan_memory_record_count': len(scan_files),
        'retrieval_item_count': len(index.get('items', [])),
        'item_type_counts': dict(Counter(item.get('item_type', 'unknown') for item in index.get('items', []))),
        'latest_scan_records': list_scan_rag_memory(limit=10),
        'schema': rag_memory_schema(),
    }


def list_scan_rag_memory(limit: int = 100) -> list[dict[str, Any]]:
    ensure_rag_memory_dirs()
    max_records = max(0, limit)
    if max_records == 0:
        return []
    records: list[dict[str, Any]] = []
    for path in sorted(rag_memory_scans_dir().glob('*.json'), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            records.append(scan_index_record(json.loads(path.read_text(encoding='utf-8'))))
        except (OSError, json.JSONDecodeError) as exc:
            records.append({'scan_id': path.stem, 'status': 'unreadable', 'error': str(exc)[:200]})
        if len(records) >= max_records:
            break
    return records


def list_memory_versions(scan_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    registry = load_memory_versions()
    requested = str(scan_id or '').strip()
    versions = registry.get('versions', [])
    if requested:
        versions = [version for version in versions if version.get('scan_id') == requested]
    return sorted(versions, key=lambda item: item.get('created_at') or '', reverse=True)[:max(0, limit)]


def load_memory_version(version_id: str) -> dict[str, Any]:
    path = rag_memory_versions_dir() / f'{safe_scan_filename(version_id)}.json'
    if not path.exists():
        raise FileNotFoundError(version_id)
    return json.loads(path.read_text(encoding='utf-8'))


def rollback_rag_memory_version(version_id: str, *, actor: str = 'system', reason: str = '') -> dict[str, Any]:
    ensure_rag_memory_dirs()
    memory = load_memory_version(version_id)
    scan_id = str(memory.get('source', {}).get('scan_id') or '')
    if not scan_id:
        raise ValueError('memory version does not contain a source scan_id')
    scan_path = rag_memory_scans_dir() / f'{safe_scan_filename(scan_id)}.json'
    previous_version_id = latest_memory_version_for_scan(scan_id)
    scan_path.write_text(json.dumps(memory, indent=2), encoding='utf-8')
    set_active_memory_version(scan_id, str(memory.get('memory_version', {}).get('version_id') or version_id))
    update_global_index(memory)
    try:
        from .governance import record_governance_event

        record_governance_event(
            actor=actor,
            action='rag_memory.version_rolled_back',
            category='memory-rollback',
            resource=version_id,
            scan_id=scan_id,
            reason=reason or 'RAG memory version restored by an authorized user.',
            metadata={
                'previous_active_version_id': previous_version_id,
                'restored_version_id': version_id,
                'item_count': str(memory.get('item_count', 0)),
            },
            evidence_refs={'memory_version': memory.get('memory_version') or {}, 'source': memory.get('source') or {}},
        )
    except Exception:
        pass
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'status': 'rolled_back',
        'scan_id': scan_id,
        'restored_version_id': version_id,
        'previous_active_version_id': previous_version_id,
        'item_count': memory.get('item_count', 0),
        'guardrails': ['Rollback restored sanitized RAG memory only; raw scans and repositories were not modified.'],
    }


def list_rag_memory_items(limit: int = 100, item_type: str | None = None) -> list[dict[str, Any]]:
    index = load_rag_memory_index()
    items = index.get('items', [])
    if item_type:
        items = [item for item in items if item.get('item_type') == item_type]
    return items[:max(0, limit)]


def query_rag_memory(query: str, limit: int = 5, tags: list[str] | None = None) -> dict[str, Any]:
    index = load_rag_memory_index()
    items = [item for item in index.get('items', []) if item.get('eligibility', {}).get('retrieval_allowed')]
    requested_tags = {str(tag).upper() for tag in tags or [] if tag}
    query_terms = Counter(tokenize(query))
    scored: list[dict[str, Any]] = []
    doc_freq = memory_document_frequencies(items)
    for item in items:
        score = score_memory_item(item, query, query_terms, requested_tags, doc_freq, len(items))
        if score > 0:
            result = public_memory_item(item)
            result['score'] = round(score, 3)
            scored.append(result)
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'query': query,
        'tags': sorted(requested_tags),
        'total_indexed': len(items),
        'results': sorted(scored, key=lambda item: (-item['score'], item.get('title', ''), item.get('item_id', '')))[:max(0, limit)],
        'guardrails': ['Results are sourced from sanitized report lake memory items only.'],
    }


def build_memory_items(report: dict[str, Any], retrieval_allowed: bool) -> list[dict[str, Any]]:
    source = source_from_report(report)
    eligibility = dict(report.get('learning_eligibility') or {})
    items: list[dict[str, Any]] = []
    items.append(scan_summary_item(report, source, eligibility, retrieval_allowed))
    items.extend(finding_pattern_item(finding, source, eligibility, retrieval_allowed) for finding in report.get('findings', [])[:MAX_FINDING_ITEMS_PER_SCAN])
    items.extend(rule_pattern_items(report, source, eligibility, retrieval_allowed))
    items.extend(dependency_signal_items(report, source, eligibility, retrieval_allowed))
    items.append(scanner_status_item(report, source, eligibility, retrieval_allowed))
    return [item for item in items if item]


def scan_summary_item(report: dict[str, Any], source: dict[str, Any], eligibility: dict[str, Any], retrieval_allowed: bool) -> dict[str, Any]:
    summary = report.get('summary') or {}
    languages = ', '.join(f'{key}:{value}' for key, value in (summary.get('languages') or {}).items()) or 'unknown'
    priorities = ', '.join(f'{key}:{value}' for key, value in (summary.get('priorities') or {}).items()) or 'none'
    text = (
        f"Scan summary for {source['project_name']}: {summary.get('total_findings', 0)} findings, "
        f"{summary.get('production_findings', 0)} production findings, max risk {summary.get('max_risk_score', 0)}, "
        f"average risk {summary.get('avg_risk_score', 0)}. Languages: {languages}. Priorities: {priorities}."
    )
    return make_memory_item(
        item_type='scan-summary',
        title=f"Scan summary: {source['project_name']}",
        text=text,
        tags=['SCAN', 'SUMMARY', *summary_tags(summary)],
        metadata={
            'total_findings': str(summary.get('total_findings', 0)),
            'files_scanned': str(summary.get('files_scanned', 0)),
            'max_risk_score': str(summary.get('max_risk_score', 0)),
        },
        source=source,
        eligibility=eligibility,
        retrieval_allowed=retrieval_allowed,
        key_parts=['scan-summary', source['scan_id']],
    )


def finding_pattern_item(finding: dict[str, Any], source: dict[str, Any], eligibility: dict[str, Any], retrieval_allowed: bool) -> dict[str, Any]:
    risk = finding.get('risk') or {}
    location = finding.get('location') or {}
    decision = finding.get('decision') or {}
    tags = finding_tags(finding)
    text = ' '.join(
        [
            f"{finding.get('severity', 'INFO')} {risk.get('priority', 'P4')} finding in {source['project_name']}.",
            f"Rule {finding.get('rule_id', '')} from {finding.get('source', '')}: {finding.get('title', '')}.",
            f"Scope {finding.get('scope', 'unknown')} at {location.get('path', 'unknown')} line {location.get('line', 1)}.",
            f"Risk score {risk.get('score', 0)} tier {risk.get('tier', finding.get('severity', 'INFO'))}.",
            f"Message: {finding.get('message', '')}.",
            f"Remediation: {finding.get('fix', {}).get('summary', '')}.",
            f"Decision state: {decision.get('state', 'open')}.",
        ]
    )
    return make_memory_item(
        item_type='finding-pattern',
        title=f"{finding.get('severity', 'INFO')} {finding.get('title', 'Finding')}",
        text=text,
        tags=tags,
        metadata={
            'finding_id': str(finding.get('id') or ''),
            'fingerprint': str(finding.get('fingerprint') or ''),
            'source': str(finding.get('source') or ''),
            'rule_id': str(finding.get('rule_id') or ''),
            'severity': str(finding.get('severity') or ''),
            'priority': str(risk.get('priority') or ''),
            'risk_score': str(risk.get('score') or 0),
            'scope': str(finding.get('scope') or ''),
            'path': str(location.get('path') or ''),
            'decision': str(decision.get('state') or 'open'),
        },
        source=source,
        eligibility=eligibility,
        retrieval_allowed=retrieval_allowed,
        key_parts=['finding-pattern', source['scan_id'], str(finding.get('fingerprint') or finding.get('id') or '')],
    )


def rule_pattern_items(report: dict[str, Any], source: dict[str, Any], eligibility: dict[str, Any], retrieval_allowed: bool) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in report.get('findings', []):
        grouped[str(finding.get('rule_id') or 'unknown')].append(finding)
    items: list[dict[str, Any]] = []
    for rule_id, findings in sorted(grouped.items(), key=lambda pair: (-len(pair[1]), pair[0]))[:MAX_RULE_ITEMS_PER_SCAN]:
        severities = Counter(str(item.get('severity') or 'INFO') for item in findings)
        scopes = Counter(str(item.get('scope') or 'unknown') for item in findings)
        cwe = sorted({tag for item in findings for tag in item.get('cwe', [])})
        sources = sorted({str(item.get('source') or '') for item in findings if item.get('source')})
        text = (
            f"Rule pattern {rule_id} appeared {len(findings)} time(s) in {source['project_name']}. "
            f"Severities: {dict(severities)}. Scopes: {dict(scopes)}. CWE tags: {', '.join(cwe) or 'none'}."
        )
        items.append(
            make_memory_item(
                item_type='rule-pattern',
                title=f"Rule pattern: {rule_id}",
                text=text,
                tags=['RULE', *[tag.upper() for tag in cwe], *[item.upper() for item in sources]],
                metadata={'rule_id': rule_id, 'count': str(len(findings)), 'sources': ','.join(sources)},
                source=source,
                eligibility=eligibility,
                retrieval_allowed=retrieval_allowed,
                key_parts=['rule-pattern', source['scan_id'], rule_id],
            )
        )
    return items


def dependency_signal_items(report: dict[str, Any], source: dict[str, Any], eligibility: dict[str, Any], retrieval_allowed: bool) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for finding in report.get('findings', [])[:MAX_FINDING_ITEMS_PER_SCAN]:
        metadata = finding.get('scanner_metadata') or {}
        source_name = str(finding.get('source') or '').lower()
        scope = str(finding.get('scope') or '').lower()
        metadata_text = ' '.join(f'{key}:{value}' for key, value in metadata.items()).lower()
        if not any(token in ' '.join([source_name, scope, metadata_text]) for token in ['dependency', 'pip-audit', 'govulncheck', 'package', 'cve-', 'sca']):
            continue
        risk = finding.get('risk') or {}
        package = metadata.get('dependency_name') or metadata.get('package') or metadata.get('component') or finding.get('rule_id')
        text = (
            f"Dependency signal for {package}: {finding.get('severity', 'INFO')} {finding.get('title', '')}. "
            f"Rule {finding.get('rule_id', '')}; risk score {risk.get('score', 0)}; reachability {finding.get('reachability', 'unknown')}. "
            f"Message: {finding.get('message', '')}."
        )
        items.append(
            make_memory_item(
                item_type='dependency-signal',
                title=f"Dependency signal: {package}",
                text=text,
                tags=['DEPENDENCY', 'SCA', *finding_tags(finding)],
                metadata={
                    'finding_id': str(finding.get('id') or ''),
                    'package': str(package or ''),
                    'rule_id': str(finding.get('rule_id') or ''),
                    'severity': str(finding.get('severity') or ''),
                    'priority': str(risk.get('priority') or ''),
                    'reachability': str(finding.get('reachability') or ''),
                },
                source=source,
                eligibility=eligibility,
                retrieval_allowed=retrieval_allowed,
                key_parts=['dependency-signal', source['scan_id'], str(finding.get('fingerprint') or finding.get('id') or '')],
            )
        )
        if len(items) >= MAX_DEPENDENCY_ITEMS_PER_SCAN:
            break
    return items


def scanner_status_item(report: dict[str, Any], source: dict[str, Any], eligibility: dict[str, Any], retrieval_allowed: bool) -> dict[str, Any]:
    tools = (report.get('summary') or {}).get('tools') or {}
    text = f"Scanner status for {source['project_name']}: " + '; '.join(f'{name}={status}' for name, status in tools.items())
    return make_memory_item(
        item_type='scanner-status',
        title=f"Scanner status: {source['project_name']}",
        text=text,
        tags=['SCANNER', 'STATUS', *[str(name).upper() for name in tools.keys()]],
        metadata={str(key): str(value) for key, value in tools.items()},
        source=source,
        eligibility=eligibility,
        retrieval_allowed=retrieval_allowed,
        key_parts=['scanner-status', source['scan_id']],
    )


def make_memory_item(
    *,
    item_type: str,
    title: str,
    text: str,
    tags: list[str],
    metadata: dict[str, str],
    source: dict[str, Any],
    eligibility: dict[str, Any],
    retrieval_allowed: bool,
    key_parts: list[str],
) -> dict[str, Any]:
    safe_text = compact_text(text, max_length=MAX_TEXT_LENGTH)
    item_id = stable_id(*key_parts, safe_text)
    return {
        'schema_version': SCHEMA_VERSION,
        'item_id': item_id,
        'item_type': item_type,
        'title': compact_text(title, max_length=220),
        'text': safe_text,
        'tags': sorted({normalize_tag(tag) for tag in tags if normalize_tag(tag)}),
        'metadata': {compact_text(key, max_length=80): compact_text(value, max_length=220) for key, value in metadata.items() if key},
        'source': source,
        'eligibility': {
            'retrieval_allowed': bool(retrieval_allowed),
            'agent_learning_allowed': bool(eligibility.get('agent_learning_allowed')),
            'fine_tuning_allowed': False,
            'requires_human_review': True,
            'requires_benchmark_gate': True,
            'blocked_reason': '' if retrieval_allowed else str(eligibility.get('blocked_reason') or 'rag ingest disabled by policy'),
        },
        'safety': {
            'source_record_type': 'sanitized-report-lake',
            'raw_code_included': False,
            'patches_included': False,
            'full_local_paths_included': False,
            'secret_redaction': 'inherited-from-sanitized-report-lake',
        },
        'created_at': now_iso(),
    }


def scan_memory_report(source: dict[str, Any], eligibility: dict[str, Any], status: str, items: list[dict[str, Any]], skipped_reason: str) -> dict[str, Any]:
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'memory_record_type': 'rag-memory-scan',
        'status': status,
        'source': source,
        'eligibility': eligibility,
        'item_count': len(items),
        'items': items,
        'skipped_reason': skipped_reason,
        'guardrails': rag_memory_schema()['guardrails'],
    }


def update_global_index(memory: dict[str, Any]) -> None:
    ensure_rag_memory_dirs()
    index = load_rag_memory_index()
    scan_id = str(memory.get('source', {}).get('scan_id') or '')
    existing = [item for item in index.get('items', []) if item.get('source', {}).get('scan_id') != scan_id]
    new_items = [item for item in memory.get('items', []) if item.get('eligibility', {}).get('retrieval_allowed')]
    payload = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'item_count': len(existing) + len(new_items),
        'items': [*new_items, *existing],
        'active_memory_versions': active_memory_versions_by_scan(),
        'schema': rag_memory_schema(),
    }
    rag_memory_index_path().write_text(json.dumps(payload, indent=2), encoding='utf-8')


def load_rag_memory_index() -> dict[str, Any]:
    path = rag_memory_index_path()
    if not path.exists():
        return {'schema_version': SCHEMA_VERSION, 'generated_at': None, 'item_count': 0, 'items': [], 'schema': rag_memory_schema()}
    payload = json.loads(path.read_text(encoding='utf-8'))
    payload.setdefault('items', [])
    payload.setdefault('schema_version', SCHEMA_VERSION)
    payload.setdefault('schema', rag_memory_schema())
    payload.setdefault('active_memory_versions', active_memory_versions_by_scan())
    payload['item_count'] = len(payload.get('items', []))
    return payload


def reset_rag_memory_index() -> None:
    ensure_rag_memory_dirs()
    payload = {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'item_count': 0,
        'items': [],
        'active_memory_versions': active_memory_versions_by_scan(),
        'schema': rag_memory_schema(),
    }
    rag_memory_index_path().write_text(json.dumps(payload, indent=2), encoding='utf-8')


def attach_memory_version(memory: dict[str, Any], previous_version_id: str = '') -> dict[str, Any]:
    version_id = memory_version_id(memory)
    source = dict(memory.get('source') or {})
    source['memory_version_id'] = version_id
    memory['source'] = source
    for item in memory.get('items', []):
        item_source = dict(item.get('source') or {})
        item_source['memory_version_id'] = version_id
        item['source'] = item_source
    memory['memory_version'] = {
        'version_id': version_id,
        'created_at': now_iso(),
        'previous_version_id': previous_version_id,
        'scan_id': source.get('scan_id'),
        'project_name': source.get('project_name'),
        'item_count': memory.get('item_count', 0),
        'status': memory.get('status'),
        'snapshot_path': str(rag_memory_versions_dir() / f'{safe_scan_filename(version_id)}.json'),
    }
    return memory


def memory_version_id(memory: dict[str, Any]) -> str:
    payload = {
        'status': memory.get('status'),
        'source': strip_memory_version(memory.get('source') or {}),
        'eligibility': memory.get('eligibility') or {},
        'items': [strip_memory_item(item) for item in memory.get('items', [])],
        'skipped_reason': memory.get('skipped_reason', ''),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    return 'mem-' + hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:20]


def strip_memory_item(item: dict[str, Any]) -> dict[str, Any]:
    return {key: strip_memory_version(value) if key == 'source' else value for key, value in item.items() if key not in {'created_at'}}


def strip_memory_version(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != 'memory_version_id'}


def load_memory_versions() -> dict[str, Any]:
    ensure_rag_memory_dirs()
    path = rag_memory_versions_path()
    if not path.exists():
        payload = {'schema_version': SCHEMA_VERSION, 'generated_at': now_iso(), 'versions': []}
        save_memory_versions(payload)
        return payload
    payload = json.loads(path.read_text(encoding='utf-8'))
    payload.setdefault('schema_version', SCHEMA_VERSION)
    payload.setdefault('versions', [])
    return payload


def save_memory_versions(payload: dict[str, Any]) -> dict[str, Any]:
    ensure_rag_memory_dirs()
    payload['schema_version'] = SCHEMA_VERSION
    payload['generated_at'] = now_iso()
    rag_memory_versions_path().write_text(json.dumps(payload, indent=2), encoding='utf-8')
    return payload


def register_memory_version(memory: dict[str, Any], previous_version_id: str = '') -> dict[str, Any]:
    version = memory.get('memory_version') or {}
    version_id = str(version.get('version_id') or '')
    scan_id = str(version.get('scan_id') or '')
    if not version_id or not scan_id:
        return {}
    path = rag_memory_versions_dir() / f'{safe_scan_filename(version_id)}.json'
    path.write_text(json.dumps(memory, indent=2), encoding='utf-8')
    registry = load_memory_versions()
    versions = [item for item in registry.get('versions', []) if item.get('version_id') != version_id]
    for item in versions:
        if item.get('scan_id') == scan_id:
            item['active'] = False
    record = {
        'version_id': version_id,
        'created_at': version.get('created_at') or now_iso(),
        'scan_id': scan_id,
        'project_name': version.get('project_name') or '',
        'status': version.get('status') or memory.get('status'),
        'item_count': memory.get('item_count', 0),
        'previous_version_id': previous_version_id,
        'active': True,
        'snapshot_path': str(path),
        'raw_code_included': False,
        'raw_report_included': False,
    }
    versions.append(record)
    registry['versions'] = sorted(versions, key=lambda item: item.get('created_at') or '', reverse=True)
    save_memory_versions(registry)
    return record


def set_active_memory_version(scan_id: str, version_id: str) -> None:
    registry = load_memory_versions()
    found = False
    for item in registry.get('versions', []):
        if item.get('scan_id') == scan_id:
            item['active'] = item.get('version_id') == version_id
            found = found or item['active']
    if not found:
        memory = load_memory_version(version_id)
        register_memory_version(memory, previous_version_id=latest_memory_version_for_scan(scan_id))
        return
    save_memory_versions(registry)


def latest_memory_version_for_scan(scan_id: str) -> str:
    if not scan_id:
        return ''
    registry = load_memory_versions()
    for item in registry.get('versions', []):
        if item.get('scan_id') == scan_id and item.get('active'):
            return str(item.get('version_id') or '')
    for item in registry.get('versions', []):
        if item.get('scan_id') == scan_id:
            return str(item.get('version_id') or '')
    return ''


def active_memory_versions_by_scan() -> dict[str, str]:
    registry = load_memory_versions()
    return {
        str(item.get('scan_id')): str(item.get('version_id'))
        for item in registry.get('versions', [])
        if item.get('scan_id') and item.get('version_id') and item.get('active')
    }


def source_from_report(report: dict[str, Any]) -> dict[str, Any]:
    source_scan = report.get('source_scan') or {}
    target = source_scan.get('target') or {}
    return {
        'scan_id': str(source_scan.get('scan_id') or ''),
        'project_name': str(source_scan.get('project_name') or ''),
        'created_at': str(source_scan.get('created_at') or ''),
        'repo_name': str(target.get('repo_name') or ''),
        'target_path_hash': str(target.get('target_path_hash') or ''),
        'target_path_hint': str(target.get('target_path_hint') or ''),
        'source_report_type': 'sanitized-report-lake',
    }


def scan_index_record(memory: dict[str, Any]) -> dict[str, Any]:
    return {
        'scan_id': memory.get('source', {}).get('scan_id'),
        'project_name': memory.get('source', {}).get('project_name'),
        'generated_at': memory.get('generated_at'),
        'status': memory.get('status'),
        'item_count': memory.get('item_count', 0),
        'skipped_reason': memory.get('skipped_reason', ''),
        'eligibility': memory.get('eligibility', {}),
        'memory_version': memory.get('memory_version', {}),
    }


def public_memory_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        'item_id': item.get('item_id'),
        'item_type': item.get('item_type'),
        'title': item.get('title'),
        'text': item.get('text'),
        'tags': item.get('tags', []),
        'metadata': item.get('metadata', {}),
        'source': item.get('source', {}),
        'eligibility': item.get('eligibility', {}),
        'safety': item.get('safety', {}),
    }


def finding_tags(finding: dict[str, Any]) -> list[str]:
    risk = finding.get('risk') or {}
    return [
        str(finding.get('source') or ''),
        str(finding.get('severity') or ''),
        str(risk.get('tier') or ''),
        str(risk.get('priority') or ''),
        str(finding.get('scope') or ''),
        *[str(item) for item in finding.get('cwe', [])],
        *[str(item) for item in finding.get('owasp', [])],
    ]


def summary_tags(summary: dict[str, Any]) -> list[str]:
    return [
        *[str(key) for key in (summary.get('languages') or {}).keys()],
        *[str(key) for key in (summary.get('risk_tiers') or {}).keys()],
        *[str(key) for key in (summary.get('priorities') or {}).keys()],
        *[str(key) for key in (summary.get('scope_counts') or {}).keys()],
    ]


def memory_document_frequencies(items: list[dict[str, Any]]) -> Counter:
    frequencies: Counter = Counter()
    for item in items:
        frequencies.update(set(tokenize(memory_searchable_text(item))))
    return frequencies


def score_memory_item(
    item: dict[str, Any],
    raw_query: str,
    query_terms: Counter,
    requested_tags: set[str],
    doc_freq: Counter,
    corpus_size: int,
) -> float:
    if not query_terms and not requested_tags:
        return 0.0
    text = memory_searchable_text(item)
    title_terms = Counter(tokenize(str(item.get('title') or '')))
    tag_terms = Counter(tokenize(' '.join(item.get('tags', []))))
    metadata_terms = Counter(tokenize(' '.join(str(value) for value in (item.get('metadata') or {}).values())))
    body_terms = Counter(tokenize(str(item.get('text') or '')))
    score = 0.0
    for term, query_count in query_terms.items():
        idf = math.log((corpus_size + 1) / (doc_freq.get(term, 0) + 1)) + 1
        score += min(query_count, title_terms.get(term, 0)) * 5 * idf
        score += min(query_count, tag_terms.get(term, 0)) * 4 * idf
        score += min(query_count, metadata_terms.get(term, 0)) * 2 * idf
        score += min(query_count, body_terms.get(term, 0)) * idf
    raw_lower = raw_query.lower().strip()
    if raw_lower and raw_lower in text.lower():
        score += 6
    if requested_tags:
        item_tags = {str(tag).upper() for tag in item.get('tags', [])}
        score += 8 * len(requested_tags & item_tags)
    query_vocab = set(query_terms)
    if query_vocab:
        score += 3 * (len(query_vocab & set(tokenize(text))) / len(query_vocab))
    return score


def memory_searchable_text(item: dict[str, Any]) -> str:
    metadata = item.get('metadata') or {}
    source = item.get('source') or {}
    return ' '.join(
        [
            str(item.get('title') or ''),
            str(item.get('text') or ''),
            ' '.join(str(tag) for tag in item.get('tags', [])),
            ' '.join(str(value) for value in metadata.values()),
            str(source.get('project_name') or ''),
            str(source.get('repo_name') or ''),
        ]
    )


def compact_text(value: Any, max_length: int) -> str:
    text = '' if value is None else str(value)
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    if len(text) > max_length:
        return f'{text[: max_length - 14].rstrip()}...[truncated]'
    return text


def normalize_tag(tag: Any) -> str:
    text = compact_text(tag, max_length=80).upper()
    return re.sub(r'[^A-Z0-9_.:/+-]+', '-', text).strip('-')


def stable_id(*parts: str) -> str:
    raw = '\n'.join(str(part or '') for part in parts)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:24]


def safe_scan_filename(scan_id: str) -> str:
    safe = re.sub(r'[^A-Za-z0-9_.:-]+', '-', str(scan_id or '').strip()).strip('-')
    return safe.replace(':', '-')[:160] or 'unknown'
