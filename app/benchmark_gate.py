from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .paths import data_dir

SCHEMA_VERSION = 1
PROMOTION_STATES = ['proposed', 'reviewed', 'benchmarked', 'approved', 'active']
NEXT_STATES = {
    'proposed': {'reviewed'},
    'reviewed': {'benchmarked'},
    'benchmarked': {'approved'},
    'approved': {'active'},
    'active': set(),
}
CASE_TYPES = ['rule-regression', 'false-positive', 'fix-validation']
PROBLEM_STATUS_TOKENS = ('failed', 'error', 'disabled', 'missing', 'not installed', 'not configured', 'timeout', 'timed out')
PROJECT_ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = PROJECT_ROOT / 'benchmarks' / 'language-corpus.json'


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def benchmark_gate_dir() -> Path:
    return data_dir() / 'benchmark-gate'


def lessons_path() -> Path:
    return benchmark_gate_dir() / 'lessons.json'


def ensure_benchmark_gate_dirs() -> None:
    benchmark_gate_dir().mkdir(parents=True, exist_ok=True)


def load_benchmark_corpus() -> dict[str, Any]:
    if CORPUS_PATH.exists():
        corpus = json.loads(CORPUS_PATH.read_text(encoding='utf-8'))
    else:
        corpus = default_benchmark_corpus()
    corpus.setdefault('schema_version', SCHEMA_VERSION)
    corpus.setdefault('languages', [])
    return corpus


def benchmark_corpus_report(language: str | None = None) -> dict[str, Any]:
    corpus = load_benchmark_corpus()
    requested = normalize_language(language) if language else ''
    languages = [
        item
        for item in corpus.get('languages', [])
        if not requested or normalize_language(item.get('language')) == requested
    ]
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'corpus_path': str(CORPUS_PATH),
        'language_count': len(languages),
        'case_count': sum(len(item.get('cases', [])) for item in languages),
        'case_type_counts': corpus_case_type_counts(languages),
        'languages': languages,
        'guardrails': corpus.get('guardrails', []),
    }


def benchmark_gate_status() -> dict[str, Any]:
    corpus = load_benchmark_corpus()
    lessons = load_lessons()
    languages = corpus.get('languages', [])
    lesson_rows = lessons.get('lessons', [])
    state_counts = Counter(lesson.get('promotion_state', 'proposed') for lesson in lesson_rows)
    influence_allowed = [lesson for lesson in lesson_rows if lesson_influence_allowed(lesson)]
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'status': 'ready',
        'promotion_states': PROMOTION_STATES,
        'corpus_path': str(CORPUS_PATH),
        'lesson_store': str(lessons_path()),
        'language_count': len(languages),
        'case_count': sum(len(item.get('cases', [])) for item in languages),
        'case_type_counts': corpus_case_type_counts(languages),
        'lesson_count': len(lesson_rows),
        'lesson_state_counts': dict(state_counts),
        'active_influence_count': len(influence_allowed),
        'guardrails': benchmark_guardrails(),
    }


def list_benchmark_lessons(state: str | None = None, language: str | None = None) -> dict[str, Any]:
    lessons = load_lessons().get('lessons', [])
    requested_state = normalize_state(state) if state else ''
    requested_language = normalize_language(language) if language else ''
    rows = []
    for lesson in lessons:
        if requested_state and lesson.get('promotion_state') != requested_state:
            continue
        if requested_language and normalize_language(lesson.get('language')) != requested_language:
            continue
        rows.append(lesson)
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'count': len(rows),
        'lessons': rows,
        'guardrails': benchmark_guardrails(),
    }


def load_lessons() -> dict[str, Any]:
    ensure_benchmark_gate_dirs()
    path = lessons_path()
    if not path.exists():
        payload = {'schema_version': SCHEMA_VERSION, 'generated_at': now_iso(), 'lessons': []}
        save_lessons(payload)
        return payload
    payload = json.loads(path.read_text(encoding='utf-8'))
    payload.setdefault('schema_version', SCHEMA_VERSION)
    payload.setdefault('lessons', [])
    return payload


def save_lessons(payload: dict[str, Any]) -> dict[str, Any]:
    ensure_benchmark_gate_dirs()
    payload['schema_version'] = SCHEMA_VERSION
    payload['generated_at'] = now_iso()
    lessons_path().write_text(json.dumps(payload, indent=2), encoding='utf-8')
    return payload


def upsert_benchmark_lesson(payload: dict[str, Any], actor: str = 'system') -> dict[str, Any]:
    store = load_lessons()
    lessons = store.get('lessons', [])
    normalized = normalize_lesson_payload(payload, actor=actor)
    existing_index = next((index for index, lesson in enumerate(lessons) if lesson.get('lesson_id') == normalized['lesson_id']), None)
    if existing_index is None:
        lessons.append(normalized)
    else:
        existing = lessons[existing_index]
        if existing.get('promotion_state') != 'proposed':
            raise ValueError('Only proposed benchmark lessons can be edited directly; use state transitions for promoted lessons.')
        merged = {**existing, **normalized, 'created_at': existing.get('created_at'), 'history': existing.get('history', [])}
        merged['history'].append(history_event(actor, 'lesson-updated', 'Proposed lesson metadata updated.'))
        lessons[existing_index] = merged
        normalized = merged
    store['lessons'] = sorted(lessons, key=lambda lesson: (lesson.get('language', ''), lesson.get('category', ''), lesson.get('title', '')))
    save_lessons(store)
    return normalized


def transition_benchmark_lesson(
    lesson_id: str,
    target_state: str,
    *,
    actor: str = 'system',
    note: str = '',
    benchmark_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    store = load_lessons()
    lessons = store.get('lessons', [])
    target = normalize_state(target_state)
    for index, lesson in enumerate(lessons):
        if lesson.get('lesson_id') != lesson_id:
            continue
        current = lesson.get('promotion_state', 'proposed')
        if target not in NEXT_STATES.get(current, set()):
            raise ValueError(f'Invalid benchmark promotion transition: {current} -> {target}')
        updated = dict(lesson)
        updated['updated_at'] = now_iso()
        updated.setdefault('history', [])
        if target == 'reviewed':
            updated['review'] = {'reviewed_by': actor, 'reviewed_at': now_iso(), 'note': safe_text(note, 500)}
        if target == 'benchmarked':
            evidence = benchmark_evidence or {}
            report = evaluate_benchmark_evidence(updated, evidence)
            if not report['passed']:
                raise ValueError('Benchmark evidence did not pass the benchmark gate.')
            updated['benchmark'] = report
        if target == 'approved':
            benchmark = updated.get('benchmark') or {}
            if not benchmark.get('passed'):
                raise ValueError('Lesson must have passing benchmark evidence before approval.')
            updated['approval'] = {'approved_by': actor, 'approved_at': now_iso(), 'note': safe_text(note, 500)}
        if target == 'active':
            if not lesson_influence_allowed({**updated, 'promotion_state': 'active'}):
                raise ValueError('Only approved and benchmarked lessons can become active.')
            updated['active_since'] = now_iso()
        reason = promotion_reason(updated, target, note)
        updated['promotion_reason'] = reason
        updated['promotion_state'] = target
        updated['learning_influence_allowed'] = lesson_influence_allowed(updated)
        updated['history'].append(history_event(actor, f'promoted-to-{target}', reason))
        lessons[index] = updated
        store['lessons'] = lessons
        save_lessons(store)
        try:
            from .governance import record_lesson_promotion_event

            record_lesson_promotion_event(updated, previous_state=current, target_state=target, actor=actor, reason=reason)
        except Exception:
            pass
        return updated
    raise FileNotFoundError(lesson_id)


def normalize_lesson_payload(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    language = normalize_language(payload.get('language') or infer_language(payload))
    category = safe_slug(payload.get('category') or 'scanner-learning')
    title = safe_text(payload.get('title') or 'Benchmark-gated scanner lesson', 220)
    source = safe_text(payload.get('source') or payload.get('scanner') or '', 80)
    rule_id = safe_text(payload.get('rule_id') or '', 180)
    recommendation_id = safe_text(payload.get('recommendation_id') or payload.get('id') or '', 120)
    lesson_id = safe_slug(payload.get('lesson_id') or stable_id(language, category, source, rule_id, recommendation_id, title))
    created = now_iso()
    return {
        'schema_version': SCHEMA_VERSION,
        'lesson_id': lesson_id,
        'recommendation_id': recommendation_id,
        'language': language or 'unknown',
        'category': category,
        'source': source,
        'rule_id': rule_id,
        'title': title,
        'proposed_change': safe_text(payload.get('proposed_change') or payload.get('recommended_change') or '', 1000),
        'evidence_summary': sanitize_jsonable(payload.get('evidence') or {}),
        'promotion_state': 'proposed',
        'learning_influence_allowed': False,
        'created_by': actor,
        'created_at': created,
        'updated_at': created,
        'review': {},
        'benchmark': {},
        'approval': {},
        'promotion_reason': '',
        'history': [history_event(actor, 'proposed', 'Benchmark lesson proposed.')],
        'guardrails': benchmark_guardrails(),
    }


def promotion_reason(lesson: dict[str, Any], target: str, note: str) -> str:
    cleaned = safe_text(note, 500)
    if cleaned:
        return cleaned
    if target == 'reviewed':
        return 'Human reviewer accepted the lesson for benchmark testing.'
    if target == 'benchmarked':
        checks = (lesson.get('benchmark') or {}).get('checks', [])
        passed = [check.get('name') for check in checks if check.get('status') == 'passed']
        return f'Benchmark evidence passed required checks: {", ".join(passed) or "all required checks"}.'
    if target == 'approved':
        return 'Human approval recorded after passing benchmark evidence.'
    if target == 'active':
        return 'Activated only after human approval and passing benchmark evidence.'
    return f'Lesson promoted to {target}.'


def evaluate_benchmark_evidence(lesson: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    corpus = load_benchmark_corpus()
    language = normalize_language(evidence.get('language') or lesson.get('language'))
    language_corpus = corpus_language(corpus, language)
    checks = []

    checks.append(check_corpus_coverage(language_corpus, evidence))
    checks.append(check_rule_regression(evidence))
    checks.append(check_false_positive(evidence))
    checks.append(check_fix_validation(evidence))
    checks.append(check_scanner_status(evidence))

    passed = all(check['status'] == 'passed' for check in checks)
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'language': language or 'unknown',
        'passed': passed,
        'status': 'passed' if passed else 'failed',
        'checks': checks,
        'raw_evidence': sanitize_jsonable(evidence),
        'corpus_case_counts': corpus_case_type_counts([language_corpus] if language_corpus else []),
        'requires_human_approval': True,
        'requires_no_true_positive_regression': True,
        'requires_false_positive_review': True,
        'requires_fix_validation': True,
    }


def check_corpus_coverage(language_corpus: dict[str, Any] | None, evidence: dict[str, Any]) -> dict[str, Any]:
    if not language_corpus:
        return failed_check('corpus-coverage', 'No benchmark corpus exists for this lesson language.')
    case_ids = {str(item) for item in evidence.get('benchmark_case_ids', []) if item}
    cases = language_corpus.get('cases', [])
    types = {case.get('case_type') for case in cases}
    referenced = [case for case in cases if case.get('case_id') in case_ids]
    referenced_types = {case.get('case_type') for case in referenced}
    if not case_ids:
        return failed_check('corpus-coverage', 'Benchmark evidence must reference specific corpus case IDs.')
    if case_ids and all(case_type in referenced_types for case_type in CASE_TYPES):
        return passed_check('corpus-coverage', f'Referenced benchmark cases cover {", ".join(CASE_TYPES)}.')
    if all(case_type in types for case_type in CASE_TYPES):
        return failed_check('corpus-coverage', 'Referenced benchmark cases must cover rule regression, false-positive, and fix-validation case types.')
    return failed_check('corpus-coverage', 'Language corpus is missing one or more required benchmark case types.')


def check_rule_regression(evidence: dict[str, Any]) -> dict[str, Any]:
    section = evidence.get('rule_regression') or evidence.get('true_positive_regression') or {}
    expected = safe_int(section.get('expected_true_positives') or section.get('true_positive_total') or section.get('total') or 0)
    preserved = safe_int(section.get('preserved_true_positives') or section.get('true_positive_preserved') or section.get('passed') or 0)
    if expected > 0 and preserved >= expected:
        return passed_check('rule-regression', f'Preserved {preserved}/{expected} known true-positive benchmark cases.')
    return failed_check('rule-regression', 'Benchmark evidence must preserve all known true-positive rule-regression cases.')


def check_false_positive(evidence: dict[str, Any]) -> dict[str, Any]:
    section = evidence.get('false_positive') or evidence.get('false_positive_review') or {}
    before = safe_int(section.get('before') or section.get('false_positive_before') or 0)
    after = safe_int(section.get('after') or section.get('false_positive_after') or 0)
    reviewed = safe_int(section.get('reviewed') or section.get('reviewed_false_positives') or before)
    if reviewed > 0 and after <= before:
        return passed_check('false-positive', f'False positives did not increase: before={before}, after={after}, reviewed={reviewed}.')
    return failed_check('false-positive', 'False-positive evidence must be reviewed and must not increase noise.')


def check_fix_validation(evidence: dict[str, Any]) -> dict[str, Any]:
    section = evidence.get('fix_validation') or {}
    total = safe_int(section.get('total') or section.get('validation_total') or 0)
    passed = safe_int(section.get('passed') or section.get('validation_passed') or 0)
    if total > 0 and passed >= total:
        return passed_check('fix-validation', f'Fix validation passed {passed}/{total} checks.')
    return failed_check('fix-validation', 'Fix validation tests or commands must all pass before promotion.')


def check_scanner_status(evidence: dict[str, Any]) -> dict[str, Any]:
    status = str(evidence.get('scanner_status') or evidence.get('status') or 'ok').lower()
    if not any(token in status for token in PROBLEM_STATUS_TOKENS):
        return passed_check('scanner-status', f'Scanner status evidence is {status}.')
    return failed_check('scanner-status', f'Scanner status is not promotion-safe: {status}.')


def benchmark_gate_report_for_recommendations(recommendations: list[dict[str, Any]]) -> dict[str, Any]:
    annotated = annotate_recommendations_with_benchmark_gate(recommendations)
    influence_allowed = [item for item in annotated if item.get('learning_influence_allowed')]
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'status': 'influence_allowed' if influence_allowed else 'blocked_until_benchmarked_and_approved',
        'recommendation_count': len(annotated),
        'influence_allowed_count': len(influence_allowed),
        'promotion_state_counts': dict(Counter((item.get('promotion') or {}).get('state', 'proposed') for item in annotated)),
        'recommendations': annotated,
        'active_lessons': approved_learning_influences(),
        'promotion_states': PROMOTION_STATES,
        'guardrails': benchmark_guardrails(),
    }


def annotate_recommendations_with_benchmark_gate(recommendations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    lessons = load_lessons().get('lessons', [])
    annotated = []
    for recommendation in recommendations:
        item = dict(recommendation)
        matching = matching_lessons(recommendation, lessons)
        best = best_lesson(matching)
        influence_allowed = bool(best and lesson_influence_allowed(best))
        state = best.get('promotion_state') if best else 'proposed'
        item['promotion'] = {
            'state': state,
            'lesson_id': best.get('lesson_id') if best else None,
            'benchmark_passed': bool((best.get('benchmark') or {}).get('passed')) if best else False,
            'approved': bool((best.get('approval') or {}).get('approved_at')) if best else False,
            'active': state == 'active',
            'learning_influence_allowed': influence_allowed,
            'blocked_reason': '' if influence_allowed else 'Only active lessons with passing benchmark evidence and human approval can influence scanner/rule recommendations.',
        }
        item['learning_influence_allowed'] = influence_allowed
        item['matching_lesson_count'] = len(matching)
        annotated.append(item)
    return annotated


def approved_learning_influences(language: str | None = None, category: str | None = None) -> list[dict[str, Any]]:
    requested_language = normalize_language(language) if language else ''
    requested_category = safe_slug(category) if category else ''
    rows = []
    for lesson in load_lessons().get('lessons', []):
        if not lesson_influence_allowed(lesson):
            continue
        if requested_language and normalize_language(lesson.get('language')) != requested_language:
            continue
        if requested_category and safe_slug(lesson.get('category')) != requested_category:
            continue
        rows.append(public_lesson_influence(lesson))
    return rows


def lesson_influence_allowed(lesson: dict[str, Any]) -> bool:
    return (
        lesson.get('promotion_state') == 'active'
        and bool((lesson.get('benchmark') or {}).get('passed'))
        and bool((lesson.get('approval') or {}).get('approved_at'))
    )


def matching_lessons(recommendation: dict[str, Any], lessons: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rec_id = str(recommendation.get('id') or '')
    rec_category = safe_slug(recommendation.get('category') or '')
    evidence = recommendation.get('evidence') or {}
    rec_source = safe_text(evidence.get('source') or recommendation.get('source') or '', 80)
    rec_rule = safe_text(evidence.get('rule_id') or recommendation.get('rule_id') or '', 180)
    rec_language = normalize_language(evidence.get('language_or_framework') or recommendation.get('language') or '')
    result = []
    for lesson in lessons:
        if rec_id and lesson.get('recommendation_id') == rec_id:
            result.append(lesson)
            continue
        if rec_category and safe_slug(lesson.get('category')) != rec_category:
            continue
        if rec_source and lesson.get('source') and lesson.get('source') != rec_source:
            continue
        if rec_rule and lesson.get('rule_id') and lesson.get('rule_id') != rec_rule:
            continue
        if rec_language and normalize_language(lesson.get('language')) != rec_language:
            continue
        if rec_source or rec_rule or rec_language:
            result.append(lesson)
    return result


def best_lesson(lessons: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not lessons:
        return None
    rank = {state: index for index, state in enumerate(PROMOTION_STATES)}
    return sorted(lessons, key=lambda lesson: (rank.get(lesson.get('promotion_state'), -1), lesson.get('updated_at', '')), reverse=True)[0]


def public_lesson_influence(lesson: dict[str, Any]) -> dict[str, Any]:
    return {
        'lesson_id': lesson.get('lesson_id'),
        'recommendation_id': lesson.get('recommendation_id'),
        'language': lesson.get('language'),
        'category': lesson.get('category'),
        'source': lesson.get('source'),
        'rule_id': lesson.get('rule_id'),
        'title': lesson.get('title'),
        'proposed_change': lesson.get('proposed_change'),
        'evidence_summary': lesson.get('evidence_summary') or {},
        'promotion_state': lesson.get('promotion_state'),
        'benchmark': {
            'status': (lesson.get('benchmark') or {}).get('status'),
            'passed': bool((lesson.get('benchmark') or {}).get('passed')),
            'generated_at': (lesson.get('benchmark') or {}).get('generated_at'),
        },
        'approval': {
            'approved_at': (lesson.get('approval') or {}).get('approved_at'),
            'approved_by': (lesson.get('approval') or {}).get('approved_by'),
        },
        'learning_influence_allowed': lesson_influence_allowed(lesson),
    }


def promotion_gate() -> dict[str, Any]:
    return {
        'states': PROMOTION_STATES,
        'required_sequence': 'proposed -> reviewed -> benchmarked -> approved -> active',
        'influence_rule': 'Only active lessons with passing benchmark evidence and human approval can influence future scanner/rule recommendations.',
        'required_benchmark_evidence': {
            'rule_regression': 'known true positives preserved',
            'false_positive': 'reviewed false-positive noise does not increase',
            'fix_validation': 'fix validation tests or commands pass',
            'scanner_status': 'scanner run did not fail or silently skip required coverage',
        },
    }


def benchmark_guardrails() -> list[str]:
    return [
        'Benchmark lessons never rewrite rules, parser code, scanner configuration, suppressions, or repository files automatically.',
        'Promotion must follow proposed, reviewed, benchmarked, approved, then active.',
        'A lesson cannot become active unless benchmark evidence passes and a human approval record exists.',
        'Only active lessons are exposed as learning influences for future scanner/rule recommendations.',
        'Benchmark corpus fixtures are inert expectations; run untrusted repositories only in disposable workers.',
    ]


def corpus_language(corpus: dict[str, Any], language: str) -> dict[str, Any] | None:
    requested = normalize_language(language)
    for item in corpus.get('languages', []):
        if normalize_language(item.get('language')) == requested:
            return item
    return None


def corpus_case_type_counts(languages: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter()
    for language in languages:
        for case in language.get('cases', []):
            counts[case.get('case_type', 'unknown')] += 1
    return dict(counts)


def passed_check(name: str, detail: str) -> dict[str, str]:
    return {'name': name, 'status': 'passed', 'detail': detail}


def failed_check(name: str, detail: str) -> dict[str, str]:
    return {'name': name, 'status': 'failed', 'detail': detail}


def history_event(actor: str, action: str, note: str) -> dict[str, str]:
    return {'at': now_iso(), 'actor': safe_text(actor, 120), 'action': action, 'note': safe_text(note, 500)}


def normalize_state(state: Any) -> str:
    value = safe_slug(state)
    if value not in PROMOTION_STATES:
        raise ValueError(f'Unsupported promotion state: {state}')
    return value


def infer_language(payload: dict[str, Any]) -> str:
    text = ' '.join(str(value) for value in [
        payload.get('language'),
        payload.get('title'),
        payload.get('category'),
        payload.get('source'),
        payload.get('rule_id'),
        payload.get('proposed_change'),
        payload.get('recommended_change'),
    ]).lower()
    for language in ['python', 'go', 'javascript', 'typescript', 'java', 'rust', 'php', 'ruby', 'csharp', 'yaml', 'dockerfile', 'terraform']:
        if language in text:
            return language
    if 'pip-audit' in text or 'bandit' in text:
        return 'python'
    if 'govulncheck' in text or 'golang' in text:
        return 'go'
    return 'unknown'


def normalize_language(value: Any) -> str:
    text = safe_slug(str(value or '').lower())
    aliases = {
        'js': 'javascript',
        'jsx': 'javascript',
        'ts': 'typescript',
        'tsx': 'typescript',
        'golang': 'go',
        'c': 'c',
        'c-sharp': 'csharp',
        'c#': 'csharp',
        'docker': 'dockerfile',
        'hcl': 'terraform',
    }
    return aliases.get(text, text)


def safe_slug(value: Any) -> str:
    return re.sub(r'[^a-zA-Z0-9_.:-]+', '-', str(value or '').strip()).strip('-').lower()


def safe_text(value: Any, max_length: int) -> str:
    text = re.sub(r'[\x00-\x1f\x7f]+', ' ', str(value or ''))
    text = re.sub(r'\s+', ' ', text).strip()
    return f'{text[: max_length - 14].rstrip()}...[truncated]' if len(text) > max_length else text


def safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def sanitize_jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {safe_text(key, 120): sanitize_jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_jsonable(item) for item in value[:100]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return safe_text(value, 500) if isinstance(value, str) else value
    return safe_text(value, 500)


def stable_id(*parts: Any) -> str:
    raw = '\n'.join(str(part or '') for part in parts)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:20]


def default_benchmark_corpus() -> dict[str, Any]:
    languages = []
    for language in ['python', 'go', 'javascript', 'typescript', 'java', 'rust', 'php', 'ruby', 'csharp', 'yaml', 'dockerfile', 'terraform']:
        languages.append({
            'language': language,
            'maintainer': 'AppSec',
            'cases': [
                {
                    'case_id': f'{language}-rule-regression-001',
                    'case_type': 'rule-regression',
                    'purpose': 'Preserve known true-positive security findings for this language.',
                    'expected_outcome': 'finding-preserved',
                },
                {
                    'case_id': f'{language}-false-positive-001',
                    'case_type': 'false-positive',
                    'purpose': 'Prevent noisy benign patterns from increasing after scanner tuning.',
                    'expected_outcome': 'noise-not-increased',
                },
                {
                    'case_id': f'{language}-fix-validation-001',
                    'case_type': 'fix-validation',
                    'purpose': 'Require remediation validation evidence before promotion.',
                    'expected_outcome': 'validation-passed',
                },
            ],
        })
    return {
        'schema_version': SCHEMA_VERSION,
        'name': 'secure-review-language-benchmark-corpus',
        'languages': languages,
        'guardrails': benchmark_guardrails(),
    }
