from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from .enterprise import audit_events
from .models import Finding, ScanResult
from .scope import classify_path_scope, finding_scope, is_production_impacting
from .storage import apply_decisions, list_scans, load_scan

NOISY_RULE_MIN_TOTAL = 25
NOISY_RULE_MIN_SCAN_BURST = 50
FALSE_POSITIVE_RATE_THRESHOLD = 0.25
HYGIENE_RATE_THRESHOLD = 0.65

DEPENDENCY_SOURCES = {'pip-audit', 'govulncheck', 'snyk', 'npm-audit', 'dependency-review'}
PROBLEM_STATUS_TOKENS = (
    'failed',
    'error',
    'partial',
    'timed out',
    'timeout',
    'not installed',
    'not configured',
    'missing',
    'disabled',
)

LANGUAGE_EXPECTATIONS: dict[str, dict[str, Any]] = {
    'python': {'parsers': ['python-ast', 'semgrep', 'bandit', 'pip-audit'], 'support': 'strong'},
    'javascript': {'parsers': ['semgrep', 'codeql', 'dependency-review'], 'support': 'partial'},
    'typescript': {'parsers': ['semgrep', 'codeql', 'dependency-review'], 'support': 'partial'},
    'go': {'parsers': ['semgrep', 'codeql', 'go-module', 'govulncheck'], 'support': 'strong'},
    'terraform': {'parsers': ['semgrep'], 'support': 'partial'},
    'dockerfile': {'parsers': ['semgrep'], 'support': 'partial'},
    'yaml': {'parsers': ['semgrep'], 'support': 'partial'},
    'java': {'parsers': ['semgrep', 'codeql', 'sonarqube'], 'support': 'partial'},
    'kotlin': {'parsers': ['semgrep', 'codeql', 'sonarqube'], 'support': 'partial'},
    'rust': {'parsers': ['semgrep', 'cargo-audit'], 'support': 'gap'},
    'csharp': {'parsers': ['semgrep', 'codeql', 'nuget-audit'], 'support': 'gap'},
    'php': {'parsers': ['semgrep', 'composer-audit'], 'support': 'gap'},
    'ruby': {'parsers': ['semgrep', 'bundler-audit'], 'support': 'gap'},
}


def recursive_learning_report(limit: int = 100) -> dict[str, Any]:
    scans = [apply_decisions(scan) for scan in list_scans()[: max(1, min(limit, 500))]]
    return recursive_learning_from_scans(scans, audit_events(limit=5000), scope='scan-history', requested_limit=limit)


def scan_recursive_learning_report(scan_or_id: ScanResult | str, limit: int = 100) -> dict[str, Any]:
    scan = load_scan(scan_or_id) if isinstance(scan_or_id, str) else scan_or_id
    report = recursive_learning_from_scans([apply_decisions(scan)], audit_events(limit=5000), scope='single-scan', requested_limit=limit)
    report['scan_id'] = scan.scan_id
    report['project_name'] = scan.project_name
    return report


def recursive_learning_from_scans(
    scans: list[ScanResult],
    audit_rows: list[dict[str, Any]] | None = None,
    scope: str = 'scan-history',
    requested_limit: int = 100,
) -> dict[str, Any]:
    audit_rows = audit_rows or []
    evidence = {
        'noisy_rules_to_tighten': noisy_rules(scans),
        'missing_language_framework_parsers': parser_gaps(scans),
        'bad_scope_classification': scope_classification_gaps(scans),
        'scanner_failures_by_environment': scanner_failures(scans),
        'false_positive_patterns': false_positive_patterns(scans),
        'recurring_vulnerable_dependency_families': dependency_families(scans),
        'finding_lifecycle_decisions': finding_lifecycle(scans),
        'report_section_usage': report_section_usage(audit_rows),
    }
    recommendations = build_recommendations(evidence, scans)
    return {
        'schema_version': 1,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'scope': scope,
        'scan_count': len(scans),
        'requested_limit': requested_limit,
        'latest_scan_id': scans[0].scan_id if scans else None,
        'latest_project': scans[0].project_name if scans else None,
        'status': learning_status(evidence, recommendations),
        'guardrails': [
            'This is a read-only learning report; it does not rewrite rules, configs, parsers, or scanner settings.',
            'Every scanner improvement recommendation is proposed only and requires human approval before implementation.',
            'Rule-pack promotion requires benchmark evidence that noise drops without losing known true positives.',
            'Accepted-risk and false-positive decisions are used as evidence, not as automatic suppression rules.',
        ],
        'controlled_workflow': controlled_workflow(),
        'evidence': evidence,
        'scanner_improvement_recommendations': recommendations,
        'approval_queue': [item for item in recommendations if item['requires_human_approval']],
        'promotion_gate': promotion_gate(),
    }


def noisy_rules(scans: list[ScanResult]) -> list[dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    per_scan_counts: dict[tuple[str, str, str], int] = Counter()
    for scan in scans:
        for finding in scan.findings:
            key = (finding.source, finding.rule_id)
            per_scan_counts[(scan.scan_id, finding.source, finding.rule_id)] += 1
            row = rows.setdefault(key, base_rule_row(finding))
            update_common_finding_row(row, scan, finding)
            row['hygiene_count'] += 0 if is_production_impacting(finding) else 1
            row['decision_counts'][finding.decision] += 1
            row['sample_messages'].append(short_text(finding.message, 160))
    for (scan_id, source, rule_id), count in per_scan_counts.items():
        row = rows[(source, rule_id)]
        row['max_findings_in_single_scan'] = max(row['max_findings_in_single_scan'], count)
    candidates = []
    for row in rows.values():
        total = row['finding_count']
        decision_total = sum(row['decision_counts'].values())
        false_positive_count = row['decision_counts'].get('false_positive', 0) + row['decision_counts'].get('risk_accepted', 0)
        row['hygiene_rate'] = ratio(row['hygiene_count'], total)
        row['false_positive_or_acceptance_rate'] = ratio(false_positive_count, decision_total)
        row['decision_counts'] = dict(row['decision_counts'])
        finalize_row(row)
        if (
            total >= NOISY_RULE_MIN_TOTAL
            or row['max_findings_in_single_scan'] >= NOISY_RULE_MIN_SCAN_BURST
            or row['hygiene_rate'] >= HYGIENE_RATE_THRESHOLD
            or row['false_positive_or_acceptance_rate'] >= FALSE_POSITIVE_RATE_THRESHOLD
        ):
            candidates.append(row)
    return sorted(candidates, key=lambda item: (-item['finding_count'], -item['false_positive_or_acceptance_rate'], item['source']))[:25]


def parser_gaps(scans: list[ScanResult]) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for scan in scans:
        tool_status = {tool.lower(): str(status).lower() for tool, status in scan.summary.tools.items()}
        for language, files in scan.summary.languages.items():
            key = normalize_language(language)
            expected = LANGUAGE_EXPECTATIONS.get(key)
            if not expected:
                rows.setdefault(key, {
                    'language_or_framework': language,
                    'support': 'unknown',
                    'files_observed': 0,
                    'scan_ids': set(),
                    'projects': set(),
                    'expected_parsers': [],
                    'missing_or_problem_parsers': [],
                    'recommendation': f'Add explicit parser and dependency-review expectations for {language}.',
                })
                row = rows[key]
                row['files_observed'] += files
                row['scan_ids'].add(scan.scan_id)
                row['projects'].add(scan.project_name)
                continue
            missing = []
            for parser in expected['parsers']:
                status = status_for_parser(parser, tool_status)
                if not status or is_problem_status(status):
                    missing.append({'parser': parser, 'status': status or 'not reported'})
            if expected['support'] == 'gap' or missing:
                row = rows.setdefault(key, {
                    'language_or_framework': language,
                    'support': expected['support'],
                    'files_observed': 0,
                    'scan_ids': set(),
                    'projects': set(),
                    'expected_parsers': expected['parsers'],
                    'missing_or_problem_parsers': [],
                    'recommendation': parser_recommendation(language, expected['support']),
                })
                row['files_observed'] += files
                row['scan_ids'].add(scan.scan_id)
                row['projects'].add(scan.project_name)
                row['missing_or_problem_parsers'].extend(missing)
    return finalize_rows(rows.values(), sort_key=lambda item: (-item['files_observed'], item['language_or_framework']))[:25]


def scope_classification_gaps(scans: list[ScanResult]) -> dict[str, Any]:
    conflicts = []
    blockers = []
    scope_counts = Counter()
    for scan in scans:
        for finding in scan.findings:
            expected = classify_path_scope(finding.location.path)
            actual = finding_scope(finding)
            scope_counts[actual] += 1
            if expected != actual:
                conflicts.append({
                    'scan_id': scan.scan_id,
                    'project_name': scan.project_name,
                    'finding_id': finding.id,
                    'path': finding.location.path,
                    'source': finding.source,
                    'rule_id': finding.rule_id,
                    'expected_scope': expected,
                    'actual_scope': actual,
                })
            if expected == 'test' and is_production_impacting(finding):
                blockers.append({
                    'scan_id': scan.scan_id,
                    'project_name': scan.project_name,
                    'finding_id': finding.id,
                    'path': finding.location.path,
                    'source': finding.source,
                    'rule_id': finding.rule_id,
                    'reason': 'test-scope finding still blocks production because it is a high-confidence or critical secret',
                })
    return {
        'status': 'attention_required' if conflicts else 'ok',
        'scope_counts': dict(sorted(scope_counts.items())),
        'conflict_count': len(conflicts),
        'conflicts': conflicts[:50],
        'test_scope_secret_blockers': blockers[:50],
        'recommendation': 'Review conflicts before changing gates; test-scope secret blockers are intentional policy behavior.',
    }


def scanner_failures(scans: list[ScanResult]) -> list[dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for scan in scans:
        for tool, status in scan.summary.tools.items():
            text = str(status)
            if not is_problem_status(text):
                continue
            key = (tool, text)
            row = rows.setdefault(key, {
                'tool': tool,
                'status': text,
                'count': 0,
                'scan_ids': set(),
                'projects': set(),
                'recommendation': scanner_failure_recommendation(tool, text),
            })
            row['count'] += 1
            row['scan_ids'].add(scan.scan_id)
            row['projects'].add(scan.project_name)
    return finalize_rows(rows.values(), sort_key=lambda item: (-item['count'], item['tool']))[:25]


def false_positive_patterns(scans: list[ScanResult]) -> list[dict[str, Any]]:
    rows: dict[tuple[str, str, str], dict[str, Any]] = {}
    for scan in scans:
        for finding in scan.findings:
            if finding.decision not in {'false_positive', 'risk_accepted', 'accepted_fix'}:
                continue
            key = (finding.decision, finding.source, finding.rule_id)
            row = rows.setdefault(key, base_rule_row(finding))
            row['decision'] = finding.decision
            update_common_finding_row(row, scan, finding)
            if finding.decision_reason:
                row['decision_reasons'].append(short_text(finding.decision_reason, 180))
    for row in rows.values():
        finalize_row(row)
    return sorted(rows.values(), key=lambda item: (-item['finding_count'], item['decision'], item['source']))[:25]


def dependency_families(scans: list[ScanResult]) -> list[dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for scan in scans:
        for finding in scan.findings:
            metadata = finding.scanner_metadata or {}
            source = finding.source.lower()
            package = dependency_package_name(finding)
            ecosystem = dependency_ecosystem(finding)
            if not package and source not in DEPENDENCY_SOURCES:
                continue
            package = package or normalize_dependency_title(finding.title)
            key = (ecosystem, package)
            row = rows.setdefault(key, {
                'ecosystem': ecosystem,
                'package': package,
                'finding_count': 0,
                'sources': Counter(),
                'rule_ids': Counter(),
                'severities': Counter(),
                'projects': set(),
                'scan_ids': set(),
                'fix_versions': set(),
                'reachable_count': 0,
                'sample_titles': [],
            })
            row['finding_count'] += 1
            row['sources'][finding.source] += 1
            row['rule_ids'][finding.rule_id] += 1
            row['severities'][finding.severity] += 1
            row['projects'].add(scan.project_name)
            row['scan_ids'].add(scan.scan_id)
            row['sample_titles'].append(short_text(finding.title, 120))
            fixed = metadata.get('fixed_version') or metadata.get('fixed_versions') or metadata.get('fix_version')
            if fixed:
                row['fix_versions'].add(fixed)
            if finding.reachability in {'reachable', 'direct', 'imported'} or metadata.get('dependency_reachability') in {'reachable-source-import', 'reachable-runtime'}:
                row['reachable_count'] += 1
    finalized = []
    for row in rows.values():
        row['sources'] = dict(row['sources'].most_common())
        row['rule_ids'] = counter_items(row['rule_ids'], 10)
        row['severities'] = dict(row['severities'].most_common())
        finalize_row(row)
        finalized.append(row)
    return sorted(finalized, key=lambda item: (-item['finding_count'], -item['reachable_count'], item['ecosystem']))[:25]


def finding_lifecycle(scans: list[ScanResult]) -> dict[str, Any]:
    decisions = Counter()
    by_rule: dict[tuple[str, str], Counter] = defaultdict(Counter)
    for scan in scans:
        for finding in scan.findings:
            decisions[finding.decision] += 1
            by_rule[(finding.source, finding.rule_id)][finding.decision] += 1
    rule_rows = []
    for (source, rule_id), counts in by_rule.items():
        total = sum(counts.values())
        if total < 2:
            continue
        rule_rows.append({
            'source': source,
            'rule_id': rule_id,
            'total': total,
            'decisions': dict(counts),
            'non_open_rate': ratio(total - counts.get('open', 0), total),
        })
    return {
        'decision_counts': dict(decisions),
        'top_rules_by_decision_activity': sorted(rule_rows, key=lambda item: (-item['non_open_rate'], -item['total']))[:25],
        'recommendation': 'Use accepted/fixed/ignored decisions as review evidence; convert only repeated, reviewed patterns into approved tuning changes.',
    }


def report_section_usage(audit_rows: list[dict[str, Any]]) -> dict[str, Any]:
    sections = Counter()
    actions = Counter()
    for row in audit_rows:
        action = str(row.get('action', ''))
        section = section_for_audit_action(action)
        if section:
            sections[section] += 1
            actions[action] += 1
    return {
        'status': 'has_usage' if sections else 'no_audit_usage_observed',
        'sections': counter_items(sections, 25),
        'actions': counter_items(actions, 25),
        'recommendation': 'Keep high-use report sections easy to reach; inspect low-use sections before removing or redesigning them.',
    }


def build_recommendations(evidence: dict[str, Any], scans: list[ScanResult]) -> list[dict[str, Any]]:
    recommendations: list[dict[str, Any]] = []
    for row in evidence['noisy_rules_to_tighten'][:10]:
        recommendations.append(recommendation(
            category='noisy-rule-tuning',
            title=f"Tighten noisy rule {row['source']}:{row['rule_id']}",
            priority='high' if row['finding_count'] >= 100 or row['false_positive_or_acceptance_rate'] >= 0.4 else 'medium',
            evidence=row,
            recommended_change='Review rule pattern, scope filters, test/example exclusions, and confidence mapping before editing the rule pack.',
            validation_plan=[
                'Run the current rule against benchmark repositories and record true-positive and false-positive counts.',
                'Apply the proposed rule change in a temporary branch or candidate rule pack only.',
                'Compare old-vs-new findings and promote only if noise drops without losing known true positives.',
            ],
        ))
    for row in evidence['missing_language_framework_parsers'][:10]:
        recommendations.append(recommendation(
            category='parser-gap',
            title=f"Add or harden parser coverage for {row['language_or_framework']}",
            priority='high' if row['support'] == 'gap' else 'medium',
            evidence=row,
            recommended_change=row['recommendation'],
            validation_plan=[
                'Choose representative benchmark repositories for this language/framework.',
                'Add parser/scanner configuration behind an explicit feature flag or auto-detect gate.',
                'Verify findings, SBOM components, and dependency reachability are stable across benchmark reruns.',
            ],
        ))
    scope_gaps = evidence['bad_scope_classification']
    if scope_gaps['conflict_count']:
        recommendations.append(recommendation(
            category='scope-classification',
            title='Review path scope classification conflicts',
            priority='high',
            evidence=scope_gaps,
            recommended_change='Adjust scope classifier tests and path heuristics only after reviewing the conflicting examples.',
            validation_plan=[
                'Add regression tests for each reviewed path pattern.',
                'Confirm production risk score and quality gate exclude hygiene findings but still block high-confidence secrets.',
            ],
        ))
    for row in evidence['scanner_failures_by_environment'][:10]:
        recommendations.append(recommendation(
            category='scanner-environment',
            title=f"Stabilize {row['tool']} scanner environment",
            priority='high' if row['count'] >= 2 else 'medium',
            evidence=row,
            recommended_change=row['recommendation'],
            validation_plan=[
                'Document the required executable, token, or environment variable.',
                'Run the scanner on the benchmark set and capture status evidence.',
                'Keep failed adapters non-blocking until the environment is configured intentionally.',
            ],
        ))
    for row in evidence['false_positive_patterns'][:10]:
        recommendations.append(recommendation(
            category='false-positive-pattern',
            title=f"Review repeated {row['decision']} pattern for {row['source']}:{row['rule_id']}",
            priority='medium',
            evidence=row,
            recommended_change='Convert repeated reviewed decisions into candidate suppressions or rule refinements only after AppSec approval.',
            validation_plan=[
                'Review decision reasons and confirm the same pattern repeats across repositories.',
                'Test a candidate suppression/rule refinement against known vulnerable examples.',
            ],
        ))
    for row in evidence['recurring_vulnerable_dependency_families'][:10]:
        recommendations.append(recommendation(
            category='dependency-family',
            title=f"Track recurring vulnerable dependency family {row['ecosystem']}:{row['package']}",
            priority='high' if any(sev in row['severities'] for sev in ('CRITICAL', 'HIGH')) else 'medium',
            evidence=row,
            recommended_change='Create dependency campaign guidance and reachability checks for this package family.',
            validation_plan=[
                'Confirm fixed versions and runtime reachability in dependency-review artifacts.',
                'Verify SBOM vulnerability attachment and policy status after upgrades.',
            ],
        ))
    lifecycle = evidence['finding_lifecycle_decisions']
    if lifecycle['top_rules_by_decision_activity']:
        recommendations.append(recommendation(
            category='decision-learning',
            title='Use finding decisions to prioritize tuning candidates',
            priority='low',
            evidence=lifecycle,
            recommended_change='Review high non-open-rate rules during tuning planning; do not auto-suppress from decisions alone.',
            validation_plan=[
                'Sample accepted/fixed/ignored findings and confirm reviewer rationale.',
                'Translate only consistent, approved patterns into benchmark-tested rule changes.',
            ],
        ))
    usage = evidence['report_section_usage']
    if usage['sections']:
        recommendations.append(recommendation(
            category='report-usage',
            title='Tune dashboard/report layout using observed usage',
            priority='low',
            evidence=usage,
            recommended_change='Preserve high-use report sections and review low-use sections with users before changing UI/report defaults.',
            validation_plan=[
                'Compare usage before and after UI/report changes.',
                'Keep all compliance and audit artifacts available even if dashboard placement changes.',
            ],
        ))
    if not recommendations:
        recommendations.append(recommendation(
            category='baseline',
            title='Collect more scan evidence before changing scanner behavior',
            priority='low',
            evidence={'scan_count': len(scans)},
            recommended_change='Run benchmark repositories and record decisions to create a reliable tuning baseline.',
            validation_plan=[
                'Scan representative repositories for each MVP language.',
                'Record false-positive and accepted-risk decisions.',
                'Review generated recommendations before editing rule packs.',
            ],
        ))
    return recommendations


def recommendation(category: str, title: str, priority: str, evidence: Any, recommended_change: str, validation_plan: list[str]) -> dict[str, Any]:
    rec_id = stable_id(category, title)
    return {
        'id': rec_id,
        'category': category,
        'title': title,
        'priority': priority,
        'status': 'proposed',
        'requires_human_approval': True,
        'auto_apply': False,
        'evidence': evidence,
        'recommended_change': recommended_change,
        'approval_prompt': 'Approve a temporary candidate change only after reviewing evidence and benchmark expectations.',
        'validation_plan': validation_plan,
        'promotion_gate': promotion_gate(),
    }


def controlled_workflow() -> list[dict[str, str]]:
    return [
        {'step': '9', 'name': 'collect scan evidence', 'status': 'implemented', 'detail': 'Saved scans, decisions, scanner statuses, dependency findings, scope labels, and audit usage are summarized.'},
        {'step': '10', 'name': 'generate scanner improvement recommendations', 'status': 'implemented', 'detail': 'Recommendations are evidence-backed and marked proposed.'},
        {'step': '11', 'name': 'human approve rule/config/parser changes', 'status': 'guarded', 'detail': 'The app produces approval prompts but does not change rules automatically.'},
        {'step': '12', 'name': 'test against benchmark repos', 'status': 'required-before-promotion', 'detail': 'Benchmark comparison is the validation gate for future tuning work.'},
        {'step': '13', 'name': 'promote into main rule pack only if quality improves', 'status': 'required-before-promotion', 'detail': 'Promotion requires lower noise without loss of known true positives.'},
    ]


def promotion_gate() -> dict[str, Any]:
    return {
        'requires_benchmark_set': True,
        'requires_human_approval': True,
        'requires_no_true_positive_regression': True,
        'requires_noise_reduction': True,
        'minimum_evidence': [
            'before/after finding counts by rule and repository',
            'false-positive samples reviewed by a human',
            'known true-positive fixtures or benchmark findings preserved',
            'scanner status remained ok or intentionally skipped',
            'production quality gate did not weaken',
        ],
    }


def learning_status(evidence: dict[str, Any], recommendations: list[dict[str, Any]]) -> str:
    if any(item['priority'] == 'high' for item in recommendations):
        return 'recommendations_need_review'
    if evidence['scanner_failures_by_environment'] or evidence['noisy_rules_to_tighten']:
        return 'tuning_candidates_found'
    return 'collecting_evidence'


def base_rule_row(finding: Finding) -> dict[str, Any]:
    return {
        'source': finding.source,
        'rule_id': finding.rule_id,
        'finding_count': 0,
        'projects': set(),
        'scan_ids': set(),
        'severity_counts': Counter(),
        'scope_counts': Counter(),
        'sample_paths': [],
        'sample_messages': [],
        'decision_counts': Counter(),
        'decision_reasons': [],
        'hygiene_count': 0,
        'max_findings_in_single_scan': 0,
    }


def update_common_finding_row(row: dict[str, Any], scan: ScanResult, finding: Finding) -> None:
    row['finding_count'] += 1
    row['projects'].add(scan.project_name)
    row['scan_ids'].add(scan.scan_id)
    row['severity_counts'][finding.severity] += 1
    row['scope_counts'][finding_scope(finding)] += 1
    if len(row['sample_paths']) < 5:
        row['sample_paths'].append(finding.location.path)


def finalize_rows(rows: Any, sort_key: Any) -> list[dict[str, Any]]:
    finalized = list(rows)
    for row in finalized:
        finalize_row(row)
    return sorted(finalized, key=sort_key)


def finalize_row(row: dict[str, Any]) -> None:
    for key in ('projects', 'scan_ids', 'fix_versions'):
        if isinstance(row.get(key), set):
            row[key] = sorted(row[key])
    for key in ('severity_counts', 'scope_counts'):
        if isinstance(row.get(key), Counter):
            row[key] = dict(row[key].most_common())
    for key in ('sample_paths', 'sample_messages', 'decision_reasons', 'missing_or_problem_parsers', 'sample_titles'):
        if isinstance(row.get(key), list):
            row[key] = unique_limited(row[key], 8)


def counter_items(counter: Counter, limit: int) -> list[dict[str, Any]]:
    return [{'key': key, 'count': count} for key, count in counter.most_common(limit)]


def ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 3) if denominator else 0.0


def is_problem_status(status: str) -> bool:
    text = str(status).lower()
    return any(token in text for token in PROBLEM_STATUS_TOKENS)


def status_for_parser(parser: str, tool_status: dict[str, str]) -> str | None:
    parser_key = parser.lower()
    if parser_key in tool_status:
        return tool_status[parser_key]
    for tool, status in tool_status.items():
        if parser_key in tool or tool in parser_key:
            return status
    if parser_key == 'go-module':
        for tool, status in tool_status.items():
            if 'go' in tool and 'module' in tool:
                return status
    return None


def normalize_language(language: str) -> str:
    value = str(language or '').strip().lower()
    aliases = {
        'js': 'javascript',
        'jsx': 'javascript',
        'ts': 'typescript',
        'tsx': 'typescript',
        'golang': 'go',
        'c#': 'csharp',
        'c-sharp': 'csharp',
        'tf': 'terraform',
        'hcl': 'terraform',
    }
    return aliases.get(value, value)


def parser_recommendation(language: str, support: str) -> str:
    if support == 'gap':
        return f'Add first-class parser/dependency scanner coverage for {language} before treating it as MVP-grade.'
    return f'Harden configured parser/scanner coverage for {language} and document required local tools.'


def scanner_failure_recommendation(tool: str, status: str) -> str:
    lower = f'{tool} {status}'.lower()
    if 'codeql' in lower:
        return 'Verify CodeQL executable, language support, build mode, and query packs for benchmark repositories.'
    if 'sonar' in lower:
        return 'Set SONAR_HOST_URL, SONAR_TOKEN, SONAR_PROJECT_KEY, and SONAR_ORGANIZATION for SonarCloud when needed.'
    if 'gitleaks' in lower or 'trufflehog' in lower:
        return 'Verify project-local secret scanner binaries and keep built-in secret scanning as fallback evidence.'
    if 'govulncheck' in lower:
        return 'Verify Go toolchain, module download access, GOVULNCHECK_EXE, and timeout settings.'
    if 'pip-audit' in lower:
        return 'Verify Python environment, dependency manifests, and pip-audit network/cache access.'
    return f'Review local environment and configuration for {tool}.'


def dependency_package_name(finding: Finding) -> str:
    metadata = finding.scanner_metadata or {}
    return (
        metadata.get('dependency_name')
        or metadata.get('package')
        or metadata.get('package_name')
        or metadata.get('module')
        or metadata.get('component_name')
        or ''
    ).strip()


def dependency_ecosystem(finding: Finding) -> str:
    metadata = finding.scanner_metadata or {}
    value = (
        metadata.get('dependency_ecosystem')
        or metadata.get('ecosystem')
        or metadata.get('package_type')
        or metadata.get('purl_type')
        or ''
    ).strip().lower()
    if value:
        return value
    source = finding.source.lower()
    if source == 'pip-audit':
        return 'pypi'
    if source == 'govulncheck':
        return 'golang'
    return 'unknown'


def normalize_dependency_title(title: str) -> str:
    text = str(title or '').strip()
    if not text:
        return 'unknown'
    for separator in (' ', ':', '@'):
        if separator in text:
            head = text.split(separator)[0].strip()
            if head:
                return head
    return text[:80]


def section_for_audit_action(action: str) -> str | None:
    if action.startswith('reports.'):
        return 'Report Bundle'
    if action.startswith('scanner_mesh.'):
        return 'Scanner Mesh'
    if action.startswith('scanner_depth.'):
        return 'Scanner Depth'
    if action.startswith('dependencies.'):
        return 'Dependency Review'
    if action.startswith('sonarqube.'):
        return 'SonarQube'
    if action.startswith('secrets.'):
        return 'Secret Policy'
    if action.startswith('sbom.'):
        return 'SBOM/SPDX'
    if action.startswith('finding_ai.') or action.startswith('advanced_ai.'):
        return 'AI Review'
    if action.startswith('team_learning.'):
        return 'Team Learning'
    if action.startswith('fix.'):
        return 'Fix Workflow'
    if action.startswith('github.'):
        return 'GitHub PR'
    if action.startswith('code_hosts.'):
        return 'Code Host Review'
    if action.startswith('chat.'):
        return 'Chat Agent'
    if action.startswith('enterprise.'):
        return 'Compliance'
    if action.startswith('rag.'):
        return 'RAG/Knowledge'
    return None


def stable_id(category: str, title: str) -> str:
    import hashlib

    return hashlib.sha256(f'{category}:{title}'.encode('utf-8')).hexdigest()[:16]


def short_text(value: str, limit: int) -> str:
    text = ' '.join(str(value or '').split())
    return text if len(text) <= limit else f'{text[: limit - 3]}...'


def unique_limited(values: list[Any], limit: int) -> list[Any]:
    seen = set()
    output = []
    for value in values:
        marker = repr(value)
        if marker in seen:
            continue
        seen.add(marker)
        output.append(value)
        if len(output) >= limit:
            break
    return output
