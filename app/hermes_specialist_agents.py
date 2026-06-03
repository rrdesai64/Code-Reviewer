from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

SPECIALIST_AGENT_VERSION = '1.0.0'

PROBLEM_WORDS = ('error', 'failed', 'failure', 'not installed', 'disabled', 'missing', 'skipped', 'unavailable', 'timeout', 'timed out')
HIGH_RISK_CATEGORIES = {
    'dangerous-execution',
    'injection',
    'unsafe-deserialization',
    'secret-handling',
    'malware-or-quarantine',
    'iac-exposure',
}
DEPENDENCY_CATEGORIES = {'dependency-risk', 'dependency-hygiene', 'sbom-gap'}

CATEGORY_PATTERNS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    (
        'dangerous-execution',
        (
            'eval',
            'exec(',
            'child_process',
            'processbuilder',
            'runtime.getruntime',
            'system(',
            'shell=true',
            'command injection',
            'cwe-78',
        ),
        'dangerous execution or command-injection evidence appears in sanitized memory.',
    ),
    (
        'injection',
        (
            'sql injection',
            'nosql injection',
            'ldap injection',
            'template injection',
            'raw sql',
            'cwe-89',
            'cwe-94',
        ),
        'injection-risk evidence appears in sanitized memory.',
    ),
    (
        'xss',
        ('xss', 'cross-site scripting', 'innerhtml', 'dangerouslysetinnerhtml', 'cwe-79'),
        'client-side injection or XSS evidence appears in sanitized memory.',
    ),
    (
        'unsafe-deserialization',
        ('deserialization', 'deserialize', 'pickle', 'yaml.load', 'marshal.loads', 'binaryformatter', 'cwe-502'),
        'unsafe deserialization evidence appears in sanitized memory.',
    ),
    (
        'crypto-or-tls',
        ('weak crypto', 'md5', 'sha1', 'insecure tls', 'verify=false', 'rejectunauthorized=false', 'cwe-295'),
        'cryptography or TLS-hardening evidence appears in sanitized memory.',
    ),
    (
        'secret-handling',
        ('secret', 'password', 'token', 'private key', 'api_key', 'apikey', 'gitleaks', 'trufflehog', 'cwe-798'),
        'secret-handling evidence appears in sanitized memory.',
    ),
    (
        'dependency-risk',
        ('cve-', 'vulnerable', 'vulnerability', 'osv', 'pip-audit', 'npm audit', 'govulncheck', 'composer audit', 'bundle audit'),
        'vulnerable package evidence appears in sanitized memory.',
    ),
    (
        'dependency-hygiene',
        ('unpinned', 'wildcard', 'broad range', 'malicious locking range', 'dependency confusion', 'typosquat', 'lockfile'),
        'dependency hygiene or locking-range evidence appears in sanitized memory.',
    ),
    (
        'sbom-gap',
        ('sbom missing', 'spdx missing', 'cyclonedx missing', 'manifest missing', 'lockfile missing'),
        'SBOM or manifest coverage evidence appears in sanitized memory.',
    ),
    (
        'iac-exposure',
        ('public bucket', '0.0.0.0/0', 'privileged container', 'runasroot', 'hostpath', 'iam:*', 'unencrypted'),
        'IaC or DevOps exposure evidence appears in sanitized memory.',
    ),
    (
        'malware-or-quarantine',
        ('malware', 'backdoor', 'quarantine', 'yara', 'trojan', 'suspicious payload', 'push protection'),
        'malware, quarantine, or push-protection evidence appears in sanitized memory.',
    ),
)

SPECIALIST_PROFILES: tuple[dict[str, Any], ...] = (
    {
        'key': 'javascript-typescript',
        'agent_id': 'hermes-javascript-typescript-security-specialist',
        'name': 'Hermes JavaScript/TypeScript Security Specialist',
        'display': 'JavaScript/TypeScript',
        'languages': ['javascript', 'typescript'],
        'lesson_languages': ['javascript', 'typescript'],
        'markers': [
            'javascript',
            'typescript',
            'node.js',
            'nodejs',
            'npm',
            'yarn',
            'pnpm',
            'package.json',
            'package-lock.json',
            'yarn.lock',
            'pnpm-lock.yaml',
            '.js',
            '.jsx',
            '.ts',
            '.tsx',
            'react',
            'next.js',
            'express',
        ],
        'unique_sources': ['npm-audit', 'npm audit', 'yarn audit', 'pnpm audit'],
        'scanner_tools': ['semgrep', 'codeql', 'sonarqube', 'npm-audit', 'npm audit', 'eslint'],
        'scanner_expectations': ['semgrep', 'codeql', 'npm-audit'],
        'validation_commands': ['npm test', 'npm audit', 'npm run typecheck'],
    },
    {
        'key': 'go',
        'agent_id': 'hermes-go-security-specialist',
        'name': 'Hermes Go Security Specialist',
        'display': 'Go',
        'languages': ['go'],
        'lesson_languages': ['go'],
        'markers': ['golang', 'go.mod', 'go.sum', '.go', 'govulncheck', 'gosec'],
        'unique_sources': ['govulncheck', 'gosec'],
        'scanner_tools': ['govulncheck', 'gosec', 'semgrep', 'codeql', 'sonarqube'],
        'scanner_expectations': ['govulncheck', 'semgrep', 'codeql'],
        'validation_commands': ['go test ./...', 'go vet ./...', 'govulncheck ./...'],
    },
    {
        'key': 'rust',
        'agent_id': 'hermes-rust-security-specialist',
        'name': 'Hermes Rust Security Specialist',
        'display': 'Rust',
        'languages': ['rust'],
        'lesson_languages': ['rust'],
        'markers': ['rust', 'cargo.toml', 'cargo.lock', '.rs', 'cargo audit', 'cargo-audit', 'cargo deny'],
        'unique_sources': ['cargo-audit', 'cargo audit', 'cargo-deny', 'cargo deny'],
        'scanner_tools': ['cargo-audit', 'cargo audit', 'cargo-deny', 'semgrep', 'codeql'],
        'scanner_expectations': ['cargo-audit', 'semgrep'],
        'validation_commands': ['cargo test', 'cargo audit', 'cargo deny check'],
    },
    {
        'key': 'php',
        'agent_id': 'hermes-php-security-specialist',
        'name': 'Hermes PHP Security Specialist',
        'display': 'PHP',
        'languages': ['php'],
        'lesson_languages': ['php'],
        'markers': ['php', 'composer.json', 'composer.lock', '.php', 'phpunit', 'laravel', 'symfony'],
        'unique_sources': ['composer-audit', 'composer audit', 'psalm', 'phpstan'],
        'scanner_tools': ['composer-audit', 'composer audit', 'psalm', 'phpstan', 'semgrep', 'sonarqube'],
        'scanner_expectations': ['composer-audit', 'semgrep'],
        'validation_commands': ['composer audit', 'vendor/bin/phpunit', 'vendor/bin/phpstan analyse'],
    },
    {
        'key': 'java-kotlin',
        'agent_id': 'hermes-java-kotlin-security-specialist',
        'name': 'Hermes Java/Kotlin Security Specialist',
        'display': 'Java/Kotlin',
        'languages': ['java', 'kotlin'],
        'lesson_languages': ['java', 'kotlin'],
        'markers': ['java', 'kotlin', 'pom.xml', 'build.gradle', 'build.gradle.kts', 'gradle.lockfile', '.java', '.kt', 'maven', 'gradle'],
        'unique_sources': ['spotbugs', 'dependency-check', 'maven-audit', 'gradle-audit'],
        'scanner_tools': ['semgrep', 'codeql', 'sonarqube', 'spotbugs', 'dependency-check', 'maven', 'gradle'],
        'scanner_expectations': ['semgrep', 'codeql', 'sonarqube'],
        'validation_commands': ['mvn test or gradle test', 'mvn dependency-check:check or gradle dependencyCheckAnalyze'],
    },
    {
        'key': 'dotnet-csharp',
        'agent_id': 'hermes-dotnet-csharp-security-specialist',
        'name': 'Hermes .NET/C# Security Specialist',
        'display': '.NET/C#',
        'languages': ['csharp', 'dotnet'],
        'lesson_languages': ['csharp'],
        'markers': ['csharp', 'c#', '.net', 'dotnet', '.csproj', '.sln', '.cs', 'packages.lock.json', 'nuget'],
        'unique_sources': ['nuget-audit', 'dotnet-audit'],
        'scanner_tools': ['semgrep', 'codeql', 'sonarqube', 'nuget', 'dotnet'],
        'scanner_expectations': ['semgrep', 'codeql', 'sonarqube'],
        'validation_commands': ['dotnet test', 'dotnet list package --vulnerable'],
    },
    {
        'key': 'ruby',
        'agent_id': 'hermes-ruby-security-specialist',
        'name': 'Hermes Ruby Security Specialist',
        'display': 'Ruby',
        'languages': ['ruby'],
        'lesson_languages': ['ruby'],
        'markers': ['ruby', 'gemfile', 'gemfile.lock', '.rb', 'rails', 'brakeman', 'bundler-audit', 'bundle audit'],
        'unique_sources': ['brakeman', 'bundler-audit', 'bundle audit'],
        'scanner_tools': ['brakeman', 'bundler-audit', 'bundle audit', 'semgrep', 'codeql'],
        'scanner_expectations': ['brakeman', 'bundler-audit', 'semgrep'],
        'validation_commands': ['bundle exec rake test', 'bundle audit', 'brakeman'],
    },
    {
        'key': 'iac-devops',
        'agent_id': 'hermes-iac-devops-security-specialist',
        'name': 'Hermes IaC/DevOps Security Specialist',
        'display': 'IaC/DevOps',
        'languages': ['iac-devops', 'yaml', 'dockerfile', 'terraform'],
        'lesson_languages': ['iac-devops', 'yaml', 'dockerfile', 'terraform'],
        'markers': ['terraform', '.tf', 'dockerfile', 'kubernetes', 'k8s', 'helm', '.yaml', '.yml', 'github actions', '.github/workflows', 'devops', 'iac'],
        'unique_sources': ['checkov', 'tfsec', 'trivy config', 'kube-linter', 'hadolint'],
        'scanner_tools': ['checkov', 'tfsec', 'trivy', 'kube-linter', 'hadolint', 'semgrep'],
        'scanner_expectations': ['checkov', 'trivy', 'semgrep'],
        'validation_commands': ['terraform validate', 'trivy config .', 'checkov -d .'],
    },
    {
        'key': 'dependency-sbom',
        'agent_id': 'hermes-dependency-sbom-specialist',
        'name': 'Hermes Dependency/SBOM Specialist',
        'display': 'Dependency/SBOM',
        'languages': ['dependency-sbom'],
        'lesson_languages': ['dependency-sbom'],
        'markers': [
            'dependency',
            'sbom',
            'spdx',
            'cyclonedx',
            'lockfile',
            'manifest',
            'package-lock.json',
            'poetry.lock',
            'go.sum',
            'cargo.lock',
            'composer.lock',
            'gemfile.lock',
            'packages.lock.json',
        ],
        'unique_sources': ['osv', 'osv-scanner', 'syft', 'grype', 'trivy', 'dependency-review'],
        'scanner_tools': ['osv-scanner', 'syft', 'grype', 'trivy', 'pip-audit', 'npm-audit', 'govulncheck'],
        'scanner_expectations': ['dependency-review', 'osv-scanner', 'syft'],
        'validation_commands': ['Generate SBOM with Syft or native build tooling', 'Run OSV/Grype/dependency review against lockfiles'],
        'dependency_first': True,
    },
    {
        'key': 'secrets-malware-quarantine',
        'agent_id': 'hermes-secrets-malware-quarantine-specialist',
        'name': 'Hermes Secrets/Malware/Quarantine Specialist',
        'display': 'Secrets/Malware/Quarantine',
        'languages': ['secrets-malware-quarantine'],
        'lesson_languages': ['secrets-malware-quarantine'],
        'markers': ['secret', 'password', 'token', 'private key', 'malware', 'quarantine', 'yara', 'trufflehog', 'gitleaks', 'push protection'],
        'unique_sources': ['gitleaks', 'trufflehog', 'secret-scan', 'secret scan', 'yara', 'malware-scan', 'quarantine'],
        'scanner_tools': ['gitleaks', 'trufflehog', 'secret-scan', 'yara', 'quarantine'],
        'scanner_expectations': ['gitleaks', 'trufflehog', 'quarantine'],
        'validation_commands': ['Review quarantine registry record', 'Re-run secret scan in a disposable worker', 'Rotate exposed credentials before closure'],
        'secret_first': True,
    },
    {
        'key': 'scanner-reliability',
        'agent_id': 'hermes-scanner-reliability-specialist',
        'name': 'Hermes Scanner Reliability Specialist',
        'display': 'Scanner Reliability',
        'languages': ['scanner-reliability'],
        'lesson_languages': ['scanner-reliability'],
        'markers': ['scanner-status', 'scanner status', 'scanner', 'codeql', 'sonar', 'sonarqube', 'semgrep', 'bandit', 'govulncheck', 'disabled', 'skipped', 'failed'],
        'unique_sources': ['scanner-status', 'scanner status', 'scan-runner'],
        'scanner_tools': ['semgrep', 'codeql', 'sonarqube', 'bandit', 'pip-audit', 'govulncheck', 'gitleaks', 'trufflehog'],
        'scanner_expectations': [],
        'validation_commands': ['Run scanner diagnostics before rescanning', 'Check Sonar API diagnostics', 'Confirm CodeQL/Semgrep tool availability'],
        'scanner_first': True,
    },
)

SPECIALIST_AGENT_IDS = {profile['agent_id'] for profile in SPECIALIST_PROFILES}
PROFILES_BY_AGENT_ID = {profile['agent_id']: profile for profile in SPECIALIST_PROFILES}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def specialist_agent_registry_entries() -> list[dict[str, Any]]:
    return [specialist_agent_registry_entry(profile) for profile in SPECIALIST_PROFILES]


def specialist_agent_registry_entry(profile: dict[str, Any]) -> dict[str, Any]:
    key = profile['key']
    return {
        'agent_id': profile['agent_id'],
        'name': profile['name'],
        'version': SPECIALIST_AGENT_VERSION,
        'enabled': True,
        'deterministic': True,
        'capabilities': [
            f'{key}-security-review',
            f'{key}-dependency-review',
            f'{key}-scanner-coverage',
            f'{key}-remediation-routing',
        ],
        'item_types': ['scan-summary', 'finding-pattern', 'rule-pattern', 'dependency-signal', 'scanner-status'],
        'languages': profile['languages'],
        'safety_level': 'sanitized-memory-only',
        'framework_alignment': {
            'upstream': 'NousResearch/hermes-agent',
            'integration_mode': 'native-compatible-agent',
            'dependency_policy': 'no new runtime packages',
            'security_model': 'Disposable VM/worktree isolation is the execution boundary; this agent reads only sanitized RAG memory.',
        },
    }


def specialist_task_types_for_item(item: dict[str, Any], goal: str) -> list[tuple[str, str]]:
    tasks: list[tuple[str, str]] = []
    for profile in SPECIALIST_PROFILES:
        if not profile_matches_item(profile, item):
            continue
        tasks.extend(profile_task_types_for_item(profile, item))
    return filter_tasks_for_goal(tasks, goal)


def profile_task_types_for_item(profile: dict[str, Any], item: dict[str, Any]) -> list[tuple[str, str]]:
    key = profile['key']
    display = profile['display']
    item_type = item.get('item_type')
    tasks: list[tuple[str, str]] = []
    if item_type in {'finding-pattern', 'rule-pattern'} or profile.get('secret_first') or profile.get('scanner_first'):
        tasks.append((f'{key}-specialist-review', f'{display} specialist review should triage sanitized evidence with domain context.'))
    if item_type in {'finding-pattern', 'rule-pattern'} and not profile.get('scanner_first'):
        tasks.append((f'{key}-remediation-routing', f'{display} remediation guidance must stay review-only and benchmark-gated.'))
    if is_dependency_item(item) or profile.get('dependency_first'):
        tasks.append((f'{key}-dependency-review', f'{display} package, lockfile, SBOM, or vulnerable dependency evidence needs specialist triage.'))
    if is_scanner_item(item) or profile.get('scanner_first'):
        tasks.append((f'{key}-scanner-coverage-review', f'{display} scanner coverage should be checked for failed, skipped, missing, or partial tools.'))
    return dedupe_tasks(tasks)


def filter_tasks_for_goal(tasks: list[tuple[str, str]], goal: str) -> list[tuple[str, str]]:
    if goal == 'supply-chain-review':
        return [task for task in tasks if task[0].endswith('-dependency-review')] or tasks[:1]
    if goal == 'scanner-improvement-planning':
        return [task for task in tasks if task[0].endswith('-scanner-coverage-review')] or tasks[:1]
    if goal == 'release-readiness':
        return [
            task
            for task in tasks
            if task[0].endswith('-specialist-review') or task[0].endswith('-dependency-review') or task[0].endswith('-scanner-coverage-review')
        ] or tasks[:1]
    return tasks


def specialist_agent_matches_task(agent: dict[str, Any], task: dict[str, Any]) -> bool:
    profile = PROFILES_BY_AGENT_ID.get(str(agent.get('agent_id') or ''))
    if not profile:
        return False
    return str(task.get('task_type') or '') in profile_task_names(profile)


def run_specialist_agent(agent: dict[str, Any], task: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    profile = PROFILES_BY_AGENT_ID.get(agent['agent_id'])
    if not profile:
        raise ValueError(f"unknown specialist Hermes agent: {agent['agent_id']}")

    task_type = str(task.get('task_type') or '')
    signals = specialist_signals(profile, item)
    findings: list[str] = []
    recommendations: list[str] = []

    if task_type.endswith('-scanner-coverage-review'):
        if signals['scanner_gaps']:
            status = 'coverage-gap'
            findings.extend(signals['scanner_gaps'])
            recommendations.extend([
                f"Confirm {profile['display']} scanner coverage before treating the scan as complete.",
                'Keep scanner and rule changes as benchmarked proposals; do not mutate rules or suppressions automatically.',
            ])
        else:
            status = 'record-only'
            findings.append(f"No {profile['display']} scanner coverage gap was visible in sanitized memory.")
            recommendations.append(f"Keep {profile['display']} scanner coverage evidence attached to the scan record.")
    elif task_type.endswith('-dependency-review'):
        status = dependency_status(signals)
        findings.extend(signals['dependency_findings'] or [f"{profile['display']} dependency, manifest, lockfile, or SBOM signal requires review."])
        recommendations.extend([
            'Confirm fixed versions, lockfile impact, SBOM coverage, and runtime reachability before closure.',
            'Avoid broad version ranges for security fixes; prefer reviewed pins or bounded ranges with a lockfile.',
        ])
    elif task_type.endswith('-remediation-routing'):
        status = 'human-approval-required' if signals['high_risk'] else 'manual-remediation'
        findings.extend(signals['risk_findings'] or [f"{profile['display']} remediation should be prepared as review-only guidance."])
        recommendations.extend(validation_steps(profile, signals))
    else:
        status = review_status(signals)
        findings.extend(signals['risk_findings'] or [f"No {profile['display']} blocker detected from sanitized memory."])
        recommendations.extend(validation_steps(profile, signals))

    active_lessons: list[dict[str, Any]] = []

    return {
        'result_id': stable_id(agent['agent_id'], task['task_id'], status),
        'agent_id': agent['agent_id'],
        'agent_name': agent['name'],
        'agent_version': agent['version'],
        'task_id': task['task_id'],
        'task_type': task['task_type'],
        'item_id': item.get('item_id'),
        'item_type': item.get('item_type'),
        'status': status,
        'confidence': confidence_for_status(status),
        'findings': dedupe(findings),
        'recommendations': dedupe(recommendations),
        'evidence_refs': {
            'scan_id': item.get('source', {}).get('scan_id'),
            'project_name': item.get('source', {}).get('project_name'),
            'memory_item_id': item.get('item_id'),
            'language_family': profile['display'],
            'tags': item.get('tags', [])[:20],
        },
        'specialist_review': {
            'profile': profile['key'],
            'language_family': profile['display'],
            'categories': sorted(signals['categories']),
            'scanner_gaps': signals['scanner_gaps'],
            'dependency_findings': signals['dependency_findings'],
            'validation_commands': validation_commands(profile, signals),
            'active_teacher_lessons': active_lessons,
            'teacher_student_learning_enabled': False,
            'requires_human_approval': True,
            'requires_benchmark_gate': signals['scanner_tuning_candidate'],
        },
        'side_effects': [],
        'safety': {
            'raw_code_accessed': False,
            'repository_executed': False,
            'external_calls_made': False,
            'files_modified': False,
            'dependency_installed': False,
        },
        'generated_at': now_iso(),
    }


def profile_matches_item(profile: dict[str, Any], item: dict[str, Any]) -> bool:
    item_type = str(item.get('item_type') or '')
    tags = {str(tag).lower() for tag in item.get('tags', [])}
    metadata = {str(key).lower(): str(value).lower() for key, value in (item.get('metadata') or {}).items()}
    text = normalized_text(item)
    source = metadata.get('source') or metadata.get('engine') or ''

    if profile.get('dependency_first') and is_dependency_item(item):
        return True
    if profile.get('secret_first') and (tags & {'secret', 'secrets', 'malware', 'quarantine'} or any(marker in text for marker in profile['markers'])):
        return True
    if profile.get('scanner_first') and (
        item_type == 'scanner-status'
        or 'scanner' in text
        or any(str(tool).lower() in text for tool in profile.get('scanner_tools', []))
    ):
        return True
    if tags & {language.lower() for language in profile.get('languages', [])}:
        return True
    if tags & {profile['key'].lower(), profile['display'].lower()}:
        return True
    if source and source in {str(item).lower() for item in profile.get('unique_sources', [])}:
        return True
    return any(marker in text for marker in profile.get('markers', []))


def specialist_signals(profile: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get('metadata') or {}
    tags = {str(tag).upper() for tag in item.get('tags', [])}
    text = normalized_text(item)
    categories: set[str] = set()
    findings: list[str] = []
    dependency_findings: list[str] = []

    risk_score = safe_int(metadata.get('risk_score') or metadata.get('max_risk_score') or 0)
    priority = str(metadata.get('priority') or best_tag(tags, ['P0', 'P1', 'P2', 'P3', 'P4']))
    severity = str(metadata.get('severity') or best_tag(tags, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']))

    for category, tokens, finding in CATEGORY_PATTERNS:
        if any(token in text for token in tokens):
            categories.add(category)
            if category in DEPENDENCY_CATEGORIES:
                package = metadata.get('package') or metadata.get('dependency_name') or metadata.get('component') or metadata.get('rule_id') or 'unknown package'
                dependency_findings.append(f"{profile['display']} dependency/SBOM signal for {package}.")
            else:
                findings.append(f"{profile['display']} {finding}")

    if is_dependency_item(item):
        categories.add('dependency-risk')
        package = metadata.get('package') or metadata.get('dependency_name') or metadata.get('component') or metadata.get('rule_id') or 'unknown package'
        dependency_findings.append(f"{profile['display']} dependency/SBOM signal for {package}.")

    scanner_gaps = specialist_scanner_gaps(profile, item)
    if scanner_gaps:
        categories.add('scanner-coverage')
        findings.extend(scanner_gaps)

    high_risk = priority in {'P0', 'P1'} or severity in {'CRITICAL', 'HIGH'} or risk_score >= 70
    return {
        'categories': categories,
        'risk_findings': dedupe(findings),
        'dependency_findings': dedupe(dependency_findings),
        'scanner_gaps': scanner_gaps,
        'risk_score': risk_score,
        'priority': priority,
        'severity': severity,
        'high_risk': high_risk,
        'scanner_tuning_candidate': bool(scanner_gaps or 'scanner-coverage' in categories),
    }


def specialist_scanner_gaps(profile: dict[str, Any], item: dict[str, Any]) -> list[str]:
    metadata = item.get('metadata') or {}
    text = normalized_text(item)
    tools = [str(tool).lower() for tool in profile.get('scanner_tools', [])]
    expected_tools = [str(tool).lower() for tool in profile.get('scanner_expectations', [])]
    gaps: list[str] = []
    for key, value in metadata.items():
        key_text = str(key).lower()
        value_text = str(value).lower()
        if any(tool in key_text for tool in tools) and any(word in value_text for word in PROBLEM_WORDS):
            gaps.append(f"{profile['display']} scanner coverage gap: {key}={value}")
    if item.get('item_type') == 'scanner-status':
        if any(word in text for word in PROBLEM_WORDS):
            gaps.append(f"{profile['display']} scanner status includes failed, skipped, disabled, missing, or unavailable coverage.")
        for tool in expected_tools:
            if tool and tool not in text:
                gaps.append(f"{profile['display']} scanner status does not mention {tool}.")
    return dedupe(gaps)


def active_teacher_lessons_for_item(profile: dict[str, Any], item: dict[str, Any], signals: dict[str, Any]) -> list[dict[str, Any]]:
    return []


def lesson_recommendations(lessons: list[dict[str, Any]]) -> list[str]:
    return []


def public_teacher_lesson(lesson: dict[str, Any]) -> dict[str, Any]:
    return {
        'lesson_id': lesson.get('lesson_id'),
        'title': lesson.get('title'),
        'language': lesson.get('language'),
        'category': lesson.get('category'),
        'source': lesson.get('source'),
        'rule_id': lesson.get('rule_id'),
        'proposed_change': lesson.get('proposed_change'),
        'learning_influence_allowed': bool(lesson.get('learning_influence_allowed')),
    }


def validation_steps(profile: dict[str, Any], signals: dict[str, Any]) -> list[str]:
    steps = [
        'Use disposable worktrees or VM workers for untrusted repositories.',
        'Keep generated remediation as review-only until approved and benchmarked.',
    ]
    if signals['categories'] & HIGH_RISK_CATEGORIES:
        steps.append(f"Add focused {profile['display']} regression tests for the affected source-to-sink behavior.")
    if signals['categories'] & DEPENDENCY_CATEGORIES:
        steps.append('Re-run dependency, SBOM, and reachability checks after package or lockfile changes.')
    if signals['scanner_gaps']:
        steps.append('Fix scanner availability first, then rerun the scan before accepting coverage.')
    steps.extend(f'Validation command: {command}' for command in validation_commands(profile, signals))
    return steps


def validation_commands(profile: dict[str, Any], signals: dict[str, Any]) -> list[str]:
    commands = list(profile.get('validation_commands', []))
    if signals['scanner_gaps']:
        commands.append('Rerun the affected scanner after diagnostics pass')
    return dedupe(commands)


def review_status(signals: dict[str, Any]) -> str:
    categories = signals['categories']
    if signals['scanner_gaps']:
        return 'coverage-gap'
    if categories & {'malware-or-quarantine'}:
        return 'release-blocker'
    if categories & HIGH_RISK_CATEGORIES and signals['high_risk']:
        return 'release-blocker'
    if categories & DEPENDENCY_CATEGORIES and signals['high_risk']:
        return 'critical-dependency-risk'
    if categories:
        return 'review-required'
    return 'record-only'


def dependency_status(signals: dict[str, Any]) -> str:
    if signals['high_risk'] or signals['categories'] & DEPENDENCY_CATEGORIES:
        return 'critical-dependency-risk'
    return 'review-required'


def profile_task_names(profile: dict[str, Any]) -> set[str]:
    key = profile['key']
    return {
        f'{key}-specialist-review',
        f'{key}-remediation-routing',
        f'{key}-dependency-review',
        f'{key}-scanner-coverage-review',
    }


def is_dependency_item(item: dict[str, Any]) -> bool:
    item_type = item.get('item_type')
    tags = {str(tag).upper() for tag in item.get('tags', [])}
    text = normalized_text(item)
    return (
        item_type == 'dependency-signal'
        or bool(tags & {'DEPENDENCY', 'SCA', 'SBOM', 'CVE'})
        or any(token in text for token in ['dependency', 'sbom', 'spdx', 'cyclonedx', 'cve-', 'vulnerable package', 'lockfile', 'manifest'])
    )


def is_scanner_item(item: dict[str, Any]) -> bool:
    text = normalized_text(item)
    return item.get('item_type') == 'scanner-status' or 'scanner' in text or any(word in text for word in PROBLEM_WORDS)


def dedupe_tasks(tasks: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen = set()
    result = []
    for task in tasks:
        if task[0] in seen:
            continue
        seen.add(task[0])
        result.append(task)
    return result


def normalized_text(item: dict[str, Any]) -> str:
    metadata = item.get('metadata') or {}
    return ' '.join(
        [
            str(item.get('title') or ''),
            str(item.get('text') or ''),
            ' '.join(str(tag) for tag in item.get('tags', [])),
            ' '.join(f'{key}:{value}' for key, value in metadata.items()),
            str(item.get('source', {}).get('project_name') or ''),
        ]
    ).lower()


def confidence_for_status(status: str) -> str:
    if status in {'release-blocker', 'critical-dependency-risk', 'coverage-gap'}:
        return 'high'
    if status in {'review-required', 'human-approval-required', 'manual-remediation'}:
        return 'medium'
    return 'low'


def best_tag(tags: set[str], options: list[str]) -> str:
    for option in options:
        if option in tags:
            return option
    return ''


def safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def stable_id(*parts: str) -> str:
    raw = '\n'.join(str(part or '') for part in parts)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:24]


def dedupe(values: list[str]) -> list[str]:
    seen = set()
    result: list[str] = []
    for value in values:
        text = re.sub(r'\s+', ' ', str(value or '')).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def dedupe_lessons(lessons: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for lesson in lessons:
        key = lesson.get('lesson_id') or lesson.get('title')
        if key and key not in seen:
            seen.add(key)
            result.append(lesson)
    return result
