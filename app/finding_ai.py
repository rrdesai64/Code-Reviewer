from __future__ import annotations

import hashlib
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from .ai import explain, suggest_fix
from .llm import generate, provider_status
from .memory import repository_context
from .models import Finding, LLMRequest, ScanResult
from .rag import retrieve_for_finding
from .refactor import validation_commands_for
from .scope import finding_scope, scope_sort_rank

MAX_REVIEW_LIMIT = 100
OPEN_DECISIONS = {'open', 'accepted_fix'}

SCENARIO_LIBRARY: list[dict[str, Any]] = [
    {
        'id': 'secret-exposure',
        'label': 'Secret or credential exposure',
        'signals': ['secret', 'credential', 'password', 'token', 'api key', 'private key', 'gitleaks', 'trufflehog', 'secret-scan', 'cwe-798'],
        'impact': 'Leaked credentials can be reused outside the application boundary and may remain valid after the code is changed.',
        'false_positive_checks': ['Confirm whether the value is a real credential, test fixture, or obvious placeholder.', 'Check whether the value was already committed to shared history.', 'Confirm whether the secret has been rotated.'],
        'remediation_patterns': ['Rotate exposed values before closing the finding.', 'Move secret material to an approved vault or runtime secret store.', 'Add push protection and CI secret scanning for the repository.'],
    },
    {
        'id': 'vulnerable-dependency',
        'label': 'Vulnerable or risky dependency',
        'signals': ['pip-audit', 'dependency', 'package', 'npm', 'snyk', 'cve-', 'pysec-', 'vulnerable and outdated components', 'a06'],
        'impact': 'A vulnerable dependency can expose the application even when first-party source code is otherwise safe.',
        'false_positive_checks': ['Confirm the affected package and version are present in the deployed artifact.', 'Check whether the vulnerable code path is reachable at runtime.', 'Verify whether a compensating control materially reduces exploitability.'],
        'remediation_patterns': ['Upgrade to the nearest fixed version and update lockfiles.', 'Prioritize reachable runtime dependencies over unused or dev-only packages.', 'Run dependency tests and a new dependency audit after the change.'],
    },
    {
        'id': 'command-injection',
        'label': 'Command injection or unsafe process execution',
        'signals': ['command injection', 'shell=true', 'subprocess', 'os.system', 'execfile', 'child_process', 'cwe-78', 'cwe-77'],
        'impact': 'Attacker-controlled input can change the command that executes on the host.',
        'false_positive_checks': ['Confirm whether any part of the command or argument list is user-controlled.', 'Check whether an allowlist constrains the command and arguments.', 'Verify the code avoids shell parsing entirely.'],
        'remediation_patterns': ['Use argument-list process execution instead of shell strings.', 'Allowlist permitted commands and arguments.', 'Add malicious-input tests for shell metacharacters and unexpected options.'],
    },
    {
        'id': 'sql-injection',
        'label': 'SQL or query injection',
        'signals': ['sql injection', 'query injection', 'raw sql', 'cwe-89', 'cwe-564'],
        'impact': 'Untrusted input can alter database queries, exposing or changing data outside intended authorization boundaries.',
        'false_positive_checks': ['Confirm whether all variables are bound parameters rather than string interpolation.', 'Check ORM escape behavior and whether raw query APIs are used.', 'Verify stored procedures do not concatenate untrusted input internally.'],
        'remediation_patterns': ['Use parameterized queries or ORM bind variables.', 'Keep identifiers and sort fields on allowlists.', 'Add tests with quote characters, boolean payloads, and stacked-query probes.'],
    },
    {
        'id': 'xss',
        'label': 'Cross-site scripting',
        'signals': ['xss', 'cross-site scripting', 'innerhtml', 'dangerouslysetinnerhtml', 'cwe-79', 'cwe-80', 'a03'],
        'impact': 'Untrusted browser-rendered content can execute script in another user session.',
        'false_positive_checks': ['Confirm whether the value is encoded for the exact browser context.', 'Check whether a trusted sanitizer is applied before rendering.', 'Verify CSP is a defense-in-depth control, not the only mitigation.'],
        'remediation_patterns': ['Use framework-safe rendering APIs by default.', 'Sanitize allowed rich text with a reviewed sanitizer policy.', 'Add regression tests for HTML, attribute, URL, and script contexts.'],
    },
    {
        'id': 'path-traversal',
        'label': 'Path traversal or unsafe file access',
        'signals': ['path traversal', '../', 'directory traversal', 'cwe-22', 'cwe-23', 'file access'],
        'impact': 'Untrusted paths can escape the intended directory and read or write unauthorized files.',
        'false_positive_checks': ['Confirm whether paths are normalized and constrained to an approved root.', 'Check whether symbolic links or alternate separators bypass validation.', 'Verify that user input never directly controls filesystem targets.'],
        'remediation_patterns': ['Resolve paths and enforce containment under an approved base directory.', 'Use file identifiers instead of raw user-provided paths.', 'Add tests for dot-dot segments, symlinks, absolute paths, and encoded separators.'],
    },
    {
        'id': 'ssrf',
        'label': 'Server-side request forgery',
        'signals': ['ssrf', 'server-side request forgery', 'cwe-918', 'urlopen', 'requests.get', 'http client'],
        'impact': 'Server-side fetches can be abused to reach internal services or cloud metadata endpoints.',
        'false_positive_checks': ['Confirm whether destination hosts are controlled by users or external data.', 'Check redirects, DNS rebinding, and private address ranges.', 'Verify that egress controls also block internal destinations.'],
        'remediation_patterns': ['Use destination allowlists and block private or link-local ranges.', 'Disable or strictly validate redirects.', 'Add tests for localhost, metadata IPs, private CIDRs, and encoded hostnames.'],
    },
    {
        'id': 'unsafe-deserialization',
        'label': 'Unsafe deserialization or dynamic object loading',
        'signals': ['deserialization', 'pickle', 'yaml.load', 'marshal', 'objectinputstream', 'cwe-502'],
        'impact': 'Untrusted serialized data can instantiate unexpected objects or execute code during parsing.',
        'false_positive_checks': ['Confirm whether serialized input can cross a trust boundary.', 'Check whether the parser constructs objects or only plain data.', 'Verify signing is present and key management is sound.'],
        'remediation_patterns': ['Use safe parsers that produce plain data structures.', 'Reject untrusted serialized object formats.', 'Add tests that malicious serialized payloads are rejected.'],
    },
    {
        'id': 'auth-access-control',
        'label': 'Authentication or authorization weakness',
        'signals': ['auth', 'authorization', 'authentication', 'access control', 'idor', 'permission', 'cwe-287', 'cwe-306', 'cwe-639', 'cwe-862', 'cwe-863'],
        'impact': 'Users may access actions or data outside their intended role or ownership boundary.',
        'false_positive_checks': ['Confirm the route or action is protected by a server-side authorization check.', 'Check object ownership and tenant boundaries, not only authentication.', 'Verify tests cover negative authorization cases.'],
        'remediation_patterns': ['Enforce authorization at the server-side boundary closest to the protected object.', 'Use centralized policy helpers where possible.', 'Add tests for unauthenticated, wrong-role, and wrong-owner requests.'],
    },
    {
        'id': 'crypto-weakness',
        'label': 'Cryptographic weakness',
        'signals': ['crypto', 'md5', 'sha1', 'weak cipher', 'random', 'cwe-326', 'cwe-327', 'cwe-328', 'cwe-330'],
        'impact': 'Weak cryptography can make secrets, tokens, or integrity checks easier to break or forge.',
        'false_positive_checks': ['Confirm whether the primitive is used for security rather than non-security checksums.', 'Check key length, mode, padding, and randomness source.', 'Verify migration impact for existing data or tokens.'],
        'remediation_patterns': ['Use modern reviewed library defaults.', 'Replace weak hashes or random sources with security-grade alternatives.', 'Plan migrations for stored hashes, encrypted data, or tokens.'],
    },
    {
        'id': 'insecure-transport',
        'label': 'Insecure transport or TLS validation weakness',
        'signals': ['http://', 'verify=false', 'tls', 'ssl', 'certificate', 'cwe-295', 'cwe-319'],
        'impact': 'Network attackers can observe or alter traffic when transport protections are absent or disabled.',
        'false_positive_checks': ['Confirm whether the endpoint is internal-only and still carries sensitive data.', 'Check whether certificate verification is disabled in production code.', 'Verify TLS configuration through deployment settings as well as source code.'],
        'remediation_patterns': ['Use HTTPS/TLS with certificate verification enabled.', 'Remove test-only TLS bypasses from deployable paths.', 'Add deployment checks for secure URLs and TLS verification flags.'],
    },
    {
        'id': 'debug-misconfiguration',
        'label': 'Debug or security configuration weakness',
        'signals': ['debug', 'misconfiguration', 'security hotspot', 'quality gate', 'sonarqube', 'cwe-489', 'a05'],
        'impact': 'Unsafe defaults or debug behavior can expose internals, weaken controls, or fail production governance gates.',
        'false_positive_checks': ['Confirm whether the setting is reachable in production or only local tests.', 'Check environment-specific configuration overrides.', 'Verify the quality gate condition and related issue status.'],
        'remediation_patterns': ['Default deployable configuration to secure values.', 'Move environment-specific settings to controlled runtime config.', 'Add CI checks that fail on production debug or failed quality gates.'],
    },
    {
        'id': 'iac-cloud-container',
        'label': 'Infrastructure, cloud, or container security weakness',
        'signals': ['terraform', 'kubernetes', 'dockerfile', 'container', 'privileged', 'securitycontext', 'iam', 's3', 'public access', 'cwe-732'],
        'impact': 'Infrastructure weaknesses can expose services, credentials, data, or runtime privileges outside code-level controls.',
        'false_positive_checks': ['Confirm whether the manifest applies to production or only local development.', 'Check compensating cloud policies and network controls.', 'Verify least privilege and exposure settings in the effective deployed configuration.'],
        'remediation_patterns': ['Apply least privilege to runtime users, IAM, and network exposure.', 'Pin base images and avoid privileged container settings.', 'Validate the generated or deployed manifest after remediation.'],
    },
    {
        'id': 'ci-cd-supply-chain',
        'label': 'CI/CD or build supply-chain weakness',
        'signals': ['github actions', '.github/workflows', 'pipeline', 'build script', 'workflow', 'untrusted checkout', 'supply chain'],
        'impact': 'A build or pipeline weakness can compromise releases, artifacts, or credentials even when application code is safe.',
        'false_positive_checks': ['Confirm whether the workflow runs on untrusted pull request input.', 'Check token permissions and secret exposure in pipeline steps.', 'Verify third-party actions or scripts are pinned and trusted.'],
        'remediation_patterns': ['Pin actions and dependencies to reviewed versions.', 'Reduce workflow token permissions and secret exposure.', 'Add branch protection and artifact provenance checks.'],
    },
    {
        'id': 'generic-secure-coding',
        'label': 'Generic secure coding review',
        'signals': [],
        'impact': 'The scanner identified a security-sensitive pattern that needs human review with local code context.',
        'false_positive_checks': ['Confirm whether attacker-controlled input can reach the finding.', 'Check whether framework or platform controls already mitigate the risk.', 'Verify the scanner rule intent against the local implementation.'],
        'remediation_patterns': ['Prefer framework-provided safe APIs.', 'Apply the smallest behavior-preserving safe change.', 'Add a regression test that proves the unsafe behavior is blocked.'],
    },
]


def finding_ai_status() -> dict[str, Any]:
    return {
        'generated_at': now_iso(),
        'features': ['dynamic-prompt-templates', 'vulnerability-explanations', 'remediation-suggestions', 'scenario-classification', 'rag-context'],
        'providers': provider_status(),
        'scenario_count': len(SCENARIO_LIBRARY),
        'scenarios': scenario_taxonomy(),
        'privacy': 'Offline provider stays local. Cloud providers receive finding metadata, RAG snippets, and repository memory text only when explicitly selected.',
    }


def build_scan_ai_review(scan: ScanResult, provider: str = 'offline', model: str | None = None, limit: int = 25, include_prompts: bool = False) -> dict[str, Any]:
    candidates = [finding for finding in scan.findings if finding.decision in OPEN_DECISIONS]
    candidates = sorted(candidates, key=lambda item: (-scope_sort_rank(item), -item.risk.score, item.location.path, item.location.line, item.id))[:max(1, min(limit, MAX_REVIEW_LIMIT))]
    reviews = [build_finding_ai_review(scan, finding.id, provider=provider, model=model, include_prompts=include_prompts) for finding in candidates]
    scenario_counts = Counter(review['scenario']['id'] for review in reviews)
    return {
        'schema_version': 1,
        'generated_at': now_iso(),
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'provider': normalized_provider(provider),
        'model': resolved_model(provider, model),
        'review_count': len(reviews),
        'scenario_counts': dict(sorted(scenario_counts.items())),
        'scenario_coverage': scenario_taxonomy(),
        'prompt_strategy': 'Prompt templates are generated per finding from scenario, scanner metadata, risk, RAG context, and repository memory.',
        'reviews': reviews,
    }


def build_finding_ai_review(scan: ScanResult, finding_id: str, provider: str = 'offline', model: str | None = None, include_prompts: bool = True) -> dict[str, Any]:
    finding = next((item for item in scan.findings if item.id == finding_id), None)
    if not finding:
        raise ValueError('finding not found')
    scenario = classify_scenario(finding)
    context_chunks = retrieve_for_finding(finding, limit=4)
    memory_text = repository_context(scan.target_path)
    templates = build_prompt_templates(scan, finding, scenario, context_chunks, memory_text)
    explanation_fallback = offline_explanation(finding, scenario)
    remediation_fallback = offline_remediation(finding, scenario, scan)
    explanation = generate_text(
        prompt=templates['vulnerability_explanation_prompt'],
        system=templates['system_prompt'],
        provider=provider,
        model=model,
        context=context_chunks,
        fallback=explanation_fallback,
    )
    remediation = generate_text(
        prompt=templates['remediation_suggestion_prompt'],
        system=templates['system_prompt'],
        provider=provider,
        model=model,
        context=context_chunks,
        fallback=remediation_fallback,
    )
    validation_commands = validation_commands_for(scan, finding)
    result = {
        'schema_version': 1,
        'generated_at': now_iso(),
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'finding_id': finding.id,
        'finding': finding_summary(finding),
        'scenario': scenario_public(scenario),
        'template_ids': {
            'system': templates['system_template_id'],
            'vulnerability_explanation': templates['vulnerability_template_id'],
            'remediation_suggestion': templates['remediation_template_id'],
        },
        'ai_explanation': explanation,
        'remediation_suggestion': {
            **remediation,
            'steps': remediation_steps(finding, scenario),
            'validation_commands': validation_commands,
        },
        'false_positive_checks': scenario['false_positive_checks'],
        'guardrails': review_guardrails(finding),
        'context_summary': {
            'rag_chunks': len(context_chunks),
            'rag_titles': [chunk.title for chunk in context_chunks],
            'memory_context': 'available' if 'No prior repository memory' not in memory_text else 'not available',
            'references': finding.references[:10],
        },
    }
    if include_prompts:
        result['prompt_templates'] = templates
    return result


def build_prompt_templates(scan: ScanResult, finding: Finding, scenario: dict[str, Any], context_chunks: list[Any], memory_text: str) -> dict[str, str]:
    evidence = finding_prompt_evidence(scan, finding, scenario, memory_text)
    context_summary = '\n'.join(f'- {chunk.title}: {redact(chunk.text[:500])}' for chunk in context_chunks) or '- No RAG context retrieved.'
    system_prompt = (
        'You are a private, security-first secure code review assistant. Use only the supplied scanner evidence, risk metadata, RAG context, and repository memory. '
        'Do not invent vulnerable code, hidden files, or exploitability that is not supported by evidence. If evidence is incomplete, state what to verify. '
        'Do not repeat secret values; redact credentials and tokens. Keep guidance actionable and concise.'
    )
    explanation_prompt = f'''Task: Generate a vulnerability explanation for one finding.

Scenario: {scenario['label']} ({scenario['id']})
Scenario impact model: {scenario['impact']}

Finding evidence:
{evidence}

RAG context:
{context_summary}

Required explanation coverage:
- What the scanner detected in plain language.
- Why this can matter in a real attack or compliance review.
- Preconditions that make the finding exploitable or important.
- False-positive checks a reviewer should perform.
- How the scanner severity and app risk score should influence priority.

Output format:
1. Explanation
2. Attack or failure path
3. Evidence to verify
4. Reviewer caution
'''
    remediation_prompt = f'''Task: Generate remediation suggestions for one finding.

Scenario: {scenario['label']} ({scenario['id']})
Scenario remediation patterns:
{bullet_list(scenario['remediation_patterns'])}

Finding evidence:
{evidence}

RAG context:
{context_summary}

Required remediation coverage:
- Safest minimal change.
- Safer long-term design pattern.
- Tests or validation commands to run.
- Deployment or operational cautions.
- When risk acceptance is acceptable and what rationale must be recorded.

Output format:
1. Recommended fix
2. Safer pattern
3. Validation
4. Rollout and risk acceptance notes
'''
    return {
        'system_template_id': template_id('system', scenario, finding, system_prompt),
        'vulnerability_template_id': template_id('vulnerability', scenario, finding, explanation_prompt),
        'remediation_template_id': template_id('remediation', scenario, finding, remediation_prompt),
        'system_prompt': system_prompt,
        'vulnerability_explanation_prompt': explanation_prompt,
        'remediation_suggestion_prompt': remediation_prompt,
        'template_inputs': 'scenario + finding metadata + risk score + RAG context + repository memory',
    }


def generate_text(prompt: str, system: str, provider: str, model: str | None, context: list[Any], fallback: str) -> dict[str, Any]:
    resolved_provider = normalized_provider(provider)
    if resolved_provider == 'offline':
        return {
            'provider': 'offline',
            'model': 'dynamic-template',
            'text': fallback,
            'used_fallback': False,
            'template_fallback': True,
            'error': None,
        }
    response = generate(LLMRequest(prompt=prompt, provider=resolved_provider, model=model, system=system, context=context))
    text = response.text.strip()
    template_fallback = bool(response.used_fallback or not text)
    if template_fallback:
        text = fallback
    return {
        'provider': response.provider,
        'model': response.model,
        'text': text,
        'used_fallback': response.used_fallback,
        'template_fallback': template_fallback,
        'error': response.error,
    }


def classify_scenario(finding: Finding) -> dict[str, Any]:
    text = evidence_text(finding)
    best = SCENARIO_LIBRARY[-1]
    best_score = 0
    best_matches: list[str] = []
    for scenario in SCENARIO_LIBRARY[:-1]:
        matches = [signal for signal in scenario['signals'] if signal and signal in text]
        score = len(matches)
        if finding.source in {'secret-scan', 'gitleaks', 'trufflehog'} and scenario['id'] == 'secret-exposure':
            score += 4
            matches.append(f'source:{finding.source}')
        if finding.source in {'pip-audit', 'dependency-manifest', 'snyk'} and scenario['id'] == 'vulnerable-dependency':
            score += 4
            matches.append(f'source:{finding.source}')
        if finding.source == 'sonarqube' and scenario['id'] == 'debug-misconfiguration':
            score += 1
            matches.append('source:sonarqube')
        if score > best_score:
            best = scenario
            best_score = score
            best_matches = matches
    result = dict(best)
    result['confidence'] = 'high' if best_score >= 3 else 'medium' if best_score >= 1 else 'fallback'
    result['matched_signals'] = sorted(set(best_matches))[:12]
    return result


def evidence_text(finding: Finding) -> str:
    values = [
        finding.source,
        finding.rule_id,
        finding.title,
        finding.message,
        finding.location.path,
        finding.severity,
        finding.confidence,
        finding.exploitability,
        finding.reachability,
        ' '.join(finding.cwe),
        ' '.join(finding.owasp),
        ' '.join(finding.references),
        ' '.join(finding.policy_impact),
        ' '.join(finding.remediation),
        ' '.join(f'{key}:{value}' for key, value in (finding.scanner_metadata or {}).items()),
    ]
    return ' '.join(str(value).lower() for value in values if value)


def finding_prompt_evidence(scan: ScanResult, finding: Finding, scenario: dict[str, Any], memory_text: str) -> str:
    risk_factors = '; '.join(f'{factor.label}: {factor.detail}' for factor in finding.risk.factors) or 'none recorded'
    metadata = ', '.join(f'{key}={value}' for key, value in sorted((finding.scanner_metadata or {}).items())[:20]) or 'none'
    remediation = '; '.join(finding.remediation or finding.fix.guidance or []) or finding.fix.summary
    return '\n'.join([
        f'Scan: {scan.scan_id} project={scan.project_name}',
        f'Finding: {finding.id} title={redact(finding.title)}',
        f'Source: {finding.source} rule={finding.rule_id}',
        f'Location: {finding.location.path}:{finding.location.line}:{finding.location.column}',
        f'Severity: {finding.severity} confidence={finding.confidence}',
        f'Risk: priority={finding.risk.priority} score={finding.risk.score} tier={finding.risk.tier}',
        f'Risk action: {finding.risk.recommended_action}',
        f'Exploitability: {finding.exploitability} reachability={finding.reachability}',
        f'CWE: {", ".join(finding.cwe) or "none"}',
        f'OWASP: {", ".join(finding.owasp) or "none"}',
        f'Message: {redact(finding.message)}',
        f'Existing explanation: {redact(finding.explanation)}',
        f'Existing fix summary: {redact(finding.fix.summary)}',
        f'Existing remediation hints: {redact(remediation)}',
        f'Risk factors: {redact(risk_factors)}',
        f'Scanner metadata: {redact(metadata)}',
        f'Selected scenario: {scenario["label"]} confidence={scenario.get("confidence", "unknown")}',
        f'Repository memory: {redact(memory_text[:1200])}',
    ])


def offline_explanation(finding: Finding, scenario: dict[str, Any]) -> str:
    base = explain(finding.rule_id, finding.message, finding.cwe, finding.owasp)
    checks = ' '.join(f'- {item}' for item in scenario['false_positive_checks'][:3])
    return (
        f'Explanation: {base}\n\n'
        f'Attack or failure path: {scenario["impact"]} The finding is most important when the flagged path can be reached by untrusted input, production configuration, or deployed package/runtime state.\n\n'
        f'Evidence to verify: source={finding.source}, rule={finding.rule_id}, location={finding.location.path}:{finding.location.line}, priority={finding.risk.priority}, risk_score={finding.risk.score}.\n\n'
        f'Reviewer caution: Validate these false-positive checks before closing the finding. {checks}'
    )


def offline_remediation(finding: Finding, scenario: dict[str, Any], scan: ScanResult) -> str:
    fix = suggest_fix(finding.rule_id, finding.message)
    steps = remediation_steps(finding, scenario)
    commands = validation_commands_for(scan, finding)
    return (
        f'Recommended fix: {fix.summary}\n\n'
        f'Safer pattern: {" ".join(steps[:3])}\n\n'
        f'Validation: {"; ".join(commands) if commands else "rerun the scan and project tests"}.\n\n'
        'Rollout and risk acceptance notes: keep the change small, review it with the code owner, rerun the scanner, and record explicit rationale if the team accepts residual risk.'
    )


def remediation_steps(finding: Finding, scenario: dict[str, Any]) -> list[str]:
    steps: list[str] = []
    steps.extend(scenario.get('remediation_patterns', []))
    steps.extend(finding.remediation or [])
    steps.extend(finding.fix.guidance or [])
    steps.append('Rerun the secure review scan after remediation.')
    return dedupe(steps)[:10]


def finding_summary(finding: Finding) -> dict[str, Any]:
    return {
        'id': finding.id,
        'source': finding.source,
        'rule_id': finding.rule_id,
        'title': finding.title,
        'severity': finding.severity,
        'confidence': finding.confidence,
        'scope': finding_scope(finding),
        'location': finding.location.model_dump(),
        'cwe': finding.cwe,
        'owasp': finding.owasp,
        'risk': finding.risk.model_dump(),
        'decision': finding.decision,
    }


def scenario_public(scenario: dict[str, Any]) -> dict[str, Any]:
    return {
        'id': scenario['id'],
        'label': scenario['label'],
        'confidence': scenario.get('confidence', 'fallback'),
        'matched_signals': scenario.get('matched_signals', []),
        'impact': scenario['impact'],
    }


def scenario_taxonomy() -> list[dict[str, Any]]:
    return [{'id': item['id'], 'label': item['label'], 'signals': item['signals']} for item in SCENARIO_LIBRARY]


def review_guardrails(finding: Finding) -> list[str]:
    guardrails = [
        'AI output is advisory and must be reviewed by a human before merge or deployment.',
        'Do not paste or preserve real secrets in prompts, comments, tickets, or remediation notes.',
        'Prefer the smallest behavior-preserving safe change and validate with tests plus a new scan.',
    ]
    if finding.risk.priority in {'P0', 'P1'}:
        guardrails.append('High-priority findings should not be deferred without explicit risk acceptance rationale.')
    if finding.source in {'secret-scan', 'gitleaks', 'trufflehog'}:
        guardrails.append('Rotate exposed credentials before marking the finding resolved.')
    return guardrails


def template_id(kind: str, scenario: dict[str, Any], finding: Finding, prompt: str) -> str:
    raw = f'{kind}:{scenario["id"]}:{finding.id}:{prompt}'.encode('utf-8')
    return hashlib.sha256(raw).hexdigest()[:16]


def normalized_provider(provider: str) -> str:
    value = (provider or 'offline').replace('-', '_').lower().strip()
    return 'openai_compatible' if value in {'compatible', 'openai_compatible'} else value


def resolved_model(provider: str, model: str | None) -> str:
    if model:
        return model
    status = provider_status().get(normalized_provider(provider), {})
    return status.get('model') or 'dynamic-template'


def bullet_list(items: list[str]) -> str:
    return '\n'.join(f'- {item}' for item in items)


def redact(value: str) -> str:
    text = str(value or '')
    text = re.sub(r'(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key)(\s*[:=]\s*)([^\s,;]+)', r'\1\2[REDACTED]', text)
    text = re.sub(r'(?i)(bearer\s+)[a-z0-9._\-]+', r'\1[REDACTED]', text)
    return text


def dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        clean = str(item or '').strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        result.append(clean)
    return result


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()