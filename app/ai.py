from __future__ import annotations

from . import catalog_knowledge as kb
from .models import FixSuggestion


def explain(rule_id: str, message: str, cwe: list[str], owasp: list[str]) -> str:
    rule = kb.match_rule(rule_id, message, cwe)
    if rule is not None:
        return kb.build_explanation(rule, cwe, owasp)
    return _legacy_explain(rule_id, message, cwe, owasp)


def suggest_fix(rule_id: str, message: str, cwe: list[str] | None = None) -> FixSuggestion:
    rule = kb.match_rule(rule_id, message, cwe)
    if rule is not None:
        return kb.build_fix(rule)
    return _legacy_suggest_fix(rule_id, message)


# --- legacy keyword fallbacks (used when no catalog rule matches) -------------
def _legacy_explain(rule_id: str, message: str, cwe: list[str], owasp: list[str]) -> str:
    suffix = kb.context_suffix(cwe, owasp)
    lower = f'{rule_id} {message}'.lower()
    if 'shell' in lower or 'subprocess' in lower:
        return f'This code may pass attacker-controlled input to a shell command. Prefer argument arrays and validate inputs before invoking the process. {suffix}'.strip()
    if 'eval' in lower or 'exec' in lower:
        return f'Dynamic code execution can turn data into executable instructions. This is a common path to remote code execution when input is not fully trusted. {suffix}'.strip()
    if 'secret' in lower or 'password' in lower or 'token' in lower:
        return f'Hardcoded credentials can leak through source control, logs, builds, or screenshots. Move secrets to a managed secret store or environment-specific configuration. {suffix}'.strip()
    if 'debug' in lower:
        return f'Debug mode can expose stack traces and interactive tools that disclose internals or enable code execution in some frameworks. {suffix}'.strip()
    if 'dependency' in lower or 'unpinned' in lower:
        return f'Loose dependency constraints make builds less reproducible and can accidentally pull vulnerable versions. Pin versions and review dependency advisories. {suffix}'.strip()
    return f'This finding indicates a security-sensitive pattern that should be reviewed before release. {suffix}'.strip()


def _legacy_suggest_fix(rule_id: str, message: str) -> FixSuggestion:
    lower = f'{rule_id} {message}'.lower()
    if 'shell' in lower or 'subprocess' in lower:
        return FixSuggestion(summary='Avoid shell execution for untrusted input.', guidance=['Pass command arguments as a list.', 'Use allowlists for user-selectable commands.', 'Capture and handle process errors explicitly.'])
    if 'eval' in lower or 'exec' in lower:
        return FixSuggestion(summary='Remove dynamic code execution.', guidance=['Replace eval/exec with explicit parsing or dispatch tables.', 'Validate input against a strict schema.', 'Keep executable code separate from user-controlled data.'])
    if 'secret' in lower or 'password' in lower or 'token' in lower:
        return FixSuggestion(summary='Move secrets out of source code.', guidance=['Rotate the exposed secret.', 'Load secrets from environment variables or a vault.', 'Add secret scanning to CI.'])
    if 'debug' in lower:
        return FixSuggestion(summary='Disable debug mode in deployable configurations.', guidance=['Read debug flags from environment-specific config.', 'Default production settings to debug=false.', 'Add a deployment check that fails if debug is enabled.'])
    if 'dependency' in lower or 'unpinned' in lower:
        return FixSuggestion(summary='Tighten dependency management.', guidance=['Pin direct dependencies.', 'Commit lockfiles for application projects.', 'Run dependency audit tooling in CI.'])
    return FixSuggestion(summary='Review and remediate this pattern.', guidance=['Confirm whether the input is trusted.', 'Prefer framework-provided safe APIs.', 'Add a regression test for the safe behavior.'])
