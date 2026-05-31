"""Scanner capability map for the code-review rule catalog.

The catalog defines what Secure Review wants to find. This module reports which
scanner families can plausibly detect each rule today, and which areas still
need query/rule work. It is intentionally metadata-driven: it does not promote
new rules or infer findings from source code.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Iterable

from . import catalog_knowledge as kb


@dataclass(frozen=True)
class ToolCapability:
    name: str
    label: str
    detections: frozenset[str]
    languages: frozenset[str]
    categories: frozenset[str]
    confidence: str
    notes: str
    rule_ids: frozenset[str] = frozenset()


ALL = frozenset({"*"})

TOOL_CAPABILITIES: tuple[ToolCapability, ...] = (
    ToolCapability(
        name="catalog-native",
        label="Native byte-level catalog scanner",
        detections=frozenset({"binary_scan"}),
        languages=ALL,
        categories=frozenset({"encoding_unicode", "lexical"}),
        confidence="high",
        notes="Implemented in Secure Review's native byte scanner for raw bytes, Unicode, line endings, and lexical traps.",
    ),
    ToolCapability(
        name="semgrep",
        label="Semgrep",
        detections=frozenset({"pattern", "ast"}),
        languages=frozenset({"python", "javascript", "typescript", "java", "go", "ruby", "php", "c", "cpp", "csharp", "kotlin", "rust", "yaml", "dockerfile", "terraform", "hcl"}),
        categories=frozenset({"security", "input_validation", "error_handling", "resource_mgmt", "language_idiom", "config_iac", "maintainability"}),
        confidence="medium",
        notes="Best for pattern and AST checks; rule coverage depends on enabled Semgrep packs and custom rules.",
    ),
    ToolCapability(
        name="bandit",
        label="Bandit",
        detections=frozenset({"pattern", "ast"}),
        languages=frozenset({"python"}),
        categories=frozenset({"security", "input_validation", "crypto", "secrets"}),
        confidence="medium",
        notes="Python security scanner; strong for common Python AST security checks, not general design invariants.",
    ),
    ToolCapability(
        name="shellcheck",
        label="ShellCheck",
        detections=frozenset({"pattern", "ast"}),
        languages=frozenset({"shell"}),
        categories=frozenset({"security", "language_idiom"}),
        confidence="high",
        notes="External ShellCheck adapter for shell script findings; strict-mode and pipefail completeness still need benchmarked policy rules.",
        rule_ids=frozenset({"SH-001", "SH-003", "SH-004"}),
    ),
    ToolCapability(
        name="sql-artifact",
        label="Native SQL artifact scanner",
        detections=frozenset({"pattern", "ast", "dataflow", "interprocedural"}),
        languages=frozenset({"sql"}),
        categories=frozenset({"maintainability", "input_validation", "security", "language_idiom", "performance", "error_handling"}),
        confidence="high",
        notes="First-party scanner for standalone .sql files such as migrations, stored procedures, and database scripts.",
        rule_ids=frozenset({"SQL-001", "SQL-002", "SQL-003", "SQL-004", "SQL-005", "SQL-006", "SQL-007"}),
    ),
    ToolCapability(
        name="codeql",
        label="CodeQL",
        detections=frozenset({"ast", "dataflow", "interprocedural"}),
        languages=frozenset({"python", "javascript", "typescript", "java", "go", "ruby", "c", "cpp", "csharp", "kotlin"}),
        categories=frozenset({"security", "input_validation", "null_handling", "error_handling", "resource_mgmt", "dependencies", "language_idiom"}),
        confidence="medium",
        notes="Semantic and dataflow engine; exact coverage depends on installed query packs and local build support.",
    ),
    ToolCapability(
        name="sonarqube",
        label="SonarQube/SonarCloud",
        detections=frozenset({"pattern", "ast", "dataflow", "interprocedural", "metric"}),
        languages=frozenset({"python", "javascript", "typescript", "java", "go", "ruby", "php", "c", "cpp", "csharp", "kotlin", "rust", "yaml", "dockerfile", "terraform", "hcl", "xml", "html"}),
        categories=ALL,
        confidence="medium",
        notes="Broad quality, security, and metric coverage; issue extraction depends on project key, scanner execution, and API permissions.",
    ),
    ToolCapability(
        name="pip-audit",
        label="pip-audit",
        detections=frozenset({"external_db"}),
        languages=frozenset({"python"}),
        categories=frozenset({"dependencies"}),
        confidence="high",
        notes="Python dependency vulnerability checks against advisory data.",
    ),
    ToolCapability(
        name="govulncheck",
        label="govulncheck",
        detections=frozenset({"external_db", "dataflow"}),
        languages=frozenset({"go"}),
        categories=frozenset({"dependencies", "security"}),
        confidence="high",
        notes="Go vulnerability detection with package and reachable-call context when available.",
    ),
    ToolCapability(
        name="secret-scanners",
        label="Gitleaks/TruffleHog secret scanners",
        detections=frozenset({"pattern"}),
        languages=ALL,
        categories=frozenset({"security", "input_validation"}),
        confidence="high",
        notes="Secret and credential pattern detection through local adapters when installed.",
    ),
)


def _as_set(values: Iterable[str] | None) -> set[str]:
    return {str(value).lower() for value in (values or [])}


def _intersects(rule_values: set[str], tool_values: frozenset[str]) -> bool:
    return "*" in rule_values or "*" in tool_values or bool(rule_values & set(tool_values))


def _supports_rule(tool: ToolCapability, rule: dict) -> bool:
    if tool.rule_ids:
        return str(rule.get("id") or "") in tool.rule_ids
    rule_detection = str(rule.get("detection") or "").lower()
    rule_category = str(rule.get("category") or "").lower()
    rule_languages = _as_set(rule.get("languages") or ["*"])
    detection_match = rule_detection in tool.detections
    category_match = "*" in tool.categories or rule_category in tool.categories
    language_match = _intersects(rule_languages, tool.languages)
    return detection_match and category_match and language_match


def _adjacent_support(tool: ToolCapability, rule: dict) -> bool:
    rule_detection = str(rule.get("detection") or "").lower()
    rule_category = str(rule.get("category") or "").lower()
    rule_languages = _as_set(rule.get("languages") or ["*"])
    language_match = _intersects(rule_languages, tool.languages)
    category_match = "*" in tool.categories or rule_category in tool.categories
    semantic_overlap = rule_detection in {"dataflow", "interprocedural"} and bool(tool.detections & {"ast", "dataflow", "interprocedural"})
    external_overlap = rule_category == "dependencies" and "external_db" in tool.detections
    metric_overlap = rule_detection == "metric" and "metric" in tool.detections
    return language_match and category_match and (semantic_overlap or external_overlap or metric_overlap)


def _catalog_version() -> str:
    if not kb.CATALOG_PATH.exists():
        return "unknown"
    try:
        import yaml
    except ImportError:  # pragma: no cover
        return "unknown"
    doc = yaml.safe_load(kb.CATALOG_PATH.read_text(encoding="utf-8")) or {}
    return str(doc.get("catalog_version") or "unknown")


def _rule_entry(rule: dict, tools: tuple[ToolCapability, ...]) -> dict:
    direct = [tool for tool in tools if _supports_rule(tool, rule)]
    adjacent = [tool for tool in tools if tool not in direct and _adjacent_support(tool, rule)]
    if direct:
        status = "covered"
        confidence = "high" if any(tool.confidence == "high" for tool in direct) else "medium"
        reason = "At least one scanner family directly matches the rule detection method, category, and language metadata."
    elif adjacent:
        status = "partial"
        confidence = "low"
        reason = "Scanner families have adjacent semantic coverage, but this rule still needs validated query/rule support."
    else:
        status = "blind_spot"
        confidence = "low"
        reason = "No current scanner family maps to the rule detection method, category, and language metadata."

    cwe = [f"CWE-{item}" for item in (rule.get("cwe") or [])]
    return {
        "rule_id": rule.get("id"),
        "name": rule.get("name"),
        "category": rule.get("category"),
        "severity": rule.get("severity"),
        "languages": rule.get("languages") or [],
        "detection": rule.get("detection"),
        "cwe": cwe,
        "owasp": rule.get("owasp"),
        "status": status,
        "confidence": confidence,
        "tools": [tool.name for tool in direct],
        "adjacent_tools": [tool.name for tool in adjacent],
        "blind_spot": status == "blind_spot",
        "reason": reason,
    }


def _counter_to_rows(counter: Counter) -> list[dict]:
    return [{"name": name, "count": count} for name, count in sorted(counter.items())]


def catalog_coverage_map(include_rules: bool = True, tool_names: Iterable[str] | None = None) -> dict:
    selected_names = {name.lower() for name in tool_names} if tool_names else None
    tools = tuple(tool for tool in TOOL_CAPABILITIES if selected_names is None or tool.name in selected_names)
    rules = list(kb.all_rules())
    entries = [_rule_entry(rule, tools) for rule in rules]

    status_counts = Counter(entry["status"] for entry in entries)
    detection_counts: dict[str, Counter] = defaultdict(Counter)
    language_counts: dict[str, Counter] = defaultdict(Counter)
    category_counts: dict[str, Counter] = defaultdict(Counter)
    tool_counts = Counter()

    for entry in entries:
        status = entry["status"]
        detection_counts[str(entry["detection"])][status] += 1
        category_counts[str(entry["category"])][status] += 1
        for language in entry["languages"] or ["*"]:
            language_counts[str(language)][status] += 1
        for tool_name in entry["tools"]:
            tool_counts[tool_name] += 1

    report = {
        "schema_version": 1,
        "catalog_version": _catalog_version(),
        "rule_count": len(entries),
        "tooling": [
            {
                "name": tool.name,
                "label": tool.label,
                "detections": sorted(tool.detections),
                "languages": sorted(tool.languages),
                "categories": sorted(tool.categories),
                "confidence": tool.confidence,
                "notes": tool.notes,
                "rule_ids": sorted(tool.rule_ids),
            }
            for tool in tools
        ],
        "summary": {
            "covered": status_counts["covered"],
            "partial": status_counts["partial"],
            "blind_spot": status_counts["blind_spot"],
        },
        "tool_summary": _counter_to_rows(tool_counts),
        "detection_summary": [
            {"detection": detection, **dict(counts)}
            for detection, counts in sorted(detection_counts.items())
        ],
        "category_summary": [
            {"category": category, **dict(counts)}
            for category, counts in sorted(category_counts.items())
        ],
        "language_summary": [
            {"language": language, **dict(counts)}
            for language, counts in sorted(language_counts.items())
        ],
        "blind_spots": [entry for entry in entries if entry["status"] == "blind_spot"],
        "interpretation": "Metadata capability map: covered means Secure Review has a scanner family suited to the rule; partial means likely adjacent support still needs benchmarked rule/query validation.",
    }
    if include_rules:
        report["rules"] = entries
    return report
