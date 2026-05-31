"""Shared knowledge layer over the code-review rule catalog.

Single source of truth for reading rules/code_review_rules.yaml and turning a
finding (from any tool) into the catalog's structured knowledge: the matching
rule plus human-readable explanation and fix guidance. Both ai.py (grounding
Semgrep/Bandit findings) and catalog_scan.py (the native byte-level scanner)
consume this, so a given issue is explained identically regardless of which
detector surfaced it.

Detection logic does NOT live here -- only knowledge (text, taxonomy, matching).
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from .models import FixSuggestion

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

CATALOG_PATH = Path(__file__).resolve().parents[1] / "rules" / "code_review_rules.yaml"

# Generic words filtered out of keyword matching to avoid spurious hits.
_STOPWORDS = {
    "with", "this", "that", "from", "into", "used", "using", "should", "avoid",
    "calls", "call", "potential", "code", "data", "true", "false", "value",
    "when", "your", "here", "been", "will", "must", "only", "also", "where",
    "which", "while", "issue", "security", "source", "mode", "identified",
}
# Map a token in a tool's rule id to a catalog language, for tie-breaking.
_LANG_HINTS = {
    "python": "python", "py": "python", "javascript": "javascript", "js": "javascript",
    "typescript": "typescript", "ts": "typescript", "java": "java", "kotlin": "kotlin",
    "kt": "kotlin", "go": "go", "golang": "go", "rust": "rust", "rs": "rust",
    "shell": "shell", "bash": "shell", "sql": "sql", "docker": "dockerfile",
    "dockerfile": "dockerfile", "terraform": "terraform",
}


@lru_cache(maxsize=1)
def _load() -> tuple[list[dict], dict[str, dict], dict[str, list[dict]]]:
    rules: list[dict] = []
    if yaml is not None and CATALOG_PATH.exists():
        doc = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8")) or {}
        rules = doc.get("rules", [])
    by_id = {r["id"]: r for r in rules}
    by_cwe: dict[str, list[dict]] = {}
    for rule in rules:
        for num in (rule.get("cwe") or []):
            by_cwe.setdefault(f"CWE-{num}", []).append(rule)
    return rules, by_id, by_cwe


def available() -> bool:
    """True when the catalog could be loaded (PyYAML present and file found)."""
    return bool(_load()[0])


def all_rules() -> list[dict]:
    return _load()[0]


def get_rule(rule_id: str) -> dict | None:
    return _load()[1].get(rule_id)


def rules_for_detection(method: str) -> list[dict]:
    return [r for r in _load()[0] if r.get("detection") == method]


# --- matching -----------------------------------------------------------------
def _lang_hint(rule_id: str) -> str | None:
    for token in re.split(r"[^a-z0-9]+", rule_id.lower()):
        if token in _LANG_HINTS:
            return _LANG_HINTS[token]
    return None


def _tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower())
            if len(t) > 3 and t not in _STOPWORDS}


def _best_by_keyword(rules: list[dict], text: str, lang_hint: str | None = None) -> tuple[dict | None, int]:
    text_tokens = _tokens(text)
    best_score = 0
    top: list[dict] = []
    for rule in rules:
        score = sum(1 for t in _tokens(rule.get("name", "")) if t in text_tokens)
        if score > best_score:
            best_score, top = score, [rule]
        elif score == best_score and score > 0:
            top.append(rule)
    if not top:
        return None, 0
    if lang_hint and len(top) > 1:
        for rule in top:
            if lang_hint in rule.get("languages", []):
                return rule, best_score
    return top[0], best_score


def match_rule(rule_id: str, message: str, cwe: list[str] | None) -> dict | None:
    """Map an incoming finding to the most relevant catalog rule.

    Precedence: exact catalog id -> shared CWE with name overlap -> whole-word
    keyword match across all rules (rescues CWE taxonomy near-misses such as a
    tool tagging eval CWE-94 while the catalog uses CWE-95) -> shared CWE alone.
    Returns None when nothing is a reasonable match.
    """
    rules, by_id, by_cwe = _load()
    if not rules:
        return None
    if rule_id in by_id:
        return by_id[rule_id]
    text = f"{rule_id} {message}"
    hint = _lang_hint(rule_id)
    cwe_pool: list[dict] = []
    for code in (cwe or []):
        cwe_pool.extend(by_cwe.get(code, []))
    if cwe_pool:
        pooled, score = _best_by_keyword(cwe_pool, text, hint)
        if pooled is not None and score >= 1:
            return pooled
    overall, score = _best_by_keyword(rules, text, hint)
    if overall is not None and score >= 2:
        return overall
    return cwe_pool[0] if cwe_pool else None


# --- human-text builders (shared by ai.py and catalog_scan.py) ----------------
def context_suffix(cwe: list[str] | None, owasp: list[str] | None) -> str:
    parts = []
    if cwe:
        parts.append("CWE: " + ", ".join(cwe))
    if owasp:
        parts.append("OWASP: " + ", ".join(owasp))
    return " ".join(parts)


def build_explanation(rule: dict, cwe: list[str] | None = None, owasp: list[str] | None = None) -> str:
    body = " ".join(p for p in (rule.get("description", "").strip(),
                                rule.get("rationale", "").strip()) if p)
    return f"{body} {context_suffix(cwe, owasp)}".strip()


def build_fix(rule: dict) -> FixSuggestion:
    guidance = [g for g in [rule.get("rationale", "").strip()] if g]
    if rule.get("good"):
        guidance.append("Recommended: " + rule["good"].strip())
    return FixSuggestion(
        summary=rule.get("remediation", "Review and remediate this pattern.").strip(),
        guidance=guidance,
    )
