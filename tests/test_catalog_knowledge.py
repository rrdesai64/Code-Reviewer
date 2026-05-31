"""Tests for the shared catalog knowledge layer (matching + text builders)."""
import pytest

from app import catalog_knowledge as kb
from app.models import FixSuggestion


def test_catalog_loads():
    assert kb.available()
    assert len(kb.all_rules()) > 100


def test_get_rule_and_detection_filter():
    assert kb.get_rule("SEC-002")["name"]
    assert kb.get_rule("does-not-exist") is None
    byte_rules = kb.rules_for_detection("binary_scan")
    assert {r["id"] for r in byte_rules} >= {"ENC-005", "LEX-001"}


@pytest.mark.parametrize("rule_id,message,cwe,expected", [
    ("python-subprocess-shell-true", "Avoid subprocess shell=True.", ["CWE-78"], "SEC-002"),
    ("javascript-innerhtml-assignment", "innerHTML can introduce XSS.", ["CWE-79"], "SEC-004"),
    ("python-dynamic-execution", "Avoid eval/exec on dynamic data.", ["CWE-94"], "PY-003"),
    ("javascript-dynamic-execution", "Avoid eval or Function with dynamic data.", ["CWE-94"], "JS-005"),
    ("python-hardcoded-secret", "Potential hardcoded secret in source code.", ["CWE-798"], "SEC-006"),
    ("B602", "subprocess call with shell=True identified.", ["CWE-78"], "SEC-002"),
    ("SEC-005", "exact id wins", [], "SEC-005"),
])
def test_match_rule_expected(rule_id, message, cwe, expected):
    rule = kb.match_rule(rule_id, message, cwe)
    assert rule is not None and rule["id"] == expected


@pytest.mark.parametrize("rule_id,message,cwe", [
    ("some-unknown-rule", "completely unrelated lint message about spacing", []),
    ("flask-debug-enabled", "Flask debug mode should not be enabled.", ["CWE-489"]),
])
def test_match_rule_falls_back_to_none(rule_id, message, cwe):
    assert kb.match_rule(rule_id, message, cwe) is None


def test_whole_word_not_substring():
    # 'unknown' must not match the rule named 'Known-vulnerable dependency'
    assert kb.match_rule("some-unknown-rule", "unknown lint", []) is None


def test_language_disambiguation():
    py = kb.match_rule("python-dynamic-execution", "Avoid eval/exec on dynamic data.", ["CWE-94"])
    js = kb.match_rule("javascript-dynamic-execution", "Avoid eval or Function with dynamic data.", ["CWE-94"])
    assert py["id"] == "PY-003" and js["id"] == "JS-005"


def test_build_explanation_includes_text_and_taxonomy():
    rule = kb.get_rule("SEC-002")
    text = kb.build_explanation(rule, ["CWE-78"], ["A03:2021-Injection"])
    assert rule["description"].split(".")[0] in text
    assert "CWE-78" in text and "OWASP" in text


def test_build_fix_shape():
    fix = kb.build_fix(kb.get_rule("SEC-001"))
    assert isinstance(fix, FixSuggestion)
    assert fix.summary
    assert any("Recommended:" in g for g in fix.guidance)
