"""Tests for sarif.py (SARIF 2.1.0 export)."""
import pytest

from app.sarif import build_sarif, rule_from_finding, sarif_level


def test_build_sarif_top_level_shape(make_scan):
    doc = build_sarif(make_scan())
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert len(doc["runs"]) == 1
    assert doc["runs"][0]["tool"]["driver"]["name"]


def test_results_match_findings(make_scan, make_finding):
    scan = make_scan(findings=[make_finding(id="a", fingerprint="fa"), make_finding(id="b", fingerprint="fb")])
    doc = build_sarif(scan)
    results = doc["runs"][0]["results"]
    assert len(results) == 2
    r = results[0]
    assert r["ruleId"] and r["message"]["text"]
    assert r["partialFingerprints"]["secureReviewFingerprint"] == "fa"
    for key in ("source", "severity", "confidence", "cwe", "owasp", "decision"):
        assert key in r["properties"]


def test_rules_are_deduplicated(make_scan, make_finding):
    scan = make_scan(findings=[
        make_finding(id="a", rule_id="SEC-002", fingerprint="fa"),
        make_finding(id="b", rule_id="SEC-002", fingerprint="fb"),
        make_finding(id="c", rule_id="SEC-001", fingerprint="fc"),
    ])
    rules = build_sarif(scan)["runs"][0]["tool"]["driver"]["rules"]
    assert {r["id"] for r in rules} == {"SEC-002", "SEC-001"}


@pytest.mark.parametrize("severity,level", [
    ("CRITICAL", "error"), ("HIGH", "error"), ("MEDIUM", "warning"),
    ("LOW", "note"), ("INFO", "note"), ("BOGUS", "warning"),
])
def test_sarif_level_mapping(severity, level):
    assert sarif_level(severity) == level


def test_rule_from_finding_tags_and_precision(make_finding):
    finding = make_finding(cwe=["CWE-78"], owasp=["A03:2021-Injection"])
    rule = rule_from_finding(finding)
    assert rule["properties"]["tags"] == ["CWE-78", "A03:2021-Injection"]
    assert rule["properties"]["precision"] == "high"
    assert "Fix:" in rule["help"]["text"]
