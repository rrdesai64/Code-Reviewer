"""Tests for reporting.py (markdown report, HTML wrapper, PR comment)."""
from app.reporting import github_pr_comment, html_report, markdown_report


def test_markdown_report_contains_core_fields(make_scan, make_finding):
    scan = make_scan(findings=[make_finding(rule_id="SEC-002", message="shell injection risk")])
    md = markdown_report(scan)
    assert "# Secure Code Review Report: proj" in md
    assert "`scan1`" in md
    assert "SEC-002" in md
    assert "Production / Gate Findings" in md
    assert "shell injection risk" in md
    assert "**Suggested fix**" in md


def test_markdown_report_handles_no_findings(make_scan):
    md = markdown_report(make_scan(findings=[]))
    assert "No production-impacting findings were reported" in md


def test_html_report_escapes_content(make_scan, make_finding):
    scan = make_scan(findings=[make_finding(message="<script>alert(1)</script>")])
    out = html_report(scan)
    assert out.startswith("<!doctype html>")
    assert "<pre>" in out
    assert "&lt;script&gt;" in out          # escaped
    assert "<script>alert(1)" not in out    # never raw


def test_pr_comment_table_and_pipe_escape(make_scan, make_finding):
    finding = make_finding(rule_id="SEC-002", message="bad | pipe")
    finding.title = "bad | pipe"
    scan = make_scan(findings=[finding])
    comment = github_pr_comment(scan)
    assert "## Secure Code Review Summary" in comment
    assert "| Priority | Agreement | Severity | Tools | Rule/CWE | Location | Finding |" in comment
    assert "`SEC-002`" in comment
    assert "\\|" in comment  # the message pipe was escaped so the table stays intact


def test_pr_comment_truncates_after_25(make_scan, make_finding):
    findings = [make_finding(id=f"f{i}", fingerprint=f"fp{i}", line=(i * 20) + 1) for i in range(26)]
    comment = github_pr_comment(make_scan(findings=findings))
    assert "Showing 25 of 26 consolidated priorities" in comment
