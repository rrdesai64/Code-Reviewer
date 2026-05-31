from app.suppressions import apply_inline_suppressions, inline_suppression_report


def test_inline_suppression_with_reason_marks_finding_suppressed(tmp_path, make_scan, make_finding):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "# secure-review: ignore SEC-002 - sanitized upstream\n"
        "query = request.args['q']\n",
        encoding="utf-8",
    )
    finding = make_finding(rule_id="SEC-002", path="app.py", line=2, message="SQL injection")

    scan = apply_inline_suppressions(repo, make_scan(findings=[finding]))

    assert scan.findings[0].decision == "suppressed"
    assert scan.findings[0].decision_reason == "sanitized upstream"
    assert scan.suppressions[0].matched_rule == "sec-002"
    assert scan.summary.suppressed_findings == 1


def test_inline_suppression_without_reason_is_invalid_and_not_applied(tmp_path, make_scan, make_finding):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "# secure-review: ignore SEC-002\n"
        "query = request.args['q']\n",
        encoding="utf-8",
    )
    finding = make_finding(rule_id="SEC-002", path="app.py", line=2, message="SQL injection")

    scan = apply_inline_suppressions(repo, make_scan(findings=[finding]))
    report = inline_suppression_report(scan)

    assert scan.findings[0].decision == "open"
    assert scan.suppressions == []
    assert scan.invalid_suppressions[0].reason == "suppression reason is required"
    assert report["invalid_annotations"] == 1


def test_inline_suppression_supports_same_line_annotations(tmp_path, make_scan, make_finding):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text(
        "run(input); // secure-review: ignore SEC-002 - sanitized upstream\n",
        encoding="utf-8",
    )
    finding = make_finding(rule_id="SEC-002", path="app.js", line=1, message="command injection")

    scan = apply_inline_suppressions(repo, make_scan(findings=[finding]))

    assert scan.findings[0].decision == "suppressed"
    assert scan.suppressions[0].annotation_line == 1
