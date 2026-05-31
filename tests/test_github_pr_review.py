from app.github_pr import build_github_pr_review
from app.risk import score_scan


DIFF = """diff --git a/app/db.py b/app/db.py
index 1111111..2222222 100644
--- a/app/db.py
+++ b/app/db.py
@@ -1,1 +1,3 @@
 context = True
+query = request.args["q"]
+old_debt = request.args["old"]
"""


def scored_scan(make_scan, findings, new_fingerprints):
    scan = make_scan(findings=findings)
    scan.new_findings = new_fingerprints
    return score_scan(scan)


def test_github_pr_review_comments_only_on_new_added_lines(make_scan, make_finding):
    new = make_finding(id="new", fingerprint="fp-new", rule_id="SEC-002", cwe=["CWE-89"], path="app/db.py", line=2, message="SQL injection")
    old = make_finding(id="old", fingerprint="fp-old", rule_id="SEC-003", cwe=["CWE-89"], path="app/db.py", line=3, message="SQL injection")
    scan = scored_scan(make_scan, [new, old], ["fp-new"])

    review = build_github_pr_review(
        scan,
        repository="owner/repo",
        pr_number=7,
        diff_text=DIFF,
        min_inline_risk=1,
        max_inline_comments=10,
    )

    assert review["review"]["inline_comment_count"] == 1
    assert review["review"]["inline_comments"][0]["finding_id"] == "new"
    assert review["review"]["summary_only_findings"] == []
    assert "not marked new since baseline" not in review["review"]["body"]
    assert review["status"]["open_findings"] == 1
    assert review["diff"]["changed_lines"] == 2


def test_github_pr_review_uses_one_consolidated_inline_comment(make_scan, make_finding):
    semgrep = make_finding(id="sg", fingerprint="fp-sg", source="semgrep", rule_id="python.sql-injection", cwe=["CWE-89"], path="app/db.py", line=2, message="SQL injection")
    codeql = make_finding(id="ql", fingerprint="fp-ql", source="codeql", rule_id="py/sql-injection", cwe=["CWE-89"], path="app/db.py", line=2, message="SQL injection")
    scan = scored_scan(make_scan, [semgrep, codeql], ["fp-sg", "fp-ql"])

    review = build_github_pr_review(
        scan,
        repository="owner/repo",
        pr_number=7,
        diff_text=DIFF,
        min_inline_risk=1,
        max_inline_comments=10,
    )

    assert review["review"]["inline_comment_count"] == 1
    comment = review["review"]["inline_comments"][0]
    assert comment["cluster_id"].startswith("cf-")
    assert "Tool agreement" in review["review"]["payload"]["comments"][0]["body"]


def test_github_pr_review_respects_inline_suppression(make_scan, make_finding):
    finding = make_finding(id="suppressed", fingerprint="fp-suppressed", rule_id="SEC-002", cwe=["CWE-89"], path="app/db.py", line=2, message="SQL injection", decision="suppressed")
    finding.decision_reason = "sanitized upstream"
    scan = scored_scan(make_scan, [finding], ["fp-suppressed"])

    review = build_github_pr_review(
        scan,
        repository="owner/repo",
        pr_number=7,
        diff_text=DIFF,
        min_inline_risk=1,
        max_inline_comments=10,
    )

    assert review["review"]["inline_comment_count"] == 0
    assert review["review"]["summary_only_findings"][0]["reason"] == "suppressed by in-code annotation"
    assert review["status"]["open_findings"] == 0
