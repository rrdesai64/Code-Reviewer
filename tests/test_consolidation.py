from app.consolidation import consolidate_scan, consolidated_findings_report, ensure_consolidated_scan
from app.models import FindingDataflow


def test_cross_tool_sql_injection_findings_cluster_by_path_line_cwe_and_sink(make_scan, make_finding):
    findings = [
        make_finding(id="sg", fingerprint="fp-sg", source="semgrep", rule_id="python.sql-injection", cwe=["CWE-89"], path="app/db.py", line=42, message="User input reaches a SQL query"),
        make_finding(id="ql", fingerprint="fp-ql", source="codeql", rule_id="py/sql-injection", cwe=["CWE-89"], path="app/db.py", line=44, message="This query may be vulnerable to SQL injection"),
        make_finding(id="sonar", fingerprint="fp-sonar", source="sonarqube", rule_id="python:S3649", cwe=[], path="app/db.py", line=41, message="SQL injection risk in dynamic SQL"),
    ]
    scan = consolidate_scan(make_scan(findings=findings))

    assert len(scan.consolidated_findings) == 1
    cluster = scan.consolidated_findings[0]
    assert cluster.semantic_key == "CWE-89"
    assert cluster.sink == "sql-injection"
    assert cluster.sources == ["codeql", "semgrep", "sonarqube"]
    assert cluster.agreement_count == 3
    assert cluster.raw_count == 3
    assert cluster.priority == "P0"
    assert scan.summary.cross_tool_clusters == 1
    assert scan.summary.consolidated_findings == 1


def test_consolidation_does_not_merge_different_weaknesses_on_same_line(make_scan, make_finding):
    findings = [
        make_finding(id="sql", fingerprint="fp-sql", source="semgrep", rule_id="sql", cwe=["CWE-89"], path="app/views.py", line=12, message="SQL injection"),
        make_finding(id="xss", fingerprint="fp-xss", source="codeql", rule_id="xss", cwe=["CWE-79"], path="app/views.py", line=12, message="Reflected XSS"),
    ]
    scan = consolidate_scan(make_scan(findings=findings))

    assert len(scan.consolidated_findings) == 2
    assert {cluster.semantic_key for cluster in scan.consolidated_findings} == {"CWE-79", "CWE-89"}


def test_consolidation_rebuilds_stale_clusters_when_findings_are_added(make_scan, make_finding):
    syntax = make_finding(
        id="syntax",
        fingerprint="fp-syntax",
        source="python-ast",
        rule_id="python-ast-syntax-error",
        severity="LOW",
        path="app/main.py",
        line=4,
        message="Python syntax error prevented full AST analysis.",
        cwe=["CWE-758"],
    )
    scan = consolidate_scan(make_scan(findings=[syntax]))
    confirmed = make_finding(
        id="dast-confirmed",
        fingerprint="fp-dast-confirmed",
        source="dast:zap",
        rule_id="40018",
        severity="HIGH",
        path="app/main.py",
        line=4,
        message="SQL injection was dynamically confirmed.",
        cwe=["CWE-89"],
    )
    confirmed.dataflow = FindingDataflow(confirmed_exploitable=True)
    scan.findings.append(confirmed)

    rebuilt = ensure_consolidated_scan(scan)

    assert {finding_id for cluster in rebuilt.consolidated_findings for finding_id in cluster.finding_ids} == {"syntax", "dast-confirmed"}
    dast_cluster = next(cluster for cluster in rebuilt.consolidated_findings if "dast-confirmed" in cluster.finding_ids)
    assert dast_cluster.priority == "P0"


def test_consolidation_does_not_absorb_confirmed_dast_into_parser_error(make_scan, make_finding):
    syntax = make_finding(
        id="syntax",
        fingerprint="fp-syntax",
        source="python-ast",
        rule_id="python-ast-syntax-error",
        severity="LOW",
        path="app/main.py",
        line=4,
        message="Python syntax error prevented full AST analysis.",
        cwe=["CWE-758"],
    )
    confirmed = make_finding(
        id="dast-confirmed",
        fingerprint="fp-dast-confirmed",
        source="dast:zap",
        rule_id="40018",
        severity="HIGH",
        path="app/main.py",
        line=4,
        message="SQL injection was dynamically confirmed.",
        cwe=["CWE-89"],
    )
    confirmed.dataflow = FindingDataflow(confirmed_exploitable=True)

    scan = consolidate_scan(make_scan(findings=[syntax, confirmed]))

    assert len(scan.consolidated_findings) == 2
    assert {cluster.semantic_key for cluster in scan.consolidated_findings} == {"CWE-758", "CWE-89"}


def test_consolidation_does_not_merge_same_weakness_when_line_ranges_are_far_apart(make_scan, make_finding):
    findings = [
        make_finding(id="a", fingerprint="fp-a", source="semgrep", rule_id="sql", cwe=["CWE-89"], path="app/db.py", line=10, message="SQL injection"),
        make_finding(id="b", fingerprint="fp-b", source="codeql", rule_id="sql", cwe=["CWE-89"], path="app/db.py", line=40, message="SQL injection"),
    ]
    scan = consolidate_scan(make_scan(findings=findings))

    assert len(scan.consolidated_findings) == 2
    assert scan.summary.cross_tool_clusters == 0


def test_consolidation_can_match_shared_sink_when_cwe_is_missing(make_scan, make_finding):
    findings = [
        make_finding(id="sg", fingerprint="fp-sg", source="semgrep", rule_id="subprocess-shell", path="worker.py", line=7, message="Possible command injection through subprocess"),
        make_finding(id="ql", fingerprint="fp-ql", source="codeql", rule_id="py/command-line-injection", path="worker.py", line=9, message="OS command injection sink"),
    ]
    scan = consolidate_scan(make_scan(findings=findings))

    assert len(scan.consolidated_findings) == 1
    cluster = scan.consolidated_findings[0]
    assert cluster.semantic_key == "sink:command-injection"
    assert cluster.agreement_count == 2


def test_consolidated_priority_keeps_non_production_scope_discount(make_scan, make_finding):
    findings = [
        make_finding(id="sg", fingerprint="fp-sg", source="semgrep", rule_id="sql", cwe=["CWE-89"], path="tests/test_db.py", line=20, message="SQL injection"),
        make_finding(id="ql", fingerprint="fp-ql", source="codeql", rule_id="sql", cwe=["CWE-89"], path="tests/test_db.py", line=21, message="SQL injection"),
    ]
    scan = consolidate_scan(make_scan(findings=findings))

    cluster = scan.consolidated_findings[0]
    assert cluster.priority_score < 65
    assert cluster.recommended_action.startswith("Track as hygiene")
    assert any(factor.name == "scope" and factor.points < 0 for factor in cluster.factors)


def test_consolidation_cluster_id_is_stable_for_equivalent_evidence_order(make_scan, make_finding):
    first = make_finding(id="sg", fingerprint="fp-sg", source="semgrep", rule_id="sql", cwe=["CWE-89"], path="app/db.py", line=20, message="SQL injection")
    second = make_finding(id="ql", fingerprint="fp-ql", source="codeql", rule_id="sql", cwe=["CWE-89"], path="app/db.py", line=22, message="SQL injection")

    left = consolidate_scan(make_scan(findings=[first, second]))
    right = consolidate_scan(make_scan(findings=[second, first]))

    assert left.consolidated_findings[0].cluster_id == right.consolidated_findings[0].cluster_id


def test_consolidated_findings_report_preserves_raw_evidence(make_scan, make_finding):
    findings = [
        make_finding(id="sg", fingerprint="fp-sg", source="semgrep", rule_id="sql", cwe=["CWE-89"], path="app/db.py", line=20, message="SQL injection"),
        make_finding(id="ql", fingerprint="fp-ql", source="codeql", rule_id="sql", cwe=["CWE-89"], path="app/db.py", line=21, message="SQL injection"),
    ]
    report = consolidated_findings_report(make_scan(findings=findings))

    assert report["schema_version"] == "finding-consolidation-v1"
    assert report["raw_findings"] == 2
    assert report["consolidated_findings"] == 1
    assert report["clusters"][0]["evidence"][0]["finding_id"] in {"sg", "ql"}
