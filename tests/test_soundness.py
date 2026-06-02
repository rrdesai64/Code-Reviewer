from app.models import FindingDataflow, Location
from app.consolidation import ensure_consolidated_scan
from app.priority import apply_priority_scoring
from app.soundness import soundness_verdict


def test_soundness_blocks_ranked_actionable_issue(make_scan, make_finding):
    finding = make_finding(id="semgrep", fingerprint="semgrep", severity="HIGH", path="src/app.py", message="sql injection", cwe=["CWE-89"])
    finding.dataflow = FindingDataflow(
        has_dataflow=True,
        source=Location(path="src/app.py", line=3),
        sink=Location(path="src/app.py", line=12),
        steps=2,
        tool_precision="high",
    )
    corroborating = make_finding(
        id="codeql",
        fingerprint="codeql",
        source="codeql",
        severity="HIGH",
        path="src/app.py",
        message="sql injection",
        cwe=["CWE-89"],
    )
    scan = apply_priority_scoring(make_scan(findings=[finding, corroborating]))

    report = soundness_verdict(scan)

    assert report["schema_version"] == "soundness-verdict-v1"
    assert report["verdict"]["status"] == "block"
    assert report["verdict"]["blocking_issue_count"] == 1
    assert report["issues"][0]["gate"]["effect"] == "block"
    assert "priority:P0" in report["issues"][0]["gate"]["reason_codes"]
    assert report["issues"][0]["remediation"]["rescan_required"] is True
    assert report["determinism"]["scan_id_included"] is False


def test_soundness_contract_is_deterministic_without_scan_metadata(make_scan, make_finding):
    finding_a = make_finding(id="same", fingerprint="same-fp", severity="HIGH", path="src/app.py")
    finding_b = make_finding(id="same", fingerprint="same-fp", severity="HIGH", path="src/app.py")
    first = make_scan(findings=[finding_a], scan_id="scan-a")
    second = make_scan(findings=[finding_b], scan_id="scan-b")

    assert soundness_verdict(first) == soundness_verdict(second)


def test_soundness_replay_is_deterministic_when_finding_order_changes(make_scan, make_finding):
    findings = [
        make_finding(id="sg", fingerprint="sg", source="semgrep", rule_id="python.sql-injection", severity="HIGH", path="src/db.py", line=40, message="SQL injection", cwe=["CWE-89"]),
        make_finding(id="ql", fingerprint="ql", source="codeql", rule_id="py/sql-injection", severity="HIGH", path="src/db.py", line=42, message="SQL injection", cwe=["CWE-89"]),
        make_finding(id="dep", fingerprint="dep", source="pip-audit", rule_id="PYSEC-1", severity="HIGH", path="requirements.txt", line=2, message="vulnerable dependency", cwe=["CWE-937"]),
    ]
    reversed_findings = [
        make_finding(id="dep", fingerprint="dep", source="pip-audit", rule_id="PYSEC-1", severity="HIGH", path="requirements.txt", line=2, message="vulnerable dependency", cwe=["CWE-937"]),
        make_finding(id="ql", fingerprint="ql", source="codeql", rule_id="py/sql-injection", severity="HIGH", path="src/db.py", line=42, message="SQL injection", cwe=["CWE-89"]),
        make_finding(id="sg", fingerprint="sg", source="semgrep", rule_id="python.sql-injection", severity="HIGH", path="src/db.py", line=40, message="SQL injection", cwe=["CWE-89"]),
    ]

    first = soundness_verdict(make_scan(findings=findings))
    second = soundness_verdict(make_scan(findings=reversed_findings))

    assert first == second
    assert first["determinism"]["replay_digest"] == second["determinism"]["replay_digest"]
    assert first["determinism"]["agent_decisions_recomputed_after_duplicate_merge"] is True


def test_soundness_issue_id_is_line_insensitive(make_scan, make_finding):
    first = make_finding(id="a", fingerprint="a", severity="HIGH", path="src/app.py", line=10, message="same issue")
    second = make_finding(id="b", fingerprint="b", severity="HIGH", path="src/app.py", line=99, message="same issue")

    first_report = soundness_verdict(make_scan(findings=[first]))
    second_report = soundness_verdict(make_scan(findings=[second]))

    assert first_report["issues"][0]["issue_id"] == second_report["issues"][0]["issue_id"]


def test_soundness_merges_duplicate_agent_issues_across_line_shifted_clusters(make_scan, make_finding):
    first = make_finding(
        id="semgrep",
        fingerprint="semgrep",
        source="semgrep",
        rule_id="python.sql-injection",
        severity="HIGH",
        path="src/db.py",
        line=10,
        message="SQL injection",
        cwe=["CWE-89"],
    )
    second = make_finding(
        id="codeql",
        fingerprint="codeql",
        source="codeql",
        rule_id="py/sql-injection",
        severity="HIGH",
        path="src/db.py",
        line=80,
        message="SQL injection",
        cwe=["CWE-89"],
    )

    report = soundness_verdict(make_scan(findings=[first, second]))

    assert report["summary"]["consolidated_issue_count"] == 1
    issue = report["issues"][0]
    assert issue["correlation"]["duplicate_cluster_count"] == 2
    assert len(issue["correlation"]["legacy_cluster_ids"]) == 2
    assert [location["line"] for location in issue["locations"]] == [10, 80]
    assert issue["evidence"]["sources"] == ["codeql", "semgrep"]
    assert issue["evidence"]["tool_agreement_count"] == 2


def test_soundness_collapses_multi_tool_duplicate_into_one_agent_queue_item(make_scan, make_finding):
    findings = [
        make_finding(id="sg", fingerprint="sg", source="semgrep", rule_id="python.sql-injection", severity="HIGH", path="app/db.py", line=42, message="User input reaches SQL query", cwe=["CWE-89"]),
        make_finding(id="ql", fingerprint="ql", source="codeql", rule_id="py/sql-injection", severity="HIGH", path="app/db.py", line=43, message="SQL injection sink", cwe=["CWE-89"]),
        make_finding(id="bandit", fingerprint="bandit", source="bandit", rule_id="B608", severity="MEDIUM", path="app/db.py", line=41, message="Possible SQL injection vector"),
        make_finding(id="sonar", fingerprint="sonar", source="sonarqube", rule_id="python:S3649", severity="HIGH", path="app/db.py", line=44, message="SQL injection risk in dynamic SQL"),
    ]

    report = soundness_verdict(make_scan(findings=findings))

    assert len(report["issues"]) == 1
    assert report["issues"][0]["evidence"]["sources"] == ["bandit", "codeql", "semgrep", "sonarqube"]
    assert report["issues"][0]["evidence"]["actionable_finding_count"] == 4
    assert report["summary"]["agent_fix_queue_count"] == 1
    assert report["agent_fix_queue"][0]["issue_id"] == report["issues"][0]["issue_id"]
    assert "tool-agreement" in report["agent_fix_queue"][0]["precision"]["strong_signals"]
    assert report["agent_loop_readiness"]["agent_handoff_ready"] is True


def test_confirmed_exploitable_cluster_forces_p0_and_block(make_scan, make_finding):
    confirmed = make_finding(
        id="dast-confirmed",
        fingerprint="dast-confirmed",
        source="dast:zap",
        rule_id="zap-40018",
        severity="INFO",
        path="app/db.py",
        line=42,
        message="SQL injection was dynamically confirmed",
        cwe=["CWE-89"],
    )
    confirmed.dataflow = FindingDataflow(confirmed_exploitable=True)
    lower = make_finding(
        id="low-confidence",
        fingerprint="low-confidence",
        source="semgrep",
        rule_id="python.sql-injection",
        severity="INFO",
        path="app/db.py",
        line=42,
        message="Possible SQL injection",
        cwe=["CWE-89"],
    )
    scan = make_scan(findings=[lower, confirmed])

    clustered = ensure_consolidated_scan(scan)
    assert len(clustered.consolidated_findings) == 1
    assert clustered.consolidated_findings[0].priority == "P0"

    report = soundness_verdict(clustered)

    assert report["verdict"]["status"] == "block"
    assert report["verdict"]["blocking_issue_count"] == 1
    issue = report["issues"][0]
    assert issue["priority"]["tier"] == "P0"
    assert issue["gate"]["effect"] == "block"
    assert "priority:P0" in issue["gate"]["reason_codes"]
    assert issue["evidence"]["dataflow"]["confirmed_exploitable"] is True


def test_soundness_agent_fix_queue_excludes_low_value_test_and_vendor_items(make_scan, make_finding):
    test_finding = make_finding(id="test", fingerprint="test", severity="CRITICAL", path="tests/test_db.py", message="SQL injection", cwe=["CWE-89"])
    vendor_finding = make_finding(id="vendor", fingerprint="vendor", severity="HIGH", path="vendor/pkg/db.py", message="SQL injection", cwe=["CWE-89"])

    report = soundness_verdict(make_scan(findings=[test_finding, vendor_finding]))

    assert report["summary"]["agent_fix_queue_count"] == 0
    assert report["agent_fix_queue"] == []
    decisions = {issue["location"]["path"]: issue["agent"] for issue in report["issues"]}
    assert decisions["tests/test_db.py"]["fix_queue_eligible"] is False
    assert "excluded:path-class:test" in decisions["tests/test_db.py"]["reason_codes"]
    assert decisions["vendor/pkg/db.py"]["fix_queue_eligible"] is False
    assert "excluded:path-class:vendor" in decisions["vendor/pkg/db.py"]["reason_codes"]


def test_soundness_agent_fix_queue_requires_strong_precision_signal(make_scan, make_finding):
    finding = make_finding(id="single", fingerprint="single", severity="MEDIUM", path="src/app.py", message="potential issue")

    report = soundness_verdict(make_scan(findings=[finding]))

    assert report["summary"]["agent_fix_queue_count"] == 0
    assert report["agent_loop_readiness"]["status"] == "not_ready"
    assert report["issues"][0]["agent"]["fix_queue_eligible"] is False
    assert "excluded:precision:no-strong-signal" in report["issues"][0]["agent"]["reason_codes"]


def test_soundness_marks_dependency_update_as_safe_autofix_candidate(make_scan, make_finding):
    finding = make_finding(
        id="dep",
        fingerprint="dep",
        source="pip-audit",
        rule_id="PYSEC-2026-1",
        severity="HIGH",
        path="requirements.txt",
        line=1,
        message="vulnerable dependency",
    )

    report = soundness_verdict(make_scan(findings=[finding]))

    assert report["summary"]["agent_fix_queue_count"] == 1
    assert report["summary"]["safe_autofix_candidate_count"] == 1
    assert report["agent_loop_readiness"]["verified_autofix_ready"] is True
    assert report["agent_fix_queue"][0]["safety"]["safe_autofix_candidate"] is True
    assert report["agent_fix_queue"][0]["safety"]["remediation_class"] == "dependency-update"


def test_soundness_allows_agent_handoff_but_blocks_unsafe_autofix_class(make_scan, make_finding):
    finding = make_finding(id="sg", fingerprint="sg", source="semgrep", rule_id="python.sql-injection", severity="HIGH", path="src/db.py", line=10, message="SQL injection", cwe=["CWE-89"])
    finding.dataflow = FindingDataflow(has_dataflow=True, source=Location(path="src/db.py", line=2), sink=Location(path="src/db.py", line=10), tool_precision="high")

    report = soundness_verdict(make_scan(findings=[finding]))

    assert report["summary"]["agent_fix_queue_count"] == 1
    assert report["summary"]["safe_autofix_candidate_count"] == 0
    assert report["agent_loop_readiness"]["agent_handoff_ready"] is True
    assert report["agent_loop_readiness"]["verified_autofix_ready"] is False
    assert report["agent_fix_queue"][0]["agent"]["fix_queue_eligible"] is True
    assert report["agent_fix_queue"][0]["agent"]["safe_autofix_candidate"] is False
    assert "unsafe-remediation-class:manual-guidance" in report["agent_fix_queue"][0]["safety"]["blockers"]


def test_soundness_uses_catalog_grounded_fix_guidance(make_scan, make_finding):
    finding = make_finding(
        source="catalog-native",
        rule_id="ENC-009",
        severity="HIGH",
        path="src/app.py",
        message="typographic quote where ASCII quote was likely intended",
    )
    finding.scanner_metadata["catalog_rule_id"] = "ENC-009"

    report = soundness_verdict(make_scan(findings=[finding]))
    issue = report["issues"][0]

    assert issue["vulnerability"]["catalog"]["matched"] is True
    assert issue["vulnerability"]["catalog"]["rule_id"] == "ENC-009"
    assert issue["remediation"]["source"] == "catalog"
    assert issue["remediation"]["summary"] == "Replace typographic punctuation with ASCII equivalents in code."


def test_soundness_ignores_non_open_decisions_for_gate(make_scan, make_finding):
    finding = make_finding(severity="CRITICAL", path="src/app.py", decision="suppressed")

    report = soundness_verdict(make_scan(findings=[finding]))

    assert report["verdict"]["status"] == "pass"
    assert report["issues"] == []
    assert report["summary"]["suppressed_or_non_open_findings"] == 1
