from app.models import FindingDataflow, Location
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


def test_soundness_issue_id_is_line_insensitive(make_scan, make_finding):
    first = make_finding(id="a", fingerprint="a", severity="HIGH", path="src/app.py", line=10, message="same issue")
    second = make_finding(id="b", fingerprint="b", severity="HIGH", path="src/app.py", line=99, message="same issue")

    first_report = soundness_verdict(make_scan(findings=[first]))
    second_report = soundness_verdict(make_scan(findings=[second]))

    assert first_report["issues"][0]["issue_id"] == second_report["issues"][0]["issue_id"]


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
