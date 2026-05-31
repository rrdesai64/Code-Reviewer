from app.models import FindingDataflow, Location
from app.priority import apply_priority_scoring, prioritization_report


def test_p0_requires_dataflow_or_cross_tool_guard(make_scan, make_finding):
    finding = make_finding(severity="CRITICAL", path="src/app.py", message="critical issue")
    scan = apply_priority_scoring(make_scan(findings=[finding]))

    assert scan.findings[0].priority.score == 100
    assert scan.findings[0].priority.tier == "P1"
    assert scan.summary.finding_priority_counts == {"P1": 1}


def test_dataflow_and_tool_agreement_can_raise_p0(make_scan, make_finding):
    finding = make_finding(severity="HIGH", path="src/app.py", message="sql injection")
    finding.dataflow = FindingDataflow(
        has_dataflow=True,
        source=Location(path="src/app.py", line=3),
        sink=Location(path="src/app.py", line=12),
        steps=2,
        tool_precision="high",
    )
    finding.priority_context.corroborating_tools = ["semgrep", "codeql"]

    scan = apply_priority_scoring(make_scan(findings=[finding]))

    assert scan.findings[0].priority.tier == "P0"
    assert scan.findings[0].priority.score == 103
    assert scan.summary.top_finding_priority_score == 103


def test_test_vendor_generated_paths_are_capped_to_p3(make_scan, make_finding):
    finding = make_finding(severity="CRITICAL", path="tests/test_app.py")
    finding.dataflow = FindingDataflow(has_dataflow=True, tool_precision="high")
    finding.priority_context.corroborating_tools = ["semgrep", "codeql"]

    scan = apply_priority_scoring(make_scan(findings=[finding]))

    assert scan.findings[0].priority.tier == "P3"
    assert scan.findings[0].priority_context.path_class == "test"


def test_suppressed_decisions_are_excluded_from_active_ranking(make_scan, make_finding):
    finding = make_finding(severity="CRITICAL", path="src/app.py", decision="suppressed")
    finding.dataflow = FindingDataflow(has_dataflow=True)

    scan = apply_priority_scoring(make_scan(findings=[finding]))

    assert scan.findings[0].priority.tier is None
    assert scan.summary.finding_priority_counts == {}
    assert scan.summary.suppressed_prioritized_findings == 1


def test_prioritization_report_contains_ranked_records(make_scan, make_finding):
    low = make_finding(id="low", severity="LOW", fingerprint="low", path="src/a.py")
    high = make_finding(id="high", severity="HIGH", fingerprint="high", path="src/b.py")
    high.dataflow = FindingDataflow(has_dataflow=True)
    scan = apply_priority_scoring(make_scan(findings=[low, high]))

    report = prioritization_report(scan)

    assert report["schema_version"] == "finding-prioritization-v1"
    assert report["findings"][0]["finding_id"] == "high"
    assert report["policy"]["raw_code_included"] is False
