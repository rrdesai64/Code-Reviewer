import json

from app.models import FindingDataflow, Location, UnifiedSoundnessRequest
from app.soundness_tuning import build_soundness_tuning_profile_from_runs
from app.unified_soundness import outside_in_provider_registry, unified_soundness_verdict


def fastapi_app(path):
    path.mkdir(parents=True)
    (path / "app").mkdir()
    (path / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n\n"
        "@app.post('/api/orders')\n"
        "def create_order(id: str):\n"
        "    return {'id': id}\n",
        encoding="utf-8",
    )


def zap_report(path):
    path.write_text(
        json.dumps({
            "site": [{
                "alerts": [{
                    "pluginid": "40018",
                    "alert": "SQL Injection",
                    "risk": "High",
                    "confidence": "High",
                    "cweid": "89",
                    "desc": "SQL injection was confirmed dynamically.",
                    "instances": [{
                        "uri": "http://127.0.0.1:8000/api/orders",
                        "method": "POST",
                        "param": "id",
                        "attack": "' OR 1=1--",
                        "evidence": "SQL syntax error",
                    }],
                }],
            }],
        }),
        encoding="utf-8",
    )


def test_unified_soundness_reports_sound_for_clean_scan(make_scan):
    report = unified_soundness_verdict(make_scan(findings=[]))

    assert report["schema_version"] == "unified-soundness-verdict-v1"
    assert report["verdict"]["status"] == "sound"
    assert report["verdict"]["confidence"] == "high"
    assert report["issues"] == []


def test_unified_soundness_promotes_sast_dast_cluster_to_strongest_signal(tmp_path, make_scan, make_finding):
    repo = tmp_path / "repo"
    fastapi_app(repo)
    report_path = tmp_path / "zap.json"
    zap_report(report_path)
    sast = make_finding(
        id="semgrep-sqli",
        fingerprint="semgrep-sqli",
        source="semgrep",
        rule_id="python.sql-injection",
        severity="HIGH",
        path="app/main.py",
        line=5,
        message="SQL injection reaches query",
        cwe=["CWE-89"],
    )
    sast.dataflow = FindingDataflow(
        has_dataflow=True,
        source=Location(path="app/main.py", line=5),
        sink=Location(path="app/main.py", line=5),
        tool_precision="high",
    )
    scan = make_scan(findings=[sast], scan_id="unified-dast-sast")
    scan.target_path = str(repo)

    report = unified_soundness_verdict(
        scan,
        UnifiedSoundnessRequest(dast_report_paths=[str(report_path)]),
    )

    assert report["verdict"]["status"] == "unsound"
    assert report["verdict"]["confidence"] == "very-high"
    assert report["verdict"]["strongest_signal"] == "inside-out+outside-in-confirmed"
    assert report["summary"]["sast_dast_correlated_issue_count"] == 1
    top = report["issues"][0]
    assert top["signal_strength"] == "strongest"
    assert top["evidence"]["inside_out_sources"] == ["semgrep"]
    assert top["evidence"]["outside_in_sources"] == ["dast:zap"]
    assert top["agent"]["fix_queue_eligible"] is True
    assert report["outside_in"]["web"]["dast"]["performed"] is True
    assert report["outside_in"]["web"]["dast"]["complete"] is True


def test_unified_soundness_blocks_dast_only_without_autofix(tmp_path, make_scan):
    repo = tmp_path / "repo"
    fastapi_app(repo)
    report_path = tmp_path / "zap.json"
    zap_report(report_path)
    scan = make_scan(findings=[], scan_id="unified-dast-only")
    scan.target_path = str(repo)

    report = unified_soundness_verdict(
        scan,
        UnifiedSoundnessRequest(dast_report_paths=[str(report_path)]),
    )

    assert report["verdict"]["status"] == "unsound"
    top = report["issues"][0]
    assert top["signals"][0] == "outside-in-confirmed"
    assert top["agent"]["fix_queue_eligible"] is False
    assert "excluded:dast-only:no-inside-out-source" in top["agent"]["reason_codes"]


def test_dast_report_ingest_does_not_require_sandbox_running(tmp_path, make_scan):
    repo = tmp_path / "repo"
    fastapi_app(repo)
    report_path = tmp_path / "zap.json"
    zap_report(report_path)
    scan = make_scan(findings=[], scan_id="unified-ingest-no-sandbox")
    scan.target_path = str(repo)

    report = unified_soundness_verdict(
        scan,
        UnifiedSoundnessRequest(
            dast_report_paths=[str(report_path)],
            dast_run_tools=False,
            dast_require_sandbox_running=True,
        ),
    )

    dast = report["outside_in"]["web"]["dast"]
    assert dast["performed"] is True
    assert dast["complete"] is True
    assert dast["summary"]["dast_finding_count"] > 0
    assert report["summary"]["outside_in_confirmed_issue_count"] > 0
    assert report["verdict"]["status"] == "unsound"


def test_dast_run_mode_without_sandbox_is_loudly_incomplete(tmp_path, make_scan):
    repo = tmp_path / "repo"
    fastapi_app(repo)
    scan = make_scan(findings=[], scan_id="unified-run-no-sandbox")
    scan.target_path = str(repo)

    report = unified_soundness_verdict(
        scan,
        UnifiedSoundnessRequest(
            dast_base_url="http://127.0.0.1:8000",
            dast_run_tools=True,
            dast_require_sandbox_running=True,
        ),
    )

    dast = report["outside_in"]["web"]["dast"]
    assert dast["requested"] is True
    assert dast["performed"] is False
    assert dast["complete"] is False
    assert dast["status"] == "skipped"
    assert "outside-in:dast" in report["verdict"]["incomplete_dimensions"]
    assert report["verdict"]["qualification"] == "outside-in-incomplete"
    assert any("run_blocked" in reason for reason in dast["reason_codes"])


def test_feedback_tuning_profile_learns_resolved_and_recurred_signatures():
    resolved = loop_run(
        "loop-a",
        "resolved",
        "semgrep",
        "python.sql-injection",
        "SEC-002",
        resolved_ids=["issue-a"],
    )
    resolved_again = loop_run(
        "loop-b",
        "resolved",
        "semgrep",
        "python.sql-injection",
        "SEC-002",
        resolved_ids=["issue-b"],
    )
    recurred = loop_run(
        "loop-c",
        "oscillating",
        "bandit",
        "B608",
        "SEC-002",
        unresolved_ids=["issue-c"],
    )

    profile = build_soundness_tuning_profile_from_runs([resolved, resolved_again, recurred])

    weights = {item["signature"]["source"]: item for item in profile["rule_weights"]}
    assert profile["summary"]["learned_observation_count"] == 3
    assert weights["semgrep"]["priority_delta"] > 0
    assert weights["semgrep"]["precision_adjustment"] == "increase-confidence"
    assert weights["bandit"]["priority_delta"] < 0
    assert weights["bandit"]["precision_adjustment"] == "decrease-confidence"


def test_outside_in_provider_registry_keeps_non_web_deferred():
    report = outside_in_provider_registry()
    providers = {item["runtime"]: item for item in report["providers"]}

    assert providers["web"]["status"] == "ready"
    assert providers["web"]["runnable_in_loop"] is True
    assert providers["android"]["status"] == "deferred"
    assert providers["enterprise-saas"]["runnable_in_loop"] is False


def loop_run(loop_id, status, source, rule_id, vuln_class, resolved_ids=None, unresolved_ids=None):
    issue_id = (resolved_ids or unresolved_ids or ["issue"])[0]
    return {
        "loop_id": loop_id,
        "scan_id": "scan",
        "status": status,
        "gate": "passed" if status == "resolved" else "blocked",
        "dry_run": False,
        "summary": {"regression_status": "passed"},
        "selected_issues": [{"issue_id": issue_id}],
        "iterations": [{
            "selected_issue_ids": [issue_id],
            "agent_response": {"status": "verified"},
            "agent_task_packet": {"issues": [task_issue(issue_id, source, rule_id, vuln_class)]},
            "verification": {
                "resolved_issue_ids": resolved_ids or [],
                "unresolved_issue_ids": unresolved_ids or [],
                "new_blocker_issue_ids": [],
            },
        }],
        "verification": {
            "resolved_issue_ids": resolved_ids or [],
            "unresolved_issue_ids": unresolved_ids or [],
            "new_blocker_issue_ids": [],
        },
    }


def task_issue(issue_id, source, rule_id, vuln_class):
    return {
        "issue_id": issue_id,
        "agent_correlation_key": f"{source}:{rule_id}",
        "vulnerability": {
            "class": vuln_class,
            "source_rule": {
                "source": source,
                "rule_id": rule_id,
                "cwe": ["CWE-89"],
            },
        },
        "evidence_summary": {
            "sources": [source],
            "rules": [rule_id],
            "cwe": ["CWE-89"],
            "sink": vuln_class,
        },
        "safety": {"remediation_class": "manual-guidance"},
    }
