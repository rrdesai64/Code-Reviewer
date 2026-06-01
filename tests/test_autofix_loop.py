import shutil
import subprocess
import sys

import pytest

from app.autofix_loop import list_inside_out_autofix_loop_runs, load_inside_out_autofix_loop_run, run_inside_out_autofix_loop
from app.governance import enterprise_governance_report, governance_events
from app.models import InsideOutAutofixLoopRequest


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


def init_repo(repo):
    if not shutil.which("git"):
        pytest.skip("git is required for inside-out autofix loop tests")
    repo.mkdir()
    (repo / "requirements.txt").write_text("foo==1.0.0\n", encoding="utf-8")
    (repo / "check_fix.py").write_text(
        "from pathlib import Path\n"
        "assert Path('requirements.txt').read_text().strip() == 'foo==2.0.0'\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True, text=True)
    git(repo, "add", ".")
    git(repo, "-c", "user.name=Tester", "-c", "user.email=test@example.invalid", "commit", "-m", "initial")


def vulnerable_dependency_finding(make_finding):
    finding = make_finding(
        id="dep-1",
        source="pip-audit",
        rule_id="PYSEC-123",
        severity="HIGH",
        path="requirements.txt",
        line=1,
        message="vulnerable dependency foo",
    )
    finding.scanner_metadata = {"dependency_name": "foo", "best_fix_version": "2.0.0"}
    return finding


def test_inside_out_loop_dry_run_uses_soundness_safe_queue_without_rescan(tmp_path, make_scan, make_finding):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("foo==1.0.0\n", encoding="utf-8")
    scan = make_scan(findings=[vulnerable_dependency_finding(make_finding)], scan_id="loop-dry")
    scan.target_path = str(repo)

    def scanner_should_not_run(target, project_name):
        raise AssertionError("dry-run loop must not rescan")

    report = run_inside_out_autofix_loop(
        scan,
        InsideOutAutofixLoopRequest(dry_run=True, approved=True, persist=False),
        scanner_fn=scanner_should_not_run,
    )

    assert report["schema_version"] == "inside-out-autofix-loop-v1"
    assert report["status"] == "dry_run"
    assert report["gate"] == "not_run"
    assert report["summary"]["selected_issue_count"] == 1
    assert report["selected_finding_ids"] == ["dep-1"]
    assert report["iterations"][0]["agent_task_packet"]["schema_version"] == "inside-out-agent-task-v1"
    assert report["iterations"][0]["agent_task_packet"]["regression_gate"]["required"] is True
    assert report["iterations"][0]["agent_response"]["status"] == "dry_run"
    assert report["iterations"][0]["regression_check"]["status"] == "not_run"
    assert report["rescan"] is None
    assert (repo / "requirements.txt").read_text(encoding="utf-8").strip() == "foo==1.0.0"


def test_inside_out_loop_persists_run_and_governance_evidence(
    tmp_path,
    monkeypatch,
    make_scan,
    make_finding,
    isolate_enterprise,
):
    monkeypatch.setenv("SECURE_REVIEW_DATA_DIR", str(tmp_path / "data"))
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("foo==1.0.0\n", encoding="utf-8")
    scan = make_scan(findings=[vulnerable_dependency_finding(make_finding)], scan_id="loop-persist")
    scan.target_path = str(repo)

    report = run_inside_out_autofix_loop(
        scan,
        InsideOutAutofixLoopRequest(dry_run=True, approved=True, persist=True),
    )

    assert report["storage"]["persisted"] is True
    loaded = load_inside_out_autofix_loop_run(report["loop_id"])
    assert loaded["loop_id"] == report["loop_id"]
    runs = list_inside_out_autofix_loop_runs(scan_id="loop-persist")
    assert [item["loop_id"] for item in runs] == [report["loop_id"]]
    events = governance_events(category="agent-action", scan_id="loop-persist", limit=20)
    actions = {event["action"] for event in events}
    assert "inside_out_loop.requested" in actions
    assert "inside_out_loop.issues_selected" in actions
    assert "inside_out_loop.completed" in actions
    evidence = enterprise_governance_report(scan_id="loop-persist")
    assert evidence["agent_actions"]["inside_out_autofix_loops"][0]["loop_id"] == report["loop_id"]


def test_inside_out_loop_real_run_rescans_and_marks_selected_issue_resolved(
    tmp_path,
    monkeypatch,
    make_scan,
    make_finding,
    isolate_rag,
    isolate_memory,
):
    from app import verified_autofix

    repo = tmp_path / "repo"
    init_repo(repo)
    monkeypatch.setattr(verified_autofix, "DATA_DIR", tmp_path / "data")
    monkeypatch.setenv("FIX_APPLY_ENABLED", "true")
    monkeypatch.setenv("VERIFIED_AUTOFIX_ENABLED", "true")
    scan = make_scan(findings=[vulnerable_dependency_finding(make_finding)], scan_id="loop-green")
    scan.target_path = str(repo)

    def scanner_after_fix(target, project_name):
        assert (target / "requirements.txt").read_text(encoding="utf-8").strip() == "foo==2.0.0"
        rescan = make_scan(findings=[], scan_id="loop-green-rescan")
        rescan.target_path = str(target)
        return rescan

    report = run_inside_out_autofix_loop(
        scan,
        InsideOutAutofixLoopRequest(
            dry_run=False,
            approved=True,
            branch_name="secure-review/loop-green",
            test_commands=[f'"{sys.executable}" check_fix.py'],
            allow_auto_detect_tests=False,
            persist=False,
        ),
        scanner_fn=scanner_after_fix,
    )

    assert report["status"] == "resolved"
    assert report["gate"] == "passed"
    assert report["termination"] == "selected_issues_resolved_without_new_blockers_and_with_green_tests"
    assert report["summary"]["iterations_attempted"] == 1
    assert report["summary"]["resolved_issues"] == 1
    assert report["summary"]["regression_status"] == "passed"
    assert report["iterations"][0]["regression_check"]["status"] == "passed"
    assert report["iterations"][0]["agent_response"]["tests_passed"] is True
    assert report["verification"]["unresolved_issue_ids"] == []
    assert report["rescan"]["verdict"]["status"] == "pass"
    assert report["anti_oscillation"]["no_progress_detected"] is False


def test_inside_out_loop_accepts_deterministic_agent_response_packet(tmp_path, make_scan, make_finding):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("foo==2.0.0\n", encoding="utf-8")
    scan = make_scan(findings=[vulnerable_dependency_finding(make_finding)], scan_id="loop-agent-packet")
    scan.target_path = str(repo)

    def fake_agent(active_scan, verified_request, actor):
        return {
            "schema_version": "verified-autofix-v1",
            "scan_id": active_scan.scan_id,
            "project_name": active_scan.project_name,
            "actor": actor,
            "status": "verified",
            "gate": "passed",
            "dry_run": False,
            "blocked_reasons": [],
            "selected_finding_ids": verified_request.finding_ids,
            "apply": {"status": "applied", "applied": [{"path": "requirements.txt"}]},
            "verification": {
                "test_commands": ["python check_fix.py"],
                "tests": [{
                    "command": "python check_fix.py",
                    "cwd": str(repo),
                    "exit_code": 0,
                    "passed": True,
                    "duration_seconds": 0.01,
                    "stdout": "ok",
                    "stderr": "",
                    "timed_out": False,
                }],
            },
            "git": {"target_subpath": ""},
            "branch": {
                "name": verified_request.branch_name or "",
                "base": "",
                "worktree_path": str(repo),
                "source_head": "",
                "commit_sha": "abc123",
                "pushed": False,
            },
            "pull_request": {"attempted": False, "created": False, "url": ""},
            "commands": [],
        }

    def scanner_after_agent(target, project_name):
        rescan = make_scan(findings=[], scan_id="loop-agent-packet-rescan")
        rescan.target_path = str(target)
        return rescan

    report = run_inside_out_autofix_loop(
        scan,
        InsideOutAutofixLoopRequest(
            dry_run=False,
            approved=True,
            agent_id="deterministic-test-agent",
            test_commands=["python check_fix.py"],
            allow_auto_detect_tests=False,
            persist=False,
        ),
        scanner_fn=scanner_after_agent,
        autofix_fn=fake_agent,
    )

    iteration = report["iterations"][0]
    assert report["status"] == "resolved"
    assert iteration["agent_task_packet"]["agent_id"] == "deterministic-test-agent"
    assert iteration["agent_task_packet"]["expected_outcome"]["app_tests_pass"] is True
    assert iteration["agent_response"]["applied_change_count"] == 1
    assert iteration["agent_response"]["changed_paths"] == ["requirements.txt"]
    assert iteration["regression_check"]["tests"][0]["stdout_summary"] == "ok"


def test_inside_out_loop_stops_as_regressed_when_app_tests_fail(
    tmp_path,
    monkeypatch,
    make_scan,
    make_finding,
    isolate_rag,
    isolate_memory,
):
    from app import verified_autofix

    repo = tmp_path / "repo"
    init_repo(repo)
    monkeypatch.setattr(verified_autofix, "DATA_DIR", tmp_path / "data")
    monkeypatch.setenv("FIX_APPLY_ENABLED", "true")
    monkeypatch.setenv("VERIFIED_AUTOFIX_ENABLED", "true")
    scan = make_scan(findings=[vulnerable_dependency_finding(make_finding)], scan_id="loop-regressed")
    scan.target_path = str(repo)

    def scanner_should_not_run(target, project_name):
        raise AssertionError("regressed loop must stop before rescan")

    report = run_inside_out_autofix_loop(
        scan,
        InsideOutAutofixLoopRequest(
            dry_run=False,
            approved=True,
            branch_name="secure-review/loop-regressed",
            test_commands=[f'"{sys.executable}" -c "raise SystemExit(1)"'],
            allow_auto_detect_tests=False,
            persist=False,
        ),
        scanner_fn=scanner_should_not_run,
    )

    assert report["status"] == "regressed"
    assert report["gate"] == "blocked"
    assert report["termination"] == "regression_tests_failed"
    assert report["summary"]["regression_status"] == "failed"
    assert report["summary"]["regression_failures"] == 1
    assert report["iterations"][0]["regression_check"]["status"] == "failed"
    assert report["iterations"][0]["agent_response"]["commit_sha"] == ""


def test_inside_out_loop_reports_unresolved_after_rescan(
    tmp_path,
    monkeypatch,
    make_scan,
    make_finding,
    isolate_rag,
    isolate_memory,
):
    from app import verified_autofix

    repo = tmp_path / "repo"
    init_repo(repo)
    monkeypatch.setattr(verified_autofix, "DATA_DIR", tmp_path / "data")
    monkeypatch.setenv("FIX_APPLY_ENABLED", "true")
    monkeypatch.setenv("VERIFIED_AUTOFIX_ENABLED", "true")
    finding = vulnerable_dependency_finding(make_finding)
    scan = make_scan(findings=[finding], scan_id="loop-unresolved")
    scan.target_path = str(repo)

    def scanner_still_finds_issue(target, project_name):
        rescan_finding = vulnerable_dependency_finding(make_finding)
        rescan = make_scan(findings=[rescan_finding], scan_id="loop-unresolved-rescan")
        rescan.target_path = str(target)
        return rescan

    report = run_inside_out_autofix_loop(
        scan,
        InsideOutAutofixLoopRequest(
            dry_run=False,
            approved=True,
            branch_name="secure-review/loop-unresolved",
            test_commands=[f'"{sys.executable}" check_fix.py'],
            allow_auto_detect_tests=False,
            persist=False,
        ),
        scanner_fn=scanner_still_finds_issue,
    )

    assert report["status"] == "oscillating"
    assert report["gate"] == "blocked"
    assert report["termination"] == "same_issue_set_repeated_after_agent_attempt"
    assert report["summary"]["unresolved_issues"] == 1
    assert report["anti_oscillation"]["no_progress_detected"] is True
