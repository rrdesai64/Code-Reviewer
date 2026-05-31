import shutil
import subprocess
import sys

import pytest

from app.models import VerifiedAutofixRequest
from app.verified_autofix import run_verified_autofix


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


def init_repo(repo):
    if not shutil.which("git"):
        pytest.skip("git is required for verified autofix tests")
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True, text=True)
    (repo / "requirements.txt").write_text("foo==1.0.0\n", encoding="utf-8")
    (repo / "check_fix.py").write_text(
        "from pathlib import Path\n"
        "assert Path('requirements.txt').read_text().strip() == 'foo==2.0.0'\n",
        encoding="utf-8",
    )
    git(repo, "add", ".")
    git(repo, "-c", "user.name=Tester", "-c", "user.email=test@example.invalid", "commit", "-m", "initial")


def vulnerable_dependency_finding(make_finding):
    finding = make_finding(
        id="dep-1",
        source="pip-audit",
        rule_id="PYSEC-123",
        path="requirements.txt",
        line=1,
        message="vulnerable dependency foo",
    )
    finding.scanner_metadata = {"dependency_name": "foo", "best_fix_version": "2.0.0"}
    return finding


def test_verified_autofix_applies_on_branch_and_commits_after_green_tests(
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
    scan = make_scan(findings=[vulnerable_dependency_finding(make_finding)], scan_id="scan-green")
    scan.target_path = str(repo)

    report = run_verified_autofix(scan, VerifiedAutofixRequest(
        dry_run=False,
        approved=True,
        branch_name="secure-review/autofix-green",
        test_commands=[f'"{sys.executable}" check_fix.py'],
        allow_auto_detect_tests=False,
    ))

    assert report["status"] == "verified"
    assert report["gate"] == "passed"
    assert report["branch"]["commit_sha"]
    worktree = tmp_path / "data" / "verified-autofix" / "scan-green" / "secure-review__autofix-green"
    assert (worktree / "requirements.txt").read_text(encoding="utf-8").strip() == "foo==2.0.0"
    assert (repo / "requirements.txt").read_text(encoding="utf-8").strip() == "foo==1.0.0"


def test_verified_autofix_does_not_commit_when_tests_fail(
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
    scan = make_scan(findings=[vulnerable_dependency_finding(make_finding)], scan_id="scan-red")
    scan.target_path = str(repo)

    report = run_verified_autofix(scan, VerifiedAutofixRequest(
        dry_run=False,
        approved=True,
        branch_name="secure-review/autofix-red",
        test_commands=[f'"{sys.executable}" -c "raise SystemExit(1)"'],
        allow_auto_detect_tests=False,
    ))

    assert report["status"] == "tests_failed"
    assert report["gate"] == "failed"
    assert report["branch"]["commit_sha"] == ""
    assert report["pull_request"]["created"] is False


def test_verified_autofix_blocks_real_run_without_approval(tmp_path, monkeypatch, make_scan, make_finding, isolate_rag, isolate_memory):
    from app import verified_autofix

    repo = tmp_path / "repo"
    init_repo(repo)
    monkeypatch.setattr(verified_autofix, "DATA_DIR", tmp_path / "data")
    monkeypatch.setenv("FIX_APPLY_ENABLED", "true")
    monkeypatch.setenv("VERIFIED_AUTOFIX_ENABLED", "true")
    scan = make_scan(findings=[vulnerable_dependency_finding(make_finding)], scan_id="scan-blocked")
    scan.target_path = str(repo)

    report = run_verified_autofix(scan, VerifiedAutofixRequest(
        dry_run=False,
        approved=False,
        branch_name="secure-review/autofix-blocked",
        test_commands=[f'"{sys.executable}" check_fix.py'],
        allow_auto_detect_tests=False,
    ))

    assert report["status"] == "blocked"
    assert "approved=true is required for verified autofix" in report["blocked_reasons"]
