"""Tests for refactor.py (human-reviewed fix proposals). Uses offline LLM only."""
import pytest

from app import refactor
from app.models import Finding, FixSuggestion, Location


def _finding(rule_id, message, path="app.py", line=1, source="semgrep", cwe=None):
    return Finding(
        id="f1", source=source, rule_id=rule_id, title=rule_id, severity="HIGH",
        confidence="HIGH", location=Location(path=path, line=line), message=message,
        cwe=cwe or [], owasp=[], explanation="why",
        fix=FixSuggestion(summary="generic fix", guidance=["check input"]), fingerprint="fp1",
    )


def test_deterministic_patch_shell():
    lines = ["os.system(cmd)\n"]
    patched, summary, notes = refactor.deterministic_patch(lines, _finding("x", "subprocess shell=True"))
    assert any("argument list" in line for line in patched)
    assert "argument-list" in summary
    assert notes


def test_deterministic_patch_eval():
    patched, summary, _ = refactor.deterministic_patch(["eval(data)\n"], _finding("x", "eval dynamic execution"))
    assert any("Dynamic code execution disabled" in line for line in patched)
    assert "dynamic code execution" in summary.lower()


def test_deterministic_patch_secret_adds_os_import():
    patched, summary, notes = refactor.deterministic_patch(
        ["API_KEY = 'abc123'\n"], _finding("x", "hardcoded secret"))
    assert patched[0].startswith("import os")
    assert any("os.environ.get" in line for line in patched)
    assert any("Rotate" in n for n in notes)


def test_deterministic_patch_default_is_noop():
    lines = ["a = 1\n"]
    patched, summary, _ = refactor.deterministic_patch(lines, _finding("x", "some other issue"))
    assert patched == lines  # no mechanical edit -> caller falls back to manual stub


def test_make_diff_and_empty():
    assert refactor.make_diff("a.py", ["x\n"], ["x\n"]) == ""
    diff = refactor.make_diff("a.py", ["x\n"], ["y\n"])
    assert "a/a.py" in diff and "b/a.py" in diff


def test_read_lines_missing(tmp_path):
    assert refactor.read_lines(tmp_path / "nope.py") == []


def test_build_fix_proposal_shell(isolate_rag, tmp_path, make_scan):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("os.system(user_input)\n", encoding="utf-8")
    finding = _finding("python-subprocess-shell-true", "subprocess shell=True", path="app.py")
    scan = make_scan(findings=[finding])
    scan.target_path = str(repo)

    proposal = refactor.build_fix_proposal(scan, "f1", provider="offline")
    assert proposal.finding_id == "f1"
    assert proposal.requires_human_approval is True
    assert "TODO" in proposal.patch
    assert proposal.safety_notes  # includes review notes + offline LLM note


def test_build_fix_proposal_unknown_finding(isolate_rag, tmp_path, make_scan):
    scan = make_scan()
    scan.target_path = str(tmp_path)
    with pytest.raises(ValueError):
        refactor.build_fix_proposal(scan, "does-not-exist")


def test_build_fix_proposal_manual_stub_when_no_edit(isolate_rag, tmp_path, make_scan):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("a = 1\n", encoding="utf-8")
    finding = _finding("style-rule", "cosmetic nit with no mechanical fix", path="app.py")
    scan = make_scan(findings=[finding])
    scan.target_path = str(repo)
    proposal = refactor.build_fix_proposal(scan, "f1", provider="offline")
    assert "Manual fix proposal" in proposal.patch
