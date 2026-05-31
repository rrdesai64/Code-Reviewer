from app import scanner
from app.catalog_coverage import catalog_coverage_map
from app.shell_policy_scan import run_shell_policy_scan


def test_shell_policy_detects_missing_strict_mode_and_pipeline_without_pipefail(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    script = repo / "deploy.sh"
    script.write_text("#!/usr/bin/env bash\ngrep needle input.txt | sort\n", encoding="utf-8")

    findings, status = run_shell_policy_scan(repo, [script])

    assert status == "ok: 1 files, 2 shell policy rules, findings=2"
    by_rule = {finding.rule_id: finding for finding in findings}
    assert set(by_rule) == {"SH-002", "SH-006"}
    assert by_rule["SH-002"].location.line == 1
    assert by_rule["SH-006"].location.line == 2
    assert by_rule["SH-006"].location.column == 23
    assert by_rule["SH-002"].source == "shell-policy"


def test_shell_policy_accepts_strict_mode_and_ignores_quoted_or_commented_pipes(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    script = repo / "safe.sh"
    script.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "echo 'a|b'\n"
        "echo \"c|d\"\n"
        "# grep x file | sort\n"
        "grep needle input.txt | sort\n",
        encoding="utf-8",
    )

    findings, status = run_shell_policy_scan(repo, [script])

    assert status == "ok: 1 files, 2 shell policy rules, findings=0"
    assert findings == []


def test_shell_policy_statuses(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("print('ok')\n", encoding="utf-8")

    findings, status = run_shell_policy_scan(repo, [source])
    assert findings == []
    assert status == "skipped: no shell files"

    monkeypatch.setenv("SHELL_POLICY_ENABLED", "false")
    findings, status = run_shell_policy_scan(repo, [source])
    assert findings == []
    assert status == "disabled by SHELL_POLICY_ENABLED=false"


def test_run_scan_includes_shell_policy_findings(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    script = repo / "deploy.sh"
    script.write_text("#!/usr/bin/env bash\ncat release.txt | grep prod\n", encoding="utf-8")

    scan = scanner.run_scan(repo)

    assert scan.summary.tools["shell-policy"].startswith("ok: 1 files")
    assert any(finding.source == "shell-policy" and finding.rule_id == "SH-002" for finding in scan.findings)
    assert any(finding.source == "shell-policy" and finding.rule_id == "SH-006" for finding in scan.findings)


def test_shell_policy_catalog_coverage_closes_remaining_shell_blind_spots():
    report = catalog_coverage_map(tool_names=["shell-policy"])
    by_rule = {entry["rule_id"]: entry for entry in report["rules"]}

    assert by_rule["SH-002"]["status"] == "covered"
    assert by_rule["SH-002"]["tools"] == ["shell-policy"]
    assert by_rule["SH-006"]["status"] == "covered"
    assert by_rule["SH-006"]["tools"] == ["shell-policy"]
    assert by_rule["C-001"]["status"] == "blind_spot"
