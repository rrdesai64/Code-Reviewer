import json

from app import scanner
from app.catalog_coverage import catalog_coverage_map


def test_shellcheck_skips_when_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLCHECK_ENABLED", "false")
    repo = tmp_path / "repo"
    repo.mkdir()
    script = repo / "run.sh"
    script.write_text("echo $name\n", encoding="utf-8")

    findings, status = scanner.run_shellcheck(repo, [script])

    assert findings == []
    assert status == "disabled by SHELLCHECK_ENABLED=false"


def test_shellcheck_reports_not_installed(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLCHECK_ENABLED", "true")
    monkeypatch.delenv("SHELLCHECK_EXE", raising=False)
    monkeypatch.setattr(scanner, "resolve_tool", lambda name: None)
    repo = tmp_path / "repo"
    repo.mkdir()
    script = repo / "run.sh"
    script.write_text("echo $name\n", encoding="utf-8")

    findings, status = scanner.run_shellcheck(repo, [script])

    assert findings == []
    assert status == "not installed"


def test_shellcheck_skips_when_no_shell_files(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLCHECK_ENABLED", "true")
    monkeypatch.setattr(scanner, "resolve_tool", lambda name: "shellcheck")
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("print('ok')\n", encoding="utf-8")

    findings, status = scanner.run_shellcheck(repo, [source])

    assert findings == []
    assert status == "skipped: no shell files"


def test_shellcheck_json_is_normalized(tmp_path, monkeypatch):
    monkeypatch.setenv("SHELLCHECK_ENABLED", "true")
    monkeypatch.setattr(scanner, "resolve_tool", lambda name: "shellcheck")
    repo = tmp_path / "repo"
    repo.mkdir()
    script = repo / "run.sh"
    script.write_text("echo $name\nfor f in $(ls); do echo $f; done\n", encoding="utf-8")
    shellcheck_payload = {
        "comments": [
            {
                "file": str(script),
                "line": 1,
                "column": 6,
                "level": "warning",
                "code": 2086,
                "message": "Double quote to prevent globbing and word splitting.",
            },
            {
                "file": str(script),
                "line": 2,
                "column": 10,
                "level": "style",
                "code": 2045,
                "message": "Iterating over ls output is fragile. Use globs.",
            },
        ]
    }

    def fake_run_tool(command, cwd, timeout=180, env=None):
        assert command[:2] == ["shellcheck", "--format=json"]
        assert str(script) in command
        assert cwd == repo
        return 1, json.dumps(shellcheck_payload), ""

    monkeypatch.setattr(scanner, "run_tool", fake_run_tool)

    findings, status = scanner.run_shellcheck(repo, [script])

    assert status == "ok findings=2 files=1"
    assert [finding.rule_id for finding in findings] == ["SC2086", "SC2045"]
    assert findings[0].source == "shellcheck"
    assert findings[0].severity == "MEDIUM"
    assert findings[0].location.path == "run.sh"
    assert findings[0].scanner_metadata["catalog_rule_id"] == "SH-001"
    assert findings[1].severity == "INFO"
    assert findings[1].scanner_metadata["catalog_rule_id"] == "SH-003"


def test_shellcheck_catalog_coverage_is_rule_scoped():
    report = catalog_coverage_map(tool_names=["shellcheck"])
    by_rule = {entry["rule_id"]: entry for entry in report["rules"]}

    assert by_rule["SH-003"]["status"] == "covered"
    assert by_rule["SH-003"]["tools"] == ["shellcheck"]
    assert by_rule["SH-002"]["status"] == "blind_spot"
    assert by_rule["SH-006"]["status"] == "blind_spot"
    assert by_rule["SQL-001"]["status"] == "blind_spot"
