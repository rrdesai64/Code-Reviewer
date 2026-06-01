"""End-to-end smoke tests for app/cli.py."""
import json

from app.cli import main as cli_main


def test_cli_clean_repo_returns_zero(isolate_storage, isolate_enterprise, isolate_memory, tmp_path):
    repo = tmp_path / "clean"
    repo.mkdir()
    (repo / "ok.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    out = tmp_path / "scan.json"
    coverage = tmp_path / "catalog-coverage-map.json"
    code = cli_main(["--path", str(repo), "--json-out", str(out), "--catalog-coverage-out", str(coverage)])
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["summary"]["files_scanned"] >= 1
    coverage_data = json.loads(coverage.read_text(encoding="utf-8"))
    assert coverage_data["rule_count"] >= 150


def test_cli_fail_on_high_returns_2_and_writes_all_outputs(
        isolate_storage, isolate_enterprise, isolate_memory, isolate_rag, tmp_path):
    repo = tmp_path / "dirty"
    repo.mkdir()
    # Curly quotes -> ENC-009 (HIGH) from the native catalog scanner.
    (repo / "mod.py").write_bytes(b'x = \xe2\x80\x9chi\xe2\x80\x9d\n')
    outs = {name: tmp_path / f"{name}" for name in
            ("out.json", "out.sarif", "report.md", "pr.md", "compliance.json", "fixes.json", "prioritization.json", "soundness.json", "runtime-plan.json", "inside-loop.json")}
    code = cli_main([
        "--path", str(repo),
        "--json-out", str(outs["out.json"]),
        "--sarif-out", str(outs["out.sarif"]),
        "--report-out", str(outs["report.md"]),
        "--pr-comment-out", str(outs["pr.md"]),
        "--compliance-out", str(outs["compliance.json"]),
        "--fix-proposals-out", str(outs["fixes.json"]),
        "--prioritization-out", str(outs["prioritization.json"]),
        "--soundness-out", str(outs["soundness.json"]),
        "--runtime-plan-out", str(outs["runtime-plan.json"]),
        "--inside-out-autofix-loop-out", str(outs["inside-loop.json"]),
        "--inside-out-autofix-loop-no-persist",
        "--save-baseline",
        "--fail-on", "high",
    ])
    assert code == 2  # a HIGH finding meets the threshold
    for path in outs.values():
        assert path.exists() and path.stat().st_size > 0
    assert isinstance(json.loads(outs["out.sarif"].read_text()), dict)
    assert isinstance(json.loads(outs["fixes.json"].read_text()), list)
    assert json.loads(outs["prioritization.json"].read_text())["schema_version"] == "finding-prioritization-v1"
    assert json.loads(outs["soundness.json"].read_text())["schema_version"] == "soundness-verdict-v1"
    assert json.loads(outs["runtime-plan.json"].read_text())["schema_version"] == "runtime-build-plan-v1"
    assert json.loads(outs["inside-loop.json"].read_text())["schema_version"] == "inside-out-autofix-loop-v1"


def test_cli_clean_repo_with_fail_on_high_returns_zero(
        isolate_storage, isolate_enterprise, isolate_memory, tmp_path):
    repo = tmp_path / "clean2"
    repo.mkdir()
    (repo / "ok.py").write_text("value = 1\n", encoding="utf-8")
    code = cli_main(["--path", str(repo), "--fail-on", "high"])
    assert code == 0
