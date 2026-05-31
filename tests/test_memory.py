"""Tests for memory.py (repository memory and scan history)."""
from app import memory


def test_load_memory_default_shape(isolate_memory):
    mem = memory.load_memory()
    assert mem["schema_version"] >= 2
    assert mem["repositories"] == {}
    assert mem["scan_history"] == []
    assert mem["hotspots"] == {}
    assert mem["recurring_rules"] == {}


def test_repo_id_is_stable():
    a = memory.repo_id("/some/path")
    b = memory.repo_id("/some/path")
    assert a == b and len(a) == 16


def test_update_repository_memory(isolate_memory, tmp_path, make_scan, make_finding):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    findings = [make_finding(rule_id="SEC-002", path="app.py", severity="HIGH", fingerprint="fp1")]
    scan = make_scan(findings=findings)
    scan.target_path = str(repo)
    scan.new_findings = ["fp1"]

    mem = memory.update_repository_memory(scan)
    key = memory.repo_id(str(repo))
    record = mem["repositories"][key]
    assert record["project_name"] == "proj"
    assert record["last_scan_id"] == scan.scan_id
    assert record["top_hotspots"].get("app.py") == 1
    assert mem["scan_history"][0]["scan_id"] == scan.scan_id
    assert mem["recurring_rules"][key].get("SEC-002") == 1
    assert memory.MEMORY_PATH.exists()


def test_scan_history_is_capped(isolate_memory, tmp_path, make_scan):
    repo = tmp_path / "repo"
    repo.mkdir()
    for i in range(105):
        scan = make_scan(scan_id=f"s{i}")
        scan.target_path = str(repo)
        memory.update_repository_memory(scan)
    assert len(memory.load_memory()["scan_history"]) == min(105, memory.MAX_GLOBAL_HISTORY)


def test_repository_context(isolate_memory, tmp_path, make_scan):
    assert "No prior repository memory" in memory.repository_context("/nonexistent")
    repo = tmp_path / "repo"
    repo.mkdir()
    scan = make_scan()
    scan.target_path = str(repo)
    memory.update_repository_memory(scan)
    ctx = memory.repository_context(str(repo))
    assert "Repository memory:" in ctx and "proj" in ctx
