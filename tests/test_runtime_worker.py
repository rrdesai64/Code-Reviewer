import json
from pathlib import Path

import pytest

from app.models import RuntimeBuildRunRequest
from app.runtime_worker import (
    list_runtime_build_run_jobs,
    load_runtime_build_run_job,
    prepare_runtime_build_run_job,
    runtime_build_run_preview,
    runtime_worker_status,
)


def node_repo(path: Path) -> None:
    path.mkdir(parents=True)
    (path / "package.json").write_text(
        '{"scripts":{"build":"next build","start":"next start","test":"vitest run"},'
        '"dependencies":{"next":"latest","react":"latest"}}',
        encoding="utf-8",
    )


def test_runtime_worker_preview_is_side_effect_free(tmp_path, make_scan, monkeypatch):
    monkeypatch.setenv("SECURE_REVIEW_DATA_DIR", str(tmp_path / "data"))
    repo = tmp_path / "next-app"
    node_repo(repo)
    scan = make_scan(findings=[], scan_id="runtime-worker-preview")
    scan.target_path = str(repo)

    preview = runtime_build_run_preview(scan, RuntimeBuildRunRequest())

    assert preview["schema_version"] == "runtime-build-run-worker-v1"
    assert preview["phase"] == "3B"
    assert preview["persisted"] is False
    assert preview["provider"] == "container"
    assert preview["safety_controls"]["host_execution"] is False
    assert preview["safety_controls"]["scratch_copy_required"] is True
    assert preview["selected_profile"]["runtime"] == "node"
    assert preview["execution_plan"]["build_commands"] == ["npm install", "npm run build"]
    assert preview["execution_plan"]["start_command"] == "npm start"
    assert not (tmp_path / "data" / "runtime-worker").exists()


def test_prepare_runtime_worker_job_writes_container_and_vm_artifacts(tmp_path, make_scan, monkeypatch):
    monkeypatch.setenv("SECURE_REVIEW_DATA_DIR", str(tmp_path / "data"))
    repo = tmp_path / "next-app"
    node_repo(repo)
    scan = make_scan(findings=[], scan_id="runtime-worker-job")
    scan.target_path = str(repo)

    job = prepare_runtime_build_run_job(
        scan,
        RuntimeBuildRunRequest(job_name="runtime-job", run_tests=True, run_id="unit-run"),
        actor="unit-test",
    )

    assert job["job_id"] == "runtime-job"
    assert job["status"] == "prepared"
    assert job["persisted"] is True
    assert job["container"]["image"] == "node:22-bookworm-slim"
    assert job["container"]["network_mode"] == "none"
    assert job["execution_plan"]["test_commands"] == ["npm test"]
    assert job["safety_controls"]["runs_tests"] is True

    for path in job["files"].values():
        assert path and Path(path).exists()

    entrypoint = Path(job["files"]["container_entrypoint"]).read_text(encoding="utf-8")
    launcher = Path(job["files"]["container_launcher"]).read_text(encoding="utf-8")
    sandbox = Path(job["files"]["windows_sandbox_config"]).read_text(encoding="utf-8")
    manual = Path(job["files"]["manual_instructions"]).read_text(encoding="utf-8")
    assert "npm run build" in entrypoint
    assert "npm start" in entrypoint
    assert "--network none" in launcher
    assert "<ReadOnly>true</ReadOnly>" in sandbox
    assert "Health checks are intentionally deferred to Phase 3C" in manual

    loaded = load_runtime_build_run_job("runtime-job")
    assert loaded["job_id"] == "runtime-job"
    jobs = list_runtime_build_run_jobs()
    assert jobs[0]["job_id"] == "runtime-job"


def test_prepare_runtime_worker_job_blocks_missing_start_command(tmp_path, make_scan, monkeypatch):
    monkeypatch.setenv("SECURE_REVIEW_DATA_DIR", str(tmp_path / "data"))
    repo = tmp_path / "node-lib"
    repo.mkdir()
    (repo / "package.json").write_text('{"scripts":{"test":"vitest run"}}', encoding="utf-8")
    scan = make_scan(findings=[], scan_id="runtime-worker-blocked")
    scan.target_path = str(repo)

    with pytest.raises(ValueError, match="start"):
        prepare_runtime_build_run_job(scan, RuntimeBuildRunRequest(job_name="blocked"), actor="unit-test")


def test_runtime_worker_status_reports_providers():
    status = runtime_worker_status()

    assert status["schema_version"] == "runtime-build-run-worker-v1"
    assert "container" in status["providers"]
    assert "windows-sandbox" in status["providers"]
    assert "manual" in status["providers"]
    assert "Do not execute repository build, test, or start commands on the host." in status["guardrails"]


def test_runtime_worker_job_manifest_is_json_serializable(tmp_path, make_scan, monkeypatch):
    monkeypatch.setenv("SECURE_REVIEW_DATA_DIR", str(tmp_path / "data"))
    repo = tmp_path / "next-app"
    node_repo(repo)
    scan = make_scan(findings=[], scan_id="runtime-worker-json")
    scan.target_path = str(repo)

    job = prepare_runtime_build_run_job(scan, RuntimeBuildRunRequest(job_name="json-job"), actor="unit-test")

    assert json.loads(json.dumps(job))["job_id"] == "json-job"
