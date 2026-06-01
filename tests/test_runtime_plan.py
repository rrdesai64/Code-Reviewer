from app.runtime_plan import build_runtime_plan


def test_runtime_plan_detects_fastapi_build_start_and_health_candidates(tmp_path, make_scan):
    repo = tmp_path / "fastapi-app"
    (repo / "app").mkdir(parents=True)
    (repo / "pyproject.toml").write_text(
        "[project]\n"
        "dependencies = [\"fastapi\", \"uvicorn\"]\n",
        encoding="utf-8",
    )
    (repo / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n",
        encoding="utf-8",
    )
    scan = make_scan(findings=[], scan_id="runtime-fastapi")
    scan.target_path = str(repo)

    plan = build_runtime_plan(scan)

    assert plan["schema_version"] == "runtime-build-plan-v1"
    assert plan["policy"]["planning_only"] is True
    assert plan["policy"]["runs_commands"] is False
    assert plan["summary"]["status"] == "ready"
    assert plan["primary_plan"]["runtime"] == "python"
    assert plan["primary_plan"]["framework"] == "fastapi"
    assert "uvicorn app.main:app" in plan["primary_plan"]["start_command"]
    assert "http://127.0.0.1:8000/health" in plan["primary_plan"]["health_url_candidates"]


def test_runtime_plan_detects_nextjs_package_scripts(tmp_path, make_scan):
    repo = tmp_path / "next-app"
    repo.mkdir()
    (repo / "package.json").write_text(
        '{"scripts":{"build":"next build","start":"next start","test":"vitest run"},'
        '"dependencies":{"next":"latest","react":"latest"}}',
        encoding="utf-8",
    )
    scan = make_scan(findings=[], scan_id="runtime-next")
    scan.target_path = str(repo)

    plan = build_runtime_plan(scan)

    assert plan["summary"]["status"] == "ready"
    assert plan["primary_plan"]["runtime"] == "node"
    assert plan["primary_plan"]["framework"] == "nextjs"
    assert plan["primary_plan"]["build_commands"] == ["npm install", "npm run build"]
    assert plan["primary_plan"]["start_command"] == "npm start"
    assert plan["profiles"][0]["tests"]["commands"] == ["npm test"]


def test_runtime_plan_detects_go_cmd_entrypoint(tmp_path, make_scan):
    repo = tmp_path / "go-app"
    (repo / "cmd" / "server").mkdir(parents=True)
    (repo / "go.mod").write_text("module example.com/app\n", encoding="utf-8")
    (repo / "cmd" / "server" / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
    scan = make_scan(findings=[], scan_id="runtime-go")
    scan.target_path = str(repo)

    plan = build_runtime_plan(scan)

    assert plan["summary"]["status"] == "ready"
    assert plan["primary_plan"]["runtime"] == "go"
    assert plan["primary_plan"]["start_command"] == "go run ./cmd/server"
    assert plan["primary_plan"]["expected_port"] == 8080


def test_runtime_plan_blocks_when_no_supported_runtime_manifest(tmp_path, make_scan):
    repo = tmp_path / "docs-only"
    repo.mkdir()
    (repo / "README.md").write_text("hello\n", encoding="utf-8")
    scan = make_scan(findings=[], scan_id="runtime-none")
    scan.target_path = str(repo)

    plan = build_runtime_plan(scan)

    assert plan["summary"]["status"] == "blocked"
    assert plan["profiles"] == []
    assert "No supported runtime manifest" in plan["blockers"][0]
