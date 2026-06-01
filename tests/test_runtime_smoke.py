from __future__ import annotations

import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from app.models import RuntimeSmokeCheckRequest
from app.runtime_smoke import run_runtime_smoke_checks, runtime_smoke_preview, sandbox_smoke_plan
from app.runtime_plan import build_runtime_plan


def fastapi_repo(path: Path) -> None:
    path.mkdir(parents=True)
    (path / "requirements.txt").write_text("fastapi\nuvicorn\n", encoding="utf-8")
    (path / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n",
        encoding="utf-8",
    )


@contextmanager
def smoke_server(debug_route: bool = False):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            headers = {
                "Content-Security-Policy": "default-src 'none'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=()",
                "Strict-Transport-Security": "max-age=31536000",
            }
            if self.path in {"/", "/health", "/api/health"}:
                self.send_response(200)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(b"ok")
                return
            if debug_route and self.path == "/__debug__":
                self.send_response(200)
                self.send_header("X-Debug", "enabled")
                self.end_headers()
                self.wfile.write(b"Werkzeug Debugger")
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format, *args):  # noqa: A002
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_runtime_smoke_preview_is_side_effect_free(tmp_path, make_scan):
    repo = tmp_path / "api"
    fastapi_repo(repo)
    scan = make_scan(findings=[], scan_id="smoke-preview")
    scan.target_path = str(repo)

    report = runtime_smoke_preview(scan)

    assert report["schema_version"] == "runtime-smoke-posture-v1"
    assert report["phase"] == "3C"
    assert report["mode"] == "preview"
    assert report["policy"]["side_effect_free_preview"] is True
    assert report["selected_profile"]["runtime"] == "python"
    assert "/__debug__" in report["posture_targets"]["probe_paths"]
    assert report["summary"]["check_counts"]["planned"] == 6


def test_runtime_smoke_check_probes_local_health_and_headers(tmp_path, make_scan):
    repo = tmp_path / "api"
    fastapi_repo(repo)
    scan = make_scan(findings=[], scan_id="smoke-check")
    scan.target_path = str(repo)

    with smoke_server() as base_url:
        report = run_runtime_smoke_checks(
            scan,
            RuntimeSmokeCheckRequest(base_url=base_url, network_probe=True),
        )

    assert report["status"] == "passed"
    assert report["summary"]["probe_count"] >= 1
    assert any(check["check_id"] == "health-endpoint" and check["status"] == "passed" for check in report["checks"])
    assert any(check["check_id"] == "security-headers" and check["status"] == "passed" for check in report["checks"])


def test_runtime_smoke_check_flags_debug_route_exposure(tmp_path, make_scan):
    repo = tmp_path / "api"
    fastapi_repo(repo)
    scan = make_scan(findings=[], scan_id="smoke-debug")
    scan.target_path = str(repo)

    with smoke_server(debug_route=True) as base_url:
        report = run_runtime_smoke_checks(
            scan,
            RuntimeSmokeCheckRequest(base_url=base_url, network_probe=True),
        )

    assert report["status"] == "failed"
    assert any(item["category"] == "unexpected-route" and item["path"] == "/__debug__" for item in report["findings"])
    assert any(item["category"] == "debug-exposure" for item in report["findings"])


def test_runtime_smoke_blocks_remote_probe_without_explicit_allow(tmp_path, make_scan):
    repo = tmp_path / "api"
    fastapi_repo(repo)
    scan = make_scan(findings=[], scan_id="smoke-remote")
    scan.target_path = str(repo)

    report = run_runtime_smoke_checks(
        scan,
        RuntimeSmokeCheckRequest(base_url="https://example.com", network_probe=True),
    )

    assert report["status"] == "blocked"
    assert report["probes"] == []
    assert "allow_remote_base_url" in report["blockers"][0]


def test_runtime_smoke_records_unexpected_observed_ports(tmp_path, make_scan):
    repo = tmp_path / "api"
    fastapi_repo(repo)
    scan = make_scan(findings=[], scan_id="smoke-ports")
    scan.target_path = str(repo)

    report = runtime_smoke_preview(scan, RuntimeSmokeCheckRequest(observed_ports=[9000], allowed_ports=[8000]))

    assert report["posture_targets"]["unexpected_observed_ports"] == [9000]
    assert report["summary"]["unexpected_port_count"] == 1


def test_sandbox_smoke_plan_uses_runtime_plan_health_candidates(tmp_path, make_scan):
    repo = tmp_path / "api"
    fastapi_repo(repo)
    scan = make_scan(findings=[], scan_id="smoke-sandbox-plan")
    scan.target_path = str(repo)
    plan = build_runtime_plan(scan)

    smoke_plan = sandbox_smoke_plan(plan["profiles"][0], timeout_seconds=7, probe_paths=["/custom"])

    assert smoke_plan["schema_version"] == "runtime-smoke-posture-v1"
    assert smoke_plan["enabled"] is True
    assert smoke_plan["timeout_seconds"] == 7
    assert "http://127.0.0.1:8000/health" in smoke_plan["health_url_candidates"]
    assert "/custom" in smoke_plan["probe_paths"]
