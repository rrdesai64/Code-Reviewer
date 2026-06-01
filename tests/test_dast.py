import json

from app.dast import DastScanRequest, EndpointResolver, dast_verification_report, ingest_dast_reports
from app.models import FindingDataflow, Location


def fastapi_app(path):
    path.mkdir(parents=True)
    (path / "app").mkdir()
    (path / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n\n"
        "@app.post('/api/orders')\n"
        "def create_order(id: str):\n"
        "    return {'id': id}\n",
        encoding="utf-8",
    )


def zap_report(path):
    path.write_text(
        json.dumps({
            "site": [{
                "alerts": [{
                    "pluginid": "40018",
                    "alert": "SQL Injection",
                    "risk": "High",
                    "confidence": "High",
                    "cweid": "89",
                    "desc": "SQL injection was confirmed dynamically.",
                    "solution": "Use parameterized queries.",
                    "instances": [{
                        "uri": "http://127.0.0.1:8000/api/orders",
                        "method": "POST",
                        "param": "id",
                        "attack": "' OR 1=1--",
                        "evidence": "SQL syntax error",
                    }],
                }],
            }],
        }),
        encoding="utf-8",
    )


def test_zap_parser_maps_endpoint_to_fastapi_route(tmp_path, make_scan):
    repo = tmp_path / "repo"
    fastapi_app(repo)
    report_path = tmp_path / "zap.json"
    zap_report(report_path)
    scan = make_scan(findings=[], scan_id="dast-zap")
    scan.target_path = str(repo)

    findings, errors = ingest_dast_reports(scan, [report_path])

    assert errors == []
    assert len(findings) == 1
    finding = findings[0]
    assert finding.source == "dast:zap"
    assert finding.dynamic.method == "POST"
    assert finding.dynamic.param == "id"
    assert finding.location.path == "app/main.py"
    assert finding.location.line == 4
    assert finding.dataflow.confirmed_exploitable is True


def test_dast_verification_blocks_confirmed_endpoint_but_excludes_dast_only_from_autofix(tmp_path, make_scan):
    repo = tmp_path / "repo"
    fastapi_app(repo)
    report_path = tmp_path / "zap.json"
    zap_report(report_path)
    scan = make_scan(findings=[], scan_id="dast-gate")
    scan.target_path = str(repo)

    report = dast_verification_report(scan, DastScanRequest(report_paths=[str(report_path)]))

    assert report["schema_version"] == "dast-verification-v1"
    assert report["status"] == "block"
    assert report["gate"]["proof_attached"] is True
    assert report["soundness"]["verdict"]["status"] == "block"
    top = report["soundness"]["top_issue"]
    assert "dast-confirmed:zap:POST /api/orders, param id" in top["gate"]["reason_codes"]
    assert top["priority"]["tier"] == "P0"
    assert top["evidence"]["dynamic"][0]["param"] == "id"
    assert report["soundness"]["top_issue"]["agent"]["fix_queue_eligible"] is False
    assert "excluded:dast-only:no-inside-out-source" in report["soundness"]["top_issue"]["agent"]["reason_codes"]


def test_dast_and_sast_cluster_as_high_confidence_p0(tmp_path, make_scan, make_finding):
    repo = tmp_path / "repo"
    fastapi_app(repo)
    report_path = tmp_path / "zap.json"
    zap_report(report_path)
    sast = make_finding(
        id="semgrep-sqli",
        fingerprint="semgrep-sqli",
        source="semgrep",
        rule_id="python.sql-injection",
        severity="HIGH",
        path="app/main.py",
        line=5,
        message="SQL injection reaches query",
        cwe=["CWE-89"],
    )
    sast.dataflow = FindingDataflow(
        has_dataflow=True,
        source=Location(path="app/main.py", line=5),
        sink=Location(path="app/main.py", line=5),
        tool_precision="high",
    )
    scan = make_scan(findings=[sast], scan_id="dast-sast")
    scan.target_path = str(repo)

    report = dast_verification_report(scan, DastScanRequest(report_paths=[str(report_path)]))

    top = report["soundness"]["top_issue"]
    assert report["status"] == "block"
    assert top["evidence"]["sources"] == ["dast:zap", "semgrep"]
    assert top["evidence"]["dataflow"]["confirmed_exploitable"] is True
    assert top["priority"]["tier"] == "P0"
    assert top["agent"]["fix_queue_eligible"] is True


def test_nuclei_jsonl_unmapped_finding_stays_endpoint_level(tmp_path, make_scan):
    repo = tmp_path / "repo"
    fastapi_app(repo)
    nuclei = tmp_path / "nuclei.jsonl"
    nuclei.write_text(
        json.dumps({
            "template-id": "exposed-debug",
            "matched-at": "http://127.0.0.1:8000/debug",
            "request": "GET /debug HTTP/1.1",
            "response": "debug enabled",
            "info": {"name": "Debug endpoint exposed", "severity": "high", "classification": {"cwe-id": ["CWE-489"]}},
        }) + "\n",
        encoding="utf-8",
    )
    scan = make_scan(findings=[], scan_id="dast-nuclei")
    scan.target_path = str(repo)

    findings, errors = ingest_dast_reports(scan, [nuclei])

    assert errors == []
    assert findings[0].source == "dast:nuclei"
    assert findings[0].location.path.startswith("[endpoint] GET http://127.0.0.1:8000/debug")
    assert findings[0].scope == "endpoint"
    assert findings[0].priority_context.path_class == "endpoint"


def test_dast_run_mode_blocks_remote_without_explicit_allow(tmp_path, make_scan):
    repo = tmp_path / "repo"
    fastapi_app(repo)
    scan = make_scan(findings=[], scan_id="dast-remote")
    scan.target_path = str(repo)

    report = dast_verification_report(
        scan,
        DastScanRequest(base_url="https://example.com", run_tools=True, require_sandbox_running=False),
    )

    assert report["run"]["status"] == "blocked"
    assert "loopback/private" in report["run"]["blockers"][0]


def test_endpoint_resolver_heuristic_finds_route_literal(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "routes.js").write_text("const path = '/api/search';\n", encoding="utf-8")

    location = EndpointResolver(repo).resolve("GET", "http://127.0.0.1:3000/api/search")

    assert location.path == "routes.js"
    assert location.line == 1
