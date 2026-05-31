from app.reachability import apply_reachability_context, reachability_context_report
from app.risk import score_scan
from app.scope import classify_path_scope, is_production_impacting


def test_request_handler_untrusted_input_upranks_finding(tmp_path, make_scan, make_finding, monkeypatch):
    monkeypatch.setenv("REACHABILITY_RECENT_DAYS", "0")
    repo = tmp_path / "repo"
    path = repo / "src" / "routes" / "users.py"
    path.parent.mkdir(parents=True)
    path.write_text(
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n"
        "@app.get('/users')\n"
        "def users(request: Request):\n"
        "    query = request.query_params['q']\n"
        "    return db.execute('select * from users where name = ' + query)\n",
        encoding="utf-8",
    )
    finding = make_finding(
        id="sql",
        rule_id="SEC-002",
        path="src/routes/users.py",
        line=6,
        message="SQL injection from request query",
        cwe=["CWE-89"],
    )
    scan = make_scan(findings=[finding])
    scan.target_path = str(repo)
    scan.new_findings = [finding.fingerprint]

    scan = score_scan(apply_reachability_context(repo, scan))

    assert finding.reachability == "untrusted-entrypoint"
    assert finding.exploitability == "high-untrusted-input"
    assert scan.summary.request_handler_findings == 1
    assert scan.summary.reachability_counts["untrusted-entrypoint"] == 1
    assert any(factor.name == "reachability" and factor.points > 0 for factor in finding.risk.factors)
    assert any(factor.name == "exploitability-context" for factor in finding.risk.factors)


def test_test_fixture_is_low_reachability_hygiene(tmp_path, make_scan, make_finding, monkeypatch):
    monkeypatch.setenv("REACHABILITY_RECENT_DAYS", "0")
    repo = tmp_path / "repo"
    path = repo / "tests" / "fixtures" / "app.py"
    path.parent.mkdir(parents=True)
    path.write_text("def fixture(request):\n    return eval(request.GET['x'])\n", encoding="utf-8")
    finding = make_finding(
        id="eval-test",
        rule_id="SEC-003",
        path="tests/fixtures/app.py",
        line=2,
        message="dynamic exec from request",
        cwe=["CWE-94"],
    )
    scan = make_scan(findings=[finding])
    scan.target_path = str(repo)

    scan = score_scan(apply_reachability_context(repo, scan))

    assert finding.reachability == "non-production-test"
    assert finding.exploitability == "low-non-production"
    assert not is_production_impacting(finding)
    assert finding.risk.score < 40


def test_changed_file_context_is_reported(tmp_path, make_scan, make_finding, monkeypatch):
    monkeypatch.setenv("REACHABILITY_RECENT_DAYS", "0")
    monkeypatch.setenv("SECURE_REVIEW_CHANGED_FILES", "src/service.py")
    repo = tmp_path / "repo"
    path = repo / "src" / "service.py"
    path.parent.mkdir(parents=True)
    path.write_text("value = input()\nos.system(value)\n", encoding="utf-8")
    finding = make_finding(
        id="cmd",
        rule_id="SEC-001",
        path="src/service.py",
        line=2,
        message="command injection via os.system",
        cwe=["CWE-78"],
    )
    scan = make_scan(findings=[finding])
    scan.target_path = str(repo)

    scan = score_scan(apply_reachability_context(repo, scan))
    report = reachability_context_report(scan)

    assert finding.reachability == "changed-production-file"
    assert scan.summary.changed_file_findings == 1
    assert report["summary"]["changed_file_findings"] == 1
    assert report["findings"][0]["context"]["changed_file"] is True


def test_vendor_paths_are_non_production_scope():
    assert classify_path_scope("vendor/package/module.py") == "vendor"
    assert classify_path_scope("src/generated/client.js") == "generated"
