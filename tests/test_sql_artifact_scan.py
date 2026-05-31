from app import scanner
from app.catalog_coverage import catalog_coverage_map
from app.sql_artifact_scan import run_sql_artifact_scan


def test_sql_artifact_scanner_detects_sql_001_through_sql_007(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    migration = repo / "migration.sql"
    migration.write_text(
        "\n".join([
            "SELECT * FROM users;",
            "DELETE FROM audit_log;",
            "EXEC('SELECT id FROM users WHERE id=' + @id);",
            "SELECT id FROM users WHERE deleted_at = NULL;",
            "SELECT id FROM users WHERE YEAR(created_at) = 2026;",
            "INSERT INTO accounts(id) VALUES (1);",
            "UPDATE profiles SET display_name = 'ok' WHERE id = 1;",
            "SELECT users.id FROM users, orders;",
        ]),
        encoding="utf-8",
    )

    findings, status = run_sql_artifact_scan(repo, [migration])

    assert status.startswith("ok: 1 files, 7 SQL rules")
    found = {finding.rule_id: finding for finding in findings}
    assert set(found) == {"SQL-001", "SQL-002", "SQL-003", "SQL-004", "SQL-005", "SQL-006", "SQL-007"}
    assert found["SQL-002"].severity == "CRITICAL"
    assert found["SQL-003"].cwe == ["CWE-89"]
    assert found["SQL-003"].owasp == ["A03"]
    assert found["SQL-007"].location.path == "migration.sql"


def test_sql_artifact_scanner_ignores_comments_and_string_literals_for_structural_rules(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    migration = repo / "safe.sql"
    migration.write_text(
        "\n".join([
            "-- SELECT * FROM commented_table;",
            "SELECT 'SELECT * FROM not_a_query' AS sample;",
            "SELECT id, email FROM users WHERE deleted_at IS NULL;",
            "UPDATE users SET active = 0 WHERE deleted_at IS NOT NULL;",
            "BEGIN TRANSACTION;",
            "INSERT INTO audit_log(id) VALUES (1);",
            "UPDATE audit_log SET processed = 1 WHERE id = 1;",
            "COMMIT;",
        ]),
        encoding="utf-8",
    )

    findings, status = run_sql_artifact_scan(repo, [migration])

    assert status == "ok: 1 files, 7 SQL rules, findings=0"
    assert findings == []


def test_sql_artifact_scanner_statuses(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    script = repo / "app.py"
    script.write_text("print('ok')\n", encoding="utf-8")

    findings, status = run_sql_artifact_scan(repo, [script])
    assert findings == []
    assert status == "skipped: no SQL files"

    monkeypatch.setenv("SQL_ARTIFACT_ENABLED", "false")
    findings, status = run_sql_artifact_scan(repo, [script])
    assert findings == []
    assert status == "disabled by SQL_ARTIFACT_ENABLED=false"


def test_run_scan_includes_sql_artifact_findings(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    migration = repo / "bad.sql"
    migration.write_text("DELETE FROM users;\n", encoding="utf-8")

    scan = scanner.run_scan(repo)

    assert scan.summary.tools["sql-artifact"].startswith("ok: 1 files")
    assert any(finding.source == "sql-artifact" and finding.rule_id == "SQL-002" for finding in scan.findings)
    assert scan.summary.languages["SQL"] == 1


def test_sql_artifact_catalog_coverage_closes_sql_blind_spots():
    report = catalog_coverage_map(tool_names=["sql-artifact"])
    by_rule = {entry["rule_id"]: entry for entry in report["rules"]}

    for rule_id in ("SQL-001", "SQL-002", "SQL-003", "SQL-004", "SQL-005", "SQL-006", "SQL-007"):
        assert by_rule[rule_id]["status"] == "covered"
        assert by_rule[rule_id]["tools"] == ["sql-artifact"]
    assert by_rule["C-001"]["status"] == "blind_spot"
