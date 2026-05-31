from app.ingestion import finding_from_semgrep, findings_from_sarif_payload


def test_semgrep_dataflow_trace_is_normalized_without_raw_trace(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("print('demo')\n", encoding="utf-8")
    item = {
        "path": str(source),
        "check_id": "python.flask.security.sql-injection",
        "start": {"line": 20, "col": 5},
        "extra": {
            "severity": "ERROR",
            "message": "Tainted data reaches SQL execution.",
            "metadata": {"cwe": ["CWE-89"], "confidence": "HIGH"},
            "dataflow_trace": {
                "taint_source": [{"path": str(source), "start": {"line": 4, "col": 10}}],
                "intermediate_vars": [{"path": str(source), "start": {"line": 9, "col": 3}}],
                "taint_sink": [{"path": str(source), "start": {"line": 20, "col": 5}}],
            },
        },
    }

    finding = finding_from_semgrep(item, repo)

    assert finding.dataflow.has_dataflow is True
    assert finding.dataflow.tool_precision == "high"
    assert finding.dataflow.source.path == "app.py"
    assert finding.dataflow.source.line == 4
    assert finding.dataflow.sink.line == 20
    assert finding.scanner_metadata["dataflow_trace"] == "source-to-sink"


def test_sarif_code_flow_is_normalized_as_dataflow():
    payload = {
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CodeQL",
                    "rules": [{
                        "id": "py/sql-injection",
                        "name": "SQL injection",
                        "properties": {"tags": ["cwe-89"], "precision": "high"},
                    }],
                }
            },
            "results": [{
                "ruleId": "py/sql-injection",
                "level": "error",
                "message": {"text": "User input reaches a SQL query."},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/app.py"},
                        "region": {"startLine": 20, "startColumn": 5},
                    }
                }],
                "codeFlows": [{
                    "threadFlows": [{
                        "locations": [
                            {"location": {"physicalLocation": {
                                "artifactLocation": {"uri": "src/app.py"},
                                "region": {"startLine": 3, "startColumn": 1},
                            }}},
                            {"location": {"physicalLocation": {
                                "artifactLocation": {"uri": "src/app.py"},
                                "region": {"startLine": 20, "startColumn": 5},
                            }}},
                        ]
                    }]
                }],
            }],
        }]
    }

    findings = findings_from_sarif_payload(payload, source="codeql")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.source == "codeql"
    assert finding.dataflow.has_dataflow is True
    assert finding.dataflow.source.line == 3
    assert finding.dataflow.sink.line == 20
    assert finding.dataflow.steps == 2
    assert finding.dataflow.tool_precision == "high"
