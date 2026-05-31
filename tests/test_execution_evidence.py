from app.execution_evidence import coverage_provider_from_paths


def test_cobertura_coverage_evidence(tmp_path):
    coverage = tmp_path / "coverage.xml"
    coverage.write_text(
        """<?xml version="1.0" ?>
<coverage>
  <packages><package><classes>
    <class filename="src/app.py">
      <lines>
        <line number="10" hits="3" />
        <line number="11" hits="0" />
      </lines>
    </class>
  </classes></package></packages>
</coverage>
""",
        encoding="utf-8",
    )
    provider = coverage_provider_from_paths([coverage])

    executed = provider.evidence("src/app.py", 10)
    uncovered = provider.evidence("src/app.py", 11)
    unknown = provider.evidence("src/app.py", 99)

    assert executed.state == "executed"
    assert executed.hits == 3
    assert uncovered.state == "not_executed"
    assert uncovered.hits == 0
    assert unknown.state == "unknown"
    assert provider.evidence("app.py", 10).state == "executed"


def test_istanbul_coverage_evidence(tmp_path):
    coverage = tmp_path / "coverage-final.json"
    coverage.write_text(
        """{
  "src/app.js": {
    "statementMap": {
      "0": {"start": {"line": 5}, "end": {"line": 5}},
      "1": {"start": {"line": 8}, "end": {"line": 9}}
    },
    "s": {"0": 2, "1": 0}
  }
}
""",
        encoding="utf-8",
    )
    provider = coverage_provider_from_paths([coverage])

    assert provider.evidence("src/app.js", 5).state == "executed"
    assert provider.evidence("src/app.js", 8).state == "not_executed"
    assert provider.evidence("src/app.js", 9).state == "not_executed"
    assert provider.evidence("src/app.js", 12).state == "unknown"


def test_go_coverprofile_evidence(tmp_path):
    coverage = tmp_path / "cover.out"
    coverage.write_text(
        """mode: set
pkg/main.go:3.1,4.2 1 1
pkg/main.go:8.1,8.10 1 0
""",
        encoding="utf-8",
    )
    provider = coverage_provider_from_paths([coverage])

    assert provider.evidence("pkg/main.go", 3).state == "executed"
    assert provider.evidence("pkg/main.go", 4).state == "executed"
    assert provider.evidence("pkg/main.go", 8).state == "not_executed"
    assert provider.evidence("pkg/main.go", 20).state == "unknown"
