from app.catalog_coverage import catalog_coverage_map


def test_catalog_coverage_map_summarizes_detector_capability():
    report = catalog_coverage_map()

    assert report["schema_version"] == 1
    assert report["rule_count"] >= 150
    assert report["summary"]["covered"] > 0
    assert report["summary"]["covered"] + report["summary"]["partial"] + report["summary"]["blind_spot"] == report["rule_count"]
    assert any(tool["name"] == "catalog-native" for tool in report["tooling"])


def test_catalog_coverage_map_marks_native_byte_rules_covered():
    report = catalog_coverage_map()
    by_rule = {entry["rule_id"]: entry for entry in report["rules"]}

    assert by_rule["ENC-005"]["status"] == "covered"
    assert "catalog-native" in by_rule["ENC-005"]["tools"]


def test_catalog_coverage_map_can_scope_to_selected_tools():
    report = catalog_coverage_map(tool_names=["catalog-native"])

    assert [tool["name"] for tool in report["tooling"]] == ["catalog-native"]
    assert report["summary"]["covered"] >= 1
    assert any(entry["status"] == "blind_spot" for entry in report["rules"])
