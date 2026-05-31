"""Structural validation of the rule catalog so a typo can't break the loader."""
from pathlib import Path

import pytest
import yaml

CATALOG = Path(__file__).resolve().parents[1] / "rules" / "code_review_rules.yaml"

REQUIRED_FIELDS = {
    "id", "name", "category", "severity", "languages",
    "detection", "cwe", "owasp", "description", "rationale", "remediation",
}


@pytest.fixture(scope="module")
def doc():
    return yaml.safe_load(CATALOG.read_text(encoding="utf-8"))


def test_catalog_parses(doc):
    assert doc["rules"], "catalog has no rules"


def test_ids_unique(doc):
    ids = [r["id"] for r in doc["rules"]]
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes, f"duplicate ids: {dupes}"


def test_required_fields_present(doc):
    for rule in doc["rules"]:
        missing = REQUIRED_FIELDS - set(rule)
        assert not missing, f"{rule.get('id')} missing {missing}"


def test_vocab_is_declared(doc):
    cats, sevs = set(doc["categories"]), set(doc["severities"])
    dets, langs = set(doc["detection_methods"]), set(doc["languages_supported"])
    for rule in doc["rules"]:
        rid = rule["id"]
        assert rule["category"] in cats, f"{rid}: bad category"
        assert rule["severity"] in sevs, f"{rid}: bad severity"
        assert rule["detection"] in dets, f"{rid}: bad detection"
        for lang in rule["languages"]:
            assert lang in langs, f"{rid}: undeclared language {lang}"


def test_cwe_and_owasp_types(doc):
    for rule in doc["rules"]:
        cwe = rule["cwe"]
        assert cwe is None or (isinstance(cwe, list) and all(isinstance(x, int) for x in cwe)), \
            f"{rule['id']}: cwe must be null or list[int]"
        assert rule["owasp"] is None or isinstance(rule["owasp"], str), \
            f"{rule['id']}: owasp must be null or str"
