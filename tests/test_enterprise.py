"""Tests for enterprise.py (RBAC defaults, audit log, compliance reporting)."""
from app import enterprise


def test_load_enterprise_creates_defaults(isolate_enterprise):
    data = enterprise.load_enterprise()
    role_names = {r["name"] for r in data["roles"]}
    assert role_names == {"admin", "security_reviewer", "developer", "auditor"}
    assert any(u["username"] == "local-admin" for u in data["users"])
    assert data["sso"]["enabled"] is False
    assert len(data["policies"]) >= 3
    # persisted to the isolated path
    assert (isolate_enterprise / "enterprise.json").exists()


def test_save_enterprise_roundtrip(isolate_enterprise):
    data = enterprise.load_enterprise()
    data["sso"]["enabled"] = True
    enterprise.save_enterprise(data)
    assert enterprise.load_enterprise()["sso"]["enabled"] is True


def test_default_policies_have_ids():
    ids = {p["id"] for p in enterprise.default_policies()}
    assert {"block-high-new-findings", "require-dependency-audit", "require-human-fix-approval"} <= ids


def test_audit_writes_and_reads(isolate_enterprise):
    enterprise.audit("alice", "scan.created", "scan1", {"project": "proj"})
    enterprise.audit("bob", "auth.login", "oidc")
    events = enterprise.audit_events()
    assert [e["action"] for e in events] == ["scan.created", "auth.login"]
    assert enterprise.audit_events(limit=1)[0]["actor"] == "bob"


def test_compliance_report_flags_high_new_findings(isolate_enterprise, make_scan, make_finding):
    high = make_finding(severity="HIGH", fingerprint="fp-high",
                        cwe=["CWE-78"], owasp=["A03:2021-Injection"])
    scan = make_scan(findings=[high], tools={"pip-audit": "ok"})
    scan.new_findings = ["fp-high"]

    report = enterprise.compliance_report(scan)
    results = {p["policy_id"]: p for p in report["policy_results"]}
    assert results["block-high-new-findings"]["status"] == "attention_required"
    assert results["block-high-new-findings"]["count"] == 1
    assert results["require-dependency-audit"]["status"] == "passed"
    assert results["require-human-fix-approval"]["status"] == "configured"
    assert report["owasp_coverage"] == {"A03:2021-Injection": 1}
    assert report["cwe_coverage"] == {"CWE-78": 1}
    assert report["scan_id"] == scan.scan_id


def test_compliance_report_passes_clean_scan(isolate_enterprise, make_scan, make_finding):
    low = make_finding(severity="LOW", fingerprint="fp-low")
    scan = make_scan(findings=[low], tools={"pip-audit": "skipped: no requirements files"})
    scan.new_findings = []
    report = enterprise.compliance_report(scan)
    results = {p["policy_id"]: p for p in report["policy_results"]}
    assert results["block-high-new-findings"]["status"] == "passed"
    assert results["require-dependency-audit"]["status"] == "passed"
