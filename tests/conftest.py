"""Shared fixtures for the test suite.

Critically, `isolate_storage` and `isolate_enterprise` redirect the modules'
module-level data paths into a tmp dir so tests never touch the repo's real
data/ directory and stay deterministic.
"""
import pytest

from app.models import Finding, FixSuggestion, Location, ScanResult, ScanSummary

_SEVS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


@pytest.fixture
def make_finding():
    def _make(id="f1", rule_id="SEC-002", severity="HIGH", fingerprint="fp1",
              source="semgrep", cwe=None, owasp=None, message="msg",
              path="a.py", line=1, decision="open"):
        return Finding(
            id=id, source=source, rule_id=rule_id, title=rule_id, severity=severity,
            confidence="HIGH", location=Location(path=path, line=line), message=message,
            cwe=cwe or [], owasp=owasp or [], explanation="because reasons",
            fix=FixSuggestion(summary="fix it", guidance=["do x"]),
            fingerprint=fingerprint, decision=decision,
        )
    return _make


@pytest.fixture
def make_scan(make_finding):
    def _make(findings=None, scan_id="scan1", files_scanned=1, tools=None):
        findings = [make_finding()] if findings is None else findings
        counts = {s: sum(1 for f in findings if f.severity == s) for s in _SEVS}
        summary = ScanSummary(
            total_findings=len(findings), critical=counts["CRITICAL"], high=counts["HIGH"],
            medium=counts["MEDIUM"], low=counts["LOW"], info=counts["INFO"],
            files_scanned=files_scanned, tools=tools or {},
        )
        return ScanResult(scan_id=scan_id, project_name="proj", target_path="/tmp/proj",
                          summary=summary, findings=findings)
    return _make


@pytest.fixture
def isolate_storage(tmp_path, monkeypatch):
    from app import storage
    monkeypatch.setenv("SECURE_REVIEW_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    monkeypatch.setattr(storage, "SCANS_DIR", tmp_path / "scans")
    monkeypatch.setattr(storage, "BASELINE_PATH", tmp_path / "baseline.json")
    monkeypatch.setattr(storage, "DECISIONS_PATH", tmp_path / "decisions.json")
    return tmp_path


@pytest.fixture
def isolate_enterprise(tmp_path, monkeypatch):
    from app import enterprise
    monkeypatch.setattr(enterprise, "ENTERPRISE_PATH", tmp_path / "enterprise.json")
    monkeypatch.setattr(enterprise, "AUDIT_PATH", tmp_path / "audit.log")
    return tmp_path


@pytest.fixture
def isolate_rag(tmp_path, monkeypatch):
    from app import rag
    kdir = tmp_path / "knowledge"
    kdir.mkdir(exist_ok=True)
    monkeypatch.setattr(rag, "KNOWLEDGE_DIR", kdir)
    monkeypatch.setattr(rag, "INDEX_PATH", tmp_path / "rag_index.json")
    return kdir


@pytest.fixture
def isolate_memory(tmp_path, monkeypatch):
    from app import memory
    monkeypatch.setattr(memory, "MEMORY_PATH", tmp_path / "memory.json")
    return tmp_path / "memory.json"


@pytest.fixture
def clean_auth_env(monkeypatch):
    for var in ("AUTH_REQUIRED", "AUTH_MODE", "AUTH_SESSION_SECRET", "PUBLIC_BASE_URL",
                "AUTH_COOKIE_SECURE", "AUTH_COOKIE_SAMESITE", "AUTH_ADMIN_EMAILS",
                "AUTH_GROUP_ROLE_MAP", "AUTH_DEFAULT_ROLES", "OIDC_CLIENT_ID",
                "OIDC_CLIENT_SECRET", "OIDC_DISCOVERY_URL", "SAML_IDP_SSO_URL",
                "SAML_IDP_X509_CERT"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def disable_external_scanners(monkeypatch):
    monkeypatch.setenv("SEMGREP_ENABLED", "false")
    monkeypatch.setenv("BANDIT_ENABLED", "false")
    monkeypatch.setenv("SHELLCHECK_ENABLED", "false")
    monkeypatch.setenv("PIP_AUDIT_ENABLED", "false")
    monkeypatch.setenv("CODEQL_ENABLED", "false")
    monkeypatch.setenv("SONARQUBE_ENABLED", "false")
    monkeypatch.setenv("GOVULNCHECK_ENABLED", "false")
