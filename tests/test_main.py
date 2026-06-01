"""Integration tests for the FastAPI app (main.py) via TestClient.

By default AUTH_REQUIRED is unset, so requests resolve to the local dev admin
(all permissions) and endpoints are reachable without login. Enforcement and
the SSO redirect behavior are exercised by flipping AUTH_REQUIRED on.
All data paths are redirected to a tmp dir by the isolation fixtures.
"""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(isolate_storage, isolate_enterprise, isolate_rag, isolate_memory,
           clean_auth_env, tmp_path, monkeypatch):
    from app import main
    monkeypatch.setattr(main, "UPLOAD_DIR", tmp_path / "uploads")
    return TestClient(main.app, follow_redirects=False)


@pytest.fixture
def scanned(client, tmp_path):
    """Create a scan over a file with a planted ENC-009 (curly quote) finding."""
    repo = tmp_path / "dirty"
    repo.mkdir()
    (repo / "mod.py").write_bytes(b'msg = \xe2\x80\x9chi\xe2\x80\x9d\n')
    resp = client.post("/api/scans", data={"repo_path": str(repo), "project_name": "demo"})
    assert resp.status_code == 200, resp.text
    return resp.json()


# --- basic / health / identity ------------------------------------------------
def test_health(client):
    body = client.get("/api/health").json()
    assert body["ok"] is True
    assert "auth" in body and "llm_providers" in body


def test_index_served(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "<" in resp.text  # the static HTML page


def test_auth_me_local_dev_admin(client):
    body = client.get("/auth/me").json()
    assert body["username"] == "local-admin"
    assert "admin" in body["roles"]


# --- scan lifecycle -----------------------------------------------------------
def test_scan_create_and_fetch(client, scanned):
    scan_id = scanned["scan_id"]
    assert scanned["summary"]["total_findings"] >= 1
    got = client.get(f"/api/scans/{scan_id}")
    assert got.status_code == 200 and got.json()["scan_id"] == scan_id


def test_scan_listing(client, scanned):
    ids = {s["scan_id"] for s in client.get("/api/scans").json()}
    assert scanned["scan_id"] in ids


def test_missing_scan_404(client):
    assert client.get("/api/scans/nope").status_code == 404


def test_sarif_and_reports(client, scanned):
    sid = scanned["scan_id"]
    sarif = client.get(f"/api/scans/{sid}/sarif")
    assert sarif.status_code == 200
    assert sarif.json()["version"] == "2.1.0"
    consolidated = client.get(f"/api/scans/{sid}/consolidated-findings")
    assert consolidated.status_code == 200
    assert consolidated.json()["schema_version"] == "finding-consolidation-v1"
    prioritization = client.get(f"/api/scans/{sid}/prioritization")
    assert prioritization.status_code == 200
    assert prioritization.json()["schema_version"] == "finding-prioritization-v1"
    soundness = client.get(f"/api/scans/{sid}/soundness")
    assert soundness.status_code == 200
    assert soundness.json()["schema_version"] == "soundness-verdict-v1"
    reachability = client.get(f"/api/scans/{sid}/reachability-context")
    assert reachability.status_code == 200
    assert reachability.json()["schema_version"] == "reachability-context-v1"
    suppressions = client.get(f"/api/scans/{sid}/suppressions")
    assert suppressions.status_code == 200
    assert suppressions.json()["schema_version"] == 1
    assert client.get(f"/api/scans/{sid}/report.md").status_code == 200
    assert client.get(f"/api/scans/{sid}/report.html").status_code == 200
    assert client.get(f"/api/scans/{sid}/github-pr-comment").status_code == 200


def test_baseline_roundtrip(client, scanned):
    sid = scanned["scan_id"]
    assert client.post(f"/api/scans/{sid}/baseline").json()["saved"] is True
    assert "fingerprints" in client.get("/api/baseline").json()


def test_decisions(client, scanned):
    sid = scanned["scan_id"]
    fid = scanned["findings"][0]["id"]
    ok = client.post(f"/api/scans/{sid}/decisions",
                     json={"finding_id": fid, "state": "false_positive", "reason": "noise"})
    assert ok.status_code == 200 and ok.json()["saved"] is True
    bad = client.post(f"/api/scans/{sid}/decisions",
                      json={"finding_id": "ghost", "state": "open"})
    assert bad.status_code == 404


def test_fix_proposal(client, scanned):
    sid, fid = scanned["scan_id"], scanned["findings"][0]["id"]
    resp = client.post(f"/api/scans/{sid}/findings/{fid}/fix-proposal?provider=offline")
    assert resp.status_code == 200
    assert resp.json()["requires_human_approval"] is True
    autofix = client.post(f"/api/scans/{sid}/fixes/verified-autofix", json={"dry_run": True})
    assert autofix.status_code == 200
    assert autofix.json()["schema_version"] == "verified-autofix-v1"
    loop = client.post(f"/api/scans/{sid}/fixes/inside-out-loop", json={"dry_run": True, "persist": False})
    assert loop.status_code == 200
    assert loop.json()["schema_version"] == "inside-out-autofix-loop-v1"


def test_compliance(client, scanned):
    resp = client.get(f"/api/scans/{scanned['scan_id']}/compliance")
    assert resp.status_code == 200
    assert "policy_results" in resp.json()


# --- rag / memory / llm / enterprise -----------------------------------------
def test_rag_endpoints(client):
    assert client.get("/api/rag/query", params={"q": "injection"}).status_code == 200
    assert client.post("/api/rag/reindex").status_code == 200
    doc = client.post("/api/rag/documents", json={"title": "SSRF Notes", "text": "guidance"})
    assert doc.status_code == 200 and doc.json()["title"] == "SSRF Notes"


def test_memory_and_enterprise(client, scanned):
    assert "repositories" in client.get("/api/memory").json()
    assert "roles" in client.get("/api/enterprise").json()
    assert "events" in client.get("/api/audit").json()


def test_llm_endpoints(client):
    assert client.get("/api/llm/providers").status_code == 200
    resp = client.post("/api/llm/generate", json={"prompt": "hi", "provider": "offline"})
    assert resp.status_code == 200 and resp.json()["provider"] == "offline"


# --- auth enforcement / SSO ---------------------------------------------------
def test_oidc_login_unconfigured_returns_503(client):
    assert client.get("/auth/login/oidc").status_code == 503


def test_logout_redirects(client):
    resp = client.get("/auth/logout")
    assert resp.status_code == 303


def test_enforcement_blocks_api_when_required(client, monkeypatch):
    monkeypatch.setenv("AUTH_REQUIRED", "true")
    resp = client.get("/api/scans")
    assert resp.status_code == 401


def test_enforcement_redirects_browser_to_oidc(client, monkeypatch):
    monkeypatch.setenv("AUTH_REQUIRED", "true")
    resp = client.get("/")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/auth/login/oidc"


def test_enforcement_redirects_browser_to_saml(client, monkeypatch):
    monkeypatch.setenv("AUTH_REQUIRED", "true")
    monkeypatch.setenv("AUTH_MODE", "saml")
    resp = client.get("/")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/auth/login/saml"


def test_health_exempt_even_when_required(client, monkeypatch):
    monkeypatch.setenv("AUTH_REQUIRED", "true")
    assert client.get("/api/health").status_code == 200


def test_saml_metadata(client):
    resp = client.get("/auth/saml/metadata")
    assert resp.status_code == 200
    assert "EntityDescriptor" in resp.text


def test_oidc_callback_exchanges_token_and_logs_in(client, monkeypatch):
    from app import main

    class FakeOidcClient:
        async def authorize_access_token(self, request):
            return {"id_token": "signed-id-token"}

        async def parse_id_token(self, request, token):
            assert token["id_token"] == "signed-id-token"
            return {
                "preferred_username": "alice",
                "email": "alice@example.test",
                "name": "Alice Reviewer",
                "groups": ["Security Team"],
            }

    class FakeOAuth:
        oidc = FakeOidcClient()

    monkeypatch.setattr(main, "oauth", FakeOAuth())
    monkeypatch.setenv("AUTH_REQUIRED", "true")
    monkeypatch.setenv("AUTH_GROUP_ROLE_MAP", "Security Team:security_reviewer")

    blocked = client.get("/api/scans")
    assert blocked.status_code == 401

    callback = client.get("/auth/callback/oidc")
    assert callback.status_code == 303
    assert callback.headers["location"] == "/"

    me = client.get("/auth/me")
    assert me.status_code == 200
    body = me.json()
    assert body["username"] == "alice"
    assert body["provider"] == "oidc"
    assert body["roles"] == ["security_reviewer"]
    assert "id_token" not in body["raw_claims"]


def test_saml_acs_consumes_signed_assertion_and_logs_in(client, monkeypatch):
    from app import main

    signed_saml_response = "base64-encoded-signed-saml-fixture"

    class FakeSamlAuth:
        def __init__(self):
            self.processed = False

        def process_response(self):
            self.processed = True

        def get_errors(self):
            assert self.processed is True
            return []

        def is_authenticated(self):
            return True

        def get_last_error_reason(self):
            return ""

        def get_attributes(self):
            return {
                "email": ["saml-user@example.test"],
                "name": ["SAML Reviewer"],
                "groups": ["Auditors"],
            }

        def get_nameid(self):
            return "saml-user"

    async def fake_make_saml_auth(request):
        form = await request.form()
        assert form["SAMLResponse"] == signed_saml_response
        return FakeSamlAuth()

    monkeypatch.setattr(main, "make_saml_auth", fake_make_saml_auth)
    monkeypatch.setenv("AUTH_REQUIRED", "true")
    monkeypatch.setenv("AUTH_MODE", "saml")
    monkeypatch.setenv("AUTH_GROUP_ROLE_MAP", "Auditors:auditor")

    callback = client.post("/auth/saml/acs", data={"SAMLResponse": signed_saml_response})
    assert callback.status_code == 303
    assert callback.headers["location"] == "/"

    me = client.get("/auth/me")
    assert me.status_code == 200
    body = me.json()
    assert body["username"] == "saml-user"
    assert body["provider"] == "saml"
    assert body["roles"] == ["auditor"]


def test_saml_acs_rejects_failed_assertion(client, monkeypatch):
    from app import main

    class FailedSamlAuth:
        def process_response(self):
            return None

        def get_errors(self):
            return ["invalid_response"]

        def is_authenticated(self):
            return False

        def get_last_error_reason(self):
            return "signature validation failed"

    async def fake_make_saml_auth(request):
        return FailedSamlAuth()

    monkeypatch.setattr(main, "make_saml_auth", fake_make_saml_auth)

    resp = client.post("/auth/saml/acs", data={"SAMLResponse": "bad-fixture"})
    assert resp.status_code == 401
    assert resp.json()["detail"]["errors"] == ["invalid_response"]


def test_catalog_coverage_map_endpoint(client):
    resp = client.get("/api/catalog/coverage-map?include_rules=false")
    assert resp.status_code == 200
    body = resp.json()
    assert body["rule_count"] >= 150
    assert "rules" not in body
    assert body["summary"]["covered"] > 0
