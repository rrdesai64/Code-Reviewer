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
