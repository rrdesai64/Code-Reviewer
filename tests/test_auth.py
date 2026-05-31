"""Tests for auth.py pure logic: config, claims, RBAC mapping, request guards.

The SAML/OIDC request flows (metadata, ACS, middleware redirects) need a live
Starlette request/IdP and are out of scope here; this covers the deterministic
core. The module needs authlib/python3-saml/fastapi installed, so it is skipped
cleanly where those are absent.
"""
import pytest

auth = pytest.importorskip("app.auth")
from app.models import Finding  # noqa: E402  (after importorskip)


class FakeRequest:
    def __init__(self, session=None):
        self.session = session if session is not None else {}


# --- config / status ----------------------------------------------------------
def test_auth_config_defaults(clean_auth_env):
    cfg = auth.auth_config()
    assert cfg.required is False
    assert cfg.mode == "disabled"
    assert cfg.cookie_same_site == "lax"


def test_auth_config_reads_env(clean_auth_env, monkeypatch):
    monkeypatch.setenv("AUTH_REQUIRED", "true")
    monkeypatch.setenv("AUTH_MODE", "oidc")
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "true")
    cfg = auth.auth_config()
    assert cfg.required is True and cfg.mode == "oidc" and cfg.cookie_secure is True


def test_auth_status_reports_provider_config(clean_auth_env, monkeypatch):
    monkeypatch.setenv("OIDC_CLIENT_ID", "x")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "y")
    monkeypatch.setenv("OIDC_DISCOVERY_URL", "https://issuer/.well-known")
    status = auth.auth_status()
    assert status["oidc_configured"] is True
    assert status["saml_configured"] is False


# --- exemptions ---------------------------------------------------------------
@pytest.mark.parametrize("path,exempt", [
    ("/auth/login/oidc", True), ("/static/app.js", True), ("/api/health", True),
    ("/favicon.ico", True), ("/api/scans", False), ("/", False),
])
def test_is_exempt(path, exempt):
    assert auth.is_exempt(path) is exempt


# --- claim parsing ------------------------------------------------------------
def test_first_claim_unwraps_single_list():
    assert auth.first_claim({"email": ["a@b.com"]}, ["email"]) == "a@b.com"
    assert auth.first_claim({"sub": "u1"}, ["email", "sub"]) == "u1"
    assert auth.first_claim({}, ["email"]) is None


def test_claim_list_variants():
    assert auth.claim_list(None) == []
    assert auth.claim_list(["a", "b"]) == ["a", "b"]
    assert auth.claim_list("a, b ,c") == ["a", "b", "c"]


def test_parse_group_role_map():
    mapping = auth.parse_group_role_map("Security Team:security_reviewer;Auditors:auditor,developer")
    assert mapping == {"Security Team": ["security_reviewer"], "Auditors": ["auditor", "developer"]}


def test_safe_claims_strips_tokens():
    cleaned = auth.safe_claims({"sub": "u", "access_token": "secret", "id_token": "jwt"})
    assert "sub" in cleaned
    assert "access_token" not in cleaned and "id_token" not in cleaned


# --- RBAC mapping (needs isolated enterprise data) ----------------------------
def test_permissions_for_roles(clean_auth_env, isolate_enterprise):
    perms = auth.permissions_for_roles(["admin"])
    assert "enterprise:write" in perms and "scan:run" in perms
    assert auth.permissions_for_roles(["does-not-exist"]) == []


def test_roles_for_known_account(clean_auth_env, isolate_enterprise):
    # default enterprise data has local-admin -> admin
    assert auth.roles_for_identity("local-admin", None, []) == ["admin"]


def test_roles_default_when_unknown(clean_auth_env, isolate_enterprise):
    assert auth.roles_for_identity("stranger", "s@x.com", []) == ["developer"]


def test_roles_from_admin_email_env(clean_auth_env, isolate_enterprise, monkeypatch):
    monkeypatch.setenv("AUTH_ADMIN_EMAILS", "boss@corp.com")
    assert auth.roles_for_identity("boss", "boss@corp.com", []) == ["admin"]


def test_roles_from_group_map(clean_auth_env, isolate_enterprise, monkeypatch):
    monkeypatch.setenv("AUTH_GROUP_ROLE_MAP", "Security Team:security_reviewer")
    assert auth.roles_for_identity("alice", "a@x.com", ["Security Team"]) == ["security_reviewer"]


def test_normalize_user_builds_authuser(clean_auth_env, isolate_enterprise, monkeypatch):
    monkeypatch.setenv("AUTH_GROUP_ROLE_MAP", "Security Team:security_reviewer")
    user = auth.normalize_user(
        {"preferred_username": "alice", "email": "alice@corp.com",
         "name": "Alice", "groups": ["Security Team"], "id_token": "should-be-stripped"},
        provider="oidc",
    )
    assert user.username == "alice" and user.email == "alice@corp.com"
    assert user.roles == ["security_reviewer"]
    assert "scan:run" in user.permissions
    assert "id_token" not in user.raw_claims


def test_local_dev_user_is_admin(clean_auth_env, isolate_enterprise):
    user = auth.local_dev_user()
    assert "admin" in user.roles and user.provider == "local"


# --- request guards -----------------------------------------------------------
def test_require_user_returns_dev_user_when_optional(clean_auth_env, isolate_enterprise):
    user = auth.require_user(FakeRequest(session={}))
    assert user.provider == "local"


def test_require_user_from_session(clean_auth_env, isolate_enterprise):
    dev = auth.local_dev_user()
    user = auth.require_user(FakeRequest(session={auth.SESSION_USER_KEY: dev.model_dump()}))
    assert user.username == dev.username


def test_require_user_raises_when_required(clean_auth_env, isolate_enterprise, monkeypatch):
    monkeypatch.setenv("AUTH_REQUIRED", "true")
    with pytest.raises(auth.HTTPException) as exc:
        auth.require_user(FakeRequest(session={}))
    assert exc.value.status_code == 401


def test_require_permission_allows_and_denies(clean_auth_env, isolate_enterprise):
    session = {auth.SESSION_USER_KEY: auth.AuthUser(
        username="dev", display_name="Dev", roles=["developer"],
        permissions=["scan:run", "scan:read"]).model_dump()}
    req = FakeRequest(session=session)
    assert auth.require_permission("scan:run")(req).username == "dev"
    with pytest.raises(auth.HTTPException) as exc:
        auth.require_permission("enterprise:write")(req)
    assert exc.value.status_code == 403
