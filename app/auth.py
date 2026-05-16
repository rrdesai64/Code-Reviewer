from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

from authlib.integrations.starlette_client import OAuth
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

from .enterprise import audit, load_enterprise

SESSION_USER_KEY = 'secure_review_user'
SESSION_ID_TOKEN_KEY = 'secure_review_id_token'
AUTH_EXEMPT_PREFIXES = ('/auth', '/static')
AUTH_EXEMPT_PATHS = {'/api/health', '/favicon.ico'}


class AuthUser(BaseModel):
    username: str
    email: str | None = None
    display_name: str
    roles: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    provider: str = 'local'
    raw_claims: dict = Field(default_factory=dict)


@dataclass(frozen=True)
class AuthConfig:
    required: bool
    mode: str
    session_secret: str
    public_base_url: str
    cookie_secure: bool
    cookie_same_site: str


def auth_config() -> AuthConfig:
    return AuthConfig(
        required=os.getenv('AUTH_REQUIRED', 'false').lower() == 'true',
        mode=os.getenv('AUTH_MODE', 'disabled').lower(),
        session_secret=os.getenv('AUTH_SESSION_SECRET', 'change-me-in-production'),
        public_base_url=os.getenv('PUBLIC_BASE_URL', 'http://127.0.0.1:8002').rstrip('/'),
        cookie_secure=os.getenv('AUTH_COOKIE_SECURE', 'false').lower() == 'true',
        cookie_same_site=os.getenv('AUTH_COOKIE_SAMESITE', 'lax'),
    )


def auth_status() -> dict:
    cfg = auth_config()
    return {
        'required': cfg.required,
        'mode': cfg.mode,
        'session_secret_configured': cfg.session_secret != 'change-me-in-production',
        'oidc_configured': bool(os.getenv('OIDC_CLIENT_ID') and os.getenv('OIDC_CLIENT_SECRET') and os.getenv('OIDC_DISCOVERY_URL')),
        'saml_configured': bool(os.getenv('SAML_IDP_SSO_URL') and os.getenv('SAML_IDP_X509_CERT')),
        'cookie_secure': cfg.cookie_secure,
        'cookie_same_site': cfg.cookie_same_site,
    }


def make_oauth() -> OAuth:
    oauth = OAuth()
    if os.getenv('OIDC_CLIENT_ID') and os.getenv('OIDC_CLIENT_SECRET') and os.getenv('OIDC_DISCOVERY_URL'):
        oauth.register(
            name='oidc',
            client_id=os.getenv('OIDC_CLIENT_ID'),
            client_secret=os.getenv('OIDC_CLIENT_SECRET'),
            server_metadata_url=os.getenv('OIDC_DISCOVERY_URL'),
            client_kwargs={'scope': os.getenv('OIDC_SCOPE', 'openid profile email')},
        )
    return oauth


def require_user(request: Request) -> AuthUser:
    cfg = auth_config()
    user = request.session.get(SESSION_USER_KEY) if hasattr(request, 'session') else None
    if user:
        return AuthUser.model_validate(user)
    if not cfg.required:
        return local_dev_user()
    raise HTTPException(status_code=401, detail='Authentication required')


def require_permission(permission: str) -> Callable[[Request], AuthUser]:
    def dependency(request: Request) -> AuthUser:
        user = require_user(request)
        if permission not in user.permissions and 'enterprise:write' not in user.permissions:
            raise HTTPException(status_code=403, detail=f'Missing permission: {permission}')
        return user
    return dependency


def login_user(request: Request, user: AuthUser, id_token: str | None = None) -> None:
    request.session[SESSION_USER_KEY] = user.model_dump()
    if id_token:
        request.session[SESSION_ID_TOKEN_KEY] = id_token
    audit(user.username, 'auth.login', user.provider, {'email': user.email or ''})


def logout_user(request: Request) -> AuthUser | None:
    user_data = request.session.pop(SESSION_USER_KEY, None)
    request.session.pop(SESSION_ID_TOKEN_KEY, None)
    if user_data:
        user = AuthUser.model_validate(user_data)
        audit(user.username, 'auth.logout', user.provider, {})
        return user
    return None


def local_dev_user() -> AuthUser:
    return normalize_user({'sub': 'local-admin', 'email': 'local-admin@localhost', 'name': 'Local Admin'}, 'local')


def normalize_user(claims: dict, provider: str) -> AuthUser:
    email = first_claim(claims, ['email', 'mail', 'upn', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'])
    username = first_claim(claims, ['preferred_username', 'sub', 'name_id', 'uid', 'NameID']) or email or 'unknown-user'
    display_name = first_claim(claims, ['name', 'displayName', 'cn', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name']) or username
    groups = claim_list(first_claim(claims, ['groups', 'roles', 'memberOf', 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups']))
    roles = roles_for_identity(username, email, groups)
    permissions = permissions_for_roles(roles)
    return AuthUser(username=username, email=email, display_name=display_name, roles=roles, permissions=permissions, provider=provider, raw_claims=safe_claims(claims))


def first_claim(claims: dict, names: list[str]) -> str | list[str] | None:
    for name in names:
        value = claims.get(name)
        if value:
            if isinstance(value, list) and len(value) == 1:
                return value[0]
            return value
    return None


def claim_list(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [part.strip() for part in str(value).split(',') if part.strip()]


def roles_for_identity(username: str, email: str | None, groups: list[str]) -> list[str]:
    enterprise = load_enterprise()
    users = enterprise.get('users', [])
    for account in users:
        if account.get('username') in {username, email} and account.get('active', True):
            return list(account.get('roles', []))
    admin_emails = {item.strip().lower() for item in os.getenv('AUTH_ADMIN_EMAILS', '').split(',') if item.strip()}
    if email and email.lower() in admin_emails:
        return ['admin']
    mapping = parse_group_role_map(os.getenv('AUTH_GROUP_ROLE_MAP', ''))
    mapped = sorted({role for group in groups for role in mapping.get(group, [])})
    if mapped:
        return mapped
    defaults = [item.strip() for item in os.getenv('AUTH_DEFAULT_ROLES', 'developer').split(',') if item.strip()]
    return defaults or ['developer']


def parse_group_role_map(raw: str) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    for item in raw.split(';'):
        if ':' not in item:
            continue
        group, roles = item.split(':', 1)
        mapping[group.strip()] = [role.strip() for role in roles.split(',') if role.strip()]
    return mapping


def permissions_for_roles(role_names: list[str]) -> list[str]:
    enterprise = load_enterprise()
    role_lookup = {role['name']: role.get('permissions', []) for role in enterprise.get('roles', [])}
    permissions = sorted({permission for role in role_names for permission in role_lookup.get(role, [])})
    return permissions


def safe_claims(claims: dict) -> dict:
    blocked = {'access_token', 'refresh_token', 'id_token'}
    return {str(key): value for key, value in claims.items() if str(key) not in blocked}


def saml_settings() -> dict:
    base = auth_config().public_base_url
    return {
        'strict': os.getenv('SAML_STRICT', 'true').lower() == 'true',
        'debug': os.getenv('SAML_DEBUG', 'false').lower() == 'true',
        'sp': {
            'entityId': os.getenv('SAML_SP_ENTITY_ID', f'{base}/auth/saml/metadata'),
            'assertionConsumerService': {'url': os.getenv('SAML_SP_ACS_URL', f'{base}/auth/saml/acs'), 'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'},
            'singleLogoutService': {'url': os.getenv('SAML_SP_SLS_URL', f'{base}/auth/saml/sls'), 'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'},
            'NameIDFormat': os.getenv('SAML_NAME_ID_FORMAT', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'),
            'x509cert': os.getenv('SAML_SP_X509_CERT', ''),
            'privateKey': os.getenv('SAML_SP_PRIVATE_KEY', ''),
        },
        'idp': {
            'entityId': os.getenv('SAML_IDP_ENTITY_ID', ''),
            'singleSignOnService': {'url': os.getenv('SAML_IDP_SSO_URL', ''), 'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'},
            'singleLogoutService': {'url': os.getenv('SAML_IDP_SLO_URL', ''), 'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'},
            'x509cert': os.getenv('SAML_IDP_X509_CERT', ''),
        },
        'security': {
            'authnRequestsSigned': os.getenv('SAML_AUTHN_REQUESTS_SIGNED', 'false').lower() == 'true',
            'logoutRequestSigned': os.getenv('SAML_LOGOUT_REQUEST_SIGNED', 'false').lower() == 'true',
            'logoutResponseSigned': os.getenv('SAML_LOGOUT_RESPONSE_SIGNED', 'false').lower() == 'true',
            'wantMessagesSigned': os.getenv('SAML_WANT_MESSAGES_SIGNED', 'false').lower() == 'true',
            'wantAssertionsSigned': os.getenv('SAML_WANT_ASSERTIONS_SIGNED', 'true').lower() == 'true',
            'wantNameId': True,
            'wantNameIdEncrypted': False,
            'wantAssertionsEncrypted': os.getenv('SAML_WANT_ASSERTIONS_ENCRYPTED', 'false').lower() == 'true',
            'signatureAlgorithm': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            'digestAlgorithm': 'http://www.w3.org/2001/04/xmlenc#sha256',
        },
    }


async def prepare_saml_request(request: Request) -> dict:
    parsed = urlparse(str(request.url))
    form = await request.form() if request.method == 'POST' else {}
    return {
        'https': 'on' if parsed.scheme == 'https' else 'off',
        'http_host': request.headers.get('host', parsed.netloc),
        'server_port': str(parsed.port or (443 if parsed.scheme == 'https' else 80)),
        'script_name': parsed.path,
        'get_data': dict(request.query_params),
        'post_data': dict(form),
    }


async def make_saml_auth(request: Request) -> OneLogin_Saml2_Auth:
    return OneLogin_Saml2_Auth(await prepare_saml_request(request), old_settings=saml_settings())


def saml_metadata_response() -> Response:
    settings = OneLogin_Saml2_Settings(settings=saml_settings(), sp_validation_only=True)
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    if errors:
        raise HTTPException(status_code=500, detail='SAML metadata validation failed: ' + ', '.join(errors))
    return Response(content=metadata, media_type='application/samlmetadata+xml')


class AuthEnforcementMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        cfg = auth_config()
        path = request.url.path
        if not cfg.required or is_exempt(path):
            return await call_next(request)
        if request.session.get(SESSION_USER_KEY):
            return await call_next(request)
        if path.startswith('/api'):
            return JSONResponse({'detail': 'Authentication required'}, status_code=401)
        login_path = '/auth/login/saml' if cfg.mode == 'saml' else '/auth/login/oidc'
        return RedirectResponse(url=login_path, status_code=303)


def is_exempt(path: str) -> bool:
    return path in AUTH_EXEMPT_PATHS or any(path.startswith(prefix) for prefix in AUTH_EXEMPT_PREFIXES)
