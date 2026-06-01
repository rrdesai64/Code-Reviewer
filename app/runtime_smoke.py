from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from .models import RuntimeSmokeCheckRequest, ScanResult
from .runtime_plan import build_runtime_plan

SCHEMA_VERSION = 'runtime-smoke-posture-v1'
PHASE = '3C'
DEFAULT_TIMEOUT_SECONDS = 10
HEALTH_PATHS = ['/health', '/healthz', '/api/health', '/ready', '/readiness', '/live', '/liveness', '/status', '/']
DEBUG_ROUTE_PATHS = ['/debug', '/__debug__', '/_debug_toolbar', '/actuator/env', '/actuator/heapdump', '/phpinfo.php']
OBSERVABILITY_ROUTE_PATHS = ['/metrics', '/docs', '/openapi.json', '/swagger.json', '/actuator']
DEFAULT_PROBE_PATHS = [*HEALTH_PATHS, *DEBUG_ROUTE_PATHS, *OBSERVABILITY_ROUTE_PATHS]
SECURITY_HEADERS = [
    'content-security-policy',
    'x-content-type-options',
    'x-frame-options',
    'referrer-policy',
    'permissions-policy',
    'strict-transport-security',
]
DEBUG_BODY_MARKERS = [
    'werkzeug debugger',
    'traceback (most recent call last)',
    'django debug',
    'debug toolbar',
    'phpinfo()',
    'spring boot actuator',
    'environment properties',
]
LOCAL_HOSTNAMES = {'localhost', '127.0.0.1', '::1', 'host.docker.internal'}


def runtime_smoke_status() -> dict[str, Any]:
    return {
        'schema_version': SCHEMA_VERSION,
        'phase': PHASE,
        'generated_at': now_iso(),
        'capabilities': [
            'app-start-reachability',
            'health-endpoint-probe',
            'security-header-posture',
            'debug-mode-exposure-detection',
            'unexpected-route-detection',
            'unexpected-port-policy',
        ],
        'guardrails': runtime_smoke_guardrails(),
    }


def runtime_smoke_preview(scan: ScanResult, request: RuntimeSmokeCheckRequest | None = None) -> dict[str, Any]:
    request = request or RuntimeSmokeCheckRequest()
    plan = build_runtime_plan(scan)
    profile = select_profile(plan, request.profile_id)
    return base_report(
        scan=scan,
        request=request,
        plan=plan,
        profile=profile,
        mode='preview',
        status='planned' if profile else 'blocked',
        network_probe=False,
        checks=planned_checks(profile, request),
        probes=[],
        findings=[],
        blockers=[] if profile else ['runtime smoke checks need a Phase 3A runtime profile'],
    )


def run_runtime_smoke_checks(scan: ScanResult, request: RuntimeSmokeCheckRequest | None = None) -> dict[str, Any]:
    request = request or RuntimeSmokeCheckRequest()
    plan = build_runtime_plan(scan)
    profile = select_profile(plan, request.profile_id)
    blockers: list[str] = []
    if not profile:
        blockers.append('runtime smoke checks need a Phase 3A runtime profile')
    if not request.network_probe:
        return base_report(
            scan=scan,
            request=request,
            plan=plan,
            profile=profile,
            mode='preview',
            status='planned' if profile else 'blocked',
            network_probe=False,
            checks=planned_checks(profile, request),
            probes=[],
            findings=[],
            blockers=blockers,
        )
    if not request.base_url:
        blockers.append('network_probe=true requires base_url')
    elif not allowed_base_url(request.base_url, allow_remote=request.allow_remote_base_url):
        blockers.append('base_url host is not loopback/private; set allow_remote_base_url=true for an explicit remote probe')
    if blockers:
        return base_report(
            scan=scan,
            request=request,
            plan=plan,
            profile=profile,
            mode='network-probe',
            status='blocked',
            network_probe=True,
            checks=blocked_checks(blockers),
            probes=[],
            findings=[],
            blockers=blockers,
        )

    assert request.base_url is not None
    probes = run_http_probes(request.base_url, request, profile)
    checks, findings = evaluated_checks(request, profile, probes)
    return base_report(
        scan=scan,
        request=request,
        plan=plan,
        profile=profile,
        mode='network-probe',
        status=overall_status(checks),
        network_probe=True,
        checks=checks,
        probes=probes,
        findings=findings,
        blockers=[],
    )


def sandbox_smoke_plan(
    profile: dict[str, Any],
    *,
    enabled: bool = True,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    probe_paths: list[str] | None = None,
    allowed_ports: list[int] | None = None,
) -> dict[str, Any]:
    expected_port = int(profile.get('start', {}).get('expected_port') or 0)
    health_candidates = list(profile.get('start', {}).get('health_url_candidates') or [])
    ports = sorted_unique_int([*(allowed_ports or []), *([expected_port] if expected_port else [])])
    return {
        'schema_version': SCHEMA_VERSION,
        'phase': PHASE,
        'enabled': bool(enabled),
        'timeout_seconds': bounded_timeout(timeout_seconds),
        'expected_port': expected_port,
        'allowed_ports': ports,
        'health_url_candidates': health_candidates,
        'probe_paths': route_probe_paths(profile, probe_paths or []),
        'required_security_headers': SECURITY_HEADERS,
        'output_artifact': 'runtime-smoke-posture.json',
    }


def base_report(
    *,
    scan: ScanResult,
    request: RuntimeSmokeCheckRequest,
    plan: dict[str, Any],
    profile: dict[str, Any] | None,
    mode: str,
    status: str,
    network_probe: bool,
    checks: list[dict[str, Any]],
    probes: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    blockers: list[str],
) -> dict[str, Any]:
    target = posture_targets(profile, request)
    return {
        'schema_version': SCHEMA_VERSION,
        'phase': PHASE,
        'generated_at': now_iso(),
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'mode': mode,
        'status': status,
        'policy': {
            'side_effect_free_preview': not network_probe,
            'network_probe': network_probe,
            'runs_repository_commands': False,
            'starts_services_on_host': False,
            'sandbox_required_for_app_start': True,
            'raw_source_included': False,
            'remote_probe_requires_explicit_allow': True,
        },
        'runtime_plan': {
            'schema_version': plan.get('schema_version'),
            'status': plan.get('summary', {}).get('status', ''),
            'primary_profile_id': plan.get('summary', {}).get('primary_profile_id', ''),
            'profile_count': plan.get('summary', {}).get('profile_count', 0),
        },
        'selected_profile': selected_profile_card(profile),
        'posture_targets': target,
        'summary': {
            'status': status,
            'check_counts': count_statuses(checks),
            'probe_count': len(probes),
            'finding_count': len(findings),
            'unexpected_route_count': sum(1 for item in findings if item.get('category') == 'unexpected-route'),
            'unexpected_port_count': len(target.get('unexpected_observed_ports') or []),
            'missing_security_header_count': sum(
                len(item.get('missing_headers') or [])
                for item in checks
                if item.get('check_id') == 'security-headers'
            ),
        },
        'checks': checks,
        'probes': probes,
        'findings': findings,
        'blockers': blockers,
        'guardrails': runtime_smoke_guardrails(),
    }


def planned_checks(profile: dict[str, Any] | None, request: RuntimeSmokeCheckRequest) -> list[dict[str, Any]]:
    if not profile:
        return blocked_checks(['runtime profile unavailable'])
    target = posture_targets(profile, request)
    return [
        check('app-start', 'planned', 'App start must be proven by a Phase 3B disposable worker or explicit base_url probe.'),
        check('health-endpoint', 'planned', f"{len(target['health_url_candidates'])} health endpoint candidate(s) queued."),
        check('security-headers', 'planned', 'Security headers will be evaluated from the first reachable HTTP response.', headers=SECURITY_HEADERS),
        check('debug-exposure', 'planned', 'Debug headers, debug route exposure, and debug response bodies will be checked.'),
        check('unexpected-routes', 'planned', f"{len(target['probe_paths'])} safe GET route probe(s) queued."),
        check('unexpected-ports', 'planned', 'Observed ports are compared to expected/allowed ports; no blind port scan is run.'),
    ]


def blocked_checks(blockers: list[str]) -> list[dict[str, Any]]:
    return [
        check('app-start', 'blocked', '; '.join(blockers)),
        check('health-endpoint', 'blocked', 'Runtime smoke checks cannot probe without a valid runtime target.'),
        check('security-headers', 'blocked', 'No HTTP response was available for header inspection.', headers=SECURITY_HEADERS),
        check('debug-exposure', 'blocked', 'No HTTP response was available for debug exposure inspection.'),
        check('unexpected-routes', 'blocked', 'No route probes were run.'),
        check('unexpected-ports', 'blocked', 'No observed port evidence was supplied.'),
    ]


def evaluated_checks(
    request: RuntimeSmokeCheckRequest,
    profile: dict[str, Any] | None,
    probes: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    target = posture_targets(profile, request)
    reachable = [probe for probe in probes if int(probe.get('status_code') or 0) > 0]
    successful = [probe for probe in probes if 200 <= int(probe.get('status_code') or 0) < 400]
    health_success = [
        probe for probe in successful
        if str(probe.get('path') or '/') in set(target['health_paths'])
    ]
    representative = successful[0] if successful else reachable[0] if reachable else {}
    missing_headers = missing_security_headers(representative.get('headers') or {})
    debug_findings = debug_exposure_findings(probes)
    port_findings = unexpected_port_findings(target)
    findings = [*debug_findings, *port_findings]
    checks = [
        check(
            'app-start',
            'passed' if reachable else 'failed',
            'A HTTP response was received from the runtime target.' if reachable else 'No HTTP response was received from the runtime target.',
        ),
        check(
            'health-endpoint',
            'passed' if health_success else 'warning' if successful else 'failed',
            'At least one health endpoint returned a successful status.'
            if health_success
            else 'The app responded, but no health endpoint returned a successful status.'
            if successful
            else 'No health endpoint responded successfully.',
        ),
        check(
            'security-headers',
            'passed' if not missing_headers and representative else 'warning',
            'Recommended security headers are present.' if not missing_headers and representative else 'One or more recommended security headers are missing.',
            missing_headers=missing_headers,
            headers=SECURITY_HEADERS,
        ),
        check(
            'debug-exposure',
            'failed' if any(item.get('severity') == 'high' for item in debug_findings) else 'warning' if debug_findings else 'passed',
            'Debug exposure was detected.' if debug_findings else 'No debug route, header, or body exposure was detected.',
        ),
        check(
            'unexpected-routes',
            'failed' if debug_findings else 'passed',
            f"{len(debug_findings)} unexpected route exposure(s) detected." if debug_findings else 'No unexpected high-risk route exposure was detected.',
        ),
        check(
            'unexpected-ports',
            'failed' if port_findings else 'planned' if not target['observed_ports'] else 'passed',
            f"{len(port_findings)} unexpected observed port(s) detected."
            if port_findings
            else 'No observed port evidence was supplied; blind port scanning is intentionally not performed.'
            if not target['observed_ports']
            else 'Observed ports match the expected/allowed port policy.',
        ),
    ]
    return checks, findings


def run_http_probes(base_url: str, request: RuntimeSmokeCheckRequest, profile: dict[str, Any] | None) -> list[dict[str, Any]]:
    paths = route_probe_paths(profile, request.probe_paths)
    timeout = bounded_timeout(request.timeout_seconds)
    probes: list[dict[str, Any]] = []
    for path in paths:
        url = join_url(base_url, path)
        probes.append(fetch_url(url, path=path, timeout=timeout))
    return probes


def fetch_url(url: str, *, path: str, timeout: int) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={'User-Agent': 'SecureReviewRuntimeSmoke/1.0'})
    started = now_iso()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(8192).decode('utf-8', errors='ignore')
            return probe_record(
                url=url,
                path=path,
                status_code=int(response.status),
                headers=dict(response.headers.items()),
                body=body,
                error='',
                started_at=started,
            )
    except urllib.error.HTTPError as exc:
        body = exc.read(8192).decode('utf-8', errors='ignore')
        return probe_record(
            url=url,
            path=path,
            status_code=int(exc.code),
            headers=dict(exc.headers.items()) if exc.headers else {},
            body=body,
            error='',
            started_at=started,
        )
    except Exception as exc:
        return probe_record(url=url, path=path, status_code=0, headers={}, body='', error=str(exc)[:300], started_at=started)


def probe_record(
    *,
    url: str,
    path: str,
    status_code: int,
    headers: dict[str, str],
    body: str,
    error: str,
    started_at: str,
) -> dict[str, Any]:
    return {
        'url': redact_url(url),
        'path': path,
        'status_code': status_code,
        'headers': {str(key).lower(): str(value)[:200] for key, value in headers.items()},
        'body_markers': body_markers(body),
        'debug_header_markers': debug_header_markers(headers),
        'error': error,
        'started_at': started_at,
        'completed_at': now_iso(),
    }


def posture_targets(profile: dict[str, Any] | None, request: RuntimeSmokeCheckRequest) -> dict[str, Any]:
    expected_port = int(profile.get('start', {}).get('expected_port') or 0) if profile else 0
    base_port = base_url_port(request.base_url)
    observed_ports = sorted_unique_int(request.observed_ports)
    allowed_ports = sorted_unique_int([*request.allowed_ports, *base_port, *([expected_port] if expected_port else [])])
    health_candidates = list(profile.get('start', {}).get('health_url_candidates') or []) if profile else []
    paths = route_probe_paths(profile, request.probe_paths)
    health_paths = sorted_unique([parsed.path or '/' for parsed in (urllib.parse.urlparse(item) for item in health_candidates)])
    health_paths = sorted_unique([*health_paths, *[path for path in paths if path in HEALTH_PATHS]])
    unexpected_ports = [port for port in observed_ports if allowed_ports and port not in allowed_ports]
    return {
        'base_url': redact_url(request.base_url or ''),
        'base_url_port': base_port[0] if base_port else 0,
        'expected_port': expected_port,
        'allowed_ports': allowed_ports,
        'observed_ports': observed_ports,
        'unexpected_observed_ports': unexpected_ports,
        'health_url_candidates': health_candidates,
        'health_paths': health_paths,
        'probe_paths': paths,
        'security_headers': SECURITY_HEADERS,
    }


def route_probe_paths(profile: dict[str, Any] | None, extra_paths: list[str] | None = None) -> list[str]:
    health_candidates = profile.get('start', {}).get('health_url_candidates', []) if profile else []
    inferred_paths = [urllib.parse.urlparse(item).path or '/' for item in health_candidates]
    return sorted_unique(normalize_path(path) for path in [*DEFAULT_PROBE_PATHS, *inferred_paths, *(extra_paths or [])])


def selected_profile_card(profile: dict[str, Any] | None) -> dict[str, Any]:
    if not profile:
        return {}
    start = profile.get('start') or {}
    return {
        'profile_id': profile.get('profile_id', ''),
        'runtime': profile.get('runtime', ''),
        'framework': profile.get('framework', ''),
        'confidence': profile.get('confidence', ''),
        'expected_port': start.get('expected_port', 0),
        'health_url_candidates': start.get('health_url_candidates', []),
    }


def select_profile(plan: dict[str, Any], profile_id: str | None) -> dict[str, Any] | None:
    profiles = plan.get('profiles') or []
    if profile_id:
        return next((profile for profile in profiles if profile.get('profile_id') == profile_id), None)
    primary = plan.get('summary', {}).get('primary_profile_id')
    if primary:
        found = next((profile for profile in profiles if profile.get('profile_id') == primary), None)
        if found:
            return found
    return profiles[0] if profiles else None


def missing_security_headers(headers: dict[str, Any]) -> list[str]:
    present = {str(key).lower() for key in headers}
    return [header for header in SECURITY_HEADERS if header not in present]


def debug_exposure_findings(probes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for probe in probes:
        path = str(probe.get('path') or '')
        status_code = int(probe.get('status_code') or 0)
        markers = [*probe.get('body_markers', []), *probe.get('debug_header_markers', [])]
        if status_code and status_code < 400 and path in DEBUG_ROUTE_PATHS:
            findings.append({
                'category': 'unexpected-route',
                'severity': 'high',
                'path': path,
                'status_code': status_code,
                'reason': 'high-risk debug or diagnostic route responded successfully',
            })
        elif status_code and status_code < 400 and path in OBSERVABILITY_ROUTE_PATHS:
            findings.append({
                'category': 'unexpected-route',
                'severity': 'medium',
                'path': path,
                'status_code': status_code,
                'reason': 'observability or API documentation route is reachable; confirm this is intended for the environment',
            })
        if markers:
            findings.append({
                'category': 'debug-exposure',
                'severity': 'high',
                'path': path,
                'status_code': status_code,
                'markers': markers,
                'reason': 'debug marker found in response body or headers',
            })
    return findings


def unexpected_port_findings(target: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    for port in target.get('unexpected_observed_ports') or []:
        findings.append({
            'category': 'unexpected-port',
            'severity': 'high',
            'port': port,
            'allowed_ports': target.get('allowed_ports') or [],
            'reason': 'observed runtime port is outside the expected/allowed policy',
        })
    return findings


def body_markers(body: str) -> list[str]:
    lower = body.lower()
    return [marker for marker in DEBUG_BODY_MARKERS if marker in lower]


def debug_header_markers(headers: dict[str, Any]) -> list[str]:
    markers: list[str] = []
    lowered = {str(key).lower(): str(value).lower() for key, value in headers.items()}
    for key, value in lowered.items():
        if key in {'x-debug', 'x-debug-token', 'x-debug-token-link'}:
            markers.append(key)
        elif 'debug' in value and key in {'server', 'x-powered-by'}:
            markers.append(f'{key}:debug')
    return markers


def allowed_base_url(base_url: str, *, allow_remote: bool = False) -> bool:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
        return False
    if allow_remote:
        return True
    host = parsed.hostname.strip('[]').lower()
    if host in LOCAL_HOSTNAMES:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return False


def base_url_port(base_url: str | None) -> list[int]:
    if not base_url:
        return []
    try:
        parsed = urllib.parse.urlparse(base_url)
        if parsed.port:
            return [parsed.port]
        if parsed.scheme == 'https':
            return [443]
        if parsed.scheme == 'http':
            return [80]
    except ValueError:
        return []
    return []


def join_url(base_url: str, path: str) -> str:
    normalized_base = base_url.rstrip('/') + '/'
    normalized_path = normalize_path(path).lstrip('/')
    return urllib.parse.urljoin(normalized_base, normalized_path)


def normalize_path(path: str) -> str:
    text = str(path or '/').strip()
    if not text:
        return '/'
    if text.startswith('http://') or text.startswith('https://'):
        parsed = urllib.parse.urlparse(text)
        text = parsed.path or '/'
    if not text.startswith('/'):
        text = '/' + text
    return text


def redact_url(url: str) -> str:
    if not url:
        return ''
    parsed = urllib.parse.urlparse(url)
    if not parsed.username and not parsed.password:
        return url
    netloc = parsed.hostname or ''
    if parsed.port:
        netloc = f'{netloc}:{parsed.port}'
    return urllib.parse.urlunparse((parsed.scheme, netloc, parsed.path, '', parsed.query, ''))


def check(check_id: str, status: str, detail: str, **extra: Any) -> dict[str, Any]:
    payload = {'check_id': check_id, 'status': status, 'detail': detail}
    payload.update(extra)
    return payload


def overall_status(checks: list[dict[str, Any]]) -> str:
    statuses = {str(item.get('status')) for item in checks}
    if 'failed' in statuses:
        return 'failed'
    if 'blocked' in statuses:
        return 'blocked'
    if 'warning' in statuses:
        return 'warning'
    if statuses == {'planned'}:
        return 'planned'
    return 'passed'


def count_statuses(checks: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in checks:
        status = str(item.get('status') or 'unknown')
        counts[status] = counts.get(status, 0) + 1
    return counts


def bounded_timeout(value: int | None) -> int:
    try:
        timeout = int(value or DEFAULT_TIMEOUT_SECONDS)
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT_SECONDS
    return max(1, min(timeout, 60))


def sorted_unique(values: Any) -> list[str]:
    return sorted({str(value) for value in values if str(value)})


def sorted_unique_int(values: Any) -> list[int]:
    ints: set[int] = set()
    for value in values:
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if 0 < port <= 65535:
            ints.add(port)
    return sorted(ints)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def local_probe_socket(host: str, port: int, timeout: int = 1) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def runtime_smoke_guardrails() -> list[str]:
    return [
        'Do not start repository applications on the host for smoke checks.',
        'Use preview mode during normal scans and report bundle creation.',
        'Run network probes only against an explicit base_url or inside a disposable runtime worker.',
        'Remote base URLs require explicit allow_remote_base_url=true.',
        'Probe only safe HTTP GET routes and cap response body inspection.',
        'Do not run blind port scans; compare supplied observed ports to the allowed policy.',
    ]
