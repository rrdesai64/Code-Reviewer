from __future__ import annotations

import json
import os
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from .models import RuntimeBuildRunRequest, ScanResult
from .paths import data_dir
from .quarantine import quarantine_policy
from .runtime_plan import build_runtime_plan
from .runtime_smoke import SCHEMA_VERSION as SMOKE_SCHEMA_VERSION
from .runtime_smoke import sandbox_smoke_plan

SCHEMA_VERSION = 'runtime-build-run-worker-v1'
JOB_DIRNAME = 'runtime-worker'
DEFAULT_PROVIDER = 'container'
PROVIDERS = {'container', 'windows-sandbox', 'manual'}
NETWORK_POLICIES = {'offline', 'scanner-only', 'full'}
GUEST_REPO_SOURCE = Path('C:/secure-review-host/repo-source')
GUEST_JOB = Path('C:/secure-review-host/runtime-job')
GUEST_WORK = Path('C:/secure-review-runtime')
GUEST_REPO_WORK = GUEST_WORK / 'repo'
GUEST_STATUS = GUEST_JOB / 'runtime-worker-status.json'
GUEST_LOG = GUEST_JOB / 'runtime-worker.log'
CONTAINER_SOURCE = '/workspace/source'
CONTAINER_WORK = '/workspace/app'
CONTAINER_JOB = '/secure-review/job'


def runtime_worker_status() -> dict[str, Any]:
    docker = shutil.which('docker') or ''
    sandbox_exe = shutil.which('WindowsSandbox.exe') or str(Path(os.getenv('SystemRoot', 'C:/Windows')) / 'System32' / 'WindowsSandbox.exe')
    sandbox_available = Path(sandbox_exe).exists() if sandbox_exe else False
    return {
        'schema_version': SCHEMA_VERSION,
        'phase': '3B',
        'generated_at': now_iso(),
        'providers': {
            'container': {
                'available': bool(docker),
                'executable': docker,
                'runs_on_host': False,
                'uses_container_boundary': True,
                'supports_offline_networking': True,
                'supports_resource_limits': True,
            },
            'windows-sandbox': {
                'available': sandbox_available,
                'executable': sandbox_exe if sandbox_available else '',
                'runs_on_host': False,
                'uses_disposable_vm_boundary': True,
                'supports_offline_networking': True,
                'supports_resource_limits': False,
            },
            'manual': {
                'available': True,
                'executable': '',
                'runs_on_host': False,
                'uses_external_sandbox': True,
                'supports_offline_networking': False,
                'supports_resource_limits': False,
            },
        },
        'job_root': str(runtime_jobs_dir()),
        'guardrails': runtime_worker_guardrails(),
    }


def runtime_build_run_preview(scan: ScanResult, request: RuntimeBuildRunRequest | None = None) -> dict[str, Any]:
    request = request or RuntimeBuildRunRequest()
    plan = build_runtime_plan(scan)
    profile, blockers = select_runtime_profile(plan, request.profile_id, allow_blocked=True)
    return build_runtime_job_manifest(
        scan=scan,
        request=request,
        plan=plan,
        profile=profile,
        job_id='preview',
        job_dir=None,
        actor='system',
        persisted=False,
        extra_blockers=blockers,
    )


def prepare_runtime_build_run_job(scan: ScanResult, request: RuntimeBuildRunRequest, actor: str = 'system') -> dict[str, Any]:
    provider = normalize_choice(request.provider, PROVIDERS, DEFAULT_PROVIDER)
    network_policy = normalize_choice(request.network_policy, NETWORK_POLICIES, 'offline')
    repo = Path(scan.target_path).expanduser().resolve()
    if not repo.exists():
        raise ValueError(f'scan target path not found: {repo}')
    policy = quarantine_policy(str(repo), project_name=scan.project_name)
    if policy.get('matched') and not request.approved_quarantine:
        raise ValueError('repository is quarantined; set approved_quarantine=true to prepare a sandboxed runtime build/run job')

    plan = build_runtime_plan(scan)
    profile, blockers = select_runtime_profile(plan, request.profile_id, allow_blocked=False)
    if blockers:
        raise ValueError('; '.join(blockers))

    run = request.run_id or datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    job_id = safe_name(request.job_name or f'{scan.project_name}-{run}-{uuid.uuid4().hex[:8]}')
    job_dir = runtime_jobs_dir() / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    request = request.model_copy(update={'provider': provider, 'network_policy': network_policy})
    manifest = build_runtime_job_manifest(
        scan=scan,
        request=request,
        plan=plan,
        profile=profile,
        job_id=job_id,
        job_dir=job_dir,
        actor=actor,
        persisted=True,
        extra_blockers=[],
    )
    write_runtime_job_files(job_dir, manifest)
    return load_runtime_build_run_job(job_id)


def list_runtime_build_run_jobs(limit: int = 50) -> list[dict[str, Any]]:
    root = runtime_jobs_dir()
    if not root.exists():
        return []
    manifests = sorted(root.glob('*/manifest.json'), key=lambda item: item.stat().st_mtime, reverse=True)
    jobs: list[dict[str, Any]] = []
    for path in manifests[: max(1, min(limit, 500))]:
        try:
            jobs.append(job_card(json.loads(path.read_text(encoding='utf-8'))))
        except Exception:
            continue
    return jobs


def load_runtime_build_run_job(job_id: str) -> dict[str, Any]:
    path = runtime_jobs_dir() / safe_name(job_id) / 'manifest.json'
    if not path.exists():
        raise FileNotFoundError(job_id)
    return json.loads(path.read_text(encoding='utf-8'))


def build_runtime_job_manifest(
    *,
    scan: ScanResult,
    request: RuntimeBuildRunRequest,
    plan: dict[str, Any],
    profile: dict[str, Any] | None,
    job_id: str,
    job_dir: Path | None,
    actor: str,
    persisted: bool,
    extra_blockers: list[str],
) -> dict[str, Any]:
    repo = Path(scan.target_path).expanduser().resolve()
    provider = normalize_choice(request.provider, PROVIDERS, DEFAULT_PROVIDER)
    network_policy = normalize_choice(request.network_policy, NETWORK_POLICIES, 'offline')
    selected_profile = profile or {}
    blockers = [*extra_blockers, *selected_profile.get('blockers', [])]
    if not selected_profile.get('start', {}).get('command'):
        blockers.append('selected runtime profile does not include a start command')
    job_files = job_file_paths(job_dir)
    container_image = request.container_image or container_image_for_profile(selected_profile)
    status = 'prepared' if persisted and not blockers else 'blocked' if blockers else 'preview'
    return {
        'schema_version': SCHEMA_VERSION,
        'phase': '3B',
        'job_id': job_id,
        'status': status,
        'created_at': now_iso(),
        'actor': actor,
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'provider': provider,
        'network_policy': network_policy,
        'persisted': persisted,
        'runtime_plan': {
            'schema_version': plan.get('schema_version'),
            'status': plan.get('summary', {}).get('status', ''),
            'profile_count': plan.get('summary', {}).get('profile_count', 0),
            'primary_profile_id': plan.get('summary', {}).get('primary_profile_id', ''),
        },
        'selected_profile': selected_profile,
        'container': {
            'image': container_image,
            'network_mode': docker_network_mode(network_policy),
            'resource_limits': {
                'cpus': '2',
                'memory': '4g',
                'pids_limit': 512,
                'cap_drop': ['ALL'],
                'security_opt': ['no-new-privileges'],
            },
            'source_mount': {'host_path': str(repo), 'container_path': CONTAINER_SOURCE, 'read_only': True},
            'job_mount': {'host_path': str(job_dir) if job_dir else '', 'container_path': CONTAINER_JOB, 'read_only': False},
        },
        'execution_plan': execution_plan(selected_profile, request),
        'host_paths': {
            'repository_source': str(repo),
            'job_dir': str(job_dir) if job_dir else '',
        },
        'guest_paths': {
            'repository_source': str(GUEST_REPO_SOURCE),
            'job_dir': str(GUEST_JOB),
            'work_root': str(GUEST_WORK),
            'repository_work': str(GUEST_REPO_WORK),
        },
        'files': job_files,
        'safety_controls': {
            'host_execution': False,
            'repository_mount_readonly': True,
            'scratch_copy_required': True,
            'sandbox_required': True,
            'network_policy': network_policy,
            'runs_build_commands': True,
            'runs_start_command': True,
            'runs_tests': bool(request.run_tests),
            'runs_phase_3c_smoke_checks': bool(request.run_smoke_checks),
            'does_not_run_health_checks': not bool(request.run_smoke_checks),
            'no_blind_port_scan': True,
            'no_raw_source_export': True,
            'status_and_logs_only': True,
            'timeout_seconds': request.timeout_seconds,
            'start_timeout_seconds': request.start_timeout_seconds,
            'smoke_timeout_seconds': request.smoke_timeout_seconds,
        },
        'output_artifacts': [
            'runtime-worker-status.json',
            'runtime-worker.log',
            'runtime-smoke-posture.json',
        ],
        'blockers': sorted_unique(blockers),
        'warnings': runtime_worker_warnings(provider, network_policy),
        'workflow': [
            'Create a disposable container or VM with the repository mounted read-only.',
            'Copy the repository into sandbox scratch space before running build commands.',
            'Run Phase 3A build commands inside the sandbox.',
            'Start the app inside the sandbox long enough to prove the process stays alive.',
            'Run Phase 3C smoke/posture checks against the isolated runtime target.',
            'Write runtime-worker-status.json, runtime-worker.log, and runtime-smoke-posture.json into the job directory.',
            'Destroy the container or close the disposable VM to discard scratch state.',
        ],
        'guardrails': runtime_worker_guardrails(),
    }


def execution_plan(profile: dict[str, Any], request: RuntimeBuildRunRequest) -> dict[str, Any]:
    build_commands = profile.get('build', {}).get('commands', [])
    test_commands = profile.get('tests', {}).get('commands', []) if request.run_tests else []
    start = profile.get('start', {})
    optional_env = profile.get('optional_env', {})
    smoke_checks = sandbox_smoke_plan(
        profile,
        enabled=request.run_smoke_checks,
        timeout_seconds=request.smoke_timeout_seconds,
        probe_paths=request.smoke_probe_paths,
        allowed_ports=request.smoke_allowed_ports,
    )
    return {
        'working_directory': start.get('working_directory', '.'),
        'build_commands': build_commands,
        'test_commands': test_commands,
        'start_command': start.get('command', ''),
        'expected_port': start.get('expected_port', 0),
        'health_url_candidates': start.get('health_url_candidates', []),
        'env': optional_env,
        'run_tests': bool(request.run_tests),
        'timeout_seconds': request.timeout_seconds,
        'start_timeout_seconds': request.start_timeout_seconds,
        'smoke_checks': smoke_checks,
        'phase_3c_smoke_checks_deferred': not bool(request.run_smoke_checks),
    }


def write_runtime_job_files(job_dir: Path, manifest: dict[str, Any]) -> None:
    (job_dir / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    (job_dir / 'runtime-plan.json').write_text(json.dumps(manifest.get('runtime_plan', {}), indent=2), encoding='utf-8')
    (job_dir / 'runtime-smoke-plan.json').write_text(json.dumps(manifest.get('execution_plan', {}).get('smoke_checks', {}), indent=2), encoding='utf-8')
    (job_dir / 'runtime-smoke-check.py').write_text(python_smoke_checker_script(), encoding='utf-8')
    (job_dir / 'runtime-smoke-check.js').write_text(node_smoke_checker_script(), encoding='utf-8')
    (job_dir / 'container-entrypoint.sh').write_text(container_entrypoint_script(manifest), encoding='utf-8')
    (job_dir / 'run-container.ps1').write_text(container_launcher_script(manifest), encoding='utf-8')
    (job_dir / 'guest-run-runtime.ps1').write_text(windows_guest_runner_script(manifest), encoding='utf-8')
    (job_dir / 'job.wsb').write_text(windows_sandbox_config(manifest), encoding='utf-8')
    (job_dir / 'manual-instructions.md').write_text(manual_instructions(manifest), encoding='utf-8')


def job_file_paths(job_dir: Path | None) -> dict[str, str]:
    if not job_dir:
        return {
            'manifest': '',
            'runtime_plan': '',
            'runtime_smoke_plan': '',
            'runtime_smoke_python': '',
            'runtime_smoke_node': '',
            'container_entrypoint': '',
            'container_launcher': '',
            'windows_guest_runner': '',
            'windows_sandbox_config': '',
            'manual_instructions': '',
        }
    return {
        'manifest': str(job_dir / 'manifest.json'),
        'runtime_plan': str(job_dir / 'runtime-plan.json'),
        'runtime_smoke_plan': str(job_dir / 'runtime-smoke-plan.json'),
        'runtime_smoke_python': str(job_dir / 'runtime-smoke-check.py'),
        'runtime_smoke_node': str(job_dir / 'runtime-smoke-check.js'),
        'container_entrypoint': str(job_dir / 'container-entrypoint.sh'),
        'container_launcher': str(job_dir / 'run-container.ps1'),
        'windows_guest_runner': str(job_dir / 'guest-run-runtime.ps1'),
        'windows_sandbox_config': str(job_dir / 'job.wsb'),
        'manual_instructions': str(job_dir / 'manual-instructions.md'),
    }


def container_entrypoint_script(manifest: dict[str, Any]) -> str:
    plan = manifest['execution_plan']
    build = '\n'.join(shell_step(command) for command in plan.get('build_commands', []))
    tests = '\n'.join(shell_step(command) for command in plan.get('test_commands', []))
    start = shell_quote(plan.get('start_command', ''))
    workdir = shell_quote(plan.get('working_directory') or '.')
    start_timeout = int(plan.get('start_timeout_seconds') or 60)
    smoke_enabled = 'true' if plan.get('smoke_checks', {}).get('enabled') else 'false'
    env_lines = '\n'.join(f'export {safe_env_name(key)}={shell_quote(str(value))}' for key, value in sorted((plan.get('env') or {}).items()))
    return f"""#!/bin/sh
set -eu

STATUS="{CONTAINER_JOB}/runtime-worker-status.json"
LOG="{CONTAINER_JOB}/runtime-worker.log"
WORK="{CONTAINER_WORK}"
SMOKE_PLAN="{CONTAINER_JOB}/runtime-smoke-plan.json"
SMOKE_OUT="{CONTAINER_JOB}/runtime-smoke-posture.json"
SMOKE_ENABLED="{smoke_enabled}"

write_status() {{
  status="$1"
  message="$2"
  exit_code="${{3:-0}}"
  printf '{{"schema_version":"{SCHEMA_VERSION}","job_id":"{manifest['job_id']}","status":"%s","message":"%s","exit_code":%s,"updated_at":"%s"}}\\n' "$status" "$message" "$exit_code" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$STATUS"
}}

write_smoke_blocked() {{
  message="$1"
  printf '{{"schema_version":"{SMOKE_SCHEMA_VERSION}","phase":"3C","mode":"sandbox-container","status":"blocked","summary":{{"status":"blocked","reason":"%s"}},"checks":[],"probes":[]}}\\n' "$message" > "$SMOKE_OUT"
}}

run_smoke_checks() {{
  if [ "$SMOKE_ENABLED" != "true" ]; then
    write_smoke_blocked "smoke checks disabled by runtime job request"
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 "{CONTAINER_JOB}/runtime-smoke-check.py" "$SMOKE_PLAN" "$SMOKE_OUT" || write_smoke_blocked "python smoke checker failed"
    return 0
  fi
  if command -v python >/dev/null 2>&1; then
    python "{CONTAINER_JOB}/runtime-smoke-check.py" "$SMOKE_PLAN" "$SMOKE_OUT" || write_smoke_blocked "python smoke checker failed"
    return 0
  fi
  if command -v node >/dev/null 2>&1; then
    node "{CONTAINER_JOB}/runtime-smoke-check.js" "$SMOKE_PLAN" "$SMOKE_OUT" || write_smoke_blocked "node smoke checker failed"
    return 0
  fi
  write_smoke_blocked "no python or node runtime was available for HTTP smoke checks"
}}

write_status running "copying repository into sandbox scratch space" 0
rm -rf "$WORK"
mkdir -p "$WORK"
cp -a "{CONTAINER_SOURCE}/." "$WORK/"
cd "$WORK/{workdir.strip("'")}"
{env_lines}

write_status running "running build commands" 0
: > "$LOG"
{build or ': # no build commands inferred'}
{tests or ': # tests not requested for Phase 3B'}

write_status running "starting application process" 0
if [ -z {start} ]; then
  write_status failed "no start command was provided" 2
  exit 2
fi

sh -lc {start} >> "$LOG" 2>&1 &
app_pid="$!"
sleep {start_timeout}
if kill -0 "$app_pid" 2>/dev/null; then
  write_status running "application process stayed alive for {start_timeout} seconds; running Phase 3C smoke checks" 0
  run_smoke_checks
  write_status started "application process stayed alive for {start_timeout} seconds; Phase 3C smoke checks completed" 0
  kill "$app_pid" 2>/dev/null || true
  wait "$app_pid" 2>/dev/null || true
  exit 0
fi

write_status failed "application process exited before the start timeout" 3
wait "$app_pid" 2>/dev/null || true
exit 3
"""


def container_launcher_script(manifest: dict[str, Any]) -> str:
    container = manifest['container']
    job_dir = manifest['host_paths']['job_dir']
    repo = manifest['host_paths']['repository_source']
    name = safe_name(f"secure-review-runtime-{manifest['job_id']}").lower()
    env_args = docker_env_args(manifest.get('execution_plan', {}).get('env', {}))
    return f"""$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$JobDir = "{ps(job_dir)}"
$Repo = "{ps(repo)}"
$Image = "{ps(container['image'])}"
$ContainerName = "{ps(name)}"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {{
  throw "Docker is not available. Use the Windows Sandbox or manual job artifact instead."
}}

docker run --rm --name $ContainerName `
  --network {container['network_mode']} `
  --cpus {container['resource_limits']['cpus']} `
  --memory {container['resource_limits']['memory']} `
  --pids-limit {container['resource_limits']['pids_limit']} `
  --security-opt no-new-privileges `
  --cap-drop ALL `
  -v "$Repo`:{CONTAINER_SOURCE}:ro" `
  -v "$JobDir`:{CONTAINER_JOB}" `
  {env_args} `
  $Image /bin/sh "{CONTAINER_JOB}/container-entrypoint.sh"
"""


def windows_guest_runner_script(manifest: dict[str, Any]) -> str:
    plan = manifest['execution_plan']
    build = ps_command_array(plan.get('build_commands', []))
    tests = ps_command_array(plan.get('test_commands', []))
    start = str(plan.get('start_command') or '')
    workdir = str(plan.get('working_directory') or '.')
    timeout = int(plan.get('start_timeout_seconds') or 60)
    smoke_enabled = '$true' if plan.get('smoke_checks', {}).get('enabled') else '$false'
    env_lines = '\n'.join(f'$env:{safe_env_name(key)} = "{ps(str(value))}"' for key, value in sorted((plan.get('env') or {}).items()))
    return f"""$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$StatusPath = "{ps(str(GUEST_STATUS))}"
$LogPath = "{ps(str(GUEST_LOG))}"
$SmokePlanPath = "{ps(str(GUEST_JOB / 'runtime-smoke-plan.json'))}"
$SmokeOutPath = "{ps(str(GUEST_JOB / 'runtime-smoke-posture.json'))}"
$SmokeEnabled = {smoke_enabled}
$BuildCommands = @({build})
$TestCommands = @({tests})
$StartCommand = "{ps(start)}"
$WorkDir = Join-Path "{ps(str(GUEST_REPO_WORK))}" "{ps(workdir)}"

function Write-WorkerStatus {{
  param([string]$Status, [string]$Message = "", [int]$ExitCode = 0)
  [pscustomobject]@{{
    schema_version = "{SCHEMA_VERSION}"
    job_id = "{manifest['job_id']}"
    status = $Status
    message = $Message
    exit_code = $ExitCode
    updated_at = (Get-Date).ToUniversalTime().ToString("o")
  }} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StatusPath -Encoding UTF8
}}

function Write-SmokeBlocked {{
  param([string]$Message)
  [pscustomobject]@{{
    schema_version = "{SMOKE_SCHEMA_VERSION}"
    phase = "3C"
    mode = "sandbox-windows"
    status = "blocked"
    summary = @{{ status = "blocked"; reason = $Message }}
    checks = @()
    probes = @()
  }} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $SmokeOutPath -Encoding UTF8
}}

function Invoke-RuntimeSmokeChecks {{
  if (-not $SmokeEnabled) {{
    Write-SmokeBlocked -Message "smoke checks disabled by runtime job request"
    return
  }}
  if (-not (Test-Path -LiteralPath $SmokePlanPath)) {{
    Write-SmokeBlocked -Message "runtime smoke plan was not found"
    return
  }}
  $Plan = Get-Content -LiteralPath $SmokePlanPath -Raw | ConvertFrom-Json
  $Probes = @()
  $HealthPassed = $false
  $ProbeUrlSet = [ordered]@{{}}
  foreach ($Url in @($Plan.health_url_candidates)) {{
    if (-not [string]::IsNullOrWhiteSpace([string]$Url)) {{ $ProbeUrlSet[[string]$Url] = $true }}
  }}
  $Origins = @()
  foreach ($Url in @($Plan.health_url_candidates)) {{
    try {{
      $Parsed = [Uri]([string]$Url)
      $Origins += "$($Parsed.Scheme)://$($Parsed.Authority)/"
    }} catch {{}}
  }}
  foreach ($Origin in ($Origins | Select-Object -Unique)) {{
    foreach ($Path in @($Plan.probe_paths)) {{
      $ProbePath = [string]$Path
      if ([string]::IsNullOrWhiteSpace($ProbePath)) {{ $ProbePath = "/" }}
      if (-not $ProbePath.StartsWith("/")) {{ $ProbePath = "/" + $ProbePath }}
      try {{
        $ProbeUri = [Uri]::new([Uri]$Origin, $ProbePath.TrimStart("/"))
        $ProbeUrlSet[$ProbeUri.AbsoluteUri] = $true
      }} catch {{}}
    }}
  }}
  foreach ($Url in $ProbeUrlSet.Keys) {{
    $Path = "/"
    try {{ $Path = ([Uri]([string]$Url)).AbsolutePath }} catch {{}}
    try {{
      $Response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec ([int]$Plan.timeout_seconds)
      $Headers = @{{}}
      foreach ($Key in $Response.Headers.Keys) {{ $Headers[$Key.ToLowerInvariant()] = [string]$Response.Headers[$Key] }}
      if (@($Plan.health_url_candidates) -contains $Url -and [int]$Response.StatusCode -ge 200 -and [int]$Response.StatusCode -lt 400) {{ $HealthPassed = $true }}
      $Probes += [pscustomobject]@{{ url = $Url; path = $Path; status_code = [int]$Response.StatusCode; headers = $Headers; error = "" }}
    }} catch {{
      $StatusCode = 0
      if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {{ $StatusCode = [int]$_.Exception.Response.StatusCode }}
      $Probes += [pscustomobject]@{{ url = $Url; path = $Path; status_code = $StatusCode; headers = @{{}}; error = $_.Exception.Message }}
    }}
  }}
  $Representative = $Probes | Where-Object {{ $_.status_code -ge 200 -and $_.status_code -lt 400 }} | Select-Object -First 1
  $MissingHeaders = @()
  if ($Representative) {{
    foreach ($Header in @($Plan.required_security_headers)) {{
      if (-not $Representative.headers.ContainsKey(([string]$Header).ToLowerInvariant())) {{ $MissingHeaders += $Header }}
    }}
  }} else {{
    $MissingHeaders = @($Plan.required_security_headers)
  }}
  $DebugRoutes = @("/debug", "/__debug__", "/_debug_toolbar", "/actuator/env", "/actuator/heapdump", "/phpinfo.php")
  $ObservedRoutes = @("/metrics", "/docs", "/openapi.json", "/swagger.json", "/actuator")
  $ExposedRoutes = @($Probes | Where-Object {{ $_.status_code -ge 200 -and $_.status_code -lt 400 -and (($DebugRoutes -contains $_.path) -or ($ObservedRoutes -contains $_.path)) }})
  $HighRouteCount = @($ExposedRoutes | Where-Object {{ $DebugRoutes -contains $_.path }}).Count
  $OverallStatus = if ((-not $HealthPassed) -or $HighRouteCount -gt 0) {{ "failed" }} elseif ($MissingHeaders.Count -gt 0 -or $ExposedRoutes.Count -gt 0) {{ "warning" }} else {{ "passed" }}
  $Checks = @(
    [pscustomobject]@{{ check_id = "app-start"; status = $(if ($Probes.Count -gt 0) {{ "passed" }} else {{ "failed" }}); detail = "HTTP runtime target was probed from the disposable worker." }},
    [pscustomobject]@{{ check_id = "health-endpoint"; status = $(if ($HealthPassed) {{ "passed" }} else {{ "failed" }}); detail = "Health endpoint probe completed inside the disposable worker." }},
    [pscustomobject]@{{ check_id = "security-headers"; status = $(if ($MissingHeaders.Count -eq 0) {{ "passed" }} else {{ "warning" }}); detail = "Security header posture inspected from the first successful response."; missing_headers = $MissingHeaders }},
    [pscustomobject]@{{ check_id = "unexpected-routes"; status = $(if ($HighRouteCount -gt 0) {{ "failed" }} elseif ($ExposedRoutes.Count -gt 0) {{ "warning" }} else {{ "passed" }}); detail = "Debug, docs, metrics, and actuator route posture inspected."; exposed_routes = @($ExposedRoutes | ForEach-Object {{ @{{ path = $_.path; status_code = $_.status_code }} }}) }},
    [pscustomobject]@{{ check_id = "unexpected-ports"; status = "planned"; detail = "No blind port scan is performed by the Windows Sandbox runner." }}
  )
  [pscustomobject]@{{
    schema_version = "{SMOKE_SCHEMA_VERSION}"
    phase = "3C"
    mode = "sandbox-windows"
    status = $OverallStatus
    summary = @{{ status = $OverallStatus; probe_count = $Probes.Count; missing_security_header_count = $MissingHeaders.Count; unexpected_route_count = $ExposedRoutes.Count }}
    checks = $Checks
    probes = $Probes
  }} | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $SmokeOutPath -Encoding UTF8
}}

New-Item -ItemType Directory -Force -Path "{ps(str(GUEST_WORK))}", "{ps(str(GUEST_REPO_WORK))}" | Out-Null
Write-WorkerStatus -Status "running" -Message "copying repository into sandbox scratch space"
robocopy "{ps(str(GUEST_REPO_SOURCE))}" "{ps(str(GUEST_REPO_WORK))}" /MIR /R:1 /W:1 /NFL /NDL /NP | Out-Null
if ($LASTEXITCODE -gt 7) {{ throw "robocopy failed with exit code $LASTEXITCODE" }}
{env_lines}

Set-Location $WorkDir
"" | Set-Content -LiteralPath $LogPath -Encoding UTF8
foreach ($Command in $BuildCommands) {{
  Write-WorkerStatus -Status "running" -Message "running build command"
  cmd.exe /c $Command *>> $LogPath
  if ($LASTEXITCODE -ne 0) {{
    Write-WorkerStatus -Status "failed" -Message "build command failed" -ExitCode $LASTEXITCODE
    exit $LASTEXITCODE
  }}
}}
foreach ($Command in $TestCommands) {{
  Write-WorkerStatus -Status "running" -Message "running optional test command"
  cmd.exe /c $Command *>> $LogPath
  if ($LASTEXITCODE -ne 0) {{
    Write-WorkerStatus -Status "failed" -Message "test command failed" -ExitCode $LASTEXITCODE
    exit $LASTEXITCODE
  }}
}}
if ([string]::IsNullOrWhiteSpace($StartCommand)) {{
  Write-WorkerStatus -Status "failed" -Message "no start command was provided" -ExitCode 2
  exit 2
}}
$Process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $StartCommand -PassThru -RedirectStandardOutput $LogPath -RedirectStandardError $LogPath
Start-Sleep -Seconds {timeout}
if (-not $Process.HasExited) {{
  Write-WorkerStatus -Status "running" -Message "application process stayed alive for {timeout} seconds; running Phase 3C smoke checks"
  Invoke-RuntimeSmokeChecks
  Write-WorkerStatus -Status "started" -Message "application process stayed alive for {timeout} seconds; Phase 3C smoke checks completed"
  Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
  exit 0
}}
Write-WorkerStatus -Status "failed" -Message "application process exited before the start timeout" -ExitCode 3
exit 3
"""


def windows_sandbox_config(manifest: dict[str, Any]) -> str:
    network = '<Networking>Disable</Networking>' if manifest['network_policy'] == 'offline' else '<Networking>Default</Networking>'
    return f"""<Configuration>
  {network}
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <PrinterRedirection>Disable</PrinterRedirection>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <ProtectedClient>Enable</ProtectedClient>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{xml(manifest['host_paths']['repository_source'])}</HostFolder>
      <SandboxFolder>{xml(str(GUEST_REPO_SOURCE))}</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>{xml(manifest['host_paths']['job_dir'])}</HostFolder>
      <SandboxFolder>{xml(str(GUEST_JOB))}</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{xml(str(GUEST_JOB / 'guest-run-runtime.ps1'))}"</Command>
  </LogonCommand>
</Configuration>
"""


def manual_instructions(manifest: dict[str, Any]) -> str:
    plan = manifest['execution_plan']
    lines = [
        f"# Runtime Build/Run Job {manifest['job_id']}",
        '',
        'Run these commands only inside a disposable VM or container.',
        '',
        f"- Provider: `{manifest['provider']}`",
        f"- Network policy: `{manifest['network_policy']}`",
        f"- Runtime: `{manifest.get('selected_profile', {}).get('runtime', '')}`",
        f"- Framework: `{manifest.get('selected_profile', {}).get('framework', '')}`",
        '',
        'Build commands:',
    ]
    lines.extend(f"- `{command}`" for command in plan.get('build_commands', []) or ['<none inferred>'])
    if plan.get('test_commands'):
        lines.append('')
        lines.append('Optional test commands:')
        lines.extend(f"- `{command}`" for command in plan['test_commands'])
    lines.extend([
        '',
        'Start command:',
        f"- `{plan.get('start_command') or '<missing>'}`",
        '',
        'Phase 3C smoke/posture checks:',
        f"- Enabled: `{str(plan.get('smoke_checks', {}).get('enabled', False)).lower()}`",
        f"- Health candidates: `{len(plan.get('smoke_checks', {}).get('health_url_candidates', []))}`",
        f"- Output artifact: `{plan.get('smoke_checks', {}).get('output_artifact', 'runtime-smoke-posture.json')}`",
    ])
    return '\n'.join(lines) + '\n'


def select_runtime_profile(plan: dict[str, Any], profile_id: str | None, allow_blocked: bool) -> tuple[dict[str, Any] | None, list[str]]:
    profiles = plan.get('profiles') or []
    if not profiles:
        return None, plan.get('blockers') or ['runtime plan did not produce any profiles']
    if profile_id:
        profile = next((item for item in profiles if item.get('profile_id') == profile_id), None)
        if not profile:
            return None, [f'runtime profile not found: {profile_id}']
    else:
        profile = profiles[0]
    blockers = list(profile.get('blockers') or [])
    if blockers and not allow_blocked:
        return profile, blockers
    return profile, []


def container_image_for_profile(profile: dict[str, Any]) -> str:
    runtime = profile.get('runtime')
    framework = profile.get('framework')
    if runtime == 'python':
        return 'python:3.12-slim'
    if runtime == 'node':
        return 'node:22-bookworm-slim'
    if runtime == 'go':
        return 'golang:1.23-bookworm'
    if runtime == 'jvm':
        return 'maven:3.9-eclipse-temurin-21' if profile.get('package_manager') == 'maven' else 'gradle:8.10-jdk21'
    if runtime == 'dotnet':
        return 'mcr.microsoft.com/dotnet/sdk:8.0'
    if runtime == 'php':
        return 'php:8.3-cli'
    if runtime == 'ruby':
        return 'ruby:3.3'
    if runtime == 'container' or framework == 'docker':
        return 'docker:27-cli'
    return 'ubuntu:24.04'


def python_smoke_checker_script() -> str:
    return r'''from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "__SMOKE_SCHEMA_VERSION__"


def now_iso():
    return datetime.now(timezone.utc).isoformat()


DEBUG_ROUTE_PATHS = {"/debug", "/__debug__", "/_debug_toolbar", "/actuator/env", "/actuator/heapdump", "/phpinfo.php"}
OBSERVABILITY_ROUTE_PATHS = {"/metrics", "/docs", "/openapi.json", "/swagger.json", "/actuator"}


def probe_urls(plan):
    candidates = [str(url) for url in plan.get("health_url_candidates", []) if str(url)]
    origins = []
    for url in candidates:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme and parsed.netloc:
            origins.append(urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "/", "", "", "")))
    paths = [normalize_path(path) for path in plan.get("probe_paths", [])]
    urls = [*candidates]
    for origin in origins:
        for path in paths:
            urls.append(urllib.parse.urljoin(origin, path.lstrip("/")))
    seen = set()
    ordered = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            ordered.append(url)
    return ordered


def normalize_path(path):
    text = str(path or "/").strip()
    if not text.startswith("/"):
        text = "/" + text
    return text


def fetch(url, timeout):
    started = now_iso()
    req = urllib.request.Request(url, headers={"User-Agent": "SecureReviewRuntimeSmoke/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(8192).decode("utf-8", errors="ignore").lower()
            return {
                "url": url,
                "path": urllib.parse.urlparse(url).path or "/",
                "status_code": int(resp.status),
                "headers": {str(k).lower(): str(v)[:200] for k, v in resp.headers.items()},
                "body_markers": body_markers(body),
                "error": "",
                "started_at": started,
                "completed_at": now_iso(),
            }
    except urllib.error.HTTPError as exc:
        body = exc.read(8192).decode("utf-8", errors="ignore").lower()
        return {
            "url": url,
            "path": urllib.parse.urlparse(url).path or "/",
            "status_code": int(exc.code),
            "headers": {str(k).lower(): str(v)[:200] for k, v in (exc.headers or {}).items()},
            "body_markers": body_markers(body),
            "error": "",
            "started_at": started,
            "completed_at": now_iso(),
        }
    except Exception as exc:
        return {"url": url, "path": urllib.parse.urlparse(url).path or "/", "status_code": 0, "headers": {}, "body_markers": [], "error": str(exc)[:300], "started_at": started, "completed_at": now_iso()}


def body_markers(body):
    markers = ["werkzeug debugger", "traceback (most recent call last)", "django debug", "debug toolbar", "phpinfo()", "spring boot actuator"]
    return [marker for marker in markers if marker in body]


def main():
    plan_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    if not plan.get("enabled"):
        out_path.write_text(json.dumps(blocked("smoke checks disabled by runtime job request"), indent=2), encoding="utf-8")
        return 0
    timeout = max(1, min(int(plan.get("timeout_seconds") or 10), 60))
    probes = [fetch(url, timeout) for url in probe_urls(plan)]
    successes = [probe for probe in probes if 200 <= int(probe.get("status_code") or 0) < 400]
    health_urls = set(plan.get("health_url_candidates", []))
    health_passed = any(probe.get("url") in health_urls and 200 <= int(probe.get("status_code") or 0) < 400 for probe in probes)
    representative = successes[0] if successes else {}
    headers = representative.get("headers") or {}
    required = [str(item).lower() for item in plan.get("required_security_headers", [])]
    missing = [header for header in required if header not in headers]
    debug_markers = [marker for probe in probes for marker in probe.get("body_markers", [])]
    exposed_routes = [
        probe for probe in successes
        if probe.get("path") in DEBUG_ROUTE_PATHS or probe.get("path") in OBSERVABILITY_ROUTE_PATHS
    ]
    high_route_count = sum(1 for probe in exposed_routes if probe.get("path") in DEBUG_ROUTE_PATHS)
    status = "failed" if debug_markers or high_route_count or not health_passed else "warning" if missing or exposed_routes else "passed"
    checks = [
        {"check_id": "app-start", "status": "passed" if probes else "failed", "detail": "HTTP runtime target was probed inside the disposable worker."},
        {"check_id": "health-endpoint", "status": "passed" if health_passed else "failed", "detail": "Health endpoint probe completed inside the disposable worker."},
        {"check_id": "security-headers", "status": "passed" if not missing and representative else "warning", "detail": "Security header posture inspected from the first successful response.", "missing_headers": missing},
        {"check_id": "debug-exposure", "status": "failed" if debug_markers else "passed", "detail": "Debug response markers were inspected.", "markers": debug_markers},
        {"check_id": "unexpected-routes", "status": "failed" if high_route_count else "warning" if exposed_routes else "passed", "detail": "Debug, docs, metrics, and actuator route posture inspected.", "exposed_routes": [{"path": probe.get("path"), "status_code": probe.get("status_code")} for probe in exposed_routes]},
        {"check_id": "unexpected-ports", "status": "planned", "detail": "No blind port scan is performed by the sandbox runner."},
    ]
    report = {
        "schema_version": SCHEMA_VERSION,
        "phase": "3C",
        "mode": "sandbox-container",
        "status": status,
        "summary": {"status": status, "probe_count": len(probes), "missing_security_header_count": len(missing), "debug_marker_count": len(debug_markers), "unexpected_route_count": len(exposed_routes)},
        "checks": checks,
        "probes": probes,
        "guardrails": ["HTTP GET probes only", "No blind port scan", "Runs inside disposable runtime worker"],
    }
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


def blocked(message):
    return {
        "schema_version": SCHEMA_VERSION,
        "phase": "3C",
        "mode": "sandbox-container",
        "status": "blocked",
        "summary": {"status": "blocked", "reason": message},
        "checks": [],
        "probes": [],
    }


if __name__ == "__main__":
    raise SystemExit(main())
'''.replace('__SMOKE_SCHEMA_VERSION__', SMOKE_SCHEMA_VERSION)


def node_smoke_checker_script() -> str:
    return r'''const fs = require("fs");
const http = require("http");
const https = require("https");

const SCHEMA_VERSION = "__SMOKE_SCHEMA_VERSION__";
const DEBUG_ROUTE_PATHS = new Set(["/debug", "/__debug__", "/_debug_toolbar", "/actuator/env", "/actuator/heapdump", "/phpinfo.php"]);
const OBSERVABILITY_ROUTE_PATHS = new Set(["/metrics", "/docs", "/openapi.json", "/swagger.json", "/actuator"]);

function nowIso() {
  return new Date().toISOString();
}

function fetchUrl(url, timeoutSeconds) {
  return new Promise((resolve) => {
    const started = nowIso();
    const client = url.startsWith("https:") ? https : http;
    const req = client.get(url, { timeout: timeoutSeconds * 1000, headers: { "User-Agent": "SecureReviewRuntimeSmoke/1.0" } }, (res) => {
      let body = "";
      res.on("data", (chunk) => {
        if (body.length < 8192) body += chunk.toString("utf8");
      });
      res.on("end", () => resolve({
        url,
        path: new URL(url).pathname || "/",
        status_code: res.statusCode || 0,
        headers: Object.fromEntries(Object.entries(res.headers).map(([k, v]) => [k.toLowerCase(), String(v).slice(0, 200)])),
        body_markers: bodyMarkers(body.toLowerCase()),
        error: "",
        started_at: started,
        completed_at: nowIso(),
      }));
    });
    req.on("timeout", () => {
      req.destroy(new Error("request timed out"));
    });
    req.on("error", (err) => resolve({ url, path: safePath(url), status_code: 0, headers: {}, body_markers: [], error: String(err.message || err).slice(0, 300), started_at: started, completed_at: nowIso() }));
  });
}

function bodyMarkers(body) {
  return ["werkzeug debugger", "traceback (most recent call last)", "django debug", "debug toolbar", "phpinfo()", "spring boot actuator"].filter((marker) => body.includes(marker));
}

function probeUrls(plan) {
  const candidates = (plan.health_url_candidates || []).map((item) => String(item)).filter(Boolean);
  const origins = [...new Set(candidates.map((item) => {
    try {
      const url = new URL(item);
      return `${url.protocol}//${url.host}/`;
    } catch {
      return "";
    }
  }).filter(Boolean))];
  const paths = (plan.probe_paths || []).map(normalizePath);
  const urls = [...candidates];
  for (const origin of origins) {
    for (const path of paths) urls.push(new URL(path.replace(/^\/+/, ""), origin).toString());
  }
  return [...new Set(urls)];
}

function normalizePath(path) {
  const text = String(path || "/").trim();
  return text.startsWith("/") ? text : `/${text}`;
}

function safePath(url) {
  try {
    return new URL(url).pathname || "/";
  } catch {
    return "/";
  }
}

async function main() {
  const planPath = process.argv[2];
  const outPath = process.argv[3];
  const plan = JSON.parse(fs.readFileSync(planPath, "utf8"));
  if (!plan.enabled) {
    fs.writeFileSync(outPath, JSON.stringify(blocked("smoke checks disabled by runtime job request"), null, 2));
    return;
  }
  const timeout = Math.max(1, Math.min(Number(plan.timeout_seconds || 10), 60));
  const probes = [];
  for (const url of probeUrls(plan)) probes.push(await fetchUrl(url, timeout));
  const successes = probes.filter((probe) => probe.status_code >= 200 && probe.status_code < 400);
  const healthUrls = new Set(plan.health_url_candidates || []);
  const healthPassed = probes.some((probe) => healthUrls.has(probe.url) && probe.status_code >= 200 && probe.status_code < 400);
  const representative = successes[0] || {};
  const headers = representative.headers || {};
  const required = (plan.required_security_headers || []).map((item) => String(item).toLowerCase());
  const missing = required.filter((header) => !(header in headers));
  const debugMarkers = probes.flatMap((probe) => probe.body_markers || []);
  const exposedRoutes = successes.filter((probe) => DEBUG_ROUTE_PATHS.has(probe.path) || OBSERVABILITY_ROUTE_PATHS.has(probe.path));
  const highRouteCount = exposedRoutes.filter((probe) => DEBUG_ROUTE_PATHS.has(probe.path)).length;
  const status = debugMarkers.length || highRouteCount || !healthPassed ? "failed" : missing.length || exposedRoutes.length ? "warning" : "passed";
  const checks = [
    { check_id: "app-start", status: probes.length ? "passed" : "failed", detail: "HTTP runtime target was probed inside the disposable worker." },
    { check_id: "health-endpoint", status: healthPassed ? "passed" : "failed", detail: "Health endpoint probe completed inside the disposable worker." },
    { check_id: "security-headers", status: missing.length || !representative.url ? "warning" : "passed", detail: "Security header posture inspected from the first successful response.", missing_headers: missing },
    { check_id: "debug-exposure", status: debugMarkers.length ? "failed" : "passed", detail: "Debug response markers were inspected.", markers: debugMarkers },
    { check_id: "unexpected-routes", status: highRouteCount ? "failed" : exposedRoutes.length ? "warning" : "passed", detail: "Debug, docs, metrics, and actuator route posture inspected.", exposed_routes: exposedRoutes.map((probe) => ({ path: probe.path, status_code: probe.status_code })) },
    { check_id: "unexpected-ports", status: "planned", detail: "No blind port scan is performed by the sandbox runner." },
  ];
  fs.writeFileSync(outPath, JSON.stringify({
    schema_version: SCHEMA_VERSION,
    phase: "3C",
    mode: "sandbox-container",
    status,
    summary: { status, probe_count: probes.length, missing_security_header_count: missing.length, debug_marker_count: debugMarkers.length, unexpected_route_count: exposedRoutes.length },
    checks,
    probes,
    guardrails: ["HTTP GET probes only", "No blind port scan", "Runs inside disposable runtime worker"],
  }, null, 2));
}

function blocked(message) {
  return { schema_version: SCHEMA_VERSION, phase: "3C", mode: "sandbox-container", status: "blocked", summary: { status: "blocked", reason: message }, checks: [], probes: [] };
}

main().catch((err) => {
  fs.writeFileSync(process.argv[3], JSON.stringify(blocked(String(err.message || err).slice(0, 300)), null, 2));
  process.exitCode = 0;
});
'''.replace('__SMOKE_SCHEMA_VERSION__', SMOKE_SCHEMA_VERSION)


def runtime_worker_warnings(provider: str, network_policy: str) -> list[str]:
    warnings: list[str] = []
    if provider == 'container' and network_policy == 'scanner-only':
        warnings.append('Generic Docker cannot enforce scanner-only egress by itself; use a controlled proxy or firewall for strict scanner-only networking.')
    if provider == 'manual':
        warnings.append('Manual provider records policy and commands only; the operator must enforce isolation outside this app.')
    return warnings


def docker_network_mode(policy: str) -> str:
    return 'none' if policy == 'offline' else 'bridge'


def docker_env_args(env: dict[str, Any]) -> str:
    if not env:
        return ''
    return ' '.join(f'-e {safe_env_name(key)}={ps(str(value))}' for key, value in sorted(env.items()))


def shell_step(command: str) -> str:
    return f'sh -lc {shell_quote(command)} >> "$LOG" 2>&1'


def shell_quote(value: str) -> str:
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def ps_command_array(commands: list[str]) -> str:
    return ', '.join('"' + ps(command) + '"' for command in commands)


def safe_env_name(value: str) -> str:
    name = re.sub(r'[^A-Za-z0-9_]+', '_', str(value or '').strip()).strip('_')
    return name.upper() or 'SECURE_REVIEW_VALUE'


def job_card(manifest: dict[str, Any]) -> dict[str, Any]:
    profile = manifest.get('selected_profile') or {}
    return {
        'schema_version': manifest.get('schema_version', SCHEMA_VERSION),
        'job_id': manifest.get('job_id'),
        'status': manifest.get('status'),
        'created_at': manifest.get('created_at'),
        'scan_id': manifest.get('scan_id'),
        'project_name': manifest.get('project_name'),
        'provider': manifest.get('provider'),
        'network_policy': manifest.get('network_policy'),
        'runtime': profile.get('runtime', ''),
        'framework': profile.get('framework', ''),
        'profile_id': profile.get('profile_id', ''),
        'job_dir': (manifest.get('host_paths') or {}).get('job_dir', ''),
        'blocker_count': len(manifest.get('blockers') or []),
    }


def runtime_jobs_dir() -> Path:
    return data_dir() / JOB_DIRNAME / 'jobs'


def normalize_choice(value: str, allowed: set[str], fallback: str) -> str:
    normalized = str(value or fallback).strip().lower()
    return normalized if normalized in allowed else fallback


def safe_name(value: str) -> str:
    name = re.sub(r'[^A-Za-z0-9_.-]+', '-', str(value or '').strip())
    return name.strip('-._')[:120] or 'runtime-job'


def sorted_unique(values: list[str]) -> list[str]:
    return sorted({str(value) for value in values if str(value)})


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ps(value: str) -> str:
    return str(value).replace('"', '`"')


def xml(value: str) -> str:
    return escape(str(value), {'"': '&quot;'})


def runtime_worker_guardrails() -> list[str]:
    return [
        'Do not execute repository build, test, or start commands on the host.',
        'Use a disposable container or VM as the execution boundary.',
        'Mount repository sources read-only and copy into sandbox scratch space.',
        'Export only runtime-worker-status.json, runtime-worker.log, and runtime-smoke-posture.json from the sandbox job.',
        'Run Phase 3C health probes only after the runtime process is isolated and started.',
        'Do not run blind port scans from the runtime worker.',
        'Quarantined repositories require explicit approval before job preparation.',
    ]
