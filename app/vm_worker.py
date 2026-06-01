from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from .paths import ROOT, data_dir, output_root
from .quarantine import quarantine_policy

SCHEMA_VERSION = 1
DEFAULT_PROVIDER = 'windows-sandbox'
DEFAULT_NETWORK_POLICY = 'scanner-only'
NETWORK_POLICIES = {'offline', 'scanner-only', 'full'}
PROVIDERS = {'windows-sandbox', 'manual'}
GUEST_PROJECT = Path('C:/secure-review-host/app')
GUEST_REPO_SOURCE = Path('C:/secure-review-host/repo-source')
GUEST_JOB = Path('C:/secure-review-host/job')
GUEST_EXPORTS = Path('C:/secure-review-host/reports')
GUEST_WORK = Path('C:/secure-review-work')
GUEST_REPO_WORK = GUEST_WORK / 'repo'
GUEST_REPORT_WORK = GUEST_WORK / 'reports'
GUEST_OUTPUT_ROOT = GUEST_WORK / 'output'

ALLOWED_EXPORTS = [
    'scan.json',
    'secure-review.sarif',
    'scanner-mesh.json',
    'finding-consolidation.json',
    'prioritization.json',
    'soundness-verdict.json',
    'runtime-plan.json',
    'runtime-build-run-worker.json',
    'runtime-smoke-posture.json',
    'reachability-context.json',
    'dependency-review.json',
    'sonarqube-quality-gate.json',
    'scanner-depth.json',
    'catalog-coverage-map.json',
    'quarantine-policy.json',
    'inline-suppressions.json',
    'sanitized-report.json',
    'rag-memory.json',
    'hermes-orchestration.json',
    'advanced-ai.json',
    'ai-review.json',
    'cyclonedx-sbom.json',
    'spdx-sbom.json',
    'spdx-compliance.json',
    'sbom-policy.json',
    'secret-policy.json',
    'github-pr-review.json',
    'code-host-review.json',
    'sbom-compare.json',
    'secure-review.md',
    'pr-comment.md',
    'compliance.json',
    'fix-proposals.json',
    'remediation-plan.json',
    'issue-plan.json',
    'chat-notification.json',
    'team-learning-dashboard.json',
    'recursive-learning.json',
    'benchmark-gate.json',
    'messaging-gateway.json',
    'governance-evidence.json',
    'fix-bundle.json',
    'fix-apply-dry-run.json',
    'verified-autofix-dry-run.json',
    'inside-out-autofix-loop-dry-run.json',
    'vm-worker-status.json',
    'vm-worker.log',
]


def vm_worker_status() -> dict[str, Any]:
    sandbox_exe = shutil.which('WindowsSandbox.exe') or str(Path(os.getenv('SystemRoot', 'C:/Windows')) / 'System32' / 'WindowsSandbox.exe')
    sandbox_available = Path(sandbox_exe).exists() if sandbox_exe else False
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now_iso(),
        'providers': {
            'windows-sandbox': {
                'available': sandbox_available,
                'executable': sandbox_exe if sandbox_available else '',
                'launches_disposable_desktop': True,
                'supports_offline_networking': True,
                'supports_scanner_only_networking': False,
            },
            'manual': {
                'available': True,
                'executable': '',
                'launches_disposable_desktop': False,
                'supports_offline_networking': False,
                'supports_scanner_only_networking': False,
            },
        },
        'guardrails': worker_guardrails(),
        'allowed_exports': ALLOWED_EXPORTS,
    }


def create_vm_scan_job(
    repository_path: str,
    repository_url: str | None = None,
    project_name: str | None = None,
    sonar_project_key: str | None = None,
    sonar_branch_name: str | None = None,
    output_root_path: str | None = None,
    reports_dir: str | None = None,
    run_id: str | None = None,
    provider: str = DEFAULT_PROVIDER,
    network_policy: str = DEFAULT_NETWORK_POLICY,
    approved_quarantine: bool = False,
    copy_git_history: bool = True,
    job_name: str | None = None,
) -> dict[str, Any]:
    provider = normalize_choice(provider, PROVIDERS, DEFAULT_PROVIDER)
    network_policy = normalize_choice(network_policy, NETWORK_POLICIES, DEFAULT_NETWORK_POLICY)
    repo = Path(repository_path).expanduser().resolve()
    if not repo.exists():
        raise ValueError(f'repository path not found: {repo}')
    repo_identity = repository_url or str(repo)
    policy = quarantine_policy(repo_identity, project_name=project_name or repo.name)
    if policy.get('matched') and not approved_quarantine:
        raise ValueError('repository is quarantined; set approved_quarantine=true to prepare a disposable-VM report-only job')

    run = run_id or datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    job_id = safe_name(job_name or f'{repo.name}-{run}-{uuid.uuid4().hex[:8]}')
    jobs_root = data_dir() / 'vm-worker' / 'jobs'
    job_dir = jobs_root / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    output = Path(output_root_path).expanduser().resolve() if output_root_path else (output_root() or Path('D:/secure-review')).resolve()
    report_root = resolve_reports_dir(output, reports_dir)
    report_dir = report_root / safe_name(repo.name) / run
    report_dir.mkdir(parents=True, exist_ok=True)

    manifest = build_manifest(
        job_id=job_id,
        job_dir=job_dir,
        repo=repo,
        repository_url=repository_url,
        project_name=project_name or repo.name,
        sonar_project_key=sonar_project_key or '',
        sonar_branch_name=sonar_branch_name or '',
        output_root_path=output,
        report_root=report_root,
        report_dir=report_dir,
        run_id=run,
        provider=provider,
        network_policy=network_policy,
        copy_git_history=copy_git_history,
        quarantine=policy,
    )
    write_job_files(job_dir, manifest)
    return load_job(job_id)


def load_job(job_id: str) -> dict[str, Any]:
    path = data_dir() / 'vm-worker' / 'jobs' / safe_name(job_id) / 'manifest.json'
    if not path.exists():
        raise FileNotFoundError(job_id)
    return json.loads(path.read_text(encoding='utf-8'))


def list_jobs(limit: int = 50) -> list[dict[str, Any]]:
    jobs_root = data_dir() / 'vm-worker' / 'jobs'
    if not jobs_root.exists():
        return []
    manifests = sorted(jobs_root.glob('*/manifest.json'), key=lambda item: item.stat().st_mtime, reverse=True)
    jobs: list[dict[str, Any]] = []
    for manifest_path in manifests[: max(1, min(limit, 500))]:
        try:
            jobs.append(json.loads(manifest_path.read_text(encoding='utf-8')))
        except Exception:
            continue
    return jobs


def build_manifest(
    *,
    job_id: str,
    job_dir: Path,
    repo: Path,
    repository_url: str | None,
    project_name: str,
    sonar_project_key: str,
    sonar_branch_name: str,
    output_root_path: Path,
    report_root: Path,
    report_dir: Path,
    run_id: str,
    provider: str,
    network_policy: str,
    copy_git_history: bool,
    quarantine: dict[str, Any],
) -> dict[str, Any]:
    artifacts = [{'name': name, 'guest_path': str(GUEST_REPORT_WORK / name), 'host_path': str(report_dir / name)} for name in ALLOWED_EXPORTS]
    launch_path = job_dir / 'launch.ps1'
    sandbox_path = job_dir / 'job.wsb'
    guest_runner_path = job_dir / 'guest-run-scan.ps1'
    manifest_path = job_dir / 'manifest.json'
    return {
        'schema_version': SCHEMA_VERSION,
        'job_id': job_id,
        'status': 'prepared',
        'created_at': now_iso(),
        'provider': provider,
        'network_policy': network_policy,
        'run_id': run_id,
        'repository': {
            'path': str(repo),
            'url': repository_url or '',
            'project_name': project_name,
            'copy_git_history': copy_git_history,
        },
        'sonar': {
            'project_key': sonar_project_key,
            'branch_name': sonar_branch_name,
        },
        'host_paths': {
            'project_root': str(ROOT),
            'repository_source': str(repo),
            'job_dir': str(job_dir),
            'output_root': str(output_root_path),
            'report_root': str(report_root),
            'report_dir': str(report_dir),
        },
        'guest_paths': {
            'project_root': str(GUEST_PROJECT),
            'repository_source': str(GUEST_REPO_SOURCE),
            'job_dir': str(GUEST_JOB),
            'work_root': str(GUEST_WORK),
            'repository_work': str(GUEST_REPO_WORK),
            'report_work': str(GUEST_REPORT_WORK),
            'output_root': str(GUEST_OUTPUT_ROOT),
            'export_dir': str(GUEST_EXPORTS),
        },
        'files': {
            'manifest': str(manifest_path),
            'guest_runner': str(guest_runner_path),
            'sandbox_config': str(sandbox_path),
            'launcher': str(launch_path),
        },
        'allowed_exports': artifacts,
        'quarantine_policy': quarantine,
        'safety_controls': {
            'host_execution': False,
            'raw_repo_is_readonly_mount': True,
            'scan_runs_inside_guest': True,
            'export_whitelist_only': True,
            'destroy_guest_after_scan': True,
            'agent_learning_allowed': bool(quarantine.get('controls', {}).get('agent_learning', True)),
            'requires_user_approval_for_quarantined_repo': bool(quarantine.get('matched')),
        },
        'workflow': [
            'Launch the sandbox/VM from the generated job file.',
            'The guest copies the read-only repository mount into an isolated scratch path.',
            'The guest runs scan.ps1 against the scratch copy.',
            'The guest copies only whitelisted report artifacts to the host report directory.',
            'Close or destroy the guest VM to discard scratch state.',
        ],
        'guardrails': worker_guardrails(),
    }


def write_job_files(job_dir: Path, manifest: dict[str, Any]) -> None:
    (job_dir / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    (job_dir / 'guest-run-scan.ps1').write_text(guest_runner_script(manifest), encoding='utf-8')
    (job_dir / 'job.wsb').write_text(windows_sandbox_config(manifest), encoding='utf-8')
    (job_dir / 'launch.ps1').write_text(launch_script(manifest), encoding='utf-8')


def guest_runner_script(manifest: dict[str, Any]) -> str:
    args = scan_arguments(manifest)
    artifact_array = ', '.join("'" + item['name'].replace("'", "''") + "'" for item in manifest['allowed_exports'])
    git_exclude = '' if manifest['repository'].get('copy_git_history') else '/XD .git'
    return f"""$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ManifestPath = "{ps(str(GUEST_JOB / 'manifest.json'))}"
$Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$StatusPath = Join-Path "{ps(str(GUEST_JOB))}" "status.json"
$LogPath = Join-Path "{ps(str(GUEST_JOB))}" "guest-run.log"
$AllowedArtifacts = @({artifact_array})

function Write-JobStatus {{
  param([string]$Status, [string]$Message = "", [int]$ExitCode = 0)
  [pscustomobject]@{{
    status = $Status
    message = $Message
    exit_code = $ExitCode
    updated_at = (Get-Date).ToUniversalTime().ToString("o")
    job_id = $Manifest.job_id
  }} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StatusPath -Encoding UTF8
}}

try {{
  Write-JobStatus -Status "running" -Message "Preparing scratch workspace."
  New-Item -ItemType Directory -Force -Path "{ps(str(GUEST_WORK))}", "{ps(str(GUEST_REPO_WORK))}", "{ps(str(GUEST_REPORT_WORK))}", "{ps(str(GUEST_OUTPUT_ROOT))}" | Out-Null
  $env:SECURE_REVIEW_OUTPUT_ROOT = "{ps(str(GUEST_OUTPUT_ROOT))}"
  $env:SECURE_REVIEW_DATA_DIR = Join-Path "{ps(str(GUEST_OUTPUT_ROOT))}" "data"
  $env:REPORT_BUNDLE_DIR = Join-Path "{ps(str(GUEST_OUTPUT_ROOT))}" "reports"
  $env:PYTHONDONTWRITEBYTECODE = "1"
  $env:TEMP = Join-Path "{ps(str(GUEST_OUTPUT_ROOT))}" "cache\\temp"
  $env:TMP = $env:TEMP
  $env:SONAR_USER_HOME = Join-Path "{ps(str(GUEST_OUTPUT_ROOT))}" "cache\\sonar"
  New-Item -ItemType Directory -Force -Path $env:TEMP, $env:SONAR_USER_HOME | Out-Null

  robocopy "{ps(str(GUEST_REPO_SOURCE))}" "{ps(str(GUEST_REPO_WORK))}" /MIR /R:1 /W:1 {git_exclude} /NFL /NDL /NP | Out-Null
  if ($LASTEXITCODE -gt 7) {{
    throw "robocopy failed with exit code $LASTEXITCODE"
  }}

  Write-JobStatus -Status "running" -Message "Running secure review scan inside disposable guest."
  Push-Location "{ps(str(GUEST_PROJECT))}"
  try {{
    & ".\\scan.ps1" {args} *> $LogPath
    $scanExit = $LASTEXITCODE
  }} finally {{
    Pop-Location
  }}

  New-Item -ItemType Directory -Force -Path "{ps(str(GUEST_EXPORTS))}" | Out-Null
  foreach ($artifact in $AllowedArtifacts) {{
    $source = Join-Path "{ps(str(GUEST_REPORT_WORK))}" $artifact
    if (Test-Path -LiteralPath $source) {{
      Copy-Item -LiteralPath $source -Destination (Join-Path "{ps(str(GUEST_EXPORTS))}" $artifact) -Force
    }}
  }}

  if ($scanExit -eq 0) {{
    Write-JobStatus -Status "completed" -Message "Scan completed and whitelisted artifacts exported." -ExitCode 0
  }} else {{
    Write-JobStatus -Status "failed" -Message "Scan failed inside guest. See vm-worker.log." -ExitCode $scanExit
  }}
  Copy-Item -LiteralPath $StatusPath -Destination (Join-Path "{ps(str(GUEST_EXPORTS))}" "vm-worker-status.json") -Force -ErrorAction SilentlyContinue
  Copy-Item -LiteralPath $LogPath -Destination (Join-Path "{ps(str(GUEST_EXPORTS))}" "vm-worker.log") -Force -ErrorAction SilentlyContinue
  if ($scanExit -ne 0) {{
    exit $scanExit
  }}
}} catch {{
  Write-JobStatus -Status "failed" -Message $_.Exception.Message -ExitCode 1
  throw
}}
"""


def scan_arguments(manifest: dict[str, Any]) -> str:
    args = [
        '-Path', str(GUEST_REPO_WORK),
        '-JsonOut', str(GUEST_REPORT_WORK / 'scan.json'),
        '-SarifOut', str(GUEST_REPORT_WORK / 'secure-review.sarif'),
        '-ScannerMeshOut', str(GUEST_REPORT_WORK / 'scanner-mesh.json'),
        '-ConsolidatedFindingsOut', str(GUEST_REPORT_WORK / 'finding-consolidation.json'),
        '-PrioritizationOut', str(GUEST_REPORT_WORK / 'prioritization.json'),
        '-SoundnessOut', str(GUEST_REPORT_WORK / 'soundness-verdict.json'),
        '-RuntimePlanOut', str(GUEST_REPORT_WORK / 'runtime-plan.json'),
        '-RuntimeBuildRunPreviewOut', str(GUEST_REPORT_WORK / 'runtime-build-run-worker.json'),
        '-RuntimeSmokePostureOut', str(GUEST_REPORT_WORK / 'runtime-smoke-posture.json'),
        '-ReachabilityContextOut', str(GUEST_REPORT_WORK / 'reachability-context.json'),
        '-DependencyReviewOut', str(GUEST_REPORT_WORK / 'dependency-review.json'),
        '-SonarQubeOut', str(GUEST_REPORT_WORK / 'sonarqube-quality-gate.json'),
        '-ScannerDepthOut', str(GUEST_REPORT_WORK / 'scanner-depth.json'),
        '-CatalogCoverageOut', str(GUEST_REPORT_WORK / 'catalog-coverage-map.json'),
        '-QuarantinePolicyOut', str(GUEST_REPORT_WORK / 'quarantine-policy.json'),
        '-SuppressionsOut', str(GUEST_REPORT_WORK / 'inline-suppressions.json'),
        '-SanitizedReportOut', str(GUEST_REPORT_WORK / 'sanitized-report.json'),
        '-RagMemoryOut', str(GUEST_REPORT_WORK / 'rag-memory.json'),
        '-HermesOut', str(GUEST_REPORT_WORK / 'hermes-orchestration.json'),
        '-AdvancedAiOut', str(GUEST_REPORT_WORK / 'advanced-ai.json'),
        '-AiReviewOut', str(GUEST_REPORT_WORK / 'ai-review.json'),
        '-CycloneDxOut', str(GUEST_REPORT_WORK / 'cyclonedx-sbom.json'),
        '-SpdxOut', str(GUEST_REPORT_WORK / 'spdx-sbom.json'),
        '-SpdxComplianceOut', str(GUEST_REPORT_WORK / 'spdx-compliance.json'),
        '-SbomPolicyOut', str(GUEST_REPORT_WORK / 'sbom-policy.json'),
        '-SecretPolicyOut', str(GUEST_REPORT_WORK / 'secret-policy.json'),
        '-GitHubPrReviewOut', str(GUEST_REPORT_WORK / 'github-pr-review.json'),
        '-CodeHostReviewOut', str(GUEST_REPORT_WORK / 'code-host-review.json'),
        '-SbomCompareOut', str(GUEST_REPORT_WORK / 'sbom-compare.json'),
        '-ReportOut', str(GUEST_REPORT_WORK / 'secure-review.md'),
        '-PrCommentOut', str(GUEST_REPORT_WORK / 'pr-comment.md'),
        '-ComplianceOut', str(GUEST_REPORT_WORK / 'compliance.json'),
        '-FixProposalsOut', str(GUEST_REPORT_WORK / 'fix-proposals.json'),
        '-RemediationPlanOut', str(GUEST_REPORT_WORK / 'remediation-plan.json'),
        '-IssuePlanOut', str(GUEST_REPORT_WORK / 'issue-plan.json'),
        '-ChatNotificationOut', str(GUEST_REPORT_WORK / 'chat-notification.json'),
        '-TeamLearningOut', str(GUEST_REPORT_WORK / 'team-learning-dashboard.json'),
        '-RecursiveLearningOut', str(GUEST_REPORT_WORK / 'recursive-learning.json'),
        '-BenchmarkGateOut', str(GUEST_REPORT_WORK / 'benchmark-gate.json'),
        '-MessagingGatewayOut', str(GUEST_REPORT_WORK / 'messaging-gateway.json'),
        '-GovernanceOut', str(GUEST_REPORT_WORK / 'governance-evidence.json'),
        '-FixBundleOut', str(GUEST_REPORT_WORK / 'fix-bundle.json'),
        '-FixApplyOut', str(GUEST_REPORT_WORK / 'fix-apply-dry-run.json'),
        '-VerifiedAutofixOut', str(GUEST_REPORT_WORK / 'verified-autofix-dry-run.json'),
        '-InsideOutAutofixLoopOut', str(GUEST_REPORT_WORK / 'inside-out-autofix-loop-dry-run.json'),
    ]
    sonar = manifest.get('sonar', {})
    if sonar.get('project_key'):
        args.extend(['-SonarProjectKey', str(sonar['project_key'])])
    if sonar.get('branch_name'):
        args.extend(['-SonarBranchName', str(sonar['branch_name'])])
    return ' '.join(ps_arg(item) for item in args)


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
      <HostFolder>{xml(manifest['host_paths']['project_root'])}</HostFolder>
      <SandboxFolder>{xml(str(GUEST_PROJECT))}</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
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
    <MappedFolder>
      <HostFolder>{xml(manifest['host_paths']['report_dir'])}</HostFolder>
      <SandboxFolder>{xml(str(GUEST_EXPORTS))}</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{xml(str(GUEST_JOB / 'guest-run-scan.ps1'))}"</Command>
  </LogonCommand>
</Configuration>
"""


def launch_script(manifest: dict[str, Any]) -> str:
    return f"""$ErrorActionPreference = "Stop"
$SandboxConfig = "{ps(manifest['files']['sandbox_config'])}"
if (-not (Test-Path -LiteralPath $SandboxConfig)) {{
  throw "Sandbox config not found: $SandboxConfig"
}}
$SandboxExe = (Get-Command WindowsSandbox.exe -ErrorAction SilentlyContinue).Source
if (-not $SandboxExe) {{
  $SandboxExe = Join-Path $env:SystemRoot "System32\\WindowsSandbox.exe"
}}
if (-not (Test-Path -LiteralPath $SandboxExe)) {{
  throw "Windows Sandbox is not available on this machine."
}}
Start-Process -FilePath $SandboxExe -ArgumentList $SandboxConfig
Write-Host "Disposable VM job launched: {manifest['job_id']}"
Write-Host "Close the sandbox window after completion to discard guest state."
Write-Host "Host report directory: {ps(manifest['host_paths']['report_dir'])}"
"""


def resolve_reports_dir(output: Path, reports_dir: str | None) -> Path:
    if reports_dir:
        candidate = Path(reports_dir).expanduser()
        return candidate.resolve() if candidate.is_absolute() else (output / reports_dir.strip('.\\/')).resolve()
    return (output / 'reports').resolve()


def normalize_choice(value: str, allowed: set[str], fallback: str) -> str:
    normalized = str(value or fallback).strip().lower()
    return normalized if normalized in allowed else fallback


def safe_name(value: str) -> str:
    name = re.sub(r'[^A-Za-z0-9_.-]+', '-', str(value or '').strip())
    return name.strip('-._')[:120] or 'vm-scan-job'


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ps(value: str) -> str:
    return value.replace("'", "''")


def ps_arg(value: str) -> str:
    text = str(value)
    if not text or re.search(r'\s|["\']', text):
        return "'" + ps(text) + "'"
    return text


def xml(value: str) -> str:
    return escape(str(value), {'"': '&quot;'})


def worker_guardrails() -> list[str]:
    return [
        'Do not execute untrusted repository code on the host.',
        'Mount repository sources read-only in the guest.',
        'Copy the repository into guest scratch space before scanning.',
        'Export only whitelisted reports, SARIF, SBOM, policy, and learning artifacts.',
        'Close or destroy the VM after each job to discard scratch state.',
        'Quarantined repositories require explicit approval before preparing a disposable-VM job.',
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Prepare disposable VM scan jobs')
    sub = parser.add_subparsers(dest='command')

    status = sub.add_parser('status')
    status.add_argument('--json-out')

    prepare = sub.add_parser('prepare')
    prepare.add_argument('--repo-path', required=True)
    prepare.add_argument('--repo-url')
    prepare.add_argument('--project-name')
    prepare.add_argument('--sonar-project-key')
    prepare.add_argument('--sonar-branch-name')
    prepare.add_argument('--output-root')
    prepare.add_argument('--reports-dir')
    prepare.add_argument('--run-id')
    prepare.add_argument('--provider', default=DEFAULT_PROVIDER, choices=sorted(PROVIDERS))
    prepare.add_argument('--network-policy', default=DEFAULT_NETWORK_POLICY, choices=sorted(NETWORK_POLICIES))
    prepare.add_argument('--approved-quarantine', action='store_true')
    prepare.add_argument('--no-git-history', action='store_true')
    prepare.add_argument('--job-name')
    prepare.add_argument('--json-out')

    args = parser.parse_args(argv)
    if args.command == 'status':
        payload = vm_worker_status()
    elif args.command == 'prepare':
        try:
            payload = create_vm_scan_job(
                repository_path=args.repo_path,
                repository_url=args.repo_url,
                project_name=args.project_name,
                sonar_project_key=args.sonar_project_key,
                sonar_branch_name=args.sonar_branch_name,
                output_root_path=args.output_root,
                reports_dir=args.reports_dir,
                run_id=args.run_id,
                provider=args.provider,
                network_policy=args.network_policy,
                approved_quarantine=args.approved_quarantine,
                copy_git_history=not args.no_git_history,
                job_name=args.job_name,
            )
        except ValueError as exc:
            print(str(exc))
            return 2
    else:
        parser.print_help()
        return 2

    text = json.dumps(payload, indent=2)
    if getattr(args, 'json_out', None):
        Path(args.json_out).write_text(text, encoding='utf-8')
    print(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
