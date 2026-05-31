from __future__ import annotations

import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .consolidation import ensure_consolidated_scan
from .fix_workflow import apply_fix_bundle, build_fix_bundle, fix_apply_enabled
from .models import FixApplyRequest, ScanResult, VerifiedAutofixRequest
from .storage import DATA_DIR

TRUTHY = {'1', 'true', 'yes', 'on'}
REPORT_SCHEMA = 'verified-autofix-v1'
DEFAULT_BRANCH_PREFIX = 'secure-review/autofix'
DEFAULT_TEST_TIMEOUT_SECONDS = 900
MAX_OUTPUT_CHARS = 6000


def verified_autofix_enabled() -> bool:
    return os.getenv('VERIFIED_AUTOFIX_ENABLED', 'false').strip().lower() in TRUTHY


def run_verified_autofix(scan: ScanResult, request: VerifiedAutofixRequest, actor: str = 'system') -> dict[str, Any]:
    selected_ids = prioritized_finding_ids(scan, request.finding_ids, request.limit)
    bundle = build_fix_bundle(
        scan,
        finding_ids=selected_ids,
        limit=request.limit,
        provider=request.provider,
        model=request.model,
        allow_placeholders=request.allow_placeholders,
    )
    apply_preview = apply_fix_bundle(scan, FixApplyRequest(
        finding_ids=selected_ids,
        limit=request.limit,
        provider=request.provider,
        model=request.model,
        dry_run=True,
        approved=True,
        allow_placeholders=request.allow_placeholders,
        create_backups=False,
    ))
    report = base_report(scan, request, actor, selected_ids, bundle, apply_preview)
    target = Path(scan.target_path).resolve()
    test_commands = configured_test_commands(target, request)
    report['verification']['test_commands'] = test_commands

    if request.dry_run:
        report['status'] = 'dry_run' if apply_preview.get('applied') else 'no_eligible_fixes'
        report['gate'] = 'not_run'
        report['guardrails'].append('Dry-run mode did not create a branch, apply files, run tests, push, or open a PR.')
        return report

    blockers = preflight_blockers(request, apply_preview, test_commands)
    git_context = resolve_git_context(target)
    if git_context.get('blocked'):
        blockers.extend(git_context['blocked'])
    report['git'].update({key: value for key, value in git_context.items() if key != 'blocked'})
    if blockers:
        report['status'] = 'blocked'
        report['gate'] = 'blocked'
        report['blocked_reasons'] = blockers
        return report

    branch_name = requested_branch_name(scan, request)
    worktree_path = worktree_dir(scan.scan_id, branch_name)
    report['branch'].update({
        'name': branch_name,
        'base': request.base_branch or git_context['current_branch'],
        'worktree_path': str(worktree_path),
        'source_head': git_context['head_sha'],
    })
    branch_blocker = branch_preflight(git_context['repo_root'], branch_name, worktree_path)
    if branch_blocker:
        report['status'] = 'blocked'
        report['gate'] = 'blocked'
        report['blocked_reasons'] = [branch_blocker]
        return report

    worktree_result = run_git(git_context['repo_root'], ['worktree', 'add', '-b', branch_name, str(worktree_path), git_context['head_sha']])
    report['commands'].append(worktree_result)
    if worktree_result['exit_code'] != 0:
        report['status'] = 'failed'
        report['gate'] = 'worktree_failed'
        report['blocked_reasons'] = ['git worktree creation failed']
        return report

    apply_target = worktree_path / git_context['target_subpath']
    worktree_scan = scan.model_copy(deep=True)
    worktree_scan.target_path = str(apply_target)
    apply_report = apply_fix_bundle(worktree_scan, FixApplyRequest(
        finding_ids=selected_ids,
        limit=request.limit,
        provider=request.provider,
        model=request.model,
        dry_run=False,
        approved=True,
        allow_placeholders=request.allow_placeholders,
        create_backups=False,
    ))
    report['apply'] = apply_report
    if apply_report.get('status') != 'applied' or not apply_report.get('applied'):
        report['status'] = 'no_eligible_fixes'
        report['gate'] = 'apply_failed'
        return report

    tests = run_test_commands(worktree_path, test_commands, request.test_timeout_seconds)
    report['verification']['tests'] = tests
    if any(not item['passed'] for item in tests):
        report['status'] = 'tests_failed'
        report['gate'] = 'failed'
        return report

    changed_paths = [normalize_repo_path(item['path']) for item in apply_report.get('applied', []) if item.get('path')]
    for path in changed_paths:
        add_result = run_git(worktree_path, ['add', '--', path])
        report['commands'].append(add_result)
        if add_result['exit_code'] != 0:
            report['status'] = 'failed'
            report['gate'] = 'stage_failed'
            return report
    if not staged_changes_exist(worktree_path):
        report['status'] = 'no_changes'
        report['gate'] = 'failed'
        return report

    commit_message = request.commit_message or f'Apply Secure Review fixes for {scan.scan_id}'
    commit_result = run_git(worktree_path, ['-c', 'user.name=Secure Review', '-c', 'user.email=secure-review@example.invalid', 'commit', '-m', commit_message])
    report['commands'].append(commit_result)
    if commit_result['exit_code'] != 0:
        report['status'] = 'failed'
        report['gate'] = 'commit_failed'
        return report
    commit_sha = run_git(worktree_path, ['rev-parse', 'HEAD'])
    report['commands'].append(commit_sha)
    report['branch']['commit_sha'] = commit_sha['stdout'].strip() if commit_sha['exit_code'] == 0 else ''

    if request.push_branch or request.publish_pr:
        push_result = run_git(worktree_path, ['push', '-u', request.remote, branch_name], timeout_seconds=300)
        report['commands'].append(push_result)
        report['branch']['pushed'] = push_result['exit_code'] == 0
        if push_result['exit_code'] != 0:
            report['status'] = 'push_failed'
            report['gate'] = 'verified'
            return report

    if request.publish_pr:
        pr_result = open_pull_request(worktree_path, scan, request, branch_name, report)
        report['commands'].append(pr_result)
        report['pull_request']['attempted'] = True
        report['pull_request']['created'] = pr_result['exit_code'] == 0
        report['pull_request']['url'] = extract_url(pr_result['stdout'])
        if pr_result['exit_code'] != 0:
            report['status'] = 'pr_failed'
            report['gate'] = 'verified'
            return report
        report['status'] = 'pr_opened'
        report['gate'] = 'passed'
        return report

    report['status'] = 'verified'
    report['gate'] = 'passed'
    return report


def base_report(scan: ScanResult, request: VerifiedAutofixRequest, actor: str, selected_ids: list[str], bundle: dict[str, Any], apply_preview: dict[str, Any]) -> dict[str, Any]:
    return {
        'schema_version': REPORT_SCHEMA,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'actor': actor,
        'status': 'initialized',
        'gate': 'not_run',
        'dry_run': request.dry_run,
        'blocked_reasons': [],
        'selected_finding_ids': selected_ids,
        'summary': {
            'selected': bundle['summary']['selected'],
            'eligible': bundle['summary']['eligible'],
            'preview_apply_count': len(apply_preview.get('applied', [])),
        },
        'configuration': {
            'provider': request.provider,
            'model': request.model or '',
            'limit': request.limit,
            'allow_placeholders': request.allow_placeholders,
            'verified_autofix_enabled': verified_autofix_enabled(),
            'fix_apply_enabled': fix_apply_enabled(),
            'push_branch': request.push_branch or request.publish_pr,
            'publish_pr': request.publish_pr,
            'remote': request.remote,
        },
        'guardrails': [
            'Real verified autofix requires dry_run=false, approved=true, VERIFIED_AUTOFIX_ENABLED=true, and FIX_APPLY_ENABLED=true.',
            'Fixes are applied in a separate git worktree branch, not in the original checkout.',
            'Only eligible deterministic fix-bundle patches are applied.',
            'A commit is created only after all configured test commands pass.',
            'Branch push and PR creation are optional and happen only after the green test gate.',
        ],
        'bundle': bundle,
        'apply_preview': apply_preview,
        'apply': None,
        'verification': {'test_commands': [], 'tests': []},
        'git': {},
        'branch': {'name': request.branch_name or '', 'base': request.base_branch or '', 'worktree_path': '', 'source_head': '', 'commit_sha': '', 'pushed': False},
        'pull_request': {'attempted': False, 'created': False, 'url': ''},
        'commands': [],
    }


def preflight_blockers(request: VerifiedAutofixRequest, apply_preview: dict[str, Any], test_commands: list[str]) -> list[str]:
    blockers: list[str] = []
    if not request.approved:
        blockers.append('approved=true is required for verified autofix')
    if not verified_autofix_enabled():
        blockers.append('VERIFIED_AUTOFIX_ENABLED=true is required for verified autofix')
    if not fix_apply_enabled():
        blockers.append('FIX_APPLY_ENABLED=true is required for verified autofix')
    if not apply_preview.get('applied'):
        blockers.append('no eligible deterministic fixes are available')
    if not test_commands:
        blockers.append('at least one test command is required or must be auto-detected')
    return blockers


def prioritized_finding_ids(scan: ScanResult, requested: list[str], limit: int) -> list[str]:
    if requested:
        return requested
    scan = ensure_consolidated_scan(scan)
    lookup = {finding.id: finding for finding in scan.findings}
    selected: list[str] = []
    for cluster in scan.consolidated_findings:
        candidates = [cluster.representative_finding_id, *cluster.finding_ids]
        for finding_id in candidates:
            finding = lookup.get(finding_id)
            if finding and finding.decision == 'open' and finding_id not in selected:
                selected.append(finding_id)
                break
        if len(selected) >= max(1, limit):
            return selected
    fallback = [finding.id for finding in sorted(scan.findings, key=lambda item: (-item.risk.score, item.location.path, item.location.line, item.id)) if finding.decision == 'open']
    for finding_id in fallback:
        if finding_id not in selected:
            selected.append(finding_id)
        if len(selected) >= max(1, limit):
            break
    return selected


def configured_test_commands(target: Path, request: VerifiedAutofixRequest) -> list[str]:
    if request.test_commands:
        return [item.strip() for item in request.test_commands if item.strip()]
    env_value = os.getenv('VERIFIED_AUTOFIX_TEST_COMMANDS', '').strip()
    if env_value:
        return [item.strip() for item in re.split(r'[\r\n;]+', env_value) if item.strip()]
    if not request.allow_auto_detect_tests:
        return []
    return detect_test_commands(target)


def detect_test_commands(target: Path) -> list[str]:
    commands: list[str] = []
    package_json = target / 'package.json'
    if package_json.exists():
        try:
            data = json.loads(package_json.read_text(encoding='utf-8'))
            script = str((data.get('scripts') or {}).get('test') or '').strip()
            if script and 'no test specified' not in script.lower():
                commands.append('npm test')
        except Exception:
            pass
    if any((target / name).exists() for name in ('pytest.ini', 'tox.ini', 'setup.cfg', 'pyproject.toml')) or (target / 'tests').exists():
        commands.append('python -m pytest -q')
    if (target / 'go.mod').exists():
        commands.append('go test ./...')
    if (target / 'Cargo.toml').exists():
        commands.append('cargo test')
    if (target / 'pom.xml').exists():
        commands.append('mvn test')
    if any((target / name).exists() for name in ('build.gradle', 'build.gradle.kts', 'settings.gradle')):
        commands.append('gradlew.bat test' if (target / 'gradlew.bat').exists() else 'gradle test')
    composer_json = target / 'composer.json'
    if composer_json.exists():
        try:
            data = json.loads(composer_json.read_text(encoding='utf-8'))
            if (data.get('scripts') or {}).get('test'):
                commands.append('composer test')
        except Exception:
            pass
    return dedupe(commands)


def resolve_git_context(target: Path) -> dict[str, Any]:
    if not target.exists():
        return {'blocked': ['scan target path does not exist']}
    top = run_process(['git', '-C', str(target), 'rev-parse', '--show-toplevel'])
    if top['exit_code'] != 0:
        return {'blocked': ['scan target is not inside a git repository'], 'commands': [top]}
    repo_root = Path(top['stdout'].strip()).resolve()
    try:
        target_subpath = target.resolve().relative_to(repo_root)
    except Exception:
        return {'blocked': ['scan target is outside the git repository root'], 'repo_root': str(repo_root)}
    head = run_git(repo_root, ['rev-parse', 'HEAD'])
    branch = run_git(repo_root, ['rev-parse', '--abbrev-ref', 'HEAD'])
    if head['exit_code'] != 0:
        return {'blocked': ['could not resolve git HEAD'], 'repo_root': str(repo_root)}
    return {
        'blocked': [],
        'repo_root': str(repo_root),
        'target_subpath': str(target_subpath).replace('\\', '/'),
        'head_sha': head['stdout'].strip(),
        'current_branch': branch['stdout'].strip() if branch['exit_code'] == 0 else 'main',
    }


def branch_preflight(repo_root: str, branch_name: str, worktree_path: Path) -> str:
    if worktree_path.exists():
        return 'verified autofix worktree path already exists'
    branch = run_git(Path(repo_root), ['rev-parse', '--verify', f'refs/heads/{branch_name}'])
    if branch['exit_code'] == 0:
        return 'verified autofix branch already exists'
    return ''


def requested_branch_name(scan: ScanResult, request: VerifiedAutofixRequest) -> str:
    raw = request.branch_name or f"{os.getenv('VERIFIED_AUTOFIX_BRANCH_PREFIX', DEFAULT_BRANCH_PREFIX)}-{scan.scan_id[:12]}"
    value = re.sub(r'[^A-Za-z0-9._/-]+', '-', raw).strip('/.-')
    return value or f'{DEFAULT_BRANCH_PREFIX}-{scan.scan_id[:12]}'


def worktree_dir(scan_id: str, branch_name: str) -> Path:
    slug = re.sub(r'[^A-Za-z0-9._-]+', '-', branch_name.replace('/', '__')).strip('-') or 'autofix'
    return DATA_DIR / 'verified-autofix' / scan_id / slug


def run_test_commands(worktree_path: Path, commands: list[str], timeout_seconds: int) -> list[dict[str, Any]]:
    return [run_shell_command(command, worktree_path, timeout_seconds) for command in commands]


def staged_changes_exist(worktree_path: Path) -> bool:
    result = run_git(worktree_path, ['diff', '--cached', '--quiet'])
    return result['exit_code'] == 1


def open_pull_request(worktree_path: Path, scan: ScanResult, request: VerifiedAutofixRequest, branch_name: str, report: dict[str, Any]) -> dict[str, Any]:
    title = request.pr_title or f'Secure Review autofix for {scan.project_name}'
    body = request.pr_body or pr_body(scan, report)
    args = ['gh', 'pr', 'create', '--base', request.base_branch or report['branch']['base'], '--head', branch_name, '--title', title, '--body', body]
    return run_process(args, cwd=worktree_path, timeout_seconds=300)


def pr_body(scan: ScanResult, report: dict[str, Any]) -> str:
    applied = report.get('apply', {}).get('applied', []) if report.get('apply') else []
    tests = report.get('verification', {}).get('tests', [])
    lines = [
        'Secure Review verified autofix',
        '',
        f'- Scan: `{scan.scan_id}`',
        f'- Applied fixes: `{len(applied)}`',
        f"- Test gate: `{report.get('gate')}`",
        '',
        'Tests:',
    ]
    for item in tests:
        lines.append(f"- `{item['command']}` -> exit {item['exit_code']}")
    return '\n'.join(lines)


def run_git(cwd: Path | str, args: list[str], timeout_seconds: int = 120) -> dict[str, Any]:
    return run_process(['git', '-C', str(cwd), *args], timeout_seconds=timeout_seconds)


def run_shell_command(command: str, cwd: Path, timeout_seconds: int) -> dict[str, Any]:
    return run_process(command, cwd=cwd, timeout_seconds=timeout_seconds, shell=True)


def run_process(args: list[str] | str, cwd: Path | None = None, timeout_seconds: int = 120, shell: bool = False) -> dict[str, Any]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            shell=shell,
            timeout=timeout_seconds,
        )
        return {
            'command': args if isinstance(args, str) else ' '.join(args),
            'cwd': str(cwd) if cwd else '',
            'exit_code': completed.returncode,
            'passed': completed.returncode == 0,
            'duration_seconds': round(time.monotonic() - started, 3),
            'stdout': truncate(completed.stdout),
            'stderr': truncate(completed.stderr),
            'timed_out': False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            'command': args if isinstance(args, str) else ' '.join(args),
            'cwd': str(cwd) if cwd else '',
            'exit_code': 124,
            'passed': False,
            'duration_seconds': round(time.monotonic() - started, 3),
            'stdout': truncate(exc.stdout or ''),
            'stderr': truncate(exc.stderr or f'timed out after {timeout_seconds} seconds'),
            'timed_out': True,
        }
    except OSError as exc:
        return {
            'command': args if isinstance(args, str) else ' '.join(args),
            'cwd': str(cwd) if cwd else '',
            'exit_code': 127,
            'passed': False,
            'duration_seconds': round(time.monotonic() - started, 3),
            'stdout': '',
            'stderr': truncate(str(exc)),
            'timed_out': False,
        }


def normalize_repo_path(path: str) -> str:
    return str(path or '').replace('\\', '/').strip()


def extract_url(value: str) -> str:
    match = re.search(r'https?://\S+', value or '')
    return match.group(0) if match else ''


def truncate(value: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    text = str(value or '')
    return text if len(text) <= limit else text[: max(0, limit - 3)] + '...'


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
