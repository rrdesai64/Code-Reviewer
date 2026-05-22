from __future__ import annotations

import difflib
import re
from pathlib import Path

from .llm import generate
from .memory import repository_context
from .models import Finding, FixProposal, LLMRequest, RemediationPlan, RemediationStep, ScanResult, ValidationCheck
from .scope import scope_sort_rank
from .rag import retrieve_for_finding

GUARDRAILS = [
    'Proposals are diffs first; source changes are applied only through the explicit approved fix workflow.',
    'Every proposal requires human review before merge or deployment.',
    'Non-dry-run fix apply requires approved=true and FIX_APPLY_ENABLED=true.',
    'Run the listed validation commands and rerun the security scan after applying a patch.',
    'Rotate exposed credentials instead of relying only on code changes.',
]


def build_fix_proposal(scan: ScanResult, finding_id: str, provider: str = 'offline', model: str | None = None) -> FixProposal:
    finding = next((item for item in scan.findings if item.id == finding_id), None)
    if not finding:
        raise ValueError('finding not found')
    target = Path(scan.target_path)
    source_path = (target / finding.location.path).resolve()
    original = read_lines(source_path)
    patched, summary, notes = deterministic_patch(original, finding)
    patch = make_diff(finding.location.path, original, patched)
    mechanical = bool(patch)
    if not patch:
        notes.append('No safe mechanical edit was generated. The proposal records manual guidance only.')
        patch = manual_patch_stub(finding)
    validation_checks = validate_patch(source_path, finding, patch, original, patched, mechanical=mechanical)
    validation_commands = validation_commands_for(scan, finding)
    context = retrieve_for_finding(finding, limit=4)
    memory_text = repository_context(scan.target_path)
    prompt = (
        'Create a secure refactoring review note for this proposed patch.\n'
        f'Finding: {finding.title}\n'
        f'Rule: {finding.rule_id}\n'
        f'Message: {finding.message}\n'
        f'Priority: {finding.risk.priority} risk score {finding.risk.score}\n'
        f'{memory_text}\n'
        f'Validation commands: {", ".join(validation_commands)}\n'
        f'Patch:\n{patch}\n'
        'Keep it brief and mention validation steps.'
    )
    llm_response = generate(LLMRequest(prompt=prompt, provider=provider, model=model, context=context))
    if llm_response.text:
        notes.append(llm_response.text[:1200])
    return FixProposal(
        finding_id=finding.id,
        scan_id=scan.scan_id,
        title=f'Secure refactor for {finding.title}',
        summary=summary,
        patch=patch,
        safety_notes=dedupe_text([*notes, *GUARDRAILS]),
        priority=finding.risk.priority,
        risk_score=finding.risk.score,
        effort=estimate_effort(finding, mechanical=mechanical),
        confidence='mechanical' if mechanical and not has_blocking_check(validation_checks) else 'manual-review',
        validation_checks=validation_checks,
        validation_commands=validation_commands,
        context_summary={
            'rag_chunks': str(len(context)),
            'rag_sources': ', '.join(sorted({chunk.source for chunk in context})) or 'none',
            'memory_context': 'available' if 'No prior repository memory' not in memory_text else 'not available',
        },
    )


def build_remediation_plan(scan: ScanResult, limit: int = 50) -> RemediationPlan:
    candidates = [finding for finding in scan.findings if finding.decision not in {'false_positive', 'risk_accepted'}]
    candidates = sorted(candidates, key=lambda item: (-scope_sort_rank(item), -item.risk.score, item.location.path, item.location.line))[:limit]
    steps: list[RemediationStep] = []
    commands: list[str] = []
    for finding in candidates:
        finding_commands = validation_commands_for(scan, finding)
        commands.extend(finding_commands)
        steps.append(RemediationStep(
            finding_id=finding.id,
            title=finding.title,
            priority=finding.risk.priority,
            risk_score=finding.risk.score,
            path=finding.location.path,
            line=finding.location.line,
            rule_id=finding.rule_id,
            summary=finding.fix.summary,
            effort=estimate_effort(finding, mechanical=is_mechanically_supported(finding)),
            proposal_endpoint=f'/api/scans/{scan.scan_id}/findings/{finding.id}/fix-proposal',
            validation_commands=finding_commands,
        ))
    p0_steps = sum(1 for step in steps if step.priority == 'P0')
    p1_steps = sum(1 for step in steps if step.priority == 'P1')
    return RemediationPlan(
        scan_id=scan.scan_id,
        project_name=scan.project_name,
        total_steps=len(steps),
        p0_steps=p0_steps,
        p1_steps=p1_steps,
        estimated_effort=plan_effort(steps),
        guardrails=GUARDRAILS,
        validation_commands=dedupe_text(commands),
        steps=steps,
    )


def deterministic_patch(lines: list[str], finding: Finding) -> tuple[list[str], str, list[str]]:
    notes = ['Review the diff before applying it.', 'Run tests and rerun the security scan after applying.']
    patched = list(lines)
    idx = max(finding.location.line - 1, 0)
    current = patched[idx] if idx < len(patched) else ''
    lower = f'{finding.rule_id} {finding.message}'.lower()
    prefix = comment_prefix(finding.location.path)

    if finding.source in {'dependency-manifest', 'pip-audit', 'snyk'} and finding.location.path.endswith('requirements.txt'):
        patched, changed, detail = pin_python_requirement(lines, finding)
        if changed:
            return patched, detail, notes
        if idx < len(patched):
            patched[idx] = patched[idx].rstrip() + '  # TODO: upgrade to the nearest non-vulnerable pinned version\n'
        return patched, 'Upgrade and pin the affected dependency to a non-vulnerable version.', notes
    if 'shell' in lower or 'subprocess' in lower or 'os.system' in lower or 'child_process' in lower:
        if idx < len(patched):
            indent = current[:len(current) - len(current.lstrip())]
            patched[idx] = indent + prefix + ' TODO: Replace shell string execution with argument-list execution and validated inputs.\n'
            patched.insert(idx + 1, safe_execution_example(finding.location.path, indent))
        return patched, 'Replace shell-based process execution with validated argument-list execution.', notes

    if 'eval' in lower or 'exec' in lower or 'dynamic' in lower or 'function constructor' in lower:
        if idx < len(patched):
            indent = current[:len(current) - len(current.lstrip())]
            patched[idx] = indent + prefix + ' TODO: Replace dynamic execution with a parser, schema validation, or dispatch table.\n'
            patched.insert(idx + 1, disabled_dynamic_execution_line(finding.location.path, indent))
        return patched, 'Remove dynamic code execution and replace it with explicit parsing or dispatch.', notes

    if 'secret' in lower or 'password' in lower or 'token' in lower or 'api' in lower:
        if idx < len(patched):
            patched = ensure_secret_import_or_note(patched, finding.location.path)
            if finding.location.path.endswith('.py') and not any(line.startswith('import os') for line in lines[:20]):
                idx += 1
            patched[idx] = replace_secret_literal(patched[idx], finding.location.path)
        return patched, 'Move the hardcoded secret to an environment variable or vault reference.', notes + ['Rotate any secret that may already have been committed.']


    if 'debug' in lower:
        if idx < len(patched):
            patched[idx] = re.sub(r'(?i)(debug\s*[:=]\s*)true', r'\1false', patched[idx])
        return patched, 'Disable debug mode for deployable configurations.', notes

    return patched, finding.fix.summary, notes


def pin_python_requirement(lines: list[str], finding: Finding) -> tuple[list[str], bool, str]:
    package = dependency_package_name(finding)
    fix_version = dependency_fix_version(finding)
    if not package or not fix_version:
        return list(lines), False, 'No scanner-provided fixed version was available.'
    patched = list(lines)
    for index, line in enumerate(patched):
        parsed = parse_requirement_line(line)
        if not parsed or parsed['name'].lower() != package.lower():
            continue
        ending = '\r\n' if line.endswith('\r\n') else '\n'
        comment = parsed['comment']
        requirement_name = parsed['requirement_name'] or package
        patched[index] = f'{requirement_name}=={fix_version}{comment}{ending}'
        return patched, True, f'Upgrade and pin {requirement_name} to {fix_version}.'
    return patched, False, f'Could not find a requirements line for {package}.'


def parse_requirement_line(line: str) -> dict[str, str] | None:
    body = line.rstrip('\r\n')
    clean = body.strip()
    if not clean or clean.startswith(('#', '-')):
        return None
    comment = ''
    if '#' in body:
        body, raw_comment = body.split('#', 1)
        comment = '  #' + raw_comment.rstrip()
    requirement = body.strip()
    if not requirement:
        return None
    requirement_name = requirement
    for operator in ('===', '==', '~=', '>=', '<=', '!=', '>', '<'):
        if operator in requirement:
            requirement_name = requirement.split(operator, 1)[0].strip()
            break
    if ' @ ' in requirement_name:
        requirement_name = requirement_name.split(' @ ', 1)[0].strip()
    name = requirement_name.split('[', 1)[0].strip()
    return {'name': name, 'requirement_name': requirement_name, 'comment': comment}


def dependency_package_name(finding: Finding) -> str:
    metadata = finding.scanner_metadata
    for key in ('dependency_name', 'package', 'name'):
        value = metadata.get(key)
        if value:
            return value.strip()
    title = finding.title.lower().replace('vulnerable dependency:', '').strip()
    return title.split()[0] if title else ''


def dependency_fix_version(finding: Finding) -> str:
    metadata = finding.scanner_metadata
    if metadata.get('best_fix_version'):
        return metadata['best_fix_version'].strip()
    versions = [item.strip() for item in metadata.get('fix_versions', '').split(',') if item.strip()]
    return choose_highest_version(versions)


def choose_highest_version(versions: list[str]) -> str:
    if not versions:
        return ''
    try:
        from packaging.version import Version
        return str(max(versions, key=Version))
    except Exception:
        return versions[-1]

def validate_patch(source_path: Path, finding: Finding, patch: str, original: list[str], patched: list[str], mechanical: bool) -> list[ValidationCheck]:
    checks: list[ValidationCheck] = []
    if source_path.exists() and source_path.is_file():
        checks.append(ValidationCheck(name='target-file', status='passed', detail='Target file exists and is a regular file.'))
    else:
        checks.append(ValidationCheck(name='target-file', status='blocked', detail='Target file was not found; proposal is manual guidance only.'))
    if mechanical:
        expected_from = f'--- a/{finding.location.path}'
        expected_to = f'+++ b/{finding.location.path}'
        status = 'passed' if expected_from in patch and expected_to in patch else 'warning'
        checks.append(ValidationCheck(name='single-file-diff', status=status, detail='Patch is scoped to the finding file.' if status == 'passed' else 'Could not confirm patch file scope from diff headers.'))
    else:
        checks.append(ValidationCheck(name='mechanical-edit', status='manual', detail='No safe mechanical edit was available for this finding class.'))
    changed_lines = sum(1 for line in patch.splitlines() if line.startswith(('+', '-')) and not line.startswith(('+++', '---')))
    checks.append(ValidationCheck(name='patch-size', status='passed' if changed_lines <= 30 else 'warning', detail=f'Patch changes {changed_lines} diff lines.'))
    if 'REPLACE_WITH_SECRET_NAME' in patch or 'TODO' in patch:
        checks.append(ValidationCheck(name='placeholder-review', status='warning', detail='Patch contains placeholders that must be completed by a human.'))
    if original == patched and mechanical:
        checks.append(ValidationCheck(name='diff-produced', status='blocked', detail='Patch was expected but no diff was produced.'))
    return checks


def validation_commands_for(scan: ScanResult, finding: Finding) -> list[str]:
    commands = [f'.\\scan.ps1 -Path "{scan.target_path}"']
    path = finding.location.path.lower()
    if path.endswith('.py'):
        commands.insert(0, f'.\\.venv\\Scripts\\python.exe -m compileall "{scan.target_path}"')
    if path.endswith('requirements.txt') or finding.source == 'pip-audit':
        commands.insert(0, f'.\\.venv\\Scripts\\pip-audit.exe -r "{scan.target_path}\\{finding.location.path}"')
    if path.endswith(('.js', '.jsx', '.ts', '.tsx')):
        commands.insert(0, 'npm test')
    if path.endswith(('dockerfile', '.yml', '.yaml')):
        commands.insert(0, 'Review deployment configuration and rebuild the affected image or manifest.')
    return dedupe_text(commands)


def estimate_effort(finding: Finding, mechanical: bool) -> str:
    if finding.source == 'pip-audit' or 'dependency' in finding.rule_id.lower():
        return 'medium-package-upgrade'
    if finding.risk.priority in {'P0', 'P1'} and not mechanical:
        return 'large-manual-refactor'
    if mechanical:
        return 'small-guided-patch'
    return 'medium-manual-review'


def plan_effort(steps: list[RemediationStep]) -> str:
    weights = {'small-guided-patch': 1, 'medium-package-upgrade': 3, 'medium-manual-review': 3, 'large-manual-refactor': 5}
    total = sum(weights.get(step.effort, 3) for step in steps)
    if total <= 5:
        return 'small'
    if total <= 20:
        return 'medium'
    return 'large'


def is_mechanically_supported(finding: Finding) -> bool:
    lower = f'{finding.rule_id} {finding.message}'.lower()
    return any(token in lower for token in ['shell', 'subprocess', 'os.system', 'child_process', 'eval', 'exec', 'dynamic', 'secret', 'password', 'token', 'api', 'debug']) or finding.source in {'dependency-manifest', 'pip-audit', 'snyk'}


def has_blocking_check(checks: list[ValidationCheck]) -> bool:
    return any(check.status == 'blocked' for check in checks)


def comment_prefix(path: str) -> str:
    lower = path.lower()
    if lower.endswith(('.js', '.jsx', '.ts', '.tsx', '.java', '.go', '.rs', '.cs')):
        return '//'
    return '#'


def safe_execution_example(path: str, indent: str) -> str:
    lower = path.lower()
    if lower.endswith(('.js', '.jsx', '.ts', '.tsx')):
        return indent + '// Example: use child_process.execFile(command, validatedArgs, callback)\n'
    return indent + '# Example: subprocess.run(["safe-command", validated_arg], check=True)\n'


def disabled_dynamic_execution_line(path: str, indent: str) -> str:
    lower = path.lower()
    if lower.endswith(('.js', '.jsx', '.ts', '.tsx')):
        return indent + 'throw new Error("Dynamic code execution disabled; implement a safe parser here");\n'
    return indent + 'raise ValueError("Dynamic code execution disabled; implement a safe parser here")\n'


def ensure_secret_import_or_note(lines: list[str], path: str) -> list[str]:
    if path.endswith('.py') and not any(line.startswith('import os') for line in lines[:20]):
        return ['import os\n', *lines]
    return lines


def replace_secret_literal(line: str, path: str) -> str:
    if path.endswith('.py'):
        return re.sub(r'=\s*[\'\"][^\'\"]+[\'\"]', '= os.environ.get("REPLACE_WITH_SECRET_NAME", "")', line)
    if path.lower().endswith(('.js', '.jsx', '.ts', '.tsx')):
        return re.sub(r'=\s*[\'\"][^\'\"]+[\'\"]', '= process.env.REPLACE_WITH_SECRET_NAME || ""', line)
    return re.sub(r'(:\s*)[\'\"]?[^\'\"\n#]+[\'\"]?', r'\1${REPLACE_WITH_SECRET_NAME}', line)


def read_lines(path: Path) -> list[str]:
    if not path.exists() or not path.is_file():
        return []
    return path.read_text(encoding='utf-8', errors='ignore').splitlines(keepends=True)


def make_diff(path: str, original: list[str], patched: list[str]) -> str:
    if original == patched:
        return ''
    diff = difflib.unified_diff(original, patched, fromfile=f'a/{path}', tofile=f'b/{path}', lineterm='')
    return '\n'.join(line.rstrip('\n') for line in diff) + '\n'


def manual_patch_stub(finding: Finding) -> str:
    prefix = comment_prefix(finding.location.path)
    return '\n'.join([
        f'{prefix} Manual fix proposal for {finding.location.path}:{finding.location.line}',
        f'{prefix} {finding.title}',
        f'{prefix} {finding.fix.summary}',
        *[f'{prefix} - {item}' for item in finding.fix.guidance],
        '',
    ])


def dedupe_text(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        clean = item.strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        result.append(clean)
    return result
