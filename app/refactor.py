from __future__ import annotations

import difflib
import re
from pathlib import Path

from .llm import generate
from .models import Finding, FixProposal, LLMRequest, ScanResult
from .rag import retrieve_for_finding


def build_fix_proposal(scan: ScanResult, finding_id: str, provider: str = 'offline', model: str | None = None) -> FixProposal:
    finding = next((item for item in scan.findings if item.id == finding_id), None)
    if not finding:
        raise ValueError('finding not found')
    target = Path(scan.target_path)
    source_path = (target / finding.location.path).resolve()
    original = read_lines(source_path)
    patched, summary, notes = deterministic_patch(original, finding)
    patch = make_diff(finding.location.path, original, patched)
    if patch == '':
        notes.append('No safe mechanical edit was generated. The proposal records manual guidance only.')
        patch = manual_patch_stub(finding)
    prompt = (
        'Create a secure refactoring review note for this proposed patch.\n'
        f'Finding: {finding.title}\n'
        f'Rule: {finding.rule_id}\n'
        f'Message: {finding.message}\n'
        f'Patch:\n{patch}\n'
        'Keep it brief and mention validation steps.'
    )
    context = retrieve_for_finding(finding, limit=4)
    llm_response = generate(LLMRequest(prompt=prompt, provider=provider, model=model, context=context))
    if llm_response.text:
        notes.append(llm_response.text[:1200])
    return FixProposal(
        finding_id=finding.id,
        scan_id=scan.scan_id,
        title=f'Secure refactor for {finding.title}',
        summary=summary,
        patch=patch,
        safety_notes=notes,
    )


def deterministic_patch(lines: list[str], finding: Finding) -> tuple[list[str], str, list[str]]:
    notes = ['Review the diff before applying it.', 'Run tests and rerun the security scan after applying.']
    patched = list(lines)
    idx = max(finding.location.line - 1, 0)
    current = patched[idx] if idx < len(patched) else ''
    lower = f'{finding.rule_id} {finding.message}'.lower()

    if 'shell' in lower or 'subprocess' in lower or 'os.system' in lower:
        if idx < len(patched):
            indent = current[:len(current) - len(current.lstrip())]
            patched[idx] = indent + '# TODO: Replace shell string execution with an argument list and validated inputs.\n'
            patched.insert(idx + 1, indent + '# Example: subprocess.run(["safe-command", validated_arg], check=True)\n')
        return patched, 'Replace shell-based process execution with validated argument-list execution.', notes

    if 'eval' in lower or 'exec' in lower or 'dynamic' in lower:
        if idx < len(patched):
            indent = current[:len(current) - len(current.lstrip())]
            patched[idx] = indent + '# TODO: Replace dynamic execution with a parser, schema validation, or dispatch table.\n'
            patched.insert(idx + 1, indent + 'raise ValueError("Dynamic code execution disabled; implement a safe parser here")\n')
        return patched, 'Remove dynamic code execution and replace it with explicit parsing or dispatch.', notes

    if 'secret' in lower or 'password' in lower or 'token' in lower or 'api' in lower:
        if idx < len(patched):
            if not any(line.startswith('import os') for line in patched[:20]):
                patched.insert(0, 'import os\n')
                idx += 1
            patched[idx] = re.sub(r'=\s*[\'\"][^\'\"]+[\'\"]', '= os.environ.get("REPLACE_WITH_SECRET_NAME", "")', patched[idx])
        return patched, 'Move the hardcoded secret to an environment variable or vault reference.', notes + ['Rotate any secret that may already have been committed.']

    if finding.source in {'dependency-manifest', 'pip-audit'} and finding.location.path.endswith('requirements.txt'):
        if idx < len(patched):
            patched[idx] = patched[idx].rstrip() + '  # TODO: upgrade to the nearest non-vulnerable pinned version\n'
        return patched, 'Upgrade and pin the affected dependency to a non-vulnerable version.', notes

    return patched, finding.fix.summary, notes


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
    return '\n'.join([
        f'# Manual fix proposal for {finding.location.path}:{finding.location.line}',
        f'# {finding.title}',
        f'# {finding.fix.summary}',
        *[f'# - {item}' for item in finding.fix.guidance],
        '',
    ])
