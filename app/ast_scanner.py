from __future__ import annotations

import ast
import hashlib
import os
import re
from pathlib import Path

from .ai import explain, suggest_fix
from .models import Finding, Location

SECRET_RE = re.compile(r'(?i)(password|passwd|api[_-]?key|secret|token|client[_-]?secret)')


def run_ast_analysis(target: Path, files: list[Path]) -> tuple[list[Finding], str]:
    findings: list[Finding] = []
    python_files = [path for path in files if path.suffix.lower() == '.py']
    for path in python_files:
        try:
            tree = ast.parse(path.read_text(encoding='utf-8', errors='ignore'), filename=str(path))
        except SyntaxError as exc:
            findings.append(make_finding(target, path, exc.lineno or 1, 'python-ast-syntax-error', 'Python syntax error prevented full AST analysis.', 'LOW', 'MEDIUM', ['CWE-758'], ['A05:2021-Security Misconfiguration']))
            continue
        visitor = PythonSecurityVisitor(target, path)
        visitor.visit(tree)
        findings.extend(visitor.findings)
    return findings, 'ok' if python_files else 'skipped: no Python files'


class PythonSecurityVisitor(ast.NodeVisitor):
    def __init__(self, target: Path, path: Path) -> None:
        self.target = target
        self.path = path
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:
        call_name = dotted_name(node.func)
        if call_name in {'eval', 'exec'}:
            self.add(node, 'python-ast-dynamic-execution', 'AST confirmed dynamic code execution. Replace eval/exec with explicit parsing or dispatch.', 'HIGH', ['CWE-94'], ['A03:2021-Injection'])
        if call_name in {'os.system', 'os.popen'}:
            self.add(node, 'python-ast-os-command', 'AST confirmed shell command execution through os.system/os.popen.', 'HIGH', ['CWE-78'], ['A03:2021-Injection'])
        if call_name.startswith('subprocess.') and has_shell_true(node):
            self.add(node, 'python-ast-subprocess-shell-true', 'AST confirmed subprocess call with shell=True.', 'HIGH', ['CWE-78'], ['A03:2021-Injection'])
        if call_name.endswith('.run') and has_keyword_true(node, 'debug'):
            self.add(node, 'python-ast-debug-enabled', 'AST confirmed debug=True in an application runner.', 'MEDIUM', ['CWE-489'], ['A05:2021-Security Misconfiguration'])
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if is_secret_assignment(node):
            self.add(node, 'python-ast-hardcoded-secret', 'AST confirmed assignment to a secret-looking variable with a literal value.', 'MEDIUM', ['CWE-798'], ['A07:2021-Identification and Authentication Failures'])
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if is_secret_ann_assignment(node):
            self.add(node, 'python-ast-hardcoded-secret', 'AST confirmed assignment to a secret-looking variable with a literal value.', 'MEDIUM', ['CWE-798'], ['A07:2021-Identification and Authentication Failures'])
        self.generic_visit(node)

    def add(self, node: ast.AST, rule_id: str, message: str, severity: str, cwe: list[str], owasp: list[str]) -> None:
        self.findings.append(make_finding(self.target, self.path, getattr(node, 'lineno', 1), rule_id, message, severity, 'HIGH', cwe, owasp))


def make_finding(target: Path, path: Path, line: int, rule_id: str, message: str, severity: str, confidence: str, cwe: list[str], owasp: list[str]) -> Finding:
    rel = relpath(path, target)
    fingerprint = make_fingerprint('python-ast', rule_id, rel, line, message)
    return Finding(
        id=fingerprint[:16], source='python-ast', rule_id=rule_id, title=title_from_rule(rule_id), severity=severity,
        confidence=confidence, location=Location(path=rel, line=line), message=message, cwe=cwe, owasp=owasp,
        references=[], explanation=explain(rule_id, message, cwe, owasp), fix=suggest_fix(rule_id, message), fingerprint=fingerprint,
    )


def dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f'{base}.{node.attr}' if base else node.attr
    return ''


def has_shell_true(node: ast.Call) -> bool:
    return has_keyword_true(node, 'shell')


def has_keyword_true(node: ast.Call, name: str) -> bool:
    for keyword in node.keywords:
        if keyword.arg == name and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
            return True
    return False


def is_secret_assignment(node: ast.Assign) -> bool:
    if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str) or len(node.value.value) < 8:
        return False
    return any(SECRET_RE.search(target_name(target) or '') for target in node.targets)


def is_secret_ann_assignment(node: ast.AnnAssign) -> bool:
    if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str) or len(node.value.value) < 8:
        return False
    return bool(SECRET_RE.search(target_name(node.target) or ''))


def target_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Tuple):
        return ' '.join(target_name(item) for item in node.elts)
    return ''


def make_fingerprint(source: str, rule_id: str, path: str, line: int, message: str) -> str:
    raw = f'{source}|{rule_id}|{path.replace(os.sep, "/")}|{line}|{message}'
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def title_from_rule(rule_id: str) -> str:
    return rule_id.replace('_', '-').replace('.', '-').split(':')[-1].replace('-', ' ').title()


def relpath(path: Path, target: Path) -> str:
    try:
        return str(path.resolve().relative_to(target.resolve())).replace('\\', '/')
    except Exception:
        return str(path).replace('\\', '/')
