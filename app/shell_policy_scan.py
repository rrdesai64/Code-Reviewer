"""Native shell policy scanner for catalog rules that external linters miss.

ShellCheck is excellent for unsafe constructs that are present in a script. This
module covers absence/control-flow policies from the catalog, such as missing
strict mode and pipelines whose upstream failures are masked without pipefail.
"""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Iterable

from . import catalog_knowledge as kb
from .models import Finding, Location

SHELL_EXTENSIONS = {".sh", ".bash", ".bats", ".ksh", ".zsh"}
SHELL_RULE_IDS = ("SH-002", "SH-006")
MAX_PIPELINE_FINDINGS = 25


def scanner_disabled(env_name: str) -> bool:
    return os.getenv(env_name, "").lower() in {"0", "false", "no", "off", "disabled"}


def run_shell_policy_scan(target: Path, files: Iterable[Path]) -> tuple[list[Finding], str]:
    if scanner_disabled("SHELL_POLICY_ENABLED"):
        return [], "disabled by SHELL_POLICY_ENABLED=false"
    if not kb.available():
        return [], "skipped: catalog unavailable (PyYAML missing or file not found)"
    rules = {rule_id: kb.get_rule(rule_id) for rule_id in SHELL_RULE_IDS}
    rules = {rule_id: rule for rule_id, rule in rules.items() if rule is not None}
    if not rules:
        return [], "skipped: no shell policy rules in catalog"

    shell_files = [path for path in files if path.suffix.lower() in SHELL_EXTENSIONS]
    if not shell_files:
        return [], "skipped: no shell files"

    findings: list[Finding] = []
    for path in shell_files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(scan_shell_text(text, path, target, rules))
    return findings, f"ok: {len(shell_files)} files, {len(rules)} shell policy rules, findings={len(findings)}"


def scan_shell_text(text: str, path: Path, target: Path, rules: dict[str, dict]) -> list[Finding]:
    rel_path = relpath(path, target)
    lines = text.splitlines()
    findings: list[Finding] = []
    strict = strict_mode_state(lines)
    pipefail_enabled = strict["pipefail"]

    if "SH-002" in rules and not strict["complete"] and not disabled(text, "SH-002"):
        missing = ", ".join(name for name, enabled in [
            ("errexit (-e)", strict["errexit"]),
            ("nounset (-u)", strict["nounset"]),
            ("pipefail", strict["pipefail"]),
        ] if not enabled)
        findings.append(build_finding(rules["SH-002"], rel_path, 1, 1, f"script does not enable complete strict mode; missing {missing}."))

    if "SH-006" in rules and not pipefail_enabled and not disabled(text, "SH-006"):
        pipeline_findings = []
        for line_number, line in enumerate(lines, 1):
            column = pipeline_column(line)
            if column:
                pipeline_findings.append(build_finding(rules["SH-006"], rel_path, line_number, column, "pipeline can mask an upstream command failure because pipefail is not enabled."))
                if len(pipeline_findings) >= MAX_PIPELINE_FINDINGS:
                    break
        findings.extend(pipeline_findings)

    return findings


def strict_mode_state(lines: list[str]) -> dict[str, bool]:
    state = {"errexit": False, "nounset": False, "pipefail": False}
    for line in lines:
        code = shell_code_before_comment(line).strip()
        if not code:
            continue
        match = re.match(r"^(?:builtin\s+)?set\b(?P<args>.*)$", code)
        if not match:
            continue
        args = match.group("args")
        lower = args.lower()
        if re.search(r"(^|\s)\+e\b", args) or "+o errexit" in lower:
            state["errexit"] = False
        if re.search(r"(^|\s)\+u\b", args) or "+o nounset" in lower:
            state["nounset"] = False
        if "+o pipefail" in lower:
            state["pipefail"] = False
        if has_short_option(args, "e") or "-o errexit" in lower:
            state["errexit"] = True
        if has_short_option(args, "u") or "-o nounset" in lower:
            state["nounset"] = True
        if "-o pipefail" in lower or re.search(r"(^|\s)pipefail(\s|$)", lower):
            state["pipefail"] = True
    state["complete"] = state["errexit"] and state["nounset"] and state["pipefail"]
    return state


def has_short_option(args: str, flag: str) -> bool:
    return any(flag in token[1:] for token in re.findall(r"(?<!\S)-[A-Za-z]+", args))


def pipeline_column(line: str) -> int:
    code = shell_code_before_comment(line)
    in_single = False
    in_double = False
    escaped = False
    for index, ch in enumerate(code):
        nxt = code[index + 1] if index + 1 < len(code) else ""
        prev = code[index - 1] if index > 0 else ""
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if in_single:
            if ch == "'":
                in_single = False
            continue
        if in_double:
            if ch == '"':
                in_double = False
            continue
        if ch == "'":
            in_single = True
            continue
        if ch == '"':
            in_double = True
            continue
        if ch == "|" and nxt != "|" and prev != "|":
            return index + 1
    return 0


def shell_code_before_comment(line: str) -> str:
    in_single = False
    in_double = False
    escaped = False
    for index, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if in_single:
            if ch == "'":
                in_single = False
            continue
        if in_double:
            if ch == '"':
                in_double = False
            continue
        if ch == "'":
            in_single = True
            continue
        if ch == '"':
            in_double = True
            continue
        if ch == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def disabled(text: str, rule_id: str) -> bool:
    pattern = re.compile(rf"secure-review:\s*disable\s*=\s*(?:[A-Z0-9,-]+\s*,\s*)*{re.escape(rule_id)}(?:\s*,|\b)", re.IGNORECASE)
    return bool(pattern.search(text))


def build_finding(rule: dict, rel_path: str, line: int, col: int, detail: str) -> Finding:
    rule_id = rule["id"]
    message = f"{rule['name']}: {detail}"
    cwe = [f"CWE-{item}" for item in (rule.get("cwe") or [])]
    owasp = [rule["owasp"]] if rule.get("owasp") else []
    fingerprint = make_fingerprint("shell-policy", rule_id, rel_path, line, detail)
    severity = str(rule.get("severity") or "info").upper()
    return Finding(
        id=fingerprint[:16],
        source="shell-policy",
        rule_id=rule_id,
        title=rule["name"],
        severity=severity if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} else "INFO",
        confidence="MEDIUM",
        location=Location(path=rel_path, line=line, column=col),
        message=message,
        cwe=cwe,
        owasp=owasp,
        references=[],
        explanation=kb.build_explanation(rule, cwe, owasp) or message,
        fix=kb.build_fix(rule),
        fingerprint=fingerprint,
        scanner_metadata={"engine": "shell-policy", "catalog_rule_id": rule_id},
    )


def make_fingerprint(source: str, rule_id: str, path: str, line: int, message: str) -> str:
    raw = f'{source}|{rule_id}|{path.replace(os.sep, "/")}|{line}|{message}'
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def relpath(path: Path, target: Path) -> str:
    try:
        return str(path.resolve().relative_to(target.resolve())).replace("\\", "/")
    except Exception:
        return str(path).replace("\\", "/")
