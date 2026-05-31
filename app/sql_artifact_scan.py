"""Native scanner for standalone SQL artifacts.

This scanner covers `.sql` files such as migrations, stored procedures, and
database scripts. Host-language SQL injection remains the job of Semgrep/CodeQL;
this module exists for raw SQL files that otherwise have no parser-backed review.
"""
from __future__ import annotations

import bisect
import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from . import catalog_knowledge as kb
from .models import Finding, Location

SQL_EXTENSIONS = {".sql"}
SQL_RULE_IDS = ("SQL-001", "SQL-002", "SQL-003", "SQL-004", "SQL-005", "SQL-006", "SQL-007")
MAX_HITS_PER_RULE = 25

SELECT_STAR_RE = re.compile(r"\bselect\s+(?:distinct\s+)?(?:top\s+\(?\d+\)?\s+)?\*\s+\bfrom\b", re.IGNORECASE | re.DOTALL)
MUTATING_START_RE = re.compile(r"^\s*(?:with\b.*?\)\s*)?(update|delete)\b", re.IGNORECASE | re.DOTALL)
DYNAMIC_SQL_CONCAT_RE = re.compile(
    r"(?:\bexec(?:ute)?\b|\bsp_executesql\b|(?:set|select)?\s*@\w+\s*=)?"
    r".*?(?:N)?'(?:[^']|'')*\b(?:select|insert|update|delete|merge)\b(?:[^']|'')*'\s*\+\s*(?:@\w+|:\w+|\w+)"
    r"|(?:@\w+|:\w+|\w+)\s*\+\s*(?:N)?'(?:[^']|'')*\b(?:select|insert|update|delete|merge)\b",
    re.IGNORECASE | re.DOTALL,
)
NULL_EQUALITY_RE = re.compile(r"(?:=|<>|!=)\s*null\b|\bnull\s*(?:=|<>|!=)", re.IGNORECASE)
NON_SARGABLE_RE = re.compile(
    r"\bwhere\b(?:(?!\b(group|order|having|limit|offset|union)\b).)*?"
    r"\b(?:upper|lower|year|month|day|date|convert|cast|coalesce|isnull|substring|substr|trim|ltrim|rtrim)\s*"
    r"\(\s*[A-Za-z_][\w.$\[\]`\"]*\s*(?:,|\))\s*(?:=|<>|!=|<|>|<=|>=|\blike\b|\bin\b|\bbetween\b)",
    re.IGNORECASE | re.DOTALL,
)
WRITE_START_RE = re.compile(r"^\s*(?:insert|update|delete|merge)\b", re.IGNORECASE)
TRANSACTION_RE = re.compile(r"\bbegin\s+(?:transaction|tran)\b|\bcommit\b|\brollback\b", re.IGNORECASE)
IMPLICIT_CROSS_JOIN_RE = re.compile(
    r"\bfrom\s+"
    r"(?:[`\"\[]?[A-Za-z_][\w.$]*[`\"\]]?)(?:\s+(?:as\s+)?[`\"\[]?[A-Za-z_][\w$]*[`\"\]]?)?"
    r"\s*,\s*"
    r"(?:[`\"\[]?[A-Za-z_][\w.$]*[`\"\]]?)",
    re.IGNORECASE | re.DOTALL,
)


@dataclass(frozen=True)
class SqlStatement:
    text: str
    start: int
    end: int


def scanner_disabled(env_name: str) -> bool:
    return os.getenv(env_name, "").lower() in {"0", "false", "no", "off", "disabled"}


def run_sql_artifact_scan(target: Path, files: Iterable[Path]) -> tuple[list[Finding], str]:
    if scanner_disabled("SQL_ARTIFACT_ENABLED"):
        return [], "disabled by SQL_ARTIFACT_ENABLED=false"
    if not kb.available():
        return [], "skipped: catalog unavailable (PyYAML missing or file not found)"
    rules = {rule_id: kb.get_rule(rule_id) for rule_id in SQL_RULE_IDS}
    rules = {rule_id: rule for rule_id, rule in rules.items() if rule is not None}
    if not rules:
        return [], "skipped: no SQL artifact rules in catalog"

    sql_files = [path for path in files if path.suffix.lower() in SQL_EXTENSIONS]
    if not sql_files:
        return [], "skipped: no SQL files"

    findings: list[Finding] = []
    for path in sql_files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(scan_sql_text(text, path, target, rules))
    return findings, f"ok: {len(sql_files)} files, {len(rules)} SQL rules, findings={len(findings)}"


def scan_sql_text(text: str, path: Path, target: Path, rules: dict[str, dict]) -> list[Finding]:
    line_starts = line_start_offsets(text)
    commentless = mask_sql_comments(text)
    structural = mask_sql_strings(commentless)
    statements = split_sql_statements(commentless)
    structural_statements = split_sql_statements(structural)
    rel_path = relpath(path, target)
    findings: list[Finding] = []

    findings.extend(matches_for_rule("SQL-001", rules, rel_path, structural, line_starts, iter_statement_regex(structural_statements, SELECT_STAR_RE), "SELECT * pulls every column from a standalone SQL query."))
    findings.extend(detect_mutation_without_where(rules, rel_path, structural_statements, line_starts))
    findings.extend(matches_for_rule("SQL-003", rules, rel_path, commentless, line_starts, iter_statement_regex(statements, DYNAMIC_SQL_CONCAT_RE), "dynamic SQL string is concatenated with a variable instead of parameterized."))
    findings.extend(matches_for_rule("SQL-004", rules, rel_path, structural, line_starts, iter_statement_regex(structural_statements, NULL_EQUALITY_RE), "NULL is compared with an equality operator instead of IS NULL / IS NOT NULL."))
    findings.extend(matches_for_rule("SQL-005", rules, rel_path, structural, line_starts, iter_statement_regex(structural_statements, NON_SARGABLE_RE), "function-wrapped column appears in a WHERE predicate, preventing index-friendly lookup."))
    findings.extend(detect_missing_transaction(rules, rel_path, structural, structural_statements, line_starts))
    findings.extend(matches_for_rule("SQL-007", rules, rel_path, structural, line_starts, iter_statement_regex(structural_statements, IMPLICIT_CROSS_JOIN_RE), "comma-separated tables in FROM create an implicit cross join."))
    return findings


def detect_mutation_without_where(rules: dict[str, dict], rel_path: str, statements: list[SqlStatement], line_starts: list[int]) -> list[Finding]:
    findings: list[Finding] = []
    rule = rules.get("SQL-002")
    if not rule:
        return findings
    for statement in statements:
        stripped = statement.text.strip()
        if not stripped:
            continue
        match = MUTATING_START_RE.search(stripped)
        if not match or re.search(r"\bwhere\b", stripped, re.IGNORECASE):
            continue
        absolute = statement.start + statement.text.find(match.group(1))
        line, col = line_col_for_offset(line_starts, absolute)
        verb = match.group(1).upper()
        findings.append(build_finding(rule, rel_path, line, col, f"{verb} statement has no WHERE clause."))
    return findings[:MAX_HITS_PER_RULE]


def detect_missing_transaction(rules: dict[str, dict], rel_path: str, commentless: str, statements: list[SqlStatement], line_starts: list[int]) -> list[Finding]:
    rule = rules.get("SQL-006")
    if not rule or TRANSACTION_RE.search(commentless):
        return []
    writes = [statement for statement in statements if WRITE_START_RE.search(statement.text.strip())]
    if len(writes) < 2:
        return []
    first = writes[0]
    match = WRITE_START_RE.search(first.text.strip())
    offset = first.start + first.text.find(match.group(0).strip()) if match else first.start
    line, col = line_col_for_offset(line_starts, offset)
    return [build_finding(rule, rel_path, line, col, f"{len(writes)} write statements execute without an explicit transaction boundary.")]


def matches_for_rule(
    rule_id: str,
    rules: dict[str, dict],
    rel_path: str,
    text: str,
    line_starts: list[int],
    matches: Iterator[tuple[int, str]],
    detail: str,
) -> list[Finding]:
    rule = rules.get(rule_id)
    if not rule:
        return []
    findings: list[Finding] = []
    for offset, snippet in matches:
        line, col = line_col_for_offset(line_starts, offset)
        findings.append(build_finding(rule, rel_path, line, col, f"{detail} Snippet: {compact_snippet(snippet or text[offset:offset + 120])}"))
        if len(findings) >= MAX_HITS_PER_RULE:
            break
    return findings


def iter_statement_regex(statements: list[SqlStatement], pattern: re.Pattern) -> Iterator[tuple[int, str]]:
    for statement in statements:
        for match in pattern.finditer(statement.text):
            yield statement.start + match.start(), match.group(0)


def mask_sql_comments(text: str) -> str:
    chars = list(text)
    i = 0
    in_single = False
    in_double = False
    while i < len(chars):
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < len(chars) else ""
        if in_single:
            if ch == "'" and nxt == "'":
                i += 2
                continue
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "'":
            in_single = True
            i += 1
            continue
        if ch == '"':
            in_double = True
            i += 1
            continue
        if ch == "-" and nxt == "-":
            chars[i] = " "
            chars[i + 1] = " "
            i += 2
            while i < len(chars) and chars[i] not in "\r\n":
                chars[i] = " "
                i += 1
            continue
        if ch == "/" and nxt == "*":
            chars[i] = " "
            chars[i + 1] = " "
            i += 2
            while i < len(chars):
                if chars[i] == "*" and i + 1 < len(chars) and chars[i + 1] == "/":
                    chars[i] = " "
                    chars[i + 1] = " "
                    i += 2
                    break
                if chars[i] not in "\r\n":
                    chars[i] = " "
                i += 1
            continue
        i += 1
    return "".join(chars)


def mask_sql_strings(text: str) -> str:
    chars = list(text)
    i = 0
    in_single = False
    in_double = False
    while i < len(chars):
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < len(chars) else ""
        if in_single:
            if ch == "'" and nxt == "'":
                chars[i] = " "
                chars[i + 1] = " "
                i += 2
                continue
            chars[i] = " " if ch not in "\r\n" else ch
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            chars[i] = " " if ch not in "\r\n" else ch
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "'":
            chars[i] = " "
            in_single = True
        elif ch == '"':
            chars[i] = " "
            in_double = True
        i += 1
    return "".join(chars)


def split_sql_statements(text: str) -> list[SqlStatement]:
    statements: list[SqlStatement] = []
    start = 0
    i = 0
    in_single = False
    in_double = False
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_single:
            if ch == "'" and nxt == "'":
                i += 2
                continue
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "'":
            in_single = True
        elif ch == '"':
            in_double = True
        elif ch == ";":
            statements.append(SqlStatement(text=text[start:i], start=start, end=i))
            start = i + 1
        i += 1
    if text[start:].strip():
        statements.append(SqlStatement(text=text[start:], start=start, end=len(text)))
    return statements


def build_finding(rule: dict, rel_path: str, line: int, col: int, detail: str) -> Finding:
    rule_id = rule["id"]
    message = f"{rule['name']}: {detail}"
    cwe = [f"CWE-{item}" for item in (rule.get("cwe") or [])]
    owasp = [rule["owasp"]] if rule.get("owasp") else []
    fingerprint = make_fingerprint("sql-artifact", rule_id, rel_path, line, detail)
    severity = str(rule.get("severity") or "info").upper()
    return Finding(
        id=fingerprint[:16],
        source="sql-artifact",
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
        scanner_metadata={"engine": "sql-artifact", "catalog_rule_id": rule_id},
    )


def line_start_offsets(text: str) -> list[int]:
    starts = [0]
    for match in re.finditer(r"\n", text):
        starts.append(match.end())
    return starts


def line_col_for_offset(line_starts: list[int], offset: int) -> tuple[int, int]:
    line_index = bisect.bisect_right(line_starts, max(0, offset)) - 1
    return line_index + 1, max(1, offset - line_starts[line_index] + 1)


def compact_snippet(text: str) -> str:
    return " ".join((text or "").split())[:160]


def make_fingerprint(source: str, rule_id: str, path: str, line: int, message: str) -> str:
    raw = f'{source}|{rule_id}|{path.replace(os.sep, "/")}|{line}|{message}'
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def relpath(path: Path, target: Path) -> str:
    try:
        return str(path.resolve().relative_to(target.resolve())).replace("\\", "/")
    except Exception:
        return str(path).replace("\\", "/")
