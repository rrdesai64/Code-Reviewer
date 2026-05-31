"""Native byte-level scanner for the catalog's `binary_scan` lane.

These checks look at raw bytes, not parsed syntax, so they catch issues that
Semgrep and Bandit structurally cannot see: invalid encoding, BOMs, Trojan
Source bidirectional overrides, homoglyph identifiers, zero-width spaces, and
indentation traps.

Design: the *detection logic* lives here in Python; the *metadata* (severity,
CWE, OWASP, human text) is pulled from rules/code_review_rules.yaml so the
catalog stays the single source of truth. Each detector is mapped to a catalog
rule id and emits the app's standard Finding objects.

Public entry point mirrors run_semgrep / run_bandit:
    run_catalog_native(target: Path, files: list[Path]) -> tuple[list[Finding], str]
"""
from __future__ import annotations

import hashlib
import os
import re
import unicodedata
from pathlib import Path
from typing import Iterable, Iterator

from . import catalog_knowledge as kb
from .models import Finding, Location

ROOT = Path(__file__).resolve().parents[1]

# Per (file, rule) we stop after this many hits to avoid flooding a report.
MAX_HITS_PER_RULE = 20

# Map file extension -> the catalog's lowercase language token.
EXT_TO_LANG = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".java": "java",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".cs": "csharp",
    ".go": "go", ".rs": "rust", ".php": "php", ".rb": "ruby",
    ".yml": "yaml", ".yaml": "yaml", ".json": "json", ".toml": "toml",
    ".sh": "shell", ".bash": "shell", ".ps1": "powershell", ".sql": "sql",
    ".kt": "kotlin", ".tf": "terraform", ".md": "markdown", ".txt": "text",
}
# Prose-like files where typographic punctuation / NBSP are legitimate; the
# noise-prone detectors skip these to keep precision high.
PROSE_LANGS = {"markdown", "text"}

# Dangerous Unicode code points -----------------------------------------------
BIDI_CONTROLS = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
                 0x2066, 0x2067, 0x2068, 0x2069, 0x061C}
CURLY_QUOTES = {0x2018, 0x2019, 0x201C, 0x201D}
INVISIBLE = {0x00A0, 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}
CONTROL_BYTES = (set(range(0x00, 0x09)) | {0x0B, 0x0C}
                 | set(range(0x0E, 0x20)) | {0x7F})  # excludes tab/LF/CR
UTF8_BOM = b"\xef\xbb\xbf"

_WORD_RE = re.compile(r"[^\W\d_]+", re.UNICODE)
_CONTINUATION_RE = re.compile(r"\\[ \t]+$")


# --- helpers (kept local to avoid importing scanner -> no circular import) ----
def _make_fingerprint(source: str, rule_id: str, path: str, line: int, message: str) -> str:
    raw = f'{source}|{rule_id}|{path.replace(os.sep, "/")}|{line}|{message}'
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _relpath(path: Path, target: Path) -> str:
    try:
        return str(path.resolve().relative_to(target.resolve())).replace("\\", "/")
    except Exception:
        return str(path).replace("\\", "/")


def _line_of_offset(data: bytes, offset: int) -> int:
    return data[:offset].count(b"\n") + 1


def _cp_name(cp: int) -> str:
    try:
        return unicodedata.name(chr(cp))
    except ValueError:
        return "control character"


# --- detectors ----------------------------------------------------------------
# Each detector yields (line, col, detail_message) hits.
def _d_invalid_utf8(data: bytes, lines: list[str], lang: str) -> Iterator[tuple[int, int, str]]:
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        yield (_line_of_offset(data, exc.start), 1,
               f"invalid UTF-8 byte 0x{data[exc.start]:02X} at byte offset {exc.start}")


def _d_bom(data: bytes, lines: list[str], lang: str) -> Iterator[tuple[int, int, str]]:
    if data.startswith(UTF8_BOM):
        yield (1, 1, "file begins with a UTF-8 byte-order mark (EF BB BF)")


def _d_line_endings(data: bytes, lines: list[str], lang: str) -> Iterator[tuple[int, int, str]]:
    has_crlf = b"\r\n" in data
    lf_only = b"\n" in data.replace(b"\r\n", b"")
    if has_crlf and lf_only:
        yield (1, 1, "file mixes CRLF and LF line endings")


def _d_bidi(data: bytes, lines: list[str], lang: str) -> Iterator[tuple[int, int, str]]:
    for i, line in enumerate(lines, 1):
        for col, ch in enumerate(line, 1):
            if ord(ch) in BIDI_CONTROLS:
                yield (i, col, f"bidirectional control character {_cp_name(ord(ch))} "
                               f"(U+{ord(ch):04X}) - rendered code may differ from executed code")


def _d_homoglyph(data: bytes, lines: list[str], lang: str) -> Iterator[tuple[int, int, str]]:
    for i, line in enumerate(lines, 1):
        for m in _WORD_RE.finditer(line):
            word = m.group()
            has_ascii = any("a" <= c.lower() <= "z" for c in word if ord(c) < 128)
            mixed = next((c for c in word if ord(c) > 127 and c.isalpha()), None)
            if has_ascii and mixed:
                yield (i, m.start() + 1,
                       f"mixed-script identifier {word!r} contains lookalike character "
                       f"{_cp_name(ord(mixed))} (U+{ord(mixed):04X})")


def _d_control_bytes(data: bytes, lines: list[str], lang: str) -> Iterator[tuple[int, int, str]]:
    for i, b in enumerate(data):
        if b in CONTROL_BYTES:
            label = "null byte" if b == 0 else f"control byte 0x{b:02X}"
            yield (_line_of_offset(data, i), 1, f"embedded {label}")


def _d_curly_quotes(data: bytes, lines: list[str], lang: str) -> Iterator[tuple[int, int, str]]:
    for i, line in enumerate(lines, 1):
        for col, ch in enumerate(line, 1):
            if ord(ch) in CURLY_QUOTES:
                yield (i, col, f"typographic quote {_cp_name(ord(ch))} (U+{ord(ch):04X}) "
                               "where an ASCII quote was likely intended")


def _d_invisible_space(data: bytes, lines: list[str], lang: str) -> Iterator[tuple[int, int, str]]:
    for i, line in enumerate(lines, 1):
        for col, ch in enumerate(line, 1):
            cp = ord(ch)
            if cp in INVISIBLE and not (i == 1 and col == 1 and cp == 0xFEFF):
                yield (i, col, f"invisible separator {_cp_name(cp)} (U+{cp:04X}) used as whitespace")


def _d_mixed_indent(data: bytes, lines: list[str], lang: str) -> Iterator[tuple[int, int, str]]:
    for i, line in enumerate(lines, 1):
        indent = line[: len(line) - len(line.lstrip(" \t"))]
        if " " in indent and "\t" in indent:
            yield (i, 1, "indentation mixes tabs and spaces")


def _d_trailing_continuation(data: bytes, lines: list[str], lang: str) -> Iterator[tuple[int, int, str]]:
    for i, line in enumerate(lines, 1):
        m = _CONTINUATION_RE.search(line)
        if m:
            yield (i, m.start() + 1, "whitespace after a line-continuation backslash breaks the continuation")


# rule_id -> (detector, confidence, skip_on_prose)
DETECTORS = {
    "ENC-001": (_d_invalid_utf8, "HIGH", False),
    "ENC-002": (_d_bom, "HIGH", False),
    "ENC-003": (_d_line_endings, "MEDIUM", True),
    "ENC-005": (_d_bidi, "HIGH", False),
    "ENC-006": (_d_homoglyph, "MEDIUM", True),
    "ENC-007": (_d_control_bytes, "HIGH", False),
    "ENC-009": (_d_curly_quotes, "MEDIUM", True),
    "ENC-010": (_d_invisible_space, "HIGH", True),
    "LEX-001": (_d_mixed_indent, "MEDIUM", True),
    "LEX-002": (_d_trailing_continuation, "HIGH", False),
}


# --- catalog metadata -> Finding field mappers --------------------------------
def _rule_applies(rule: dict, lang: str) -> bool:
    langs = rule.get("languages", ["*"])
    return "*" in langs or lang in langs


def _severity(rule: dict) -> str:
    sev = str(rule.get("severity", "info")).upper()
    return sev if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} else "INFO"


def _cwe(rule: dict) -> list[str]:
    cwe = rule.get("cwe")
    return [f"CWE-{n}" for n in cwe] if cwe else []


def _owasp(rule: dict) -> list[str]:
    return [rule["owasp"]] if rule.get("owasp") else []


def _build_finding(rule: dict, rel_path: str, line: int, col: int, detail: str, confidence: str) -> Finding:
    rule_id = rule["id"]
    message = f"{rule['name']}: {detail}"
    explanation = kb.build_explanation(rule, _cwe(rule), _owasp(rule))
    fingerprint = _make_fingerprint("catalog-native", rule_id, rel_path, line, detail)
    return Finding(
        id=fingerprint[:16],
        source="catalog-native",
        rule_id=rule_id,
        title=rule["name"],
        severity=_severity(rule),
        confidence=confidence,
        location=Location(path=rel_path, line=line, column=col),
        message=message,
        cwe=_cwe(rule),
        owasp=_owasp(rule),
        references=[],
        explanation=explanation or message,
        fix=kb.build_fix(rule),
        fingerprint=fingerprint,
    )


# --- public entry point -------------------------------------------------------
def run_catalog_native(target: Path, files: Iterable[Path]) -> tuple[list[Finding], str]:
    if not kb.available():
        return [], "skipped: catalog unavailable (PyYAML missing or file not found)"
    rules = {rid: kb.get_rule(rid) for rid in DETECTORS}
    rules = {rid: r for rid, r in rules.items() if r is not None}
    if not rules:
        return [], "skipped: no byte-level rules in catalog"

    findings: list[Finding] = []
    scanned = 0
    for path in files:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        scanned += 1
        lang = EXT_TO_LANG.get(path.suffix.lower(), "text")
        text = data.decode("utf-8", errors="replace")
        lines = text.splitlines()
        rel_path = _relpath(path, target)

        for rule_id, (detector, confidence, skip_prose) in DETECTORS.items():
            rule = rules.get(rule_id)
            if rule is None or not _rule_applies(rule, lang):
                continue
            if skip_prose and lang in PROSE_LANGS:
                continue
            for hits, (line, col, detail) in enumerate(detector(data, lines, lang)):
                if hits >= MAX_HITS_PER_RULE:
                    break
                findings.append(_build_finding(rule, rel_path, line, col, detail, confidence))

    return findings, f"ok: {scanned} files, {len(rules)} byte-level rules"
