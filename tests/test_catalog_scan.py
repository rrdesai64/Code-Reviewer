"""Tests for the native byte-level scanner (catalog binary_scan lane)."""
from pathlib import Path

import pytest

from app import catalog_knowledge as kb
from app.catalog_scan import run_catalog_native

# A single file with one planted instance of each detectable issue.
TRAP_BYTES = (
    b"\xef\xbb\xbf"                            # ENC-002 BOM
    b"# bidi \xe2\x80\xae override\n"          # ENC-005 U+202E
    b'msg = \xe2\x80\x9chi\xe2\x80\x9d\n'      # ENC-009 curly quotes
    b"pw = \xc2\xa0secret\n"                   # ENC-010 NBSP
    b"def f():\n\t    return 1\n"               # LEX-001 tab+space indent
    b"t = a + \\   \n"                         # LEX-002 trailing ws after backslash
    b"sc\xd0\xbepe = 1\n"                      # ENC-006 Cyrillic homoglyph
    b"x = 1\x00y = 2\n"                        # ENC-007 null byte
)


@pytest.fixture
def trap_dir(tmp_path):
    (tmp_path / "traps.py").write_bytes(TRAP_BYTES)
    (tmp_path / "bad_enc.py").write_bytes(b"name = 'caf\xe9'\n")  # ENC-001 invalid UTF-8
    return tmp_path


def _run(directory):
    files = list(directory.rglob("*.py")) + list(directory.rglob("*.md"))
    return run_catalog_native(directory, files)


def test_all_detectors_fire(trap_dir):
    findings, status = _run(trap_dir)
    fired = {f.rule_id for f in findings}
    expected = {"ENC-001", "ENC-002", "ENC-005", "ENC-006",
                "ENC-007", "ENC-009", "ENC-010", "LEX-001", "LEX-002"}
    assert expected <= fired, f"missing: {expected - fired}"
    assert status.startswith("ok")


def test_severities_match_catalog(trap_dir):
    findings, _ = _run(trap_dir)
    for f in findings:
        assert f.severity == kb.get_rule(f.rule_id)["severity"].upper()


def test_findings_are_valid_model(trap_dir):
    findings, _ = _run(trap_dir)
    for f in findings:
        dumped = f.model_dump()
        assert dumped["source"] == "catalog-native"
        assert dumped["fingerprint"] and dumped["fix"]["summary"]


def test_no_false_positives_on_clean_file(tmp_path):
    (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    findings, status = run_catalog_native(tmp_path, [tmp_path / "clean.py"])
    assert findings == []
    assert status.startswith("ok")


def test_prose_files_skip_typographic_checks(tmp_path):
    # Curly quotes in Markdown are legitimate prose, not a code defect.
    md = tmp_path / "notes.md"
    md.write_bytes(b'A doc with \xe2\x80\x9ccurly quotes\xe2\x80\x9d here.\n')
    findings, _ = run_catalog_native(tmp_path, [md])
    assert "ENC-009" not in {f.rule_id for f in findings}


def test_bidi_flagged_even_in_prose(tmp_path):
    # Trojan-source bidi controls are dangerous everywhere, prose included.
    md = tmp_path / "readme.md"
    md.write_bytes(b"text \xe2\x80\xae more\n")
    findings, _ = run_catalog_native(tmp_path, [md])
    assert "ENC-005" in {f.rule_id for f in findings}
