"""Tests for scanner helpers: cross-platform tool resolution and file walking."""
import os
import shutil

import pytest

from app import scanner


def test_resolve_tool_missing_returns_none():
    assert scanner.resolve_tool("definitely-not-a-real-tool-xyz") is None


def test_resolve_tool_prefers_venv(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    exe = bin_dir / ("semgrep.exe" if os.name == "nt" else "semgrep")
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setattr(scanner, "_venv_bin_dir", lambda: bin_dir)
    assert scanner.resolve_tool("semgrep") == str(exe)


def test_resolve_tool_falls_back_to_path(tmp_path, monkeypatch):
    # Point the venv dir at an empty location so resolution must use PATH.
    monkeypatch.setattr(scanner, "_venv_bin_dir", lambda: tmp_path)
    candidate = shutil.which("python3") or shutil.which("python")
    if not candidate:
        pytest.skip("no python on PATH to test fallback")
    name = "python3" if shutil.which("python3") else "python"
    assert scanner.resolve_tool(name) == candidate


def test_venv_bin_dir_is_os_appropriate():
    name = scanner._venv_bin_dir().name
    assert name == ("Scripts" if os.name == "nt" else "bin")


def test_iter_source_files_filters(tmp_path):
    (tmp_path / "keep.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "image.png").write_bytes(b"\x89PNG")
    skipped = tmp_path / "node_modules"
    skipped.mkdir()
    (skipped / "dep.js").write_text("x", encoding="utf-8")

    found = {p.name for p in scanner.iter_source_files(tmp_path)}
    assert "keep.py" in found
    assert "image.png" not in found     # not a recognized source extension
    assert "dep.js" not in found        # inside an excluded directory
