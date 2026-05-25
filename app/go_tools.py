from __future__ import annotations

import os
import shutil
from pathlib import Path

from .paths import data_dir

ROOT = Path(__file__).resolve().parents[1]
LOCAL_GO_ROOT = ROOT / 'tools' / 'go'
LOCAL_GO_EXE = LOCAL_GO_ROOT / 'bin' / 'go.exe'
LOCAL_GO_TOOLS_BIN = ROOT / 'tools' / 'go-tools' / 'bin'
LOCAL_GOVULNCHECK_EXE = LOCAL_GO_TOOLS_BIN / 'govulncheck.exe'


def go_executable() -> str | None:
    configured = os.getenv('GO_EXE') or os.getenv('GOCMD')
    if configured:
        return configured
    if LOCAL_GO_EXE.exists():
        return str(LOCAL_GO_EXE)
    return shutil.which('go')


def govulncheck_executable() -> str | None:
    configured = os.getenv('GOVULNCHECK_EXE')
    if configured:
        return configured
    if LOCAL_GOVULNCHECK_EXE.exists():
        return str(LOCAL_GOVULNCHECK_EXE)
    return shutil.which('govulncheck')


def go_tool_env(base: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(base or os.environ)
    path_parts: list[str] = []
    go_exe = go_executable()
    if go_exe:
        go_bin = str(Path(go_exe).parent)
        path_parts.append(go_bin)
        if LOCAL_GO_EXE.exists() and Path(go_exe).resolve() == LOCAL_GO_EXE.resolve():
            env['GOROOT'] = str(LOCAL_GO_ROOT)
    if LOCAL_GO_TOOLS_BIN.exists():
        path_parts.append(str(LOCAL_GO_TOOLS_BIN))
    if path_parts:
        env['PATH'] = os.pathsep.join([*path_parts, env.get('PATH', '')])
    cache_root = data_dir() / 'go-tools'
    (cache_root / 'pkg' / 'mod').mkdir(parents=True, exist_ok=True)
    (cache_root / 'build-cache').mkdir(parents=True, exist_ok=True)
    env.setdefault('GOTOOLCHAIN', 'local')
    env.setdefault('GOMODCACHE', str(cache_root / 'pkg' / 'mod'))
    env.setdefault('GOCACHE', str(cache_root / 'build-cache'))
    return env
