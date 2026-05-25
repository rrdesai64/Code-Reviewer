from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def output_root() -> Path | None:
    configured = os.getenv('SECURE_REVIEW_OUTPUT_ROOT', '').strip()
    return Path(configured).expanduser().resolve() if configured else None


def data_dir() -> Path:
    configured = os.getenv('SECURE_REVIEW_DATA_DIR', '').strip()
    if configured:
        return Path(configured).expanduser().resolve()
    root = output_root()
    return (root / 'data') if root else (ROOT / 'data')
