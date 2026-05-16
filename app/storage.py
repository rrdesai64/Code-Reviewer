from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ScanResult

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / 'data'
SCANS_DIR = DATA_DIR / 'scans'
BASELINE_PATH = DATA_DIR / 'baseline.json'
DECISIONS_PATH = DATA_DIR / 'decisions.json'


def ensure_data_dirs() -> None:
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    (DATA_DIR / 'uploads').mkdir(parents=True, exist_ok=True)


def save_scan(scan: ScanResult) -> None:
    ensure_data_dirs()
    path = SCANS_DIR / f'{scan.scan_id}.json'
    path.write_text(scan.model_dump_json(indent=2), encoding='utf-8')


def load_scan(scan_id: str) -> ScanResult:
    path = SCANS_DIR / f'{scan_id}.json'
    if not path.exists():
        raise FileNotFoundError(scan_id)
    return ScanResult.model_validate_json(path.read_text(encoding='utf-8'))


def list_scans() -> list[ScanResult]:
    ensure_data_dirs()
    scans: list[ScanResult] = []
    for path in sorted(SCANS_DIR.glob('*.json'), key=lambda p: p.stat().st_mtime, reverse=True):
        scans.append(ScanResult.model_validate_json(path.read_text(encoding='utf-8')))
    return scans


def save_baseline(scan: ScanResult) -> None:
    ensure_data_dirs()
    payload = {
        'scan_id': scan.scan_id,
        'created_at': scan.created_at.isoformat(),
        'fingerprints': sorted({finding.fingerprint for finding in scan.findings}),
    }
    BASELINE_PATH.write_text(json.dumps(payload, indent=2), encoding='utf-8')


def load_baseline() -> dict[str, Any] | None:
    if not BASELINE_PATH.exists():
        return None
    return json.loads(BASELINE_PATH.read_text(encoding='utf-8'))


def compare_to_baseline(scan: ScanResult) -> ScanResult:
    baseline = load_baseline()
    current = {finding.fingerprint for finding in scan.findings}
    if not baseline:
        scan.new_findings = sorted(current)
        scan.resolved_findings = []
        scan.unchanged_findings = []
        return scan
    previous = set(baseline.get('fingerprints', []))
    scan.new_findings = sorted(current - previous)
    scan.resolved_findings = sorted(previous - current)
    scan.unchanged_findings = sorted(current & previous)
    return scan


def load_decisions() -> dict[str, dict[str, str | None]]:
    if not DECISIONS_PATH.exists():
        return {}
    return json.loads(DECISIONS_PATH.read_text(encoding='utf-8'))


def save_decision(finding_id: str, state: str, reason: str | None) -> None:
    ensure_data_dirs()
    decisions = load_decisions()
    decisions[finding_id] = {'state': state, 'reason': reason}
    DECISIONS_PATH.write_text(json.dumps(decisions, indent=2), encoding='utf-8')


def apply_decisions(scan: ScanResult) -> ScanResult:
    decisions = load_decisions()
    for finding in scan.findings:
        decision = decisions.get(finding.id)
        if decision:
            finding.decision = decision.get('state') or 'open'
            finding.decision_reason = decision.get('reason')
    return scan
