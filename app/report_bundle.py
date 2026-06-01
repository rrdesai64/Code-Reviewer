from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .benchmark_gate import benchmark_gate_report_for_recommendations
from .autofix_loop import run_inside_out_autofix_loop
from .catalog_coverage import catalog_coverage_map
from .chat_agents import build_chat_notification
from .code_hosts import build_code_host_review
from .consolidation import consolidated_findings_report
from .compliance_api import compliance_evidence_bundle
from .dast import dast_verification_report
from .dependency_review import dependency_review_report
from .enterprise import compliance_report
from .finding_ai import build_scan_ai_review
from .fix_workflow import apply_fix_bundle, build_fix_bundle
from .github_pr import build_github_pr_review
from .governance import compliance_evidence_export
from .hermes import hermes_report_for_scan
from .ingestion import scanner_mesh_report
from .issue_planning import build_issue_plan
from .messaging_gateway import build_scan_gateway_report
from .models import DastScanRequest, FixApplyRequest, InsideOutAutofixLoopRequest, RuntimeBuildRunRequest, ScanResult, UnifiedSoundnessRequest, VerifiedAutofixRequest
from .priority import prioritization_report
from .quarantine import quarantine_policy_for_scan
from .reachability import reachability_context_report
from .refactor import build_remediation_plan
from .recursive_learning import scan_recursive_learning_report
from .report_lake import sanitized_scan_report
from .rag_memory import rag_memory_for_scan
from .reporting import github_pr_comment, html_report, markdown_report
from .runtime_plan import build_runtime_plan
from .runtime_smoke import runtime_smoke_preview
from .runtime_worker import runtime_build_run_preview
from .sarif import build_sarif
from .sbom import build_cyclonedx, build_spdx, compare_sboms, sbom_policy_report, spdx_compliance_report
from .scanner import ROOT
from .scanner_depth import scanner_depth_report
from .secrets import secret_policy_report
from .sonarqube import sonarqube_quality_report
from .soundness import soundness_verdict
from .storage import load_baseline, load_scan
from .suppressions import inline_suppression_report
from .team_learning import team_learning_dashboard
from .teaching_loop import teaching_loop_report_for_scan
from .unified_soundness import unified_soundness_verdict
from .verified_autofix import run_verified_autofix

DEFAULT_AI_REVIEW_LIMIT = 25
DEFAULT_FIX_BUNDLE_LIMIT = 10
REPORTS_DIR = ROOT / 'reports'


def build_report_bundle(scan: ScanResult, base_dir: Path | None = None, ai_review_limit: int = DEFAULT_AI_REVIEW_LIMIT) -> dict[str, Any]:
    bundle_dir = report_bundle_dir(scan, base_dir=base_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)
    artifacts: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    def write_text_artifact(name: str, content_fn: Callable[[], str], media_type: str) -> None:
        write_artifact(bundle_dir, name, content_fn, media_type, artifacts, errors, is_json=False)

    def write_json_artifact(name: str, payload_fn: Callable[[], Any], media_type: str = 'application/json') -> None:
        write_artifact(bundle_dir, name, payload_fn, media_type, artifacts, errors, is_json=True)

    write_json_artifact('scan.json', lambda: scan.model_dump(mode='json'))
    write_text_artifact('secure-review.md', lambda: markdown_report(scan), 'text/markdown')
    write_text_artifact('secure-review.html', lambda: html_report(scan), 'text/html')
    write_json_artifact('secure-review.sarif', lambda: build_sarif(scan), 'application/sarif+json')
    write_text_artifact('pr-comment.md', lambda: github_pr_comment(scan), 'text/markdown')
    write_json_artifact('soundness-verdict.json', lambda: soundness_verdict(scan))
    write_json_artifact('unified-soundness-verdict.json', lambda: unified_soundness_verdict(scan, UnifiedSoundnessRequest()))
    write_json_artifact('runtime-plan.json', lambda: build_runtime_plan(scan))
    write_json_artifact('runtime-build-run-worker.json', lambda: runtime_build_run_preview(scan, RuntimeBuildRunRequest()))
    write_json_artifact('runtime-smoke-posture.json', lambda: runtime_smoke_preview(scan))
    write_json_artifact('dast-verification.json', lambda: dast_verification_report(scan, DastScanRequest()))
    write_json_artifact('finding-consolidation.json', lambda: consolidated_findings_report(scan))
    write_json_artifact('prioritization.json', lambda: prioritization_report(scan))
    write_json_artifact('reachability-context.json', lambda: reachability_context_report(scan))
    write_json_artifact('scanner-mesh.json', lambda: scanner_mesh_report(scan))
    write_json_artifact('dependency-review.json', lambda: dependency_review_report(scan))
    write_json_artifact('sonarqube-quality-gate.json', lambda: sonarqube_quality_report(scan))
    write_json_artifact('scanner-depth.json', lambda: scanner_depth_report(scan))
    write_json_artifact('catalog-coverage-map.json', lambda: catalog_coverage_map())
    write_json_artifact('quarantine-policy.json', lambda: quarantine_policy_for_scan(scan))
    write_json_artifact('inline-suppressions.json', lambda: inline_suppression_report(scan))
    write_json_artifact('sanitized-report.json', lambda: sanitized_scan_report(scan))
    write_json_artifact('rag-memory.json', lambda: rag_memory_for_scan(scan))
    write_json_artifact('hermes-orchestration.json', lambda: hermes_report_for_scan(scan))
    write_json_artifact('ai-review.json', lambda: build_scan_ai_review(scan, provider='offline', limit=ai_review_limit, include_prompts=False))
    write_json_artifact('cyclonedx-sbom.json', lambda: build_cyclonedx(scan), 'application/vnd.cyclonedx+json')
    write_json_artifact('spdx-sbom.json', lambda: build_spdx(scan))
    write_json_artifact('spdx-compliance.json', lambda: spdx_compliance_report(scan))
    write_json_artifact('sbom-policy.json', lambda: sbom_policy_report(scan))
    write_json_artifact('sbom-compare.json', lambda: compare_sboms(scan, comparison_baseline_scan()))
    write_json_artifact('secret-policy.json', lambda: secret_policy_report(scan))
    write_json_artifact('github-pr-review.json', lambda: build_github_pr_review(scan, diff_text=' '))
    write_json_artifact('code-host-review.json', lambda: build_code_host_review(scan))
    write_json_artifact('compliance.json', lambda: compliance_report(scan))
    write_json_artifact('remediation-plan.json', lambda: build_remediation_plan(scan).model_dump(mode='json'))
    write_json_artifact('issue-plan.json', lambda: build_issue_plan(scan))
    write_json_artifact('chat-notification.json', lambda: build_chat_notification(scan))
    write_json_artifact('team-learning-dashboard.json', lambda: team_learning_dashboard())
    write_json_artifact('recursive-learning.json', lambda: scan_recursive_learning_report(scan))
    write_json_artifact('teacher-student-learning.json', lambda: teaching_loop_report_for_scan(scan))
    write_json_artifact('benchmark-gate.json', lambda: scan_benchmark_gate_artifact(scan))
    write_json_artifact('messaging-gateway.json', lambda: build_scan_gateway_report(scan))
    write_json_artifact('governance-evidence.json', lambda: compliance_evidence_export(scan_id=scan.scan_id))
    write_json_artifact('secure-review-compliance-evidence.json', lambda: compliance_evidence_bundle(scan_id=scan.scan_id))
    write_json_artifact('fix-bundle.json', lambda: build_fix_bundle(scan, limit=DEFAULT_FIX_BUNDLE_LIMIT, provider='offline'))
    write_json_artifact('fix-apply-dry-run.json', lambda: apply_fix_bundle(scan, FixApplyRequest(dry_run=True, approved=True, limit=DEFAULT_FIX_BUNDLE_LIMIT, provider='offline')))
    write_json_artifact('verified-autofix-dry-run.json', lambda: run_verified_autofix(scan, VerifiedAutofixRequest(dry_run=True, approved=True, limit=DEFAULT_FIX_BUNDLE_LIMIT, provider='offline')))
    write_json_artifact('inside-out-autofix-loop-dry-run.json', lambda: run_inside_out_autofix_loop(scan, InsideOutAutofixLoopRequest(dry_run=True, approved=True, limit=DEFAULT_FIX_BUNDLE_LIMIT, provider='offline', persist=False)))

    manifest = report_bundle_manifest(scan, bundle_dir, artifacts, errors)
    manifest_path = bundle_dir / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    manifest['artifacts'].insert(0, artifact_record(bundle_dir, manifest_path, 'manifest.json', 'application/json'))
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    return manifest


def report_bundle_metadata(scan: ScanResult, base_dir: Path | None = None) -> dict[str, Any]:
    bundle_dir = report_bundle_dir(scan, base_dir=base_dir)
    manifest_path = bundle_dir / 'manifest.json'
    if manifest_path.exists():
        data = json.loads(manifest_path.read_text(encoding='utf-8'))
        data.setdefault('exists', True)
        return data
    return {
        'schema_version': 1,
        'exists': False,
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'repo_name': safe_repo_name(scan.project_name or Path(scan.target_path).name),
        'bundle_dir': str(bundle_dir),
        'relative_bundle_dir': str(bundle_dir.relative_to(ROOT)) if is_relative_to(bundle_dir, ROOT) else str(bundle_dir),
        'artifacts': [],
        'errors': [],
    }


def scan_benchmark_gate_artifact(scan: ScanResult) -> dict[str, Any]:
    learning = scan_recursive_learning_report(scan)
    report = benchmark_gate_report_for_recommendations(learning.get('scanner_improvement_recommendations', []))
    report['scan_id'] = scan.scan_id
    report['project_name'] = scan.project_name
    return report


def report_bundle_dir(scan: ScanResult, base_dir: Path | None = None) -> Path:
    configured = os.getenv('REPORT_BUNDLE_DIR', '').strip()
    root = base_dir or (Path(configured) if configured else REPORTS_DIR)
    if not root.is_absolute():
        root = ROOT / root
    return root / safe_repo_name(scan.project_name or Path(scan.target_path).name) / scan.scan_id


def write_artifact(bundle_dir: Path, name: str, content_fn: Callable[[], Any], media_type: str, artifacts: list[dict[str, Any]], errors: list[dict[str, str]], is_json: bool) -> None:
    path = bundle_dir / name
    try:
        payload = content_fn()
        if is_json:
            content = json.dumps(payload, indent=2)
        else:
            content = str(payload)
        path.write_text(content, encoding='utf-8')
        artifacts.append(artifact_record(bundle_dir, path, name, media_type))
    except Exception as exc:  # report bundle generation should not fail the completed scan
        errors.append({'artifact': name, 'error': str(exc)[:1000]})


def artifact_record(bundle_dir: Path, path: Path, name: str, media_type: str) -> dict[str, Any]:
    stat = path.stat()
    return {
        'name': name,
        'path': str(path),
        'relative_path': str(path.relative_to(bundle_dir)),
        'media_type': media_type,
        'size_bytes': stat.st_size,
    }


def report_bundle_manifest(scan: ScanResult, bundle_dir: Path, artifacts: list[dict[str, Any]], errors: list[dict[str, str]]) -> dict[str, Any]:
    return {
        'schema_version': 1,
        'exists': True,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'scan_id': scan.scan_id,
        'project_name': scan.project_name,
        'repo_name': safe_repo_name(scan.project_name or Path(scan.target_path).name),
        'target_path': scan.target_path,
        'bundle_dir': str(bundle_dir),
        'relative_bundle_dir': str(bundle_dir.relative_to(ROOT)) if is_relative_to(bundle_dir, ROOT) else str(bundle_dir),
        'artifact_count': len(artifacts) + 1,
        'error_count': len(errors),
        'artifacts': artifacts,
        'errors': errors,
    }


def comparison_baseline_scan() -> ScanResult | None:
    baseline = load_baseline()
    baseline_scan_id = baseline.get('scan_id') if baseline else None
    if not baseline_scan_id:
        return None
    try:
        return load_scan(baseline_scan_id)
    except FileNotFoundError:
        return None


def safe_repo_name(value: str) -> str:
    name = re.sub(r'[^A-Za-z0-9_.-]+', '-', str(value or '').strip())
    name = name.strip('-._')
    return name[:80] or 'repository'


def is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False

