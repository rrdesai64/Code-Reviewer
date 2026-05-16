from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .enterprise import audit, compliance_report
from .memory import update_repository_memory
from .refactor import build_fix_proposal
from .reporting import github_pr_comment, markdown_report
from .sarif import build_sarif
from .scanner import SEVERITY_ORDER, run_scan
from .storage import save_baseline, save_scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Secure Code Review Assistant CLI')
    parser.add_argument('scan', nargs='?', help='run a repository scan')
    parser.add_argument('--path', required=True, help='repository path to scan')
    parser.add_argument('--project-name', default=None)
    parser.add_argument('--json-out')
    parser.add_argument('--sarif-out')
    parser.add_argument('--report-out')
    parser.add_argument('--pr-comment-out')
    parser.add_argument('--compliance-out')
    parser.add_argument('--fix-proposals-out')
    parser.add_argument('--fix-provider', default='offline')
    parser.add_argument('--save-baseline', action='store_true')
    parser.add_argument('--fail-on', choices=['critical', 'high', 'medium', 'low', 'info'], default=None)
    args = parser.parse_args(argv)

    scan = run_scan(Path(args.path), project_name=args.project_name)
    save_scan(scan)
    update_repository_memory(scan)
    audit('cli', 'scan.created', scan.scan_id, {'project': scan.project_name})
    if args.save_baseline:
        save_baseline(scan)
    if args.json_out:
        Path(args.json_out).write_text(scan.model_dump_json(indent=2), encoding='utf-8')
    if args.sarif_out:
        Path(args.sarif_out).write_text(json.dumps(build_sarif(scan), indent=2), encoding='utf-8')
    if args.report_out:
        Path(args.report_out).write_text(markdown_report(scan), encoding='utf-8')
    if args.pr_comment_out:
        Path(args.pr_comment_out).write_text(github_pr_comment(scan), encoding='utf-8')
    if args.compliance_out:
        Path(args.compliance_out).write_text(json.dumps(compliance_report(scan), indent=2), encoding='utf-8')
    if args.fix_proposals_out:
        proposals = [build_fix_proposal(scan, finding.id, provider=args.fix_provider).model_dump() for finding in scan.findings if finding.severity in {'CRITICAL', 'HIGH', 'MEDIUM'}]
        Path(args.fix_proposals_out).write_text(json.dumps(proposals, indent=2), encoding='utf-8')

    print(f'Scan {scan.scan_id}: {scan.summary.total_findings} findings across {scan.summary.files_scanned} files')
    print(f"Tools: {', '.join(f'{k}={v}' for k, v in scan.summary.tools.items())}")
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on.upper()]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in scan.findings):
            return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
