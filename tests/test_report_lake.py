import json
import os
import tempfile
import unittest
from pathlib import Path

from app.ingestion import normalize_finding
from app.models import ScanResult, ScanSummary
from app.report_lake import (
    list_sanitized_scans,
    load_sanitized_scan,
    report_lake_status,
    sanitized_scan_report,
    save_sanitized_scan,
)


class SanitizedReportLakeTests(unittest.TestCase):
    def setUp(self):
        self._old_data_dir = os.environ.get('SECURE_REVIEW_DATA_DIR')
        self.tmp = tempfile.TemporaryDirectory()
        os.environ['SECURE_REVIEW_DATA_DIR'] = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()
        if self._old_data_dir is None:
            os.environ.pop('SECURE_REVIEW_DATA_DIR', None)
        else:
            os.environ['SECURE_REVIEW_DATA_DIR'] = self._old_data_dir

    def test_sanitized_report_redacts_secrets_paths_and_patches(self):
        finding = normalize_finding(
            source='semgrep',
            rule_id='python.hardcoded-password',
            title='Hardcoded password',
            severity='HIGH',
            confidence='HIGH',
            path='G:\\My Software Projects\\Code Reviewer - Codex\\scan-workspace\\repos\\owner__repo\\src\\app.py',
            line=7,
            message='Hardcoded password=supersecret and Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456',
            cwe=['CWE-798'],
            metadata={
                'line_text': 'password=supersecret',
                'dependency_name': 'requests',
                'note': 'api_key=abcdef123456',
            },
        )
        finding.fix.patch = 'diff --git a/src/app.py b/src/app.py\n-password=supersecret'
        scan = ScanResult(
            scan_id='scan-1',
            project_name='owner__repo',
            target_path='G:\\My Software Projects\\Code Reviewer - Codex\\scan-workspace\\repos\\owner__repo',
            summary=ScanSummary(total_findings=1, high=1, files_scanned=3, languages={'Python': 3}),
            findings=[finding],
        )

        report = sanitized_scan_report(scan)
        encoded = json.dumps(report)

        self.assertNotIn('supersecret', encoded)
        self.assertNotIn('abcdefghijklmnopqrstuvwxyz123456', encoded)
        self.assertNotIn('diff --git', encoded)
        self.assertNotIn('G:\\', encoded)
        self.assertNotIn('My Software Projects', encoded)
        self.assertFalse(report['lineage']['raw_code_included'])
        self.assertFalse(report['source_scan']['target']['full_path_stored'])
        self.assertFalse(report['findings'][0]['location']['full_path_stored'])
        self.assertIn('line_text', report['findings'][0]['dropped_metadata_keys'])
        self.assertEqual(report['findings'][0]['scanner_metadata']['note'], 'api_key=[REDACTED]')

    def test_save_load_list_and_status_use_configured_lake(self):
        scan = ScanResult(
            scan_id='scan-save',
            project_name='safe-go',
            target_path='E:\\secure-review\\repos\\safe__go',
            summary=ScanSummary(total_findings=0, files_scanned=1, languages={'Go': 1}),
            findings=[],
        )

        saved = save_sanitized_scan(scan)
        loaded = load_sanitized_scan('scan-save')
        records = list_sanitized_scans(limit=10)
        status = report_lake_status()

        self.assertEqual(saved['source_scan']['scan_id'], 'scan-save')
        self.assertEqual(loaded['source_scan']['scan_id'], 'scan-save')
        self.assertEqual(records[0]['scan_id'], 'scan-save')
        self.assertEqual(status['scan_record_count'], 1)
        self.assertIn(str(Path(self.tmp.name).resolve()), status['lake_dir'])

    def test_quarantined_scan_is_not_agent_or_rag_eligible(self):
        scan = ScanResult(
            scan_id='q-scan',
            project_name='samratashok__nishang',
            target_path='E:\\secure-review\\repos\\samratashok__nishang',
            summary=ScanSummary(total_findings=1, high=1, files_scanned=1, languages={'PowerShell': 1}),
            findings=[],
        )

        report = sanitized_scan_report(scan)

        self.assertEqual(report['quarantine']['status'], 'quarantined')
        self.assertFalse(report['learning_eligibility']['agent_learning_allowed'])
        self.assertFalse(report['learning_eligibility']['rag_ingest_allowed'])
        self.assertFalse(report['learning_eligibility']['prompt_ready'])


if __name__ == '__main__':
    unittest.main()
