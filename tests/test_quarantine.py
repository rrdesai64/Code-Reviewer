import os
import tempfile
import unittest

from app.ingestion import normalize_finding
from app.models import ScanResult, ScanSummary
from app.quarantine import blocks_host_scan, quarantine_policy, upsert_quarantine_entry
from app.recursive_learning import recursive_learning_from_scans


class QuarantineRegistryTests(unittest.TestCase):
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

    def test_default_nishang_entry_blocks_host_scan_and_agent_learning(self):
        policy = quarantine_policy('https://github.com/samratashok/nishang')

        self.assertTrue(policy['matched'])
        self.assertEqual(policy['status'], 'quarantined')
        self.assertFalse(policy['controls']['raw_code_access'])
        self.assertFalse(policy['controls']['execution'])
        self.assertFalse(policy['controls']['agent_learning'])
        self.assertTrue(policy['controls']['report_only'])
        self.assertTrue(blocks_host_scan('E:\\secure-review\\repos\\samratashok__nishang'))

    def test_non_quarantined_repo_uses_clear_policy(self):
        policy = quarantine_policy('https://github.com/example/safe-repo')

        self.assertFalse(policy['matched'])
        self.assertEqual(policy['status'], 'clear')
        self.assertTrue(policy['controls']['raw_code_access'])
        self.assertTrue(policy['controls']['agent_learning'])
        self.assertFalse(policy['controls']['report_only'])

    def test_custom_quarantine_entry_persists_and_matches_alias(self):
        entry = upsert_quarantine_entry({
            'repository': 'https://github.com/example/danger-lab',
            'status': 'blocked',
            'reason': 'Known exploit corpus.',
            'aliases': ['danger-lab-local'],
        })

        self.assertEqual(entry['status'], 'blocked')
        policy = quarantine_policy('D:\\work\\danger-lab-local')
        self.assertTrue(policy['matched'])
        self.assertEqual(policy['status'], 'blocked')
        self.assertFalse(policy['controls']['agent_learning'])

    def test_recursive_learning_excludes_quarantined_scans(self):
        quarantined = ScanResult(
            scan_id='q-scan',
            project_name='samratashok__nishang',
            target_path='E:\\secure-review\\repos\\samratashok__nishang',
            summary=ScanSummary(languages={'PowerShell': 10}, tools={'semgrep': 'error: hostile sample'}),
            findings=[
                normalize_finding(
                    source='semgrep',
                    rule_id='powershell-dangerous-download',
                    title='Dangerous download',
                    severity='HIGH',
                    confidence='HIGH',
                    path='Invoke-Malware.ps1',
                    line=1,
                    message='dangerous download pattern',
                    cwe=['CWE-494'],
                )
            ],
        )
        normal = ScanResult(
            scan_id='normal-scan',
            project_name='safe-go',
            target_path='E:\\secure-review\\repos\\safe__go',
            summary=ScanSummary(languages={'Go': 4}, tools={'govulncheck': 'not installed'}),
            findings=[],
        )

        report = recursive_learning_from_scans([quarantined, normal], audit_rows=[], scope='unit-test')

        self.assertEqual(report['input_scan_count'], 2)
        self.assertEqual(report['scan_count'], 1)
        self.assertEqual(report['quarantined_scan_count'], 1)
        self.assertEqual(report['evidence']['quarantine_exclusions'][0]['scan_id'], 'q-scan')
        self.assertTrue(all('q-scan' not in row.get('scan_ids', []) for row in report['evidence']['scanner_failures_by_environment']))


if __name__ == '__main__':
    unittest.main()
