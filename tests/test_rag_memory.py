import json
import os
from pathlib import Path
import tempfile
import unittest

from app.ingestion import normalize_finding
from app.models import ScanResult, ScanSummary
from app.rag_memory import query_rag_memory, rag_memory_schema, reindex_rag_memory, save_rag_memory_for_report, scan_rag_memory_report
from app.report_lake import save_sanitized_scan, sanitized_scan_report


class RagMemorySchemaTests(unittest.TestCase):
    def setUp(self):
        self._old_data_dir = os.environ.get('SECURE_REVIEW_DATA_DIR')
        self.tmp = tempfile.TemporaryDirectory()
        os.environ['SECURE_REVIEW_DATA_DIR'] = self.tmp.name
        from app import storage

        self._old_storage_paths = (
            storage.DATA_DIR,
            storage.SCANS_DIR,
            storage.BASELINE_PATH,
            storage.DECISIONS_PATH,
        )
        storage.DATA_DIR = Path(self.tmp.name)
        storage.SCANS_DIR = storage.DATA_DIR / 'scans'
        storage.BASELINE_PATH = storage.DATA_DIR / 'baseline.json'
        storage.DECISIONS_PATH = storage.DATA_DIR / 'decisions.json'

    def tearDown(self):
        from app import storage

        (
            storage.DATA_DIR,
            storage.SCANS_DIR,
            storage.BASELINE_PATH,
            storage.DECISIONS_PATH,
        ) = self._old_storage_paths
        self.tmp.cleanup()
        if self._old_data_dir is None:
            os.environ.pop('SECURE_REVIEW_DATA_DIR', None)
        else:
            os.environ['SECURE_REVIEW_DATA_DIR'] = self._old_data_dir

    def test_schema_declares_sanitized_source_and_gates(self):
        schema = rag_memory_schema()

        self.assertEqual(schema['source_contract']['accepted_source'], 'sanitized-report-lake')
        self.assertFalse(schema['source_contract']['raw_repository_reads_allowed'])
        self.assertIn('finding-pattern', schema['item_types'])
        self.assertEqual(schema['eligibility_contract']['fine_tuning_allowed'], 'always false until a future human approval and benchmark gate is implemented')

    def test_safe_scan_creates_retrievable_memory_items(self):
        scan = self.safe_scan()
        sanitized = save_sanitized_scan(scan)
        memory = save_rag_memory_for_report(sanitized)
        result = query_rag_memory('requests dependency CVE', limit=5, tags=['DEPENDENCY'])
        encoded = json.dumps(memory)

        self.assertEqual(memory['status'], 'indexed')
        self.assertGreater(memory['item_count'], 0)
        self.assertIn('finding-pattern', {item['item_type'] for item in memory['items']})
        self.assertIn('dependency-signal', {item['item_type'] for item in memory['items']})
        self.assertGreaterEqual(result['total_indexed'], memory['item_count'])
        self.assertTrue(result['results'])
        self.assertNotIn('supersecret', encoded)
        self.assertNotIn('G:\\', encoded)
        self.assertTrue(all(item['eligibility']['retrieval_allowed'] for item in result['results']))
        self.assertTrue(all(not item['safety']['raw_code_included'] for item in result['results']))

    def test_quarantined_scan_is_skipped_for_rag_retrieval(self):
        scan = ScanResult(
            scan_id='q-rag',
            project_name='samratashok__nishang',
            target_path='E:\\secure-review\\repos\\samratashok__nishang',
            summary=ScanSummary(total_findings=1, high=1, files_scanned=1, languages={'PowerShell': 1}),
            findings=[
                normalize_finding(
                    source='semgrep',
                    rule_id='powershell-download',
                    title='Suspicious download',
                    severity='HIGH',
                    path='Invoke.ps1',
                    message='suspicious download',
                )
            ],
        )

        memory = save_rag_memory_for_report(sanitized_scan_report(scan))
        result = query_rag_memory('powershell download', limit=5)

        self.assertEqual(memory['status'], 'skipped')
        self.assertEqual(memory['item_count'], 0)
        self.assertFalse(result['results'])

    def test_reindex_reads_sanitized_report_lake_records(self):
        save_sanitized_scan(self.safe_scan(scan_id='lake-1'))

        report = reindex_rag_memory(limit=10)

        self.assertEqual(report['status'], 'completed')
        self.assertEqual(report['scan_reports_processed'], 1)
        self.assertGreater(report['retrieval_item_count'], 0)
        self.assertFalse(report['skipped'])

    def test_rebuild_creates_sanitized_lake_record_from_saved_scan(self):
        from app import storage

        scan = self.safe_scan(scan_id='saved-only-rag')
        storage.save_scan(scan)

        report = scan_rag_memory_report(scan.scan_id, rebuild=True)

        self.assertEqual(report['status'], 'indexed')
        self.assertGreater(report['item_count'], 0)
        self.assertTrue((Path(self.tmp.name) / 'report-lake' / 'scans' / 'saved-only-rag.json').exists())

    def safe_scan(self, scan_id='safe-rag'):
        finding = normalize_finding(
            source='pip-audit',
            rule_id='CVE-2024-0001',
            title='Vulnerable dependency',
            severity='HIGH',
            confidence='HIGH',
            path='G:\\My Software Projects\\Code Reviewer - Codex\\scan-workspace\\repos\\owner__repo\\requirements.txt',
            line=3,
            message='requests has a vulnerable range and password=supersecret should be redacted',
            cwe=['CWE-937'],
            metadata={'dependency_name': 'requests', 'fixed_version': '2.32.0'},
        )
        return ScanResult(
            scan_id=scan_id,
            project_name='owner__repo',
            target_path='E:\\secure-review\\repos\\owner__repo',
            summary=ScanSummary(
                total_findings=1,
                high=1,
                files_scanned=3,
                languages={'Python': 3},
                tools={'pip-audit': 'ok findings=1'},
                priorities={'P1': 1},
                risk_tiers={'HIGH': 1},
                scope_counts={'dependency': 1},
                production_findings=1,
                max_risk_score=90,
                avg_risk_score=90,
            ),
            findings=[finding],
        )


if __name__ == '__main__':
    unittest.main()
