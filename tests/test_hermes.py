import json
import os
import tempfile
import unittest

from app.hermes import create_hermes_run, hermes_report_for_scan, hermes_status, list_hermes_runs, load_hermes_run, run_hermes_on_memory
from app.ingestion import normalize_finding
from app.models import ScanResult, ScanSummary
from app.rag_memory import save_rag_memory_for_report
from app.report_lake import save_sanitized_scan, sanitized_scan_report


class HermesOrchestratorTests(unittest.TestCase):
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

    def test_safe_memory_gets_planned_dispatched_and_persisted(self):
        scan = self.safe_scan()
        sanitized = save_sanitized_scan(scan)
        memory = save_rag_memory_for_report(sanitized)

        run = run_hermes_on_memory(memory, requester='unit-test', persist=True)
        loaded = load_hermes_run(run['run_id'])
        runs = list_hermes_runs()
        encoded = json.dumps(run)

        self.assertIn(run['status'], {'blocked', 'review_required'})
        self.assertEqual(run['policy']['decision'], 'allowed')
        self.assertGreater(run['plan']['task_count'], 0)
        self.assertTrue(run['agent_results'])
        self.assertTrue(any(result['agent_id'] == 'hermes-supply-chain-governor' for result in run['agent_results']))
        self.assertEqual(loaded['run_id'], run['run_id'])
        self.assertEqual(runs[0]['run_id'], run['run_id'])
        self.assertNotIn('supersecret', encoded)
        self.assertNotIn('G:\\', encoded)
        self.assertFalse(run['approvals']['auto_apply_allowed'])
        self.assertTrue(run['approvals']['benchmark_gate_required'])

    def test_quarantined_memory_blocks_orchestration(self):
        scan = ScanResult(
            scan_id='q-hermes',
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

        run = run_hermes_on_memory(memory, requester='unit-test', persist=False)

        self.assertEqual(run['status'], 'blocked')
        self.assertEqual(run['policy']['decision'], 'blocked')
        self.assertFalse(run['tasks'])
        self.assertFalse(run['agent_results'])

    def test_allowed_agent_filter_limits_dispatch(self):
        memory = save_rag_memory_for_report(sanitized_scan_report(self.safe_scan(scan_id='filtered')))

        run = run_hermes_on_memory(memory, allowed_agents=['hermes-risk-governor'], requester='unit-test', persist=False)

        self.assertTrue(run['agent_results'])
        self.assertEqual({result['agent_id'] for result in run['agent_results']}, {'hermes-risk-governor'})
        self.assertEqual([agent['agent_id'] for agent in run['agent_registry']], ['hermes-risk-governor'])

    def test_create_run_uses_saved_sanitized_lake_and_status_reports_registry(self):
        scan = self.safe_scan(scan_id='saved-hermes')
        save_sanitized_scan(scan)

        run = create_hermes_run(scan_id='saved-hermes', requester='unit-test', persist=True)
        status = hermes_status()

        self.assertEqual(run['source']['scan_id'], 'saved-hermes')
        self.assertEqual(status['status'], 'ready')
        self.assertTrue(status['agent_registry'])

    def test_report_for_scan_is_non_persistent_artifact(self):
        run = hermes_report_for_scan(self.safe_scan(scan_id='bundle-hermes'))

        self.assertEqual(run['source']['scan_id'], 'bundle-hermes')
        self.assertNotIn('storage', run)
        self.assertGreaterEqual(run['plan']['task_count'], 1)

    def safe_scan(self, scan_id='safe-hermes'):
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
                tools={'pip-audit': 'ok findings=1', 'semgrep': 'ok findings=0'},
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
