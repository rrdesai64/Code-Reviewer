import importlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from app.ingestion import normalize_finding
from app.models import ScanResult, ScanSummary


class SecureReviewComplianceApiTests(unittest.TestCase):
    def setUp(self):
        self._old_data_dir = os.environ.get('SECURE_REVIEW_DATA_DIR')
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ['SECURE_REVIEW_DATA_DIR'] = str(self.root / 'data')

        import app.benchmark_gate as benchmark_gate
        import app.compliance_api as compliance_api
        import app.enterprise as enterprise
        import app.governance as governance
        import app.hermes as hermes
        import app.quarantine as quarantine
        import app.rag_memory as rag_memory
        import app.report_lake as report_lake

        self.benchmark_gate = importlib.reload(benchmark_gate)
        self.enterprise = importlib.reload(enterprise)
        self.governance = importlib.reload(governance)
        self.hermes = importlib.reload(hermes)
        self.quarantine = importlib.reload(quarantine)
        self.rag_memory = importlib.reload(rag_memory)
        self.report_lake = importlib.reload(report_lake)
        self.compliance_api = importlib.reload(compliance_api)

    def tearDown(self):
        self.tmp.cleanup()
        if self._old_data_dir is None:
            os.environ.pop('SECURE_REVIEW_DATA_DIR', None)
        else:
            os.environ['SECURE_REVIEW_DATA_DIR'] = self._old_data_dir

    def test_status_and_manifest_expose_vendor_neutral_compliance_contract(self):
        status = self.compliance_api.compliance_api_status()
        manifest = self.compliance_api.compliance_partner_manifest()
        schema = self.compliance_api.compliance_api_schema()

        self.assertEqual(status['status'], 'ready')
        self.assertIn('activity-events', schema['data_products'])
        self.assertFalse(schema['source_contract']['raw_repository_code_included'])
        self.assertFalse(schema['source_contract']['conversation_content_included'])
        self.assertTrue(any(item['path'] == '/api/compliance/events' for item in manifest['endpoints']))
        self.assertIn('Raw repository source export.', manifest['not_supported'])

    def test_compliance_bundle_exports_agent_approval_memory_and_scan_evidence_without_paths(self):
        scan = compliance_scan(self.root, scan_id='compliance-scan')
        sanitized = self.report_lake.save_sanitized_scan(scan)
        memory = self.rag_memory.save_rag_memory_for_report(sanitized)
        run = self.hermes.run_hermes_on_memory(memory, requester='unit-test', persist=True)
        lesson = self.create_approved_lesson(scan_id='compliance-scan')

        bundle = self.compliance_api.compliance_evidence_bundle(scan_id='compliance-scan')
        encoded = json.dumps(bundle)

        self.assertEqual(bundle['evidence_type'], 'secure-review-compliance-api-bundle')
        self.assertGreater(bundle['control_summary']['activity_events'], 0)
        self.assertGreater(bundle['control_summary']['agent_actions'], 0)
        self.assertGreaterEqual(bundle['control_summary']['approvals'], 1)
        self.assertGreaterEqual(bundle['control_summary']['memory_versions'], 1)
        self.assertEqual(bundle['scan_inventory']['records'][0]['scan_id'], 'compliance-scan')
        self.assertEqual(bundle['agent_actions']['events'][0]['event_type'], 'agent-action')
        self.assertTrue(any(record['lesson_id'] == lesson['lesson_id'] for record in bundle['approvals']['records']))
        self.assertEqual(run['source']['memory_version_id'], bundle['memory_lineage']['versions'][0]['version_id'])
        self.assertFalse(bundle['attestation']['raw_code_included'])
        self.assertFalse(bundle['attestation']['raw_report_included'])
        self.assertNotIn(str(self.root), encoded)
        self.assertNotIn('"target_path":', encoded)
        self.assertNotIn('"snapshot_path":', encoded)

    def test_quarantine_alerts_include_controls_without_opening_repository(self):
        self.quarantine.upsert_quarantine_entry({
            'repository': 'https://github.com/example/hostile',
            'status': 'blocked',
            'reason': 'Compliance test quarantine entry.',
            'source': 'unit-test',
            'tags': ['malware'],
        })

        alerts = self.compliance_api.compliance_quarantine_alerts()
        blocked = [item for item in alerts['entries'] if item['repository'] == 'https://github.com/example/hostile']

        self.assertTrue(blocked)
        self.assertFalse(blocked[0]['controls']['raw_code_access'])
        self.assertFalse(alerts['safety']['raw_code_included'])

    def create_approved_lesson(self, scan_id):
        lesson = self.benchmark_gate.upsert_benchmark_lesson({
            'recommendation_id': 'compliance-rec',
            'language': 'python',
            'category': 'noisy-rule-tuning',
            'title': 'Compliance test lesson',
            'source': 'bandit',
            'rule_id': 'B602',
            'proposed_change': 'Candidate lesson for compliance evidence.',
            'evidence': {'scan_id': scan_id},
        }, actor='teacher')
        self.benchmark_gate.transition_benchmark_lesson(lesson['lesson_id'], 'reviewed', actor='teacher')
        self.benchmark_gate.transition_benchmark_lesson(lesson['lesson_id'], 'benchmarked', actor='benchmark', benchmark_evidence=passing_python_evidence())
        self.benchmark_gate.transition_benchmark_lesson(lesson['lesson_id'], 'approved', actor='security-lead', note='Approved for compliance test.')
        return lesson


def compliance_scan(root: Path, scan_id='compliance-scan'):
    repo = root / 'repos' / 'owner__python-service'
    repo.mkdir(parents=True, exist_ok=True)
    finding = normalize_finding(
        source='bandit',
        rule_id='B602',
        title='subprocess call with shell=True',
        severity='HIGH',
        confidence='HIGH',
        path='src/runner.py',
        line=12,
        message='subprocess call with shell=True',
        cwe=['CWE-78'],
        metadata={'engine': 'bandit'},
    )
    return ScanResult(
        scan_id=scan_id,
        project_name='owner__python-service',
        target_path=str(repo),
        summary=ScanSummary(
            total_findings=1,
            high=1,
            files_scanned=3,
            languages={'Python': 3},
            tools={'bandit': 'ok findings=1', 'semgrep': 'ok findings=0'},
            priorities={'P1': 1},
            risk_tiers={'HIGH': 1},
            scope_counts={'production': 1},
            production_findings=1,
            max_risk_score=90,
            avg_risk_score=90,
        ),
        findings=[finding],
    )


def passing_python_evidence():
    return {
        'language': 'python',
        'benchmark_case_ids': [
            'python-rule-regression-001',
            'python-false-positive-001',
            'python-fix-validation-001',
        ],
        'rule_regression': {'expected_true_positives': 2, 'preserved_true_positives': 2},
        'false_positive': {'before': 3, 'after': 1, 'reviewed': 3},
        'fix_validation': {'total': 1, 'passed': 1},
        'scanner_status': 'ok',
    }


if __name__ == '__main__':
    unittest.main()
