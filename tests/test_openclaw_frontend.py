import importlib
import os
import tempfile
import unittest
from pathlib import Path

from app.ingestion import normalize_finding
from app.models import ScanResult, ScanSummary


class OpenClawFrontendTests(unittest.TestCase):
    def setUp(self):
        self._old_data_dir = os.environ.get('SECURE_REVIEW_DATA_DIR')
        self._old_output_root = os.environ.get('SECURE_REVIEW_OUTPUT_ROOT')
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ['SECURE_REVIEW_DATA_DIR'] = str(self.root / 'data')
        os.environ['SECURE_REVIEW_OUTPUT_ROOT'] = str(self.root / 'output')

        import app.benchmark_gate as benchmark_gate
        import app.openclaw_frontend as openclaw_frontend
        import app.storage as storage
        import app.vm_worker as vm_worker

        self.storage = importlib.reload(storage)
        self.benchmark_gate = importlib.reload(benchmark_gate)
        self.vm_worker = importlib.reload(vm_worker)
        self.openclaw = importlib.reload(openclaw_frontend)

    def tearDown(self):
        self.tmp.cleanup()
        restore_env('SECURE_REVIEW_DATA_DIR', self._old_data_dir)
        restore_env('SECURE_REVIEW_OUTPUT_ROOT', self._old_output_root)

    def test_status_command_reads_saved_scan_from_openclaw_payload(self):
        scan = self.save_safe_scan()

        result = self.openclaw.handle_openclaw_message({
            'channel': 'telegram',
            'message': {
                'text': f'status {scan.scan_id}',
                'from': {'username': 'rama'},
                'chat': {'id': 'secure-review'},
            },
        }, actor='unit-test')

        self.assertTrue(result['accepted'])
        self.assertEqual(result['channel'], 'telegram')
        self.assertEqual(result['sender'], 'rama')
        self.assertEqual(result['backend_action']['method'], 'GET')
        self.assertFalse(result['backend_action']['mutating'])
        self.assertEqual(result['payload']['scan_id'], scan.scan_id)

    def test_explain_finding_uses_existing_ai_review_without_prompt_templates(self):
        scan = self.save_safe_scan()
        finding_id = scan.findings[0].id

        result = self.openclaw.handle_openclaw_message({
            'channel': 'whatsapp',
            'messages': [{'from': '+15555550123', 'text': {'body': f'explain {scan.scan_id} {finding_id}'}}],
        }, actor='unit-test')
        encoded = str(result)

        self.assertTrue(result['accepted'])
        self.assertEqual(result['feature_id'], 'explain-finding')
        self.assertEqual(result['payload']['finding_id'], finding_id)
        self.assertFalse(result['backend_action']['mutating'])
        self.assertNotIn('prompt_templates', encoded)

    def test_benchmark_lesson_approval_routes_through_backend_gate(self):
        lesson = self.benchmark_gate.upsert_benchmark_lesson({
            'recommendation_id': 'rec-openclaw',
            'language': 'python',
            'category': 'noisy-rule-tuning',
            'title': 'Tighten subprocess rule',
            'source': 'bandit',
            'rule_id': 'B602',
            'proposed_change': 'Candidate rule tuning.',
        }, actor='unit-test')
        self.benchmark_gate.transition_benchmark_lesson(lesson['lesson_id'], 'reviewed', actor='unit-test')
        self.benchmark_gate.transition_benchmark_lesson(
            lesson['lesson_id'],
            'benchmarked',
            actor='unit-test',
            benchmark_evidence=passing_python_evidence(),
        )

        approved = self.openclaw.handle_openclaw_message(
            {'channel': 'slack', 'text': f'approve lesson {lesson["lesson_id"]}', 'user': 'approver'},
            actor='approver',
        )
        active = self.openclaw.handle_openclaw_message(
            {'channel': 'slack', 'text': f'activate lesson {lesson["lesson_id"]}', 'user': 'approver'},
            actor='approver',
        )

        self.assertEqual(approved['payload']['lesson']['promotion_state'], 'approved')
        self.assertEqual(active['payload']['lesson']['promotion_state'], 'active')
        self.assertTrue(active['payload']['lesson']['learning_influence_allowed'])
        self.assertTrue(active['backend_action']['mutating'])
        self.assertFalse(active['backend_action']['scanner_rule_mutation_allowed'])

    def test_rerun_vm_prepares_job_without_launching_guest(self):
        scan = self.save_safe_scan()

        result = self.openclaw.handle_openclaw_message(
            {'channel': 'teams', 'text': f'rerun this repo in disposable vm {scan.scan_id}', 'user': 'secops'},
            actor='secops',
        )
        job = result['payload']['job']

        self.assertEqual(result['status'], 'prepared')
        self.assertEqual(job['status'], 'prepared')
        self.assertEqual(job['network_policy'], 'offline')
        self.assertFalse(result['backend_action']['launch_executed'])
        self.assertIn('openclaw-control.json', [item['name'] for item in job['allowed_exports']])

    def test_direct_scanner_mutation_request_is_blocked(self):
        result = self.openclaw.handle_openclaw_message({
            'channel': 'api',
            'text': 'disable rule B602 now',
            'user': 'operator',
        }, actor='operator')

        self.assertFalse(result['accepted'])
        self.assertEqual(result['status'], 'blocked')
        self.assertIn('disable rule', result['payload']['reason'])

    def test_status_reports_peter_steinberger_openclaw_integration(self):
        status = self.openclaw.openclaw_status()

        self.assertEqual(status['upstream']['repository'], 'openclaw/openclaw')
        self.assertEqual(status['upstream']['creator'], 'Peter Steinberger')
        self.assertFalse(status['upstream']['runtime_dependency_installed'])
        self.assertIn('whatsapp', status['channels'])
        self.assertFalse(status['security']['direct_scanner_rule_mutation_allowed'])

    def save_safe_scan(self):
        repo = self.root / 'repos' / 'owner__python-service'
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
        scan = ScanResult(
            scan_id='openclaw-scan',
            project_name='owner__python-service',
            target_path=str(repo),
            summary=ScanSummary(
                total_findings=1,
                high=1,
                files_scanned=3,
                languages={'Python': 3},
                tools={'bandit': 'ok findings=1'},
                priorities={'P1': 1},
                risk_tiers={'HIGH': 1},
                scope_counts={'production': 1},
                production_findings=1,
                hygiene_findings=0,
                max_risk_score=90,
                avg_risk_score=90,
            ),
            findings=[finding],
        )
        self.storage.save_scan(scan)
        return scan


def passing_python_evidence():
    return {
        'language': 'python',
        'benchmark_case_ids': [
            'python-rule-regression-001',
            'python-false-positive-001',
            'python-fix-validation-001',
        ],
        'rule_regression': {'expected_true_positives': 3, 'preserved_true_positives': 3},
        'false_positive': {'before': 7, 'after': 3, 'reviewed': 7},
        'fix_validation': {'total': 2, 'passed': 2},
        'scanner_status': 'ok',
    }


def restore_env(name, value):
    if value is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = value


if __name__ == '__main__':
    unittest.main()
