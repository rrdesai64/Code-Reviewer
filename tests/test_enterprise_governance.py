import importlib
import os
import tempfile
import unittest
from pathlib import Path

from app.ingestion import normalize_finding
from app.models import ScanResult, ScanSummary
from app.report_lake import sanitized_scan_report


class EnterpriseGovernanceTests(unittest.TestCase):
    def setUp(self):
        self._old_data_dir = os.environ.get('SECURE_REVIEW_DATA_DIR')
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ['SECURE_REVIEW_DATA_DIR'] = str(self.root / 'data')

        import app.enterprise as enterprise
        import app.governance as governance
        import app.rag_memory as rag_memory
        import app.hermes as hermes
        import app.benchmark_gate as benchmark_gate

        self.enterprise = importlib.reload(enterprise)
        self.governance = importlib.reload(governance)
        self.rag_memory = importlib.reload(rag_memory)
        self.hermes = importlib.reload(hermes)
        self.benchmark_gate = importlib.reload(benchmark_gate)

    def tearDown(self):
        self.tmp.cleanup()
        if self._old_data_dir is None:
            os.environ.pop('SECURE_REVIEW_DATA_DIR', None)
        else:
            os.environ['SECURE_REVIEW_DATA_DIR'] = self._old_data_dir

    def test_hermes_agent_actions_are_governance_audited_with_memory_version(self):
        memory = self.save_memory(scan_id='gov-scan', finding_count=1)

        run = self.hermes.run_hermes_on_memory(memory, requester='unit-test', persist=True)
        events = self.governance.governance_events(category='agent-action')
        report = self.governance.enterprise_governance_report(scan_id='gov-scan')

        self.assertGreater(run['governance']['agent_action_events'], 0)
        self.assertGreater(len(events), 0)
        self.assertEqual(run['source']['memory_version_id'], memory['memory_version']['version_id'])
        self.assertGreater(report['agent_actions']['count'], 0)
        self.assertEqual(report['memory_lineage']['versions'][0]['version_id'], memory['memory_version']['version_id'])
        self.assertFalse(report['openclaw']['local_dependency_status']['package_dependency_present'])

    def test_lesson_approval_records_who_approved_what_and_why(self):
        lesson = self.benchmark_gate.upsert_benchmark_lesson({
            'recommendation_id': 'rec-governance',
            'language': 'python',
            'category': 'noisy-rule-tuning',
            'title': 'Tighten subprocess rule',
            'source': 'bandit',
            'rule_id': 'B602',
            'proposed_change': 'Candidate rule tuning.',
            'evidence': {'scan_id': 'gov-scan'},
        }, actor='appsec')

        self.benchmark_gate.transition_benchmark_lesson(lesson['lesson_id'], 'reviewed', actor='reviewer', note='Reviewed noisy finding trend.')
        self.benchmark_gate.transition_benchmark_lesson(
            lesson['lesson_id'],
            'benchmarked',
            actor='benchmark-bot',
            benchmark_evidence=passing_python_evidence(),
        )
        self.benchmark_gate.transition_benchmark_lesson(lesson['lesson_id'], 'approved', actor='security-lead', note='Approved after benchmark pass.')

        report = self.governance.enterprise_governance_report(scan_id='gov-scan')
        record = next(item for item in report['approvals']['records'] if item['lesson_id'] == lesson['lesson_id'])
        approval_events = self.governance.governance_events(category='approval', scan_id='gov-scan')

        self.assertEqual(record['approved_by'], 'security-lead')
        self.assertEqual(record['approval_note'], 'Approved after benchmark pass.')
        self.assertEqual(record['promotion_reason'], 'Approved after benchmark pass.')
        self.assertTrue(record['benchmark_passed'])
        self.assertTrue(any(event['action'] == 'lesson.approved' for event in approval_events))

    def test_rag_memory_version_can_be_rolled_back(self):
        first = self.save_memory(scan_id='rollback-scan', finding_count=1)
        second = self.save_memory(scan_id='rollback-scan', finding_count=2)
        first_version = first['memory_version']['version_id']

        self.assertNotEqual(first_version, second['memory_version']['version_id'])
        self.assertGreater(second['item_count'], first['item_count'])

        rollback = self.rag_memory.rollback_rag_memory_version(first_version, actor='unit-test', reason='Regression in second memory version.')
        loaded = self.rag_memory.load_scan_rag_memory('rollback-scan')
        active = [item for item in self.rag_memory.list_memory_versions(scan_id='rollback-scan') if item.get('active')]
        rollback_events = self.governance.governance_events(category='memory-rollback', scan_id='rollback-scan')

        self.assertEqual(rollback['status'], 'rolled_back')
        self.assertEqual(loaded['memory_version']['version_id'], first_version)
        self.assertEqual(loaded['item_count'], first['item_count'])
        self.assertEqual(active[0]['version_id'], first_version)
        self.assertTrue(rollback_events)

    def save_memory(self, scan_id='gov-scan', finding_count=1):
        scan = governance_scan(self.root, scan_id=scan_id, finding_count=finding_count)
        return self.rag_memory.save_rag_memory_for_report(sanitized_scan_report(scan))


def governance_scan(root: Path, scan_id='gov-scan', finding_count=1):
    repo = root / 'repos' / 'owner__python-service'
    repo.mkdir(parents=True, exist_ok=True)
    findings = []
    for index in range(finding_count):
        findings.append(normalize_finding(
            source='bandit',
            rule_id='B602',
            title='subprocess call with shell=True',
            severity='HIGH',
            confidence='HIGH',
            path=f'src/runner_{index}.py',
            line=12,
            message='subprocess call with shell=True',
            cwe=['CWE-78'],
            metadata={'engine': 'bandit'},
        ))
    return ScanResult(
        scan_id=scan_id,
        project_name='owner__python-service',
        target_path=str(repo),
        summary=ScanSummary(
            total_findings=finding_count,
            high=finding_count,
            files_scanned=3,
            languages={'Python': 3},
            tools={'bandit': f'ok findings={finding_count}', 'semgrep': 'ok findings=0'},
            priorities={'P1': finding_count},
            risk_tiers={'HIGH': finding_count},
            scope_counts={'production': finding_count},
            production_findings=finding_count,
            hygiene_findings=0,
            max_risk_score=90,
            avg_risk_score=90,
        ),
        findings=findings,
    )


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


if __name__ == '__main__':
    unittest.main()
