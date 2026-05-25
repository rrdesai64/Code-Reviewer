import os
import tempfile
import unittest

from app.benchmark_gate import (
    PROMOTION_STATES,
    benchmark_corpus_report,
    benchmark_gate_report_for_recommendations,
    benchmark_gate_status,
    transition_benchmark_lesson,
    upsert_benchmark_lesson,
)
from app.ingestion import normalize_finding
from app.models import ScanResult, ScanSummary
from app.recursive_learning import recursive_learning_from_scans


class BenchmarkGateTests(unittest.TestCase):
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

    def test_corpus_has_required_case_types_per_language(self):
        report = benchmark_corpus_report()

        self.assertGreaterEqual(report['language_count'], 10)
        for language in report['languages']:
            case_types = {case['case_type'] for case in language['cases']}
            self.assertTrue({'rule-regression', 'false-positive', 'fix-validation'} <= case_types)

    def test_lesson_cannot_skip_review_or_benchmark_gate(self):
        lesson = upsert_benchmark_lesson({
            'language': 'python',
            'category': 'noisy-rule-tuning',
            'title': 'Tighten test Python rule',
            'source': 'bandit',
            'rule_id': 'B602',
            'proposed_change': 'Candidate rule tuning.',
        }, actor='unit-test')

        with self.assertRaises(ValueError):
            transition_benchmark_lesson(lesson['lesson_id'], 'active', actor='unit-test')

        reviewed = transition_benchmark_lesson(lesson['lesson_id'], 'reviewed', actor='unit-test', note='Evidence reviewed.')
        self.assertEqual(reviewed['promotion_state'], 'reviewed')

        with self.assertRaises(ValueError):
            transition_benchmark_lesson(reviewed['lesson_id'], 'benchmarked', actor='unit-test', benchmark_evidence={
                'language': 'python',
                'rule_regression': {'expected_true_positives': 2, 'preserved_true_positives': 1},
                'false_positive': {'before': 4, 'after': 3, 'reviewed': 4},
                'fix_validation': {'total': 1, 'passed': 1},
                'scanner_status': 'ok',
            })

    def test_approved_benchmarked_lesson_can_become_active_influence(self):
        lesson = upsert_benchmark_lesson({
            'recommendation_id': 'rec-123',
            'language': 'python',
            'category': 'noisy-rule-tuning',
            'title': 'Tighten Python subprocess rule',
            'source': 'bandit',
            'rule_id': 'B602',
            'proposed_change': 'Candidate rule tuning.',
        }, actor='unit-test')

        transition_benchmark_lesson(lesson['lesson_id'], 'reviewed', actor='unit-test', note='Reviewed by AppSec.')
        benchmarked = transition_benchmark_lesson(
            lesson['lesson_id'],
            'benchmarked',
            actor='unit-test',
            benchmark_evidence=passing_python_evidence(),
        )
        approved = transition_benchmark_lesson(lesson['lesson_id'], 'approved', actor='unit-test', note='Approved for activation.')
        active = transition_benchmark_lesson(lesson['lesson_id'], 'active', actor='unit-test', note='Activated.')

        self.assertEqual(benchmarked['benchmark']['status'], 'passed')
        self.assertEqual(approved['promotion_state'], 'approved')
        self.assertEqual(active['promotion_state'], 'active')
        self.assertTrue(active['learning_influence_allowed'])
        self.assertEqual(benchmark_gate_status()['active_influence_count'], 1)

    def test_recommendations_are_blocked_until_matching_lesson_is_active(self):
        recommendation = {
            'id': 'rec-123',
            'category': 'noisy-rule-tuning',
            'title': 'Tighten Python subprocess rule',
            'priority': 'high',
            'evidence': {'source': 'bandit', 'rule_id': 'B602', 'language_or_framework': 'python'},
            'requires_human_approval': True,
        }

        blocked = benchmark_gate_report_for_recommendations([recommendation])
        self.assertEqual(blocked['status'], 'blocked_until_benchmarked_and_approved')
        self.assertFalse(blocked['recommendations'][0]['learning_influence_allowed'])

        lesson = upsert_benchmark_lesson({
            'recommendation_id': 'rec-123',
            'language': 'python',
            'category': 'noisy-rule-tuning',
            'title': 'Tighten Python subprocess rule',
            'source': 'bandit',
            'rule_id': 'B602',
            'proposed_change': 'Candidate rule tuning.',
        }, actor='unit-test')
        transition_benchmark_lesson(lesson['lesson_id'], 'reviewed', actor='unit-test')
        transition_benchmark_lesson(lesson['lesson_id'], 'benchmarked', actor='unit-test', benchmark_evidence=passing_python_evidence())
        transition_benchmark_lesson(lesson['lesson_id'], 'approved', actor='unit-test')
        transition_benchmark_lesson(lesson['lesson_id'], 'active', actor='unit-test')

        allowed = benchmark_gate_report_for_recommendations([recommendation])
        self.assertEqual(allowed['status'], 'influence_allowed')
        self.assertTrue(allowed['recommendations'][0]['learning_influence_allowed'])
        self.assertEqual(allowed['recommendations'][0]['promotion']['state'], 'active')

    def test_recursive_learning_emits_benchmark_gate_metadata(self):
        scan = noisy_python_scan()

        report = recursive_learning_from_scans([scan], audit_rows=[])

        self.assertIn('benchmark_gate', report)
        self.assertIn('approved_learning_influences', report)
        self.assertTrue(report['scanner_improvement_recommendations'])
        self.assertTrue(all(not item['learning_influence_allowed'] for item in report['scanner_improvement_recommendations']))
        self.assertEqual(report['promotion_gate']['states'], PROMOTION_STATES)


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


def noisy_python_scan():
    findings = []
    for index in range(30):
        finding = normalize_finding(
            source='bandit',
            rule_id='B602',
            title='subprocess call with shell=True',
            severity='HIGH',
            confidence='HIGH',
            path=f'tests/test_runner_{index}.py',
            line=10,
            message='subprocess call with shell=True',
            cwe=['CWE-78'],
            metadata={'engine': 'bandit'},
        )
        finding.decision = 'false_positive'
        finding.decision_reason = 'Reviewed benign test helper.'
        findings.append(finding)
    return ScanResult(
        scan_id='bench-learning-scan',
        project_name='owner__python-service',
        target_path='E:\\secure-review\\repos\\owner__python-service',
        summary=ScanSummary(
            total_findings=len(findings),
            high=len(findings),
            files_scanned=30,
            languages={'Python': 30},
            tools={'bandit': 'ok findings=30', 'semgrep': 'ok findings=0', 'pip-audit': 'ok findings=0'},
            priorities={'P1': len(findings)},
            risk_tiers={'HIGH': len(findings)},
            scope_counts={'test': len(findings)},
            production_findings=0,
            hygiene_findings=len(findings),
            max_risk_score=0,
            avg_risk_score=0,
        ),
        findings=findings,
    )


if __name__ == '__main__':
    unittest.main()
