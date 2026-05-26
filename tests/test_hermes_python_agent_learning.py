import os
import tempfile
import unittest

from app.benchmark_gate import transition_benchmark_lesson, upsert_benchmark_lesson
from app.hermes_python_agent import python_agent_registry_entry, run_python_specialist


class HermesPythonAgentLearningTests(unittest.TestCase):
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

    def test_python_agent_uses_only_active_teacher_lessons(self):
        agent = python_agent_registry_entry()
        task = {
            'task_id': 'task-python-secret',
            'task_type': 'python-specialist-review',
            'item_id': 'item-python-secret',
            'item_type': 'finding-pattern',
        }
        item = {
            'item_id': 'item-python-secret',
            'item_type': 'finding-pattern',
            'title': 'Python hardcoded token',
            'text': 'Python secret token appears in sanitized evidence.',
            'tags': ['PYTHON', 'HIGH', 'P1'],
            'metadata': {
                'source': 'gitleaks',
                'rule_id': 'generic-api-key',
                'severity': 'HIGH',
                'priority': 'P1',
                'risk_score': '90',
            },
            'source': {'scan_id': 'scan-python-secret', 'project_name': 'owner__repo'},
        }

        before = run_python_specialist(agent, task, item)
        self.assertFalse(before['python_review']['active_teacher_lessons'])

        lesson = upsert_benchmark_lesson(
            {
                'lesson_id': 'python-secret-doc-fixture-context',
                'language': 'python',
                'category': 'secret-handling',
                'title': 'Use context before blocking Python secret-like fixtures',
                'source': 'gitleaks',
                'rule_id': 'generic-api-key',
                'proposed_change': 'When sanitized evidence indicates docs, tutorials, or tests, keep the item review-required unless production exposure is confirmed.',
                'evidence': {'scan_id': 'scan-python-secret', 'teacher': 'codex'},
            },
            actor='teacher',
        )
        after_proposed = run_python_specialist(agent, task, item)
        self.assertFalse(after_proposed['python_review']['active_teacher_lessons'])

        transition_benchmark_lesson(lesson['lesson_id'], 'reviewed', actor='teacher', note='Ready for benchmark.')
        transition_benchmark_lesson(
            lesson['lesson_id'],
            'benchmarked',
            actor='teacher',
            benchmark_evidence={
                'language': 'python',
                'benchmark_case_ids': ['python-rule-regression-001', 'python-false-positive-001', 'python-fix-validation-001'],
                'rule_regression': {'expected_true_positives': 1, 'preserved_true_positives': 1},
                'false_positive': {'before': 2, 'after': 1, 'reviewed': 2},
                'fix_validation': {'total': 1, 'passed': 1},
                'scanner_status': 'ok',
            },
        )
        transition_benchmark_lesson(lesson['lesson_id'], 'approved', actor='teacher', note='Approved after benchmark.')
        transition_benchmark_lesson(lesson['lesson_id'], 'active', actor='teacher', note='Activate for future Python triage.')

        after_active = run_python_specialist(agent, task, item)

        self.assertEqual(after_active['python_review']['active_teacher_lessons'][0]['lesson_id'], lesson['lesson_id'])
        self.assertTrue(any('Active teacher lesson applies' in item for item in after_active['recommendations']))


if __name__ == '__main__':
    unittest.main()
