import os
import tempfile
import unittest

from app.teaching_loop import (
    DEFERRED,
    MASTERED,
    load_teaching_session,
    run_teaching_loop_on_memory,
    teaching_loop_schema,
)


class TeachingLoopTests(unittest.TestCase):
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

    def test_teaching_loop_masters_sanitized_memory_with_hermes_student_answer(self):
        session = run_teaching_loop_on_memory(
            memory_with_items([
                memory_item(
                    item_id='py-dangerous-exec',
                    item_type='finding-pattern',
                    title='Python subprocess shell=True',
                    text='Python subprocess shell=True command injection evidence from Bandit.',
                    tags=['PYTHON', 'HIGH', 'P1', 'CWE-78'],
                    metadata={'source': 'bandit', 'rule_id': 'B602', 'severity': 'HIGH', 'priority': 'P1', 'risk_score': '88'},
                )
            ]),
            requester='unit-test',
            persist=True,
        )
        loaded = load_teaching_session(session['session_id'])

        self.assertEqual(session['status'], MASTERED)
        self.assertEqual(session['synthesis']['mastered_count'], 1)
        self.assertEqual(session['curriculum'][0]['status'], MASTERED)
        self.assertTrue(session['mastered_records'])
        self.assertTrue(session['mastered_records'][0]['future_use']['requires_benchmark_gate'])
        self.assertFalse(session['safety']['raw_repository_reads_allowed'])
        self.assertEqual(loaded['session_id'], session['session_id'])

    def test_teaching_loop_blocks_memory_with_raw_code_safety_violation(self):
        item = memory_item(
            item_id='unsafe-item',
            item_type='finding-pattern',
            title='Unsafe memory item',
            text='raw code should not be present',
            tags=['HIGH'],
            metadata={'risk_score': '80'},
        )
        item['safety']['raw_code_included'] = True

        session = run_teaching_loop_on_memory(memory_with_items([item]), requester='unit-test', persist=False)

        self.assertEqual(session['status'], 'blocked')
        self.assertFalse(session['curriculum'])
        self.assertIn('safety violations', '; '.join(session['policy']['blocked_reasons']))

    def test_teaching_loop_circuit_breaker_defers_items_without_student_answer(self):
        session = run_teaching_loop_on_memory(
            memory_with_items([
                memory_item(
                    item_id='unknown-item',
                    item_type='unknown-memory-type',
                    title='Unknown teaching topic',
                    text='No Hermes task type should be planned for this item.',
                    tags=['UNKNOWN'],
                    metadata={},
                )
            ]),
            requester='unit-test',
            max_attempts=2,
            pass_score=7,
            persist=False,
        )

        self.assertEqual(session['status'], 'review_required')
        self.assertEqual(session['curriculum'][0]['status'], DEFERRED)
        self.assertEqual(session['curriculum'][0]['attempt_count'], 2)
        self.assertEqual(session['synthesis']['deferred_count'], 1)
        self.assertFalse(session['mastered_records'])

    def test_schema_permanently_disallows_vm_or_raw_repo_learning(self):
        source_contract = teaching_loop_schema()['source_contract']

        self.assertFalse(source_contract['raw_repository_reads_allowed'])
        self.assertFalse(source_contract['raw_report_file_reads_allowed'])
        self.assertFalse(source_contract['disposable_vm_code_inspection_allowed'])
        self.assertFalse(source_contract['source_execution_allowed'])


def memory_with_items(items):
    return {
        'schema_version': 1,
        'memory_record_type': 'rag-memory-scan',
        'status': 'indexed',
        'source': {
            'scan_id': 'teaching-scan',
            'project_name': 'owner__repo',
            'source_report_type': 'rag-memory',
            'memory_version_id': 'mem-test',
        },
        'eligibility': {
            'rag_ingest_allowed': True,
            'agent_learning_allowed': True,
        },
        'item_count': len(items),
        'items': items,
    }


def memory_item(*, item_id, item_type, title, text, tags, metadata):
    return {
        'schema_version': 1,
        'item_id': item_id,
        'item_type': item_type,
        'title': title,
        'text': text,
        'tags': tags,
        'metadata': metadata,
        'source': {'scan_id': 'teaching-scan', 'project_name': 'owner__repo', 'memory_version_id': 'mem-test'},
        'eligibility': {
            'retrieval_allowed': True,
            'agent_learning_allowed': True,
            'fine_tuning_allowed': False,
            'requires_human_review': True,
            'requires_benchmark_gate': True,
        },
        'safety': {
            'source_record_type': 'sanitized-report-lake',
            'raw_code_included': False,
            'patches_included': False,
            'full_local_paths_included': False,
            'secret_redaction': 'inherited-from-sanitized-report-lake',
        },
        'created_at': '2026-05-27T00:00:00+00:00',
    }


if __name__ == '__main__':
    unittest.main()
