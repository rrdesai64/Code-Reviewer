import os
import tempfile
import unittest

from app.hermes import hermes_review_queue, record_hermes_review, save_hermes_run


class HermesReviewTests(unittest.TestCase):
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

    def test_blocked_run_exposes_review_queue_and_records_decision(self):
        run = save_hermes_run(self.sample_run())

        queue = hermes_review_queue(run_id=run['run_id'])

        self.assertEqual(queue['status'], 'pending_review')
        self.assertEqual(queue['pending_count'], 1)
        self.assertEqual(queue['items'][0]['status'], 'release-blocker')
        self.assertEqual(queue['items'][0]['review_state'], 'pending')

        recorded = record_hermes_review(
            run['run_id'],
            decision='needs_fix',
            reviewer='security-reviewer',
            note='Confirmed blocker for remediation planning.',
            review_item_ids=[queue['items'][0]['review_item_id']],
        )
        reviewed = hermes_review_queue(run_id=run['run_id'], include_decided=True)

        self.assertEqual(recorded['status'], 'recorded')
        self.assertEqual(recorded['remaining_pending_count'], 0)
        self.assertEqual(reviewed['items'][0]['review_state'], 'decided')
        self.assertEqual(reviewed['items'][0]['latest_decision']['decision'], 'needs_fix')
        self.assertFalse(recorded['review']['safety']['scanner_rule_mutated'])
        self.assertFalse(recorded['review']['safety']['repository_mutated'])

    def test_unknown_review_item_is_rejected(self):
        run = save_hermes_run(self.sample_run(run_id='hermes-review-unknown'))

        with self.assertRaisesRegex(ValueError, 'unknown Hermes review item'):
            record_hermes_review(
                run['run_id'],
                decision='acknowledged',
                reviewer='security-reviewer',
                review_item_ids=['not-a-real-review-item'],
            )

    def sample_run(self, run_id='hermes-review-test'):
        return {
            'schema_version': 1,
            'run_id': run_id,
            'run_type': 'hermes-orchestration',
            'created_at': '2026-05-26T00:00:00Z',
            'completed_at': '2026-05-26T00:00:01Z',
            'duration_seconds': 1,
            'status': 'blocked',
            'requester': 'test',
            'goal': 'secure-review-triage',
            'source': {
                'scan_id': 'scan-review-1',
                'project_name': 'owner__repo',
                'memory_version_id': 'mem-review-1',
            },
            'policy': {'decision': 'allowed'},
            'agent_registry': [],
            'plan': {'task_count': 1, 'task_type_counts': {'risk-triage': 1}, 'agent_count': 1, 'goal': 'secure-review-triage'},
            'tasks': [],
            'agent_results': [
                {
                    'result_id': 'result-blocker',
                    'agent_id': 'hermes-risk-governor',
                    'agent_name': 'Hermes Risk Governor',
                    'agent_version': '1.0.0',
                    'task_id': 'task-1',
                    'task_type': 'risk-triage',
                    'item_id': 'item-1',
                    'item_type': 'finding-pattern',
                    'status': 'release-blocker',
                    'confidence': 'high',
                    'findings': ['Release-blocking sanitized risk signal detected.'],
                    'recommendations': ['Confirm true-positive status and owner before merge.'],
                    'evidence_refs': {'scan_id': 'scan-review-1', 'memory_item_id': 'item-1'},
                    'safety': {'raw_code_accessed': False, 'repository_executed': False, 'external_calls_made': False, 'files_modified': False},
                },
                {
                    'result_id': 'result-record-only',
                    'agent_id': 'hermes-risk-governor',
                    'agent_name': 'Hermes Risk Governor',
                    'agent_version': '1.0.0',
                    'task_id': 'task-2',
                    'task_type': 'risk-triage',
                    'item_id': 'item-2',
                    'item_type': 'finding-pattern',
                    'status': 'record-only',
                    'confidence': 'low',
                    'findings': ['No release-blocking risk factor detected.'],
                    'recommendations': ['Track through normal review cadence.'],
                    'evidence_refs': {'scan_id': 'scan-review-1', 'memory_item_id': 'item-2'},
                    'safety': {'raw_code_accessed': False, 'repository_executed': False, 'external_calls_made': False, 'files_modified': False},
                },
            ],
            'agent_errors': [],
            'synthesis': {
                'status': 'blocked',
                'summary': 'Hermes found 1 blocker result(s) for owner__repo; human security review is required.',
            },
            'approvals': {'human_approval_required': True, 'benchmark_gate_required': True, 'auto_apply_allowed': False},
            'guardrails': [],
        }


if __name__ == '__main__':
    unittest.main()
