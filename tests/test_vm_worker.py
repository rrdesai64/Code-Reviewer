import json
import os
import tempfile
import unittest
from pathlib import Path

from app.vm_worker import ALLOWED_EXPORTS, create_vm_scan_job, vm_worker_status


class DisposableVmWorkerTests(unittest.TestCase):
    def setUp(self):
        self._old_data_dir = os.environ.get('SECURE_REVIEW_DATA_DIR')
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ['SECURE_REVIEW_DATA_DIR'] = str(self.root / 'data')

    def tearDown(self):
        self.tmp.cleanup()
        if self._old_data_dir is None:
            os.environ.pop('SECURE_REVIEW_DATA_DIR', None)
        else:
            os.environ['SECURE_REVIEW_DATA_DIR'] = self._old_data_dir

    def test_prepare_windows_sandbox_job_writes_manifest_runner_and_config(self):
        repo = self.root / 'repos' / 'safe__repo'
        repo.mkdir(parents=True)

        job = create_vm_scan_job(
            repository_path=str(repo),
            repository_url='https://github.com/example/safe-repo',
            project_name='safe-repo',
            sonar_project_key='adsflaunt-enterprises_example__safe-repo',
            output_root_path=str(self.root / 'output'),
            reports_dir='reports',
            run_id='unit-run',
            network_policy='offline',
            job_name='unit-job',
        )

        self.assertEqual(job['job_id'], 'unit-job')
        self.assertEqual(job['network_policy'], 'offline')
        self.assertEqual(job['quarantine_policy']['status'], 'clear')
        self.assertIn('scan.json', [item['name'] for item in job['allowed_exports']])
        self.assertIn('runtime-plan.json', [item['name'] for item in job['allowed_exports']])
        self.assertIn('vm-worker-status.json', [item['name'] for item in job['allowed_exports']])

        for key in ['manifest', 'guest_runner', 'sandbox_config', 'launcher']:
            self.assertTrue(Path(job['files'][key]).exists(), key)

        manifest = json.loads(Path(job['files']['manifest']).read_text(encoding='utf-8'))
        sandbox = Path(job['files']['sandbox_config']).read_text(encoding='utf-8')
        runner = Path(job['files']['guest_runner']).read_text(encoding='utf-8')

        self.assertEqual(manifest['safety_controls']['host_execution'], False)
        self.assertIn('<Networking>Disable</Networking>', sandbox)
        self.assertIn('<ReadOnly>true</ReadOnly>', sandbox)
        self.assertIn('robocopy', runner)
        self.assertIn('-RuntimePlanOut', runner)
        self.assertIn('-QuarantinePolicyOut', runner)
        self.assertIn('Copy-Item', runner)

    def test_quarantined_repo_requires_explicit_approval_for_vm_job(self):
        repo = self.root / 'repos' / 'samratashok__nishang'
        repo.mkdir(parents=True)

        with self.assertRaises(ValueError):
            create_vm_scan_job(
                repository_path=str(repo),
                repository_url='https://github.com/samratashok/nishang',
                output_root_path=str(self.root / 'output'),
                run_id='unit-run',
            )

        job = create_vm_scan_job(
            repository_path=str(repo),
            repository_url='https://github.com/samratashok/nishang',
            output_root_path=str(self.root / 'output'),
            run_id='unit-run',
            approved_quarantine=True,
            job_name='nishang-approved',
        )

        self.assertEqual(job['quarantine_policy']['status'], 'quarantined')
        self.assertFalse(job['quarantine_policy']['controls']['agent_learning'])
        self.assertTrue(job['safety_controls']['requires_user_approval_for_quarantined_repo'])
        self.assertFalse(job['safety_controls']['agent_learning_allowed'])

    def test_status_reports_supported_providers_and_export_whitelist(self):
        status = vm_worker_status()

        self.assertIn('windows-sandbox', status['providers'])
        self.assertIn('manual', status['providers'])
        self.assertEqual(status['allowed_exports'], ALLOWED_EXPORTS)
        self.assertIn('Do not execute untrusted repository code on the host.', status['guardrails'])


if __name__ == '__main__':
    unittest.main()
