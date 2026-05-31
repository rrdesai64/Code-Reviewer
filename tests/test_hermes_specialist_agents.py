import os
import tempfile
import unittest

from app.benchmark_gate import benchmark_corpus_report, transition_benchmark_lesson, upsert_benchmark_lesson
from app.hermes import hermes_status, run_hermes_on_memory
from app.hermes_specialist_agents import SPECIALIST_AGENT_IDS, run_specialist_agent, specialist_agent_registry_entries


class HermesSpecialistAgentTests(unittest.TestCase):
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

    def test_registry_exposes_requested_specialist_agents(self):
        registry = hermes_status()['agent_registry']
        ids = {agent['agent_id'] for agent in registry}
        expected = {
            'hermes-javascript-typescript-security-specialist',
            'hermes-go-security-specialist',
            'hermes-rust-security-specialist',
            'hermes-php-security-specialist',
            'hermes-java-kotlin-security-specialist',
            'hermes-dotnet-csharp-security-specialist',
            'hermes-ruby-security-specialist',
            'hermes-iac-devops-security-specialist',
            'hermes-dependency-sbom-specialist',
            'hermes-secrets-malware-quarantine-specialist',
            'hermes-scanner-reliability-specialist',
        }

        self.assertEqual(expected, SPECIALIST_AGENT_IDS)
        self.assertTrue(expected <= ids)
        for agent in registry:
            if agent['agent_id'] in expected:
                self.assertEqual(agent['safety_level'], 'sanitized-memory-only')
                self.assertEqual(agent['framework_alignment']['dependency_policy'], 'no new runtime packages')
                self.assertEqual(agent['teacher_bridge']['teacher_actor'], 'codex')

    def test_language_specialists_dispatch_for_javascript_and_go(self):
        memory = memory_with_items([
            memory_item(
                item_id='js-eval',
                item_type='finding-pattern',
                title='JavaScript eval with expression',
                text='eval receives user input in src/app.ts',
                tags=['JAVASCRIPT', 'HIGH', 'P1'],
                metadata={'source': 'semgrep', 'rule_id': 'js.eval', 'severity': 'HIGH', 'priority': 'P1', 'risk_score': '82'},
            ),
            memory_item(
                item_id='go-cve',
                item_type='dependency-signal',
                title='Go vulnerable module',
                text='govulncheck reported CVE-2026-0001 in go.mod',
                tags=['GO', 'DEPENDENCY', 'HIGH', 'P1'],
                metadata={'source': 'govulncheck', 'rule_id': 'CVE-2026-0001', 'dependency_name': 'example.org/lib', 'risk_score': '88'},
            ),
        ])

        run = run_hermes_on_memory(memory, requester='unit-test', persist=False)
        agent_ids = {result['agent_id'] for result in run['agent_results']}

        self.assertIn('hermes-javascript-typescript-security-specialist', agent_ids)
        self.assertIn('hermes-go-security-specialist', agent_ids)
        js_results = [result for result in run['agent_results'] if result['agent_id'] == 'hermes-javascript-typescript-security-specialist']
        go_results = [result for result in run['agent_results'] if result['agent_id'] == 'hermes-go-security-specialist']
        self.assertTrue(any(result['task_type'] == 'javascript-typescript-specialist-review' for result in js_results))
        self.assertTrue(any(result['task_type'] == 'go-dependency-review' for result in go_results))
        self.assertTrue(all(not result['safety']['raw_code_accessed'] for result in js_results + go_results))

    def test_domain_specialists_dispatch_for_sbom_secrets_iac_and_reliability(self):
        memory = memory_with_items([
            memory_item(
                item_id='sbom-gap',
                item_type='dependency-signal',
                title='SBOM missing vulnerable package evidence',
                text='SPDX SBOM missing for lockfile with vulnerable package and broad range',
                tags=['DEPENDENCY', 'SBOM', 'HIGH'],
                metadata={'source': 'osv-scanner', 'rule_id': 'CVE-2026-0002', 'dependency_name': 'pkg-a', 'risk_score': '80'},
            ),
            memory_item(
                item_id='secret-alert',
                item_type='finding-pattern',
                title='Gitleaks secret detected',
                text='gitleaks detected token evidence and quarantine review is required',
                tags=['SECRET', 'P1', 'HIGH'],
                metadata={'source': 'gitleaks', 'rule_id': 'generic-api-key', 'severity': 'HIGH', 'risk_score': '90'},
            ),
            memory_item(
                item_id='terraform-public',
                item_type='finding-pattern',
                title='Terraform public bucket',
                text='terraform allows public bucket access from 0.0.0.0/0',
                tags=['TERRAFORM', 'HIGH'],
                metadata={'source': 'checkov', 'rule_id': 'CKV_PUBLIC_BUCKET', 'severity': 'HIGH', 'risk_score': '81'},
            ),
            memory_item(
                item_id='scanner-status',
                item_type='scanner-status',
                title='Scanner status',
                text='codeql failed during database creation; sonarqube skipped hotspot fetch',
                tags=['SCANNER'],
                metadata={'codeql': 'failed database creation', 'sonarqube': 'skipped hotspot fetch'},
            ),
        ])

        run = run_hermes_on_memory(memory, goal='release-readiness', requester='unit-test', persist=False)
        agent_ids = {result['agent_id'] for result in run['agent_results']}

        self.assertIn('hermes-dependency-sbom-specialist', agent_ids)
        self.assertIn('hermes-secrets-malware-quarantine-specialist', agent_ids)
        self.assertIn('hermes-iac-devops-security-specialist', agent_ids)
        self.assertIn('hermes-scanner-reliability-specialist', agent_ids)
        reliability_results = [result for result in run['agent_results'] if result['agent_id'] == 'hermes-scanner-reliability-specialist']
        self.assertTrue(any(result['status'] == 'coverage-gap' for result in reliability_results))
        self.assertTrue(run['synthesis']['scanner_improvement_candidates'])

    def test_specialist_uses_only_active_teacher_lessons(self):
        agent = next(agent for agent in specialist_agent_registry_entries() if agent['agent_id'] == 'hermes-javascript-typescript-security-specialist')
        task = {
            'task_id': 'task-js-eval',
            'task_type': 'javascript-typescript-specialist-review',
            'item_id': 'item-js-eval',
            'item_type': 'finding-pattern',
        }
        item = memory_item(
            item_id='item-js-eval',
            item_type='finding-pattern',
            title='JavaScript eval with expression',
            text='eval receives user input in src/app.ts',
            tags=['JAVASCRIPT', 'HIGH', 'P1'],
            metadata={'source': 'semgrep', 'rule_id': 'js.eval', 'severity': 'HIGH', 'priority': 'P1', 'risk_score': '82'},
        )

        before = run_specialist_agent(agent, task, item)
        self.assertFalse(before['specialist_review']['active_teacher_lessons'])

        lesson = upsert_benchmark_lesson(
            {
                'lesson_id': 'javascript-eval-context-lesson',
                'language': 'javascript',
                'category': 'dangerous-execution',
                'title': 'Require taint context before tuning JavaScript eval rules',
                'source': 'semgrep',
                'rule_id': 'js.eval',
                'proposed_change': 'Keep eval findings blocker-level when sanitized evidence shows user-controlled input; do not tune noise without taint context.',
                'evidence': {'teacher': 'codex', 'scan_id': 'scan-js-eval'},
            },
            actor='teacher',
        )
        after_proposed = run_specialist_agent(agent, task, item)
        self.assertFalse(after_proposed['specialist_review']['active_teacher_lessons'])

        transition_benchmark_lesson(lesson['lesson_id'], 'reviewed', actor='teacher', note='Ready for benchmark.')
        transition_benchmark_lesson(lesson['lesson_id'], 'benchmarked', actor='teacher', benchmark_evidence=passing_evidence('javascript'))
        transition_benchmark_lesson(lesson['lesson_id'], 'approved', actor='teacher', note='Approved after benchmark.')
        transition_benchmark_lesson(lesson['lesson_id'], 'active', actor='teacher', note='Activate for future JavaScript triage.')

        after_active = run_specialist_agent(agent, task, item)

        self.assertEqual(after_active['specialist_review']['active_teacher_lessons'][0]['lesson_id'], lesson['lesson_id'])
        self.assertTrue(any('Active teacher lesson applies' in item for item in after_active['recommendations']))

    def test_benchmark_corpus_covers_new_specialist_domains(self):
        languages = {item['language'] for item in benchmark_corpus_report()['languages']}

        self.assertTrue({
            'kotlin',
            'iac-devops',
            'dependency-sbom',
            'secrets-malware-quarantine',
            'scanner-reliability',
        } <= languages)


def memory_with_items(items):
    return {
        'schema_version': 1,
        'status': 'ready',
        'source': {
            'scan_id': 'specialist-scan',
            'project_name': 'owner__repo',
            'source_report_type': 'rag-memory',
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
        'item_id': item_id,
        'item_type': item_type,
        'title': title,
        'text': text,
        'tags': tags,
        'metadata': metadata,
        'source': {'scan_id': 'specialist-scan', 'project_name': 'owner__repo'},
        'eligibility': {'retrieval_allowed': True},
        'safety': {
            'raw_code_included': False,
            'patches_included': False,
            'full_local_paths_included': False,
        },
    }


def passing_evidence(language):
    return {
        'language': language,
        'benchmark_case_ids': [
            f'{language}-rule-regression-001',
            f'{language}-false-positive-001',
            f'{language}-fix-validation-001',
        ],
        'rule_regression': {'expected_true_positives': 2, 'preserved_true_positives': 2},
        'false_positive': {'before': 3, 'after': 1, 'reviewed': 3},
        'fix_validation': {'total': 1, 'passed': 1},
        'scanner_status': 'ok',
    }


if __name__ == '__main__':
    unittest.main()
