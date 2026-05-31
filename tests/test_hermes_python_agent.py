import json
import os
import tempfile
import unittest

from app.hermes import hermes_status, run_hermes_on_memory
from app.hermes_python_agent import PYTHON_AGENT_ID
from app.ingestion import normalize_finding
from app.models import ScanResult, ScanSummary
from app.rag_memory import save_rag_memory_for_report
from app.report_lake import sanitized_scan_report


class HermesPythonAgentTests(unittest.TestCase):
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

    def test_python_specialist_reviews_high_risk_execution_patterns(self):
        memory = save_rag_memory_for_report(sanitized_scan_report(self.python_scan(
            scan_id='py-exec',
            source='bandit',
            rule_id='B602',
            title='subprocess call with shell=True',
            severity='HIGH',
            path='pkg/runner.py',
            message='subprocess call with shell=True and password=supersecret',
            cwe=['CWE-78'],
            metadata={'engine': 'bandit'},
        )))

        run = run_hermes_on_memory(memory, requester='unit-test', persist=False)
        python_results = [result for result in run['agent_results'] if result['agent_id'] == PYTHON_AGENT_ID]
        specialist = [result for result in python_results if result['task_type'] == 'python-specialist-review']
        encoded = json.dumps(run)

        self.assertTrue(specialist)
        self.assertIn(specialist[0]['status'], {'release-blocker', 'review-required'})
        self.assertIn('bandit -r .', specialist[0]['python_review']['validation_commands'])
        self.assertIn('pytest', specialist[0]['python_review']['validation_commands'])
        self.assertNotIn('supersecret', encoded)
        self.assertNotIn('G:\\', encoded)
        self.assertTrue(all(not result['safety']['raw_code_accessed'] for result in python_results))

    def test_python_specialist_reviews_pip_audit_dependency_risk(self):
        memory = save_rag_memory_for_report(sanitized_scan_report(self.python_scan(
            scan_id='py-dependency',
            source='pip-audit',
            rule_id='CVE-2026-0001',
            title='Vulnerable dependency: examplepkg',
            severity='HIGH',
            path='requirements.txt',
            message='examplepkg has a vulnerable range',
            metadata={'engine': 'pip-audit', 'dependency_name': 'examplepkg', 'fix_versions': '2.0.0'},
        )))

        run = run_hermes_on_memory(memory, goal='supply-chain-review', requester='unit-test', persist=False)
        dependency_results = [
            result
            for result in run['agent_results']
            if result['agent_id'] == PYTHON_AGENT_ID and result['task_type'] == 'python-dependency-review'
        ]

        self.assertTrue(dependency_results)
        self.assertEqual(dependency_results[0]['status'], 'critical-dependency-risk')
        self.assertIn('pip-audit', dependency_results[0]['python_review']['validation_commands'])

    def test_python_specialist_flags_scanner_coverage_gap(self):
        scan = self.python_scan(
            scan_id='py-scanner-gap',
            source='semgrep',
            rule_id='python.lang.security.audit.dangerous-subprocess-use',
            title='Dangerous subprocess use',
            severity='MEDIUM',
            path='service/task.py',
            message='subprocess call requires review',
        )
        scan.summary.tools = {
            'semgrep': 'ok findings=1',
            'bandit': 'error executable not found',
        }
        memory = save_rag_memory_for_report(sanitized_scan_report(scan))

        run = run_hermes_on_memory(memory, goal='scanner-improvement-planning', requester='unit-test', persist=False)
        coverage_results = [
            result
            for result in run['agent_results']
            if result['agent_id'] == PYTHON_AGENT_ID and result['task_type'] == 'python-scanner-coverage-review'
        ]

        self.assertTrue(coverage_results)
        self.assertEqual(coverage_results[0]['status'], 'coverage-gap')
        self.assertTrue(any('bandit' in item.lower() for item in coverage_results[0]['findings']))
        self.assertTrue(coverage_results[0]['python_review']['requires_benchmark_gate'])

    def test_non_python_items_do_not_dispatch_python_specialist(self):
        finding = normalize_finding(
            source='semgrep',
            rule_id='javascript.lang.security.audit.detect-eval-with-expression',
            title='JavaScript eval',
            severity='HIGH',
            path='src/app.js',
            message='eval with expression',
            cwe=['CWE-95'],
            metadata={'engine': 'semgrep'},
        )
        scan = ScanResult(
            scan_id='js-only',
            project_name='owner__node-service',
            target_path='E:\\secure-review\\repos\\owner__node-service',
            summary=ScanSummary(
                total_findings=1,
                high=1,
                files_scanned=3,
                languages={'JavaScript': 3},
                tools={'semgrep': 'ok findings=1', 'codeql': 'ok findings=1'},
                priorities={'P1': 1},
                risk_tiers={'HIGH': 1},
                scope_counts={'production': 1},
                production_findings=1,
                max_risk_score=80,
                avg_risk_score=80,
            ),
            findings=[finding],
        )
        memory = save_rag_memory_for_report(sanitized_scan_report(scan))

        run = run_hermes_on_memory(memory, requester='unit-test', persist=False)

        self.assertFalse(any(result['agent_id'] == PYTHON_AGENT_ID for result in run['agent_results']))

    def test_registry_exposes_python_agent_alignment(self):
        registry = hermes_status()['agent_registry']
        python_agent = next(agent for agent in registry if agent['agent_id'] == PYTHON_AGENT_ID)

        self.assertEqual(python_agent['framework_alignment']['upstream'], 'NousResearch/hermes-agent')
        self.assertEqual(python_agent['framework_alignment']['dependency_policy'], 'no new runtime packages')

    def python_scan(self, *, scan_id, source, rule_id, title, severity, path, message, cwe=None, metadata=None):
        finding = normalize_finding(
            source=source,
            rule_id=rule_id,
            title=title,
            severity=severity,
            confidence='HIGH',
            path=path,
            message=message,
            cwe=cwe or [],
            metadata=metadata or {},
        )
        return ScanResult(
            scan_id=scan_id,
            project_name='owner__python-service',
            target_path='E:\\secure-review\\repos\\owner__python-service',
            summary=ScanSummary(
                total_findings=1,
                high=1 if severity in {'HIGH', 'CRITICAL'} else 0,
                medium=1 if severity == 'MEDIUM' else 0,
                files_scanned=5,
                languages={'Python': 5},
                tools={
                    'bandit': 'ok findings=1',
                    'pip-audit': 'ok findings=0',
                    'python-ast': 'ok findings=0',
                    'semgrep': 'ok findings=1',
                    'codeql': 'ok findings=0',
                },
                priorities={'P1': 1},
                risk_tiers={'HIGH': 1},
                scope_counts={'production': 1},
                production_findings=1,
                max_risk_score=85,
                avg_risk_score=85,
            ),
            findings=[finding],
        )


if __name__ == '__main__':
    unittest.main()
