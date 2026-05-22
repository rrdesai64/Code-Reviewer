import unittest

from app.ingestion import normalize_finding
from app.models import ScanResult, ScanSummary
from app.recursive_learning import recursive_learning_from_scans
from app.risk import score_scan


class RecursiveLearningTests(unittest.TestCase):
    def test_noisy_rule_recommendation_is_controlled_and_human_approved(self):
        findings = [
            normalize_finding(
                source='semgrep',
                rule_id='python-dangerous-eval',
                title='Dangerous eval',
                severity='MEDIUM',
                confidence='MEDIUM',
                path=f'tests/fixtures/test_eval_{index}.py',
                line=index + 1,
                message='eval detected in test fixture',
                cwe=['CWE-95'],
            )
            for index in range(30)
        ]
        scan = score_scan(ScanResult(
            scan_id='learning-noisy-rule',
            project_name='demo',
            target_path='demo',
            summary=ScanSummary(languages={'Python': 30}, tools={'semgrep': 'ok', 'bandit': 'ok'}),
            findings=findings,
        ))

        report = recursive_learning_from_scans([scan], audit_rows=[], scope='unit-test')
        categories = {item['category'] for item in report['scanner_improvement_recommendations']}

        self.assertIn('noisy-rule-tuning', categories)
        self.assertTrue(all(item['requires_human_approval'] for item in report['scanner_improvement_recommendations']))
        self.assertTrue(all(not item['auto_apply'] for item in report['scanner_improvement_recommendations']))
        self.assertEqual(report['promotion_gate']['requires_no_true_positive_regression'], True)

    def test_scanner_failures_and_report_usage_become_evidence(self):
        scan = ScanResult(
            scan_id='learning-failures',
            project_name='demo',
            target_path='demo',
            summary=ScanSummary(
                languages={'Go': 4, 'Rust': 3},
                tools={'codeql': 'failed: database creation timed out', 'govulncheck': 'not installed'},
            ),
            findings=[],
        )
        audit_rows = [
            {'action': 'dependencies.reviewed'},
            {'action': 'team_learning.dashboard_reported'},
            {'action': 'reports.bundle_reported'},
        ]

        report = recursive_learning_from_scans([scan], audit_rows=audit_rows, scope='unit-test')
        failures = report['evidence']['scanner_failures_by_environment']
        parser_gaps = report['evidence']['missing_language_framework_parsers']
        usage_sections = {row['key'] for row in report['evidence']['report_section_usage']['sections']}

        self.assertTrue(any(row['tool'] == 'codeql' for row in failures))
        self.assertTrue(any(row['language_or_framework'] == 'Rust' for row in parser_gaps))
        self.assertIn('Dependency Review', usage_sections)
        self.assertIn('Report Bundle', usage_sections)


if __name__ == '__main__':
    unittest.main()
