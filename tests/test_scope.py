import tempfile
import unittest
from pathlib import Path

from app.ingestion import normalize_finding
from app.models import ScanResult, ScanSummary
from app.risk import score_scan
from app.scope import apply_finding_scope, finding_scope, is_production_impacting
from app.secrets import scan_text_for_secrets


class ScopeAwareGateTests(unittest.TestCase):
    def test_test_findings_are_hygiene_not_production_gate(self):
        prod = normalize_finding(
            source='semgrep',
            rule_id='python-subprocess-shell-true',
            title='Subprocess shell true',
            severity='HIGH',
            confidence='HIGH',
            path='src/app.py',
            line=10,
            message='subprocess shell=true can allow command injection',
            cwe=['CWE-78'],
        )
        test = normalize_finding(
            source='bandit',
            rule_id='B101',
            title='assert_used',
            severity='LOW',
            confidence='HIGH',
            path='tests/test_app.py',
            line=4,
            message='Use of assert detected',
            cwe=['CWE-703'],
        )
        scan = ScanResult(scan_id='scope-test', project_name='demo', target_path='demo', summary=ScanSummary(), findings=[prod, test])
        scan.new_findings = [finding.fingerprint for finding in scan.findings]
        scan = score_scan(scan)
        self.assertEqual(finding_scope(test), 'test')
        self.assertFalse(is_production_impacting(test))
        self.assertTrue(is_production_impacting(prod))
        self.assertEqual(scan.summary.production_findings, 1)
        self.assertEqual(scan.summary.hygiene_findings, 1)
        self.assertEqual(scan.summary.priorities, {'P0': 1})
        self.assertEqual(scan.summary.all_priorities.get(test.risk.priority), 1)

    def test_high_confidence_secret_blocks_even_in_tests(self):
        secret = normalize_finding(
            source='secret-scan',
            rule_id='aws-access-key-id',
            title='AWS access key ID',
            severity='CRITICAL',
            confidence='HIGH',
            path='tests/fixtures/config.py',
            line=1,
            message='Potential AWS key detected',
            cwe=['CWE-798'],
        )
        apply_finding_scope(secret)
        self.assertEqual(finding_scope(secret), 'test')
        self.assertTrue(is_production_impacting(secret))

    def test_generic_secret_scanner_ignores_runtime_variable_assignment(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            path = target / 'src' / 'requests' / 'auth.py'
            path.parent.mkdir(parents=True)
            text = (
                'username, password = get_auth_from_url(proxy)\n'
                'password = password.encode("latin1")\n'
                'API_KEY = "abc12345realvalue"\n'
            )
            path.write_text(text, encoding='utf-8')
            findings = scan_text_for_secrets(target, path, text)
        self.assertEqual([finding.location.line for finding in findings], [3])


if __name__ == '__main__':
    unittest.main()
