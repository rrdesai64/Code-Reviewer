import importlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from app.models import Finding, FixSuggestion, Location, RiskScore, ScanResult, ScanSummary


class MessagingGatewayTests(unittest.TestCase):
    def setUp(self):
        self._old_env = dict(os.environ)
        self.tmp = tempfile.TemporaryDirectory()
        os.environ['SECURE_REVIEW_DATA_DIR'] = str(Path(self.tmp.name) / 'data')
        for key in list(os.environ):
            if key.startswith('GATEWAY_') or key in {
                'SLACK_WEBHOOK_URL',
                'TEAMS_WEBHOOK_URL',
                'SMTP_HOST',
                'EMAIL_FROM',
                'EMAIL_TO',
                'TELEGRAM_BOT_TOKEN',
                'TELEGRAM_CHAT_ID',
            }:
                os.environ.pop(key, None)

        import app.storage as storage
        import app.governance as governance
        import app.messaging_gateway as messaging_gateway

        self.storage = importlib.reload(storage)
        self.governance = importlib.reload(governance)
        self.gateway = importlib.reload(messaging_gateway)
        self.scan = sample_scan()
        self.storage.save_scan(self.scan)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old_env)
        self.tmp.cleanup()

    def test_status_reports_initial_gateway_channels(self):
        status = self.gateway.gateway_status()

        self.assertEqual(status['service'], 'secure-review-messaging-gateway')
        self.assertEqual(set(status['supported_channels']), {'slack', 'teams', 'email', 'telegram'})
        self.assertFalse(status['channels']['slack']['configured'])
        self.assertTrue(status['dry_run_default'])

    def test_scan_report_dry_runs_all_configured_channels_and_records_event(self):
        configure_all_channels()

        report = self.gateway.build_scan_gateway_report(self.scan, publish=True, persist=True, actor='unit-test')
        events = self.gateway.gateway_events()['events']
        governance = self.governance.governance_events(category='messaging-gateway')

        self.assertEqual(report['status'], 'dry_run')
        self.assertEqual(report['delivery']['dry_run'], 4)
        self.assertEqual(set(report['artifacts']), {'slack', 'teams', 'email', 'telegram'})
        self.assertEqual(events[0]['scan_id'], self.scan.scan_id)
        self.assertTrue(governance)

    def test_send_gateway_message_builds_email_and_telegram_payloads_without_publishing(self):
        configure_all_channels()

        report = self.gateway.send_gateway_message({
            'channels': ['email', 'telegram'],
            'title': 'Scanner update',
            'message': 'The scanner finished.',
            'severity': 'info',
            'publish': False,
        }, actor='unit-test', persist=False)

        self.assertEqual(report['status'], 'prepared')
        self.assertEqual(report['delivery']['attempted'], 0)
        self.assertIn('Scanner update', report['artifacts']['email']['payload']['subject'])
        self.assertIn('The scanner finished.', report['artifacts']['telegram']['payload']['text'])

    def test_telegram_webhook_requires_allowlisted_user(self):
        body = json.dumps({
            'message': {
                'text': 'status',
                'from': {'id': 42, 'username': 'reviewer'},
                'chat': {'id': 99},
            }
        }).encode('utf-8')

        blocked = self.gateway.handle_gateway_webhook('telegram', body, {}, actor='unit-test')
        os.environ['GATEWAY_TELEGRAM_ALLOWED_USERS'] = '42'
        accepted = self.gateway.handle_gateway_webhook('telegram', body, {}, actor='unit-test')

        self.assertEqual(blocked['status'], 'blocked')
        self.assertEqual(accepted['status'], 'accepted')
        self.assertEqual(accepted['command'], 'status')


def configure_all_channels():
    os.environ['GATEWAY_SLACK_WEBHOOK_URL'] = 'https://hooks.slack.example/services/test'
    os.environ['GATEWAY_TEAMS_WEBHOOK_URL'] = 'https://teams.example/webhook'
    os.environ['GATEWAY_SMTP_HOST'] = 'smtp.example.test'
    os.environ['GATEWAY_EMAIL_FROM'] = 'secure-review@example.test'
    os.environ['GATEWAY_EMAIL_TO'] = 'security@example.test'
    os.environ['GATEWAY_TELEGRAM_BOT_TOKEN'] = '123456:test-token'
    os.environ['GATEWAY_TELEGRAM_CHAT_ID'] = '987654321'


def sample_scan() -> ScanResult:
    finding = Finding(
        id='finding-1',
        source='semgrep',
        rule_id='python.danger',
        title='Dangerous call',
        severity='HIGH',
        location=Location(path='app.py', line=12),
        message='A dangerous call was detected.',
        explanation='Use a safer API.',
        fix=FixSuggestion(summary='Replace the dangerous call.'),
        fingerprint='fingerprint-1',
        risk=RiskScore(score=88, tier='HIGH', priority='P0', recommended_action='Fix before release.'),
        scope='production',
    )
    return ScanResult(
        scan_id='gateway-scan',
        project_name='gateway-project',
        target_path='G:\\example\\gateway-project',
        summary=ScanSummary(
            total_findings=1,
            high=1,
            files_scanned=3,
            max_risk_score=88,
            avg_risk_score=88,
            risk_tiers={'HIGH': 1},
            priorities={'P0': 1},
            scope_counts={'production': 1},
            production_findings=1,
            all_max_risk_score=88,
            all_avg_risk_score=88,
            all_risk_tiers={'HIGH': 1},
            all_priorities={'P0': 1},
            tools={'secret-scan': 'passed'},
        ),
        findings=[finding],
        new_findings=['fingerprint-1'],
    )
