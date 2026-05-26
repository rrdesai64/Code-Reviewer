import io
import json
import os
import unittest
import urllib.error
import urllib.parse
from unittest.mock import patch

from app.external_scanners import fetch_sonar_hotspots, fetch_sonar_issues, finding_from_sonar_hotspot


class FakeHttpResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode('utf-8')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self.payload


class SonarQubeAdapterTests(unittest.TestCase):
    def setUp(self):
        self._old_env = {name: os.environ.get(name) for name in ('SONAR_ISSUE_TYPES', 'SONAR_ORGANIZATION', 'SONAR_BRANCH_NAME', 'SONAR_PULLREQUEST_KEY')}
        os.environ.pop('SONAR_BRANCH_NAME', None)
        os.environ.pop('SONAR_PULLREQUEST_KEY', None)
        os.environ['SONAR_ORGANIZATION'] = 'example-org'

    def tearDown(self):
        for name, value in self._old_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def test_issue_fetch_uses_bearer_auth_and_excludes_hotspots(self):
        os.environ['SONAR_ISSUE_TYPES'] = 'VULNERABILITY,SECURITY_HOTSPOT,BUG'
        captured = {}

        def fake_urlopen(request, timeout):
            captured['authorization'] = request.get_header('Authorization')
            parsed = urllib.parse.urlsplit(request.full_url)
            captured['query'] = urllib.parse.parse_qs(parsed.query)
            return FakeHttpResponse({'issues': [{'key': 'issue-1'}]})

        with patch('app.external_scanners.urllib.request.urlopen', side_effect=fake_urlopen):
            issues = fetch_sonar_issues('https://sonarcloud.io', 'secret-token', 'org_project')

        self.assertEqual(issues, [{'key': 'issue-1'}])
        self.assertEqual(captured['authorization'], 'Bearer secret-token')
        self.assertEqual(captured['query']['organization'], ['example-org'])
        self.assertEqual(captured['query']['types'], ['VULNERABILITY,BUG'])

    def test_http_error_body_is_preserved_without_token(self):
        def fake_urlopen(request, timeout):
            raise urllib.error.HTTPError(
                request.full_url,
                400,
                'Bad Request',
                hdrs=None,
                fp=io.BytesIO(b'{"errors":[{"msg":"SECURITY_HOTSPOT is invalid for this endpoint: secret-token"}]}'),
            )

        with patch('app.external_scanners.urllib.request.urlopen', side_effect=fake_urlopen):
            with self.assertRaisesRegex(Exception, 'SECURITY_HOTSPOT is invalid'):
                try:
                    fetch_sonar_issues('https://sonarcloud.io', 'secret-token', 'org_project')
                except Exception as exc:
                    self.assertNotIn('secret-token', str(exc))
                    raise

    def test_hotspot_fetch_uses_hotspot_endpoint_and_normalizes_finding(self):
        captured = {}
        payload = {
            'hotspots': [
                {
                    'key': 'hotspot-1',
                    'component': 'org_project:src/app.py',
                    'line': 42,
                    'ruleKey': 'python:S2077',
                    'message': 'Review this SQL query construction.',
                    'securityCategory': 'sql-injection',
                    'vulnerabilityProbability': 'HIGH',
                    'status': 'TO_REVIEW',
                }
            ]
        }

        def fake_urlopen(request, timeout):
            captured['authorization'] = request.get_header('Authorization')
            captured['path'] = urllib.parse.urlsplit(request.full_url).path
            captured['query'] = urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query)
            return FakeHttpResponse(payload)

        with patch('app.external_scanners.urllib.request.urlopen', side_effect=fake_urlopen):
            hotspots = fetch_sonar_hotspots('https://sonarcloud.io', 'secret-token', 'org_project')

        finding = finding_from_sonar_hotspot(hotspots[0], 'org_project')

        self.assertEqual(captured['authorization'], 'Bearer secret-token')
        self.assertEqual(captured['path'], '/api/hotspots/search')
        self.assertEqual(captured['query']['projectKey'], ['org_project'])
        self.assertEqual(finding.source, 'sonarqube')
        self.assertEqual(finding.rule_id, 'python:S2077')
        self.assertEqual(finding.location.path, 'src/app.py')
        self.assertEqual(finding.location.line, 42)
        self.assertEqual(finding.scanner_metadata['sonar_kind'], 'security_hotspot')


if __name__ == '__main__':
    unittest.main()
