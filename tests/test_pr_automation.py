import hashlib
import hmac
import json

from app.pr_automation import PullRequestFeedbackItem, analyze_pr_impact_radius, build_pr_state, build_pr_state_from_github_webhook, compose_pr_feedback, hydrate_pr_state, ingest_pr_webhook, list_pr_states, load_pr_state, pr_automation_ingress_status, pr_automation_schema_report, pr_feedback_composer_status, pr_feedback_publisher_status, pr_governance_evidence, pr_governance_evidence_status, pr_impact_radius_status, pr_policy_agent_status, pr_ticket_hydration_status, publish_pr_feedback, run_pr_policy_agent, save_pr_state


def test_builds_github_pr_state_without_persisting_raw_diff():
    payload = {
        'number': 42,
        'repository': {
            'full_name': 'example/app',
            'html_url': 'https://github.com/example/app',
            'default_branch': 'main',
            'private': True,
            'visibility': 'private',
        },
        'pull_request': {
            'number': 42,
            'html_url': 'https://github.com/example/app/pull/42',
            'title': 'SEC-123 Harden auth token validation',
            'body': 'Fixes #77. Adds safer handling for auth tokens.',
            'state': 'open',
            'user': {'login': 'alice'},
            'head': {'ref': 'sec-123-auth-hardening', 'sha': 'headsha'},
            'base': {'ref': 'main', 'sha': 'basesha'},
        },
    }
    diff = """diff --git a/app/auth.py b/app/auth.py
index 1111111..2222222 100644
--- a/app/auth.py
+++ b/app/auth.py
@@ -1,2 +1,3 @@
 import os
-password = "old"
+token = request.headers["Authorization"]
+validate(token)
"""

    state = build_pr_state_from_github_webhook(payload, diff_text=diff)
    serialized = state.model_dump_json()

    assert state.schema_version == 1
    assert state.repository.full_name == 'example/app'
    assert state.pull_request.number == 42
    assert state.pull_request.author == 'alice'
    assert state.diff.raw_diff_included is False
    assert state.diff.raw_diff_sha256
    assert state.diff.raw_diff_excerpt == ''
    assert state.diff.files_changed == 1
    assert state.diff.additions == 2
    assert state.diff.deletions == 1
    assert state.diff.manifest[0].path == 'app/auth.py'
    assert state.diff.manifest[0].language == 'python'
    assert {ticket.key for ticket in state.tickets} == {'SEC-123', '#77'}
    assert 'request.headers' not in serialized


def test_generic_builder_accepts_file_changes_and_hydrated_tickets():
    state = build_pr_state(
        provider='gitlab',
        repository='group/service',
        pr_number=7,
        title='PAY-456 Update payment schema',
        description='Migration for checkout totals.',
        file_changes=[{'path': 'db/schema.sql', 'status': 'modified', 'additions': 4, 'deletions': 1}],
        tickets=[{'key': 'PAY-456', 'provider': 'jira', 'title': 'Payment schema change', 'status': 'In Review'}],
    )

    assert state.state_id.startswith('prstate-')
    assert state.diff.files_changed == 1
    assert state.diff.manifest[0].changes == 5
    assert state.tickets[0].provider == 'jira'
    assert state.intent.ticket_keys == ['PAY-456']
    assert 'schema' in state.intent.risk_keywords
    assert state.agent_status['ticket_hydration'] == 'pending'


def test_schema_report_exposes_guardrails_and_json_schema():
    report = pr_automation_schema_report()

    assert report['status'] == 'ready'
    assert 'github' in report['providers']
    assert 'state_model' in report
    assert any('raw diff' in guardrail.lower() for guardrail in report['guardrails'])


def test_ingests_github_webhook_with_signature_and_persists_state(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURE_REVIEW_DATA_DIR', str(tmp_path / 'data'))
    monkeypatch.setenv('PR_AUTOMATION_GITHUB_WEBHOOK_SECRET', 'github-secret')
    payload = {
        'action': 'opened',
        'number': 5,
        'repository': {'full_name': 'example/repo', 'html_url': 'https://github.com/example/repo'},
        'pull_request': {
            'number': 5,
            'title': 'SEC-555 Add safer auth',
            'body': 'Links #99',
            'state': 'open',
            'user': {'login': 'alice'},
            'head': {'ref': 'sec-555', 'sha': 'headsha'},
            'base': {'ref': 'main', 'sha': 'basesha'},
        },
    }
    body = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    signature = 'sha256=' + hmac.new(b'github-secret', body, hashlib.sha256).hexdigest()

    report = ingest_pr_webhook('github', 'pull_request', payload, raw_body=body, headers={'x-hub-signature-256': signature})
    state = load_pr_state(report['state_id'])
    states = list_pr_states()

    assert report['accepted'] is True
    assert report['persisted'] is True
    assert report['verification']['valid'] is True
    assert state.pull_request.repository == 'example/repo'
    assert state.intent.ticket_keys == ['SEC-555', '#99']
    assert states[0]['state_id'] == report['state_id']


def test_ingests_gitlab_webhook_with_shared_token(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURE_REVIEW_DATA_DIR', str(tmp_path / 'data'))
    monkeypatch.setenv('PR_AUTOMATION_GITLAB_WEBHOOK_SECRET', 'gitlab-token')
    payload = {
        'object_kind': 'merge_request',
        'user': {'username': 'bob'},
        'project': {'path_with_namespace': 'group/service', 'web_url': 'https://gitlab.example/group/service', 'visibility': 'private'},
        'object_attributes': {
            'iid': 12,
            'action': 'update',
            'state': 'opened',
            'title': 'PAY-12 Update checkout flow',
            'description': 'Touches dependency handling.',
            'source_branch': 'pay-12-checkout',
            'target_branch': 'main',
            'last_commit': {'id': 'commitsha'},
            'url': 'https://gitlab.example/group/service/-/merge_requests/12',
        },
    }

    report = ingest_pr_webhook('gitlab', 'merge_request', payload, raw_body=json.dumps(payload).encode('utf-8'), headers={'x-gitlab-token': 'gitlab-token'})

    assert report['accepted'] is True
    assert report['state']['pull_request']['provider'] == 'gitlab'
    assert report['state']['pull_request']['number'] == 12
    assert report['state']['intent']['ticket_keys'] == ['PAY-12']


def test_ingests_azure_devops_webhook_when_unsigned_explicitly_allowed(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURE_REVIEW_DATA_DIR', str(tmp_path / 'data'))
    monkeypatch.setenv('PR_AUTOMATION_AZURE_DEVOPS_WEBHOOK_ALLOW_UNSIGNED', 'true')
    payload = {
        'eventType': 'git.pullrequest.updated',
        'resource': {
            'pullRequestId': 22,
            'title': 'OPS-77 Harden pipeline permissions',
            'description': 'Permission update.',
            'status': 'active',
            'sourceRefName': 'refs/heads/ops-77-pipeline',
            'targetRefName': 'refs/heads/main',
            'createdBy': {'uniqueName': 'carol@example.com'},
            'repository': {'name': 'service', 'remoteUrl': 'https://dev.azure.com/org/project/_git/service', 'project': {'name': 'project'}},
            'lastMergeSourceCommit': {'commitId': 'sourcecommit'},
            'lastMergeTargetCommit': {'commitId': 'targetcommit'},
        },
    }

    report = ingest_pr_webhook('azure-devops', 'git.pullrequest.updated', payload, raw_body=json.dumps(payload).encode('utf-8'), headers={})

    assert report['accepted'] is True
    assert report['verification']['configured'] is False
    assert report['state']['pull_request']['head_branch'] == 'ops-77-pipeline'
    assert report['state']['intent']['ticket_keys'] == ['OPS-77']


def test_ignored_bitbucket_event_does_not_persist_state(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURE_REVIEW_DATA_DIR', str(tmp_path / 'data'))
    monkeypatch.setenv('PR_AUTOMATION_BITBUCKET_WEBHOOK_ALLOW_UNSIGNED', 'true')
    payload = {'repository': {'full_name': 'workspace/repo'}}

    report = ingest_pr_webhook('bitbucket', 'repo:push', payload, raw_body=b'{}', headers={})

    assert report['accepted'] is False
    assert report['persisted'] is False
    assert report['state'] is None
    assert pr_automation_ingress_status()['stored_state_count'] == 0


def test_ticket_hydration_without_credentials_is_auditable_not_configured(monkeypatch):
    for name in [
        'JIRA_BASE_URL',
        'JIRA_EMAIL',
        'JIRA_API_TOKEN',
        'JIRA_TOKEN',
        'LINEAR_API_KEY',
        'PR_AUTOMATION_GITHUB_TOKEN',
        'GITHUB_TOKEN',
        'GH_TOKEN',
        'PR_AUTOMATION_AZURE_DEVOPS_ORG',
        'AZURE_DEVOPS_ORG',
        'PR_AUTOMATION_AZURE_DEVOPS_PAT',
        'AZURE_DEVOPS_PAT',
        'AZURE_DEVOPS_TOKEN',
    ]:
        monkeypatch.delenv(name, raising=False)
    state = build_pr_state(
        provider='github',
        repository='example/app',
        pr_number=9,
        title='SEC-321 Harden token refresh',
        description='Fixes auth token rotation.',
        tickets=[{'key': 'SEC-321'}],
    )

    report = hydrate_pr_state(state=state, persist=False)

    assert report['status'] == 'not_configured'
    assert report['summary']['not_configured'] == 1
    assert report['tickets'][0]['hydration_status'] == 'not_configured'
    assert report['intent']['confidence'] == 'medium'
    assert 'token handling' in report['intent']['review_focus']
    assert pr_ticket_hydration_status()['status'] == 'ready'


def test_ticket_hydration_enriches_and_persists_state(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURE_REVIEW_DATA_DIR', str(tmp_path / 'data'))
    state = build_pr_state(
        provider='github',
        repository='example/app',
        pr_number=10,
        title='SEC-777 Harden OAuth callback',
        description='Touches auth webhook handling.',
        file_changes=[{'path': 'app/auth.py', 'status': 'modified', 'additions': 8, 'deletions': 2}],
        tickets=[{'key': 'SEC-777', 'provider': 'jira'}],
    )
    save_pr_state(state)

    def fake_fetcher(ticket, pr_state, provider):
        assert ticket.key == 'SEC-777'
        assert pr_state.state_id == state.state_id
        assert provider == 'jira'
        return {
            'title': 'Harden OAuth callback validation',
            'status': 'In Review',
            'description': 'Ensure access_token=super-secret-value is rotated and webhook signatures are checked.',
            'assignee': 'Security Reviewer',
            'labels': ['security', 'oauth'],
            'issue_type': 'Story',
            'priority': 'High',
            'metadata': {'provider_id': '10001'},
        }

    report = hydrate_pr_state(state.state_id, ticket_fetcher=fake_fetcher)
    loaded = load_pr_state(state.state_id)

    assert report['status'] == 'completed'
    assert report['summary']['hydrated'] == 1
    assert loaded.tickets[0].hydrated is True
    assert loaded.tickets[0].title == 'Harden OAuth callback validation'
    assert 'super-secret-value' not in loaded.tickets[0].description_excerpt
    assert '[REDACTED]' in loaded.tickets[0].description_excerpt
    assert loaded.intent.hydrated_from_tickets is True
    assert loaded.intent.confidence == 'high'
    assert 'webhook trust boundary' in loaded.intent.review_focus
    assert any(item.kind == 'ticket-hydration' for item in loaded.evidence)


def test_impact_radius_analyzer_scores_sensitive_cross_cutting_pr(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURE_REVIEW_DATA_DIR', str(tmp_path / 'data'))
    state = build_pr_state(
        provider='github',
        repository='example/app',
        pr_number=11,
        title='SEC-888 Harden auth dependency workflow',
        description='Updates token handling, package lock, and CI permissions.',
        file_changes=[
            {'path': 'app/auth.py', 'status': 'modified', 'additions': 40, 'deletions': 8},
            {'path': 'requirements.txt', 'status': 'modified', 'additions': 2, 'deletions': 1},
            {'path': '.github/workflows/ci.yml', 'status': 'modified', 'additions': 12, 'deletions': 2, 'language': 'yaml'},
            {'path': 'tests/test_auth.py', 'status': 'modified', 'additions': 30, 'deletions': 0},
        ],
        tickets=[{'key': 'SEC-888', 'provider': 'jira', 'title': 'Harden auth dependency workflow', 'description_excerpt': 'Auth token and CI permission update.', 'hydrated': True}],
    )
    save_pr_state(state)

    report = analyze_pr_impact_radius(state.state_id)
    loaded = load_pr_state(state.state_id)

    assert report['status'] == 'completed'
    assert report['summary']['overall_risk'] in {'high', 'critical'}
    assert report['summary']['blast_radius'] in {'broad', 'contained', 'cross-cutting'}
    assert {'app', 'dependencies', 'ci-cd'} <= set(loaded.impact_radius_modules)
    assert 'security-sensitive' in loaded.impact_radius.cross_cutting_concerns
    assert 'dependency-supply-chain' in loaded.impact_radius.cross_cutting_concerns
    assert 'ci-cd' in loaded.impact_radius.cross_cutting_concerns
    assert 'app/auth.py' in loaded.impact_radius.critical_files
    assert 'python-specialist-review' in loaded.impact_radius.recommended_agents
    assert 'dependency-sbom-agent' in loaded.impact_radius.recommended_agents
    assert any('dependency audit' in item for item in loaded.impact_radius.test_recommendations)
    assert any(item.kind == 'impact-radius' for item in loaded.evidence)
    assert pr_impact_radius_status()['status'] == 'ready'


def test_impact_radius_analyzer_handles_empty_manifest_without_persisting():
    state = build_pr_state(
        provider='github',
        repository='example/app',
        pr_number=12,
        title='DOC-12 Metadata only',
        description='No diff available yet.',
    )

    report = analyze_pr_impact_radius(state=state, persist=False)

    assert report['status'] == 'no_files'
    assert report['summary']['overall_risk'] == 'none'
    assert report['impact_radius']['raw_code_included'] is False
    assert state.agent_status['impact_radius'] == 'no_files'


def test_policy_agent_requires_review_for_security_dependency_and_ci_changes(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURE_REVIEW_DATA_DIR', str(tmp_path / 'data'))
    state = build_pr_state(
        provider='github',
        repository='example/app',
        pr_number=13,
        title='SEC-999 Harden auth dependency workflow',
        description='Updates token handling, package lock, and CI permissions.',
        file_changes=[
            {'path': 'app/auth.py', 'status': 'modified', 'additions': 44, 'deletions': 3},
            {'path': 'requirements.txt', 'status': 'modified', 'additions': 3, 'deletions': 1},
            {'path': '.github/workflows/release.yml', 'status': 'modified', 'additions': 12, 'deletions': 2, 'language': 'yaml'},
        ],
        tickets=[{'key': 'SEC-999', 'provider': 'jira'}],
    )
    save_pr_state(state)

    report = run_pr_policy_agent(state.state_id)
    loaded = load_pr_state(state.state_id)
    check_statuses = {check['check_id']: check['status'] for check in report['policy_report']['checks']}

    assert report['status'] == 'completed'
    assert report['decision'] == 'review_required'
    assert report['summary']['violations'] >= 1
    assert check_statuses['SR-PR-POLICY-020'] == 'violation'
    assert check_statuses['SR-PR-POLICY-030'] == 'warning'
    assert check_statuses['SR-PR-POLICY-040'] == 'warning'
    assert loaded.agent_status['invariant_policy'] == 'review_required'
    assert 'dependency-sbom-agent' in loaded.policy_report.required_agents
    assert 'iac-devops-agent' in loaded.policy_report.required_agents
    assert any(finding.evidence.get('agent') == 'invariant-policy-agent' for finding in loaded.invariant_violations)
    assert any(item.kind == 'invariant-policy' for item in loaded.evidence)
    assert pr_policy_agent_status()['status'] == 'ready'


def test_policy_agent_blocks_security_sensitive_delete_without_persisting():
    state = build_pr_state(
        provider='github',
        repository='example/app',
        pr_number=14,
        title='SEC-1000 Remove legacy auth token module',
        description='Deletes old token handling code.',
        file_changes=[{'path': 'app/auth_tokens.py', 'status': 'deleted', 'additions': 0, 'deletions': 120}],
    )

    report = run_pr_policy_agent(state=state, persist=False)
    check_statuses = {check['check_id']: check['status'] for check in report['policy_report']['checks']}

    assert report['decision'] == 'blocked'
    assert report['summary']['blocked_by_policy'] is True
    assert check_statuses['SR-PR-POLICY-090'] == 'violation'
    assert state.policy_report.blocked_by_policy is True
    assert state.policy_report.raw_code_included is False


def test_feedback_composer_builds_review_required_draft_and_file_comments(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURE_REVIEW_DATA_DIR', str(tmp_path / 'data'))
    state = build_pr_state(
        provider='github',
        repository='example/app',
        pr_number=15,
        title='SEC-111 Harden auth dependency workflow',
        description='Updates token handling, package lock, and CI permissions.',
        file_changes=[
            {'path': 'app/auth.py', 'status': 'modified', 'additions': 44, 'deletions': 3},
            {'path': 'requirements.txt', 'status': 'modified', 'additions': 3, 'deletions': 1},
            {'path': '.github/workflows/release.yml', 'status': 'modified', 'additions': 12, 'deletions': 2, 'language': 'yaml'},
        ],
        tickets=[{'key': 'SEC-111', 'provider': 'jira'}],
    )
    save_pr_state(state)
    run_pr_policy_agent(state.state_id)

    report = compose_pr_feedback(state.state_id)
    loaded = load_pr_state(state.state_id)

    assert report['status'] == 'completed'
    assert report['publication_state'] == 'requires_review'
    assert '## Secure Review Draft' in report['feedback_report']['summary_markdown']
    assert report['summary']['comment_count'] == len(loaded.compiled_feedback)
    assert loaded.agent_status['feedback_composition'] == 'requires_review'
    assert any(item.file_path == 'app/auth.py' for item in loaded.compiled_feedback)
    assert any(item.file_path == 'requirements.txt' for item in loaded.compiled_feedback)
    assert all(item.suggestion is None for item in loaded.compiled_feedback)
    assert loaded.feedback_report.raw_code_included is False
    assert any(item.kind == 'pr-feedback' for item in loaded.evidence)
    assert pr_feedback_composer_status()['status'] == 'ready'


def test_feedback_composer_marks_blocked_policy_without_persisting():
    state = build_pr_state(
        provider='github',
        repository='example/app',
        pr_number=16,
        title='SEC-222 Remove token module',
        description='Deletes old token handling code.',
        file_changes=[{'path': 'app/auth_tokens.py', 'status': 'deleted', 'additions': 0, 'deletions': 120}],
    )

    report = compose_pr_feedback(state=state, persist=False)

    assert report['publication_state'] == 'blocked'
    assert report['feedback_report']['raw_code_included'] is False
    assert 'blocked' in report['feedback_report']['summary_markdown']
    assert state.agent_status['feedback_composition'] == 'blocked'
    assert any(item.file_path == 'app/auth_tokens.py' for item in state.compiled_feedback)


def test_publisher_builds_github_dry_run_inline_payload_without_suggestions(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURE_REVIEW_DATA_DIR', str(tmp_path / 'data'))
    monkeypatch.setenv('PR_AUTOMATION_GITHUB_TOKEN', 'token-for-dry-run')
    state = build_pr_state(
        provider='github',
        repository='example/app',
        pr_number=17,
        title='DOC-333 Update docs',
        description='Low-risk documentation update.',
        file_changes=[{'path': 'docs/usage.md', 'status': 'modified', 'additions': 2, 'deletions': 1, 'language': 'unknown'}],
    )
    compose_pr_feedback(state=state, persist=False)
    inline = PullRequestFeedbackItem(
        title='Tighten wording',
        body='Please clarify the risky step before merge.',
        file_path='docs/usage.md',
        line=12,
        suggestion='Use the approved secure workflow.',
        requires_human_review=True,
        severity='LOW',
        category='documentation',
    )
    state.compiled_feedback.append(inline)
    state.feedback_report.file_comments.append(inline)
    save_pr_state(state)

    report = publish_pr_feedback(state.state_id, provider='github', publish=False, allow_suggestions=False)
    loaded = load_pr_state(state.state_id)
    github = report['publisher_report']['providers']['github']
    body = github['payload']['inline_comments'][0]['body']

    assert report['status'] == 'dry_run'
    assert github['configured'] is True
    assert github['publish_attempted'] is False
    assert github['inline_comment_count'] == 1
    assert github['suggestion_count'] == 0
    assert '```suggestion' not in body
    assert loaded.agent_status['publisher'] == 'dry_run'
    assert any(item.kind == 'pr-publisher' for item in loaded.evidence)
    assert pr_feedback_publisher_status()['status'] == 'ready'


def test_publisher_allows_suggestion_blocks_only_when_enabled():
    state = build_pr_state(
        provider='github',
        repository='example/app',
        pr_number=18,
        title='DOC-444 Update docs',
        description='Low-risk documentation update.',
        file_changes=[{'path': 'docs/usage.md', 'status': 'modified', 'additions': 2, 'deletions': 1, 'language': 'unknown'}],
    )
    compose_pr_feedback(state=state, persist=False)
    inline = PullRequestFeedbackItem(
        title='Suggested wording',
        body='Use safer wording here.',
        file_path='docs/usage.md',
        line=7,
        suggestion='Prefer a bounded token lifetime.',
        requires_human_review=True,
        severity='LOW',
        category='documentation',
    )
    state.compiled_feedback.append(inline)
    state.feedback_report.file_comments.append(inline)

    report = publish_pr_feedback(state=state, provider='github', publish=False, allow_suggestions=True, persist=False)
    github = report['publisher_report']['providers']['github']

    assert github['inline_comment_count'] == 1
    assert github['suggestion_count'] == 1
    assert '```suggestion' in github['payload']['inline_comments'][0]['body']
    assert state.publisher_report.raw_code_included is False


def test_publisher_blocks_real_publish_when_feedback_is_blocked():
    state = build_pr_state(
        provider='github',
        repository='example/app',
        pr_number=19,
        title='SEC-333 Remove token module',
        description='Deletes old token handling code.',
        file_changes=[{'path': 'app/auth_tokens.py', 'status': 'deleted', 'additions': 0, 'deletions': 120}],
    )
    compose_pr_feedback(state=state, persist=False)

    report = publish_pr_feedback(state=state, provider='github', publish=True, persist=False)
    github = report['publisher_report']['providers']['github']

    assert report['status'] == 'blocked'
    assert 'blocked by policy' in report['publisher_report']['blocked_reason']
    assert github['publish_attempted'] is False
    assert state.agent_status['publisher'] == 'blocked'


def test_governance_evidence_exports_full_pr_action_lineage(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURE_REVIEW_DATA_DIR', str(tmp_path / 'data'))
    monkeypatch.setenv('PR_AUTOMATION_GITHUB_WEBHOOK_SECRET', 'github-secret')
    for name in [
        'JIRA_BASE_URL',
        'JIRA_EMAIL',
        'JIRA_API_TOKEN',
        'JIRA_TOKEN',
        'LINEAR_API_KEY',
        'PR_AUTOMATION_GITHUB_TOKEN',
        'GITHUB_TOKEN',
        'GH_TOKEN',
        'PR_AUTOMATION_AZURE_DEVOPS_ORG',
        'AZURE_DEVOPS_ORG',
        'PR_AUTOMATION_AZURE_DEVOPS_PAT',
        'AZURE_DEVOPS_PAT',
        'AZURE_DEVOPS_TOKEN',
    ]:
        monkeypatch.delenv(name, raising=False)
    payload = {
        'action': 'opened',
        'number': 20,
        'repository': {'full_name': 'example/app', 'html_url': 'https://github.com/example/app'},
        'pull_request': {
            'number': 20,
            'title': 'SEC-444 Harden auth dependency workflow',
            'body': 'Fixes #44. Updates auth token handling and dependency checks.',
            'state': 'open',
            'user': {'login': 'alice'},
            'head': {'ref': 'sec-444-auth', 'sha': 'headsha20'},
            'base': {'ref': 'main', 'sha': 'basesha20'},
        },
    }
    body = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    signature = 'sha256=' + hmac.new(b'github-secret', body, hashlib.sha256).hexdigest()
    diff = """diff --git a/app/auth.py b/app/auth.py
index 1111111..2222222 100644
--- a/app/auth.py
+++ b/app/auth.py
@@ -1,2 +1,3 @@
 import os
-token = "old"
+token = request.headers["Authorization"]
+validate(token)
diff --git a/requirements.txt b/requirements.txt
index 3333333..4444444 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1 +1 @@
-fastapi==0.100.0
+fastapi>=0.110.0
"""

    ingress = ingest_pr_webhook('github', 'pull_request', payload, raw_body=body, headers={'x-hub-signature-256': signature}, diff_text=diff)
    hydrate_pr_state(ingress['state_id'])
    analyze_pr_impact_radius(ingress['state_id'])
    run_pr_policy_agent(ingress['state_id'])
    compose_pr_feedback(ingress['state_id'])
    publish_pr_feedback(ingress['state_id'], provider='github', publish=False, force=True)

    report = pr_governance_evidence(ingress['state_id'])
    loaded = load_pr_state(ingress['state_id'])
    evidence = report['governance_evidence']

    assert report['status'] == 'completed'
    assert evidence['safety']['passed'] is True
    assert evidence['raw_code_included'] is False
    assert evidence['compliance_export']['exportable'] is True
    assert report['artifact_path'].endswith(f"{loaded.state_id}.json")
    for action in ['ingress', 'ticket_hydration', 'impact_radius', 'invariant_policy', 'feedback_composition', 'publisher']:
        assert evidence['actions'][action]['completed'] is True
        assert evidence['actions'][action]['event_count'] >= 1
    assert any(item.kind == 'pr-governance-evidence' for item in loaded.evidence)
    assert loaded.governance_evidence.status == 'completed'
    assert pr_governance_evidence_status()['status'] == 'ready'


def test_governance_evidence_flags_raw_diff_safety_issue():
    state = build_pr_state(
        provider='github',
        repository='example/app',
        pr_number=21,
        title='SEC-555 Debug raw diff safety',
        description='Verifies that governance evidence refuses raw state.',
        file_changes=[{'path': 'app/auth.py', 'status': 'modified', 'additions': 1, 'deletions': 1}],
    )
    state.diff.raw_diff_included = True

    report = pr_governance_evidence(state=state, persist=False)
    evidence = report['governance_evidence']

    assert report['status'] == 'attention_required'
    assert evidence['raw_code_included'] is True
    assert evidence['safety']['raw_diff_included'] is True
    assert evidence['safety']['passed'] is False
    assert 'ingress' in evidence['missing_actions']
