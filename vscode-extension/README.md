# Secure Code Review Assistant VS Code Extension

This extension connects VS Code to the local Secure Code Review Assistant backend and exposes the same day-to-day review evidence that the CLI can generate.

## Features

- Configure the backend API URL, optional bearer token, and extra API headers.
- Run a scan for the current VS Code workspace folder.
- View findings in a dedicated activity bar view and open findings at source line.
- Set finding decisions: open, false positive, accepted fix, or risk accepted.
- Request RAG context, AI-generated finding explanations, remediation suggestions, and human-reviewed fix proposals for a finding.
- Open scan-level reports from the IDE:
  - scanner mesh
  - dependency review
  - SonarQube quality gate
  - scanner depth
  - secret policy and push protection
  - CycloneDX and SPDX SBOMs
  - SPDX compliance and SBOM policy
  - GitHub PR review preview, GitLab/Azure DevOps/Bitbucket review preview, and PR comment
  - fix proposals, fix bundle, and dry-run fix apply
  - remediation plan, Jira/Linear issue plan, Slack/Teams chat agent, team learning dashboard, memory context, advanced AI report, AI finding review, and compliance report
- Export an evidence bundle under `.secure-review-artifacts/{scan_id}` with the same core artifacts produced by `scan.ps1` and `app.cli`.
- Save a scan as the baseline from inside VS Code.
- Open the browser app for deeper review.

## Requirements

Start the backend first from the project root:

```powershell
.\run.ps1
```

Default API URL:

```text
http://127.0.0.1:8000
```

For enterprise deployments behind a gateway, configure `secureCodeReview.bearerToken` or `secureCodeReview.requestHeaders` in VS Code settings.

## Development

Open `vscode-extension/` in VS Code and run `Extension: Start Debugging` to launch an Extension Development Host.

Syntax check:

```powershell
npm run check
```

No bundling step is required. The extension uses plain JavaScript and Node built-ins.

## Safety

The extension does not apply real code changes automatically. The fix apply command exposed in the IDE sends a dry-run request only. Real apply remains guarded by backend permissions, explicit request fields, and `FIX_APPLY_ENABLED=true`.