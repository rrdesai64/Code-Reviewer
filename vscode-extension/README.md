# Secure Code Review Assistant VS Code Extension

This extension connects VS Code to the local Secure Code Review Assistant backend.

## Features

- Configure the backend API URL.
- Run a scan for the current VS Code workspace folder.
- View findings in a dedicated activity bar view.
- Open findings at the source file and line.
- Request RAG context for a finding.
- Request a human-reviewed fix proposal for a finding.
- Open a scan-level remediation plan.
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

## Development

Open `vscode-extension/` in VS Code and run `Extension: Start Debugging` to launch an Extension Development Host.

No build step is required. The extension uses plain JavaScript and Node built-ins.

## Safety

The extension never applies code changes automatically. Fix proposals are displayed as diffs and require human review before use.
