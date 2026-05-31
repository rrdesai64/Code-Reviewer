const vscode = require('vscode');
const http = require('http');
const https = require('https');
const fs = require('fs');
const fsp = require('fs/promises');
const { URL, URLSearchParams } = require('url');
const path = require('path');

let findingsProvider;
let statusBar;
let output;

function activate(context) {
  output = vscode.window.createOutputChannel('Secure Review');
  findingsProvider = new FindingsProvider(context);
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 20);
  statusBar.command = 'secureCodeReview.health';
  statusBar.text = '$(shield) Secure Review';
  statusBar.tooltip = 'Secure Code Review Assistant';
  statusBar.show();

  context.subscriptions.push(output, statusBar);
  context.subscriptions.push(vscode.window.registerTreeDataProvider('secureCodeReviewFindings', findingsProvider));

  register(context, 'secureCodeReview.configureApi', configureApi);
  register(context, 'secureCodeReview.health', checkHealth);
  register(context, 'secureCodeReview.scanWorkspace', () => scanWorkspace(context));
  register(context, 'secureCodeReview.refreshFindings', () => refreshFindings(context));
  register(context, 'secureCodeReview.showLastScan', () => showLastScan(context));
  register(context, 'secureCodeReview.showReportPicker', () => showReportPicker(context));
  register(context, 'secureCodeReview.exportEvidenceBundle', () => exportEvidenceBundle(context));
  register(context, 'secureCodeReview.saveBaseline', () => saveBaseline(context));
  register(context, 'secureCodeReview.showScannerMesh', () => showReportById(context, 'scanner-mesh'));
  register(context, 'secureCodeReview.showDependencyReview', () => showReportById(context, 'dependency-review'));
  register(context, 'secureCodeReview.showSonarQubeReport', () => showReportById(context, 'sonarqube'));
  register(context, 'secureCodeReview.showScannerDepth', () => showReportById(context, 'scanner-depth'));
  register(context, 'secureCodeReview.showSecretPolicy', () => showReportById(context, 'secret-policy'));
  register(context, 'secureCodeReview.showPushProtection', () => showReportById(context, 'push-protection'));
  register(context, 'secureCodeReview.showCycloneDx', () => showReportById(context, 'cyclonedx'));
  register(context, 'secureCodeReview.showSpdx', () => showReportById(context, 'spdx'));
  register(context, 'secureCodeReview.showSbomPolicy', () => showReportById(context, 'sbom-policy'));
  register(context, 'secureCodeReview.showSpdxCompliance', () => showReportById(context, 'spdx-compliance'));
  register(context, 'secureCodeReview.showCompliance', () => showReportById(context, 'compliance'));
  register(context, 'secureCodeReview.showGithubPrReview', () => showReportById(context, 'github-pr-review'));
  register(context, 'secureCodeReview.showCodeHostReview', () => showReportById(context, 'code-host-review'));
  register(context, 'secureCodeReview.showFixProposals', () => showReportById(context, 'fix-proposals'));
  register(context, 'secureCodeReview.showFixBundle', () => showReportById(context, 'fix-bundle'));
  register(context, 'secureCodeReview.dryRunFixApply', () => showReportById(context, 'fix-apply-dry-run'));
  register(context, 'secureCodeReview.showRemediationPlan', () => showReportById(context, 'remediation-plan'));
  register(context, 'secureCodeReview.showIssuePlan', () => showReportById(context, 'issue-plan'));
  register(context, 'secureCodeReview.showChatNotification', () => showReportById(context, 'chat-notification'));
  register(context, 'secureCodeReview.showMessagingGateway', () => showReportById(context, 'messaging-gateway'));
  register(context, 'secureCodeReview.showTeamLearning', () => showReportById(context, 'team-learning'));
  register(context, 'secureCodeReview.showRecursiveLearning', () => showReportById(context, 'recursive-learning'));
  register(context, 'secureCodeReview.showBenchmarkGate', () => showReportById(context, 'benchmark-gate'));
  register(context, 'secureCodeReview.showGovernanceEvidence', () => showReportById(context, 'governance-evidence'));
  register(context, 'secureCodeReview.showMemoryContext', () => showReportById(context, 'memory-context'));
  register(context, 'secureCodeReview.showAdvancedAiReport', () => showReportById(context, 'advanced-ai'));
  register(context, 'secureCodeReview.showAiReview', () => showReportById(context, 'ai-review'));
  register(context, 'secureCodeReview.proposeFix', item => proposeFix(context, item));
  register(context, 'secureCodeReview.showRagContext', item => showRagContext(context, item));
  register(context, 'secureCodeReview.showAiFindingReview', item => showAiFindingReview(context, item));
  register(context, 'secureCodeReview.setDecision', item => setDecision(context, item));
  register(context, 'secureCodeReview.openFinding', item => openFinding(item));
  register(context, 'secureCodeReview.openWebApp', openWebApp);

  refreshFindings(context, { silent: true });
}

function deactivate() {}

function register(context, command, callback) {
  context.subscriptions.push(vscode.commands.registerCommand(command, callback));
}

function config() {
  return vscode.workspace.getConfiguration('secureCodeReview');
}

function apiBaseUrl() {
  return (config().get('apiBaseUrl') || 'http://127.0.0.1:8000').replace(/\/+$/, '');
}

function defaultFixProvider() {
  return config().get('fixProvider') || 'offline';
}

function fixBundleLimit() {
  return Number(config().get('fixBundleLimit') || 10);
}

function routeUrl(route) {
  return new URL(route, `${apiBaseUrl()}/`).toString();
}

async function configureApi() {
  const current = apiBaseUrl();
  const value = await vscode.window.showInputBox({
    title: 'Secure Review API URL',
    prompt: 'Backend base URL',
    value: current,
    ignoreFocusOut: true,
  });
  if (!value) return;
  await config().update('apiBaseUrl', value.replace(/\/+$/, ''), vscode.ConfigurationTarget.Global);
  vscode.window.showInformationMessage(`Secure Review API URL set to ${value}`);
}

async function checkHealth() {
  try {
    const health = await apiJson('GET', '/api/health');
    statusBar.text = '$(shield) Secure Review ready';
    const features = Array.isArray(health.features) ? health.features.join(', ') : 'unknown';
    vscode.window.showInformationMessage(`Secure Review backend ready. Features: ${features}`);
  } catch (error) {
    statusBar.text = '$(warning) Secure Review offline';
    showApiError('Backend health check failed', error);
  }
}

async function scanWorkspace(context) {
  const folder = await pickWorkspaceFolder();
  if (!folder) return;
  const configuredName = config().get('projectName');
  const projectName = configuredName || folder.name;
  const body = new URLSearchParams({ project_name: projectName, repo_path: folder.uri.fsPath }).toString();

  await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'Secure Review scan running', cancellable: false }, async progress => {
    progress.report({ message: folder.uri.fsPath });
    const scan = await apiJson('POST', '/api/scans', body, { 'content-type': 'application/x-www-form-urlencoded' });
    await setLastScan(context, scan);
    findingsProvider.setScan(scan);
    statusBar.text = `$(shield) Secure Review ${scan.summary.total_findings}`;
    vscode.window.showInformationMessage(`Scan ${scan.scan_id}: ${scan.summary.total_findings} findings, max risk ${scan.summary.max_risk_score}.`);
  });
}

async function refreshFindings(context, options = {}) {
  try {
    const scan = await loadLastScan(context);
    if (!scan) {
      findingsProvider.setScan(null);
      if (!options.silent) vscode.window.showInformationMessage('No Secure Review scan is available yet. Run a workspace scan first.');
      return;
    }
    findingsProvider.setScan(scan);
    statusBar.text = `$(shield) Secure Review ${scan.summary.total_findings}`;
    if (!options.silent) vscode.window.showInformationMessage(`Loaded scan ${scan.scan_id}.`);
  } catch (error) {
    findingsProvider.setScan(null);
    if (!options.silent) showApiError('Could not refresh findings', error);
  }
}

async function showLastScan(context) {
  const scan = await requireLastScan(context);
  if (!scan) return;
  const lines = [
    `# Secure Review Scan ${scan.scan_id}`,
    '',
    `Project: ${scan.project_name}`,
    `Target: ${scan.target_path}`,
    `Findings: ${scan.summary.total_findings}`,
    `Max risk: ${scan.summary.max_risk_score}`,
    `Average risk: ${scan.summary.avg_risk_score}`,
    `Priorities: ${JSON.stringify(scan.summary.priorities || {})}`,
    `Tools: ${JSON.stringify(scan.summary.tools || {})}`,
    '',
    'Top findings:',
    ...scan.findings.slice(0, 25).map(f => `- ${safeRisk(f).priority} ${safeRisk(f).score} ${f.title} (${f.location.path}:${f.location.line})`),
  ];
  await showDocument('secure-review-scan.md', lines.join('\n'), 'markdown');
}

async function showReportPicker(context) {
  const scan = await requireLastScan(context);
  if (!scan) return;
  const reports = reportDefinitions(scan).filter(report => report.show !== false);
  const picked = await vscode.window.showQuickPick(reports.map(report => ({
    label: report.label,
    description: report.fileName,
    detail: report.detail || '',
    report,
  })), { title: 'Secure Review report' });
  if (!picked) return;
  await openReportDefinition(scan, picked.report);
}

async function showReportById(context, id) {
  const scan = await requireLastScan(context);
  if (!scan) return;
  const report = reportDefinitions(scan).find(item => item.id === id);
  if (!report) {
    vscode.window.showWarningMessage(`Unknown Secure Review report: ${id}`);
    return;
  }
  await openReportDefinition(scan, report);
}

async function openReportDefinition(scan, report) {
  try {
    const content = await fetchReportContent(scan, report);
    await showDocument(report.fileName, content, report.language || 'json');
  } catch (error) {
    showApiError(`Could not load ${report.label}`, error);
  }
}

async function exportEvidenceBundle(context) {
  const scan = await requireLastScan(context);
  if (!scan) return;
  const folder = await pickWorkspaceFolder();
  if (!folder) return;
  const defaultDir = path.join(folder.uri.fsPath, '.secure-review-artifacts', scan.scan_id);
  const targetDir = await vscode.window.showInputBox({
    title: 'Secure Review evidence bundle folder',
    prompt: 'Folder to write report artifacts into',
    value: defaultDir,
    ignoreFocusOut: true,
  });
  if (!targetDir) return;

  const reports = reportDefinitions(scan).filter(report => report.export !== false);
  await fsp.mkdir(targetDir, { recursive: true });
  const written = [];
  const failed = [];

  await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'Exporting Secure Review evidence bundle', cancellable: false }, async progress => {
    for (const report of reports) {
      progress.report({ message: report.fileName });
      try {
        const content = await fetchReportContent(scan, report);
        const filePath = path.join(targetDir, report.fileName);
        await fsp.writeFile(filePath, content, 'utf8');
        written.push(filePath);
      } catch (error) {
        failed.push(`${report.fileName}: ${error.message || error}`);
        output.appendLine(`Artifact export failed for ${report.fileName}: ${error.stack || error.message || error}`);
      }
    }
  });

  const message = `Secure Review exported ${written.length} artifact(s) to ${targetDir}${failed.length ? `, ${failed.length} failed` : ''}.`;
  const action = await vscode.window.showInformationMessage(message, 'Reveal Folder');
  if (action === 'Reveal Folder') {
    vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(targetDir));
  }
  if (failed.length) {
    output.appendLine('Evidence bundle export failures:');
    failed.forEach(item => output.appendLine(`- ${item}`));
    output.show(true);
  }
}

async function saveBaseline(context) {
  const scan = await requireLastScan(context);
  if (!scan) return;
  try {
    const result = await apiJson('POST', `/api/scans/${scan.scan_id}/baseline`);
    vscode.window.showInformationMessage(`Secure Review baseline saved for scan ${result.scan_id || scan.scan_id}.`);
  } catch (error) {
    showApiError('Could not save baseline', error);
  }
}

async function proposeFix(context, item) {
  const scan = await loadLastScan(context);
  const finding = await resolveFinding(scan, item);
  if (!scan || !finding) return;
  try {
    const params = new URLSearchParams({ provider: defaultFixProvider() });
    const proposal = await apiJson('POST', `/api/scans/${scan.scan_id}/findings/${finding.id}/fix-proposal?${params}`);
    const content = formatProposal(proposal);
    await showDocument(`secure-review-fix-${finding.id}.diff`, content, 'diff');
  } catch (error) {
    showApiError('Could not build fix proposal', error);
  }
}

async function showRagContext(context, item) {
  const scan = await loadLastScan(context);
  const finding = await resolveFinding(scan, item);
  if (!scan || !finding) return;
  try {
    const contextPayload = await apiJson('GET', `/api/scans/${scan.scan_id}/findings/${finding.id}/rag-context`);
    await showDocument(`secure-review-rag-${finding.id}.json`, JSON.stringify(contextPayload, null, 2), 'json');
  } catch (error) {
    showApiError('Could not load RAG context', error);
  }
}

async function showAiFindingReview(context, item) {
  const scan = await loadLastScan(context);
  const finding = await resolveFinding(scan, item);
  if (!scan || !finding) return;
  try {
    const params = new URLSearchParams({ provider: defaultFixProvider(), include_prompts: 'true' });
    const review = await apiJson('GET', `/api/scans/${scan.scan_id}/findings/${finding.id}/ai-review?${params}`);
    await showDocument(`secure-review-ai-${finding.id}.json`, JSON.stringify(review, null, 2), 'json');
  } catch (error) {
    showApiError('Could not build AI finding review', error);
  }
}
async function setDecision(context, item) {
  const scan = await loadLastScan(context);
  const finding = await resolveFinding(scan, item);
  if (!scan || !finding) return;
  const state = await vscode.window.showQuickPick([
    { label: 'open', description: 'Keep this finding active' },
    { label: 'false_positive', description: 'Mark as false positive' },
    { label: 'accepted_fix', description: 'Mark as fixed or accepted for remediation' },
    { label: 'risk_accepted', description: 'Accept risk with rationale' },
  ], { title: 'Secure Review decision state' });
  if (!state) return;
  const reason = await vscode.window.showInputBox({ title: 'Decision reason', value: finding.decision_reason || '', ignoreFocusOut: true });
  if (reason === undefined) return;
  try {
    await apiJson('POST', `/api/scans/${scan.scan_id}/decisions`, JSON.stringify({ finding_id: finding.id, state: state.label, reason }), { 'content-type': 'application/json' });
    const updated = await apiJson('GET', `/api/scans/${scan.scan_id}`);
    await setLastScan(context, updated);
    findingsProvider.setScan(updated);
    vscode.window.showInformationMessage(`Decision saved for ${finding.id}.`);
  } catch (error) {
    showApiError('Could not save decision', error);
  }
}

async function openFinding(item) {
  const finding = item && item.finding;
  if (!finding) return;
  const folder = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
  if (!folder) return;
  const locationPath = finding.location && finding.location.path;
  const filePath = path.isAbsolute(locationPath || '') ? locationPath : path.join(folder.uri.fsPath, locationPath || '');
  if (!filePath || !fs.existsSync(filePath)) {
    vscode.window.showWarningMessage(`Finding location is not a local file: ${locationPath || 'unknown'}`);
    return;
  }
  const document = await vscode.workspace.openTextDocument(vscode.Uri.file(filePath));
  const editor = await vscode.window.showTextDocument(document);
  const line = Math.max((finding.location.line || 1) - 1, 0);
  const column = Math.max((finding.location.column || 1) - 1, 0);
  const position = new vscode.Position(line, column);
  editor.selection = new vscode.Selection(position, position);
  editor.revealRange(new vscode.Range(position, position), vscode.TextEditorRevealType.InCenter);
}

async function openWebApp() {
  await vscode.env.openExternal(vscode.Uri.parse(apiBaseUrl()));
}

async function pickWorkspaceFolder() {
  const folders = vscode.workspace.workspaceFolders || [];
  if (folders.length === 0) {
    vscode.window.showWarningMessage('Open a folder or workspace before scanning.');
    return null;
  }
  if (folders.length === 1) return folders[0];
  const picked = await vscode.window.showQuickPick(folders.map(folder => ({ label: folder.name, folder })), { title: 'Select workspace folder' });
  return picked && picked.folder;
}

async function requireLastScan(context) {
  const scan = await loadLastScan(context);
  if (!scan) vscode.window.showInformationMessage('No scan loaded. Run Secure Review: Scan Workspace first.');
  return scan;
}

async function loadLastScan(context) {
  const lastScanId = context.globalState.get('secureCodeReview.lastScanId');
  if (lastScanId) {
    try {
      const scan = await apiJson('GET', `/api/scans/${lastScanId}`);
      await setLastScan(context, scan);
      return scan;
    } catch (error) {
      output.appendLine(`Could not load last scan ${lastScanId}: ${error.message}`);
    }
  }
  const scans = await apiJson('GET', '/api/scans');
  if (!Array.isArray(scans) || scans.length === 0) return null;
  await setLastScan(context, scans[0]);
  return scans[0];
}

async function setLastScan(context, scan) {
  await context.globalState.update('secureCodeReview.lastScanId', scan && scan.scan_id);
  await context.globalState.update('secureCodeReview.lastScan', scan || null);
}

async function resolveFinding(scan, item) {
  if (!scan) {
    vscode.window.showInformationMessage('No scan loaded.');
    return null;
  }
  if (item && item.finding) return item.finding;
  const picked = await vscode.window.showQuickPick(scan.findings.map(finding => ({
    label: `${safeRisk(finding).priority} ${safeRisk(finding).score} ${finding.title}`,
    description: `${finding.location.path}:${finding.location.line}`,
    detail: finding.message,
    finding,
  })), { title: 'Select finding' });
  return picked && picked.finding;
}

function reportDefinitions(scan) {
  const scanId = scan.scan_id;
  return [
    jsonReport('scan-json', 'Scan JSON', `/api/scans/${scanId}`, 'scan.json', 'Raw normalized scan result.'),
    jsonReport('scanner-mesh', 'Scanner Mesh', `/api/scans/${scanId}/scanner-mesh`, 'scanner-mesh.json', 'Unified scanner ingestion and source coverage.'),
    jsonReport('reachability-context', 'Reachability Context', `/api/scans/${scanId}/reachability-context`, 'reachability-context.json', 'Request-handler, changed-file, and exploitability context without raw code.'),
    jsonReport('dependency-review', 'Dependency Review', `/api/scans/${scanId}/dependencies/review`, 'dependency-review.json', 'Reachability and dependency risk scoring.'),
    jsonReport('sonarqube', 'SonarQube Quality Gate', `/api/scans/${scanId}/sonarqube/report`, 'sonarqube-quality-gate.json', 'SonarQube issue and quality gate ingestion.'),
    jsonReport('scanner-depth', 'Scanner Depth', `/api/scans/${scanId}/scanner-depth`, 'scanner-depth.json', 'Semgrep and CodeQL coverage depth.'),
    jsonReport('quarantine-policy', 'Quarantine Policy', `/api/scans/${scanId}/quarantine-policy`, 'quarantine-policy.json', 'Host execution, raw-code access, and agent-learning controls for this repository.'),
    jsonReport('sanitized-report', 'Sanitized Report Lake', `/api/scans/${scanId}/sanitized-report`, 'sanitized-report.json', 'Redacted scan record prepared for report lake and future agent memory.'),
    jsonReport('rag-memory', 'RAG Memory', `/api/scans/${scanId}/rag-memory`, 'rag-memory.json', 'Structured sanitized memory items for future Hermes/RAG retrieval.'),
    jsonReport('hermes', 'Hermes Orchestration', `/api/scans/${scanId}/hermes`, 'hermes-orchestration.json', 'Policy-gated agent orchestration over sanitized RAG memory.'),
    jsonReport('secret-policy', 'Secret Policy', `/api/scans/${scanId}/secrets/policy`, 'secret-policy.json', 'Push-protection policy evidence.'),
    jsonReport('push-protection', 'Push Protection', `/api/scans/${scanId}/push-protection`, 'push-protection.json', 'Secret blocking status.'),
    jsonReport('cyclonedx', 'CycloneDX SBOM', `/api/scans/${scanId}/sbom/cyclonedx`, 'cyclonedx-sbom.json', 'CycloneDX SBOM export.'),
    jsonReport('spdx', 'SPDX SBOM', `/api/scans/${scanId}/sbom/spdx`, 'spdx-sbom.json', 'SPDX supply-chain document.'),
    jsonReport('spdx-compliance', 'SPDX Compliance', `/api/scans/${scanId}/sbom/spdx/compliance`, 'spdx-compliance.json', 'License and procurement compliance.'),
    jsonReport('sbom-policy', 'SBOM Policy', `/api/scans/${scanId}/sbom/policy`, 'sbom-policy.json', 'SBOM vulnerability and license policy checks.'),
    jsonReport('sbom-compare', 'SBOM Compare', `/api/scans/${scanId}/sbom/compare`, 'sbom-compare.json', 'Added and removed component comparison.'),
    jsonReport('github-pr-review', 'GitHub PR Review', `/api/scans/${scanId}/github/pr-review`, 'github-pr-review.json', 'Dry-run PR review payload.'),
    jsonReport('code-host-review', 'GitLab/Azure/Bitbucket Review', `/api/scans/${scanId}/code-hosts/review`, 'code-host-review.json', 'Dry-run GitLab, Azure DevOps, and Bitbucket review payloads.'),
    textReport('pr-comment', 'GitHub PR Comment', `/api/scans/${scanId}/github-pr-comment`, 'pr-comment.md', 'markdown', 'Markdown PR comment summary.'),
    jsonReport('fix-proposals', 'Fix Proposals', null, 'fix-proposals.json', 'Top fix proposals generated through the same proposal API.', buildFixProposalsArtifact),
    jsonReport('fix-bundle', 'Fix Bundle', `/api/scans/${scanId}/fixes/bundle?limit=${fixBundleLimit()}&provider=${encodeURIComponent(defaultFixProvider())}`, 'fix-bundle.json', 'Safe one-click fix bundle.'),
    jsonPostReport('fix-apply-dry-run', 'Fix Apply Dry Run', `/api/scans/${scanId}/fixes/apply`, 'fix-apply-dry-run.json', 'Dry-run safe apply workflow.', JSON.stringify({ dry_run: true, approved: true, limit: fixBundleLimit(), provider: defaultFixProvider() })),
    jsonReport('remediation-plan', 'Remediation Plan', `/api/scans/${scanId}/remediation-plan`, 'remediation-plan.json', 'Prioritized remediation plan.'),
    jsonReport('issue-plan', 'Jira/Linear Issue Plan', `/api/scans/${scanId}/issue-plan`, 'issue-plan.json', 'Dry-run Jira and Linear work item payloads.'),
    jsonReport('chat-notification', 'Slack/Teams Agent', `/api/scans/${scanId}/chat/notification`, 'chat-notification.json', 'Dry-run Slack and Teams notification payloads.'),
    jsonReport('messaging-gateway', 'Messaging Gateway', `/api/scans/${scanId}/messaging-gateway`, 'messaging-gateway.json', 'First-party messaging and device notification gateway payloads.'),
    jsonReport('team-learning', 'Team Learning Dashboard', '/api/team-learning/dashboard', 'team-learning-dashboard.json', 'Team learning trends, campaign recommendations, and security behavior dashboard.'),
    jsonReport('recursive-learning', 'Recursive Scanner Learning', `/api/scans/${scanId}/recursive-learning`, 'recursive-learning.json', 'Controlled scanner improvement recommendations from scan evidence.'),
    jsonReport('benchmark-gate', 'Benchmark Gate', `/api/scans/${scanId}/benchmark-gate`, 'benchmark-gate.json', 'Promotion gate for benchmarked, approved scanner lessons.'),
    jsonReport('governance-evidence', 'Enterprise Governance Evidence', `/api/scans/${scanId}/governance`, 'governance-evidence.json', 'Audit, approval, memory lineage, rollback, and compliance evidence.'),
    jsonReport('memory-context', 'Repository Memory Brief', `/api/scans/${scanId}/memory-context`, 'memory-context.json', 'Repository memory attached to this scan.'),
    jsonReport('advanced-ai', 'Advanced AI Report', `/api/scans/${scanId}/advanced-ai/report`, 'advanced-ai.json', 'Embeddings, multi-agent, local runtime, and GPU report.'),
    jsonReport('ai-review', 'AI Finding Review', `/api/scans/${scanId}/ai-review?provider=${encodeURIComponent(defaultFixProvider())}&limit=${fixBundleLimit()}`, 'ai-review.json', 'Dynamic prompt AI explanations and remediation suggestions.'),
    jsonReport('compliance', 'Enterprise Compliance', `/api/scans/${scanId}/compliance`, 'compliance.json', 'Enterprise compliance evidence.'),
    jsonReport('sarif', 'SARIF', `/api/scans/${scanId}/sarif`, 'secure-review.sarif', 'SARIF export for code scanning.'),
    textReport('markdown-report', 'Markdown Report', `/api/scans/${scanId}/report.md`, 'secure-review.md', 'markdown', 'Human-readable markdown report.'),
    textReport('html-report', 'HTML Report', `/api/scans/${scanId}/report.html`, 'secure-review.html', 'html', 'Printable HTML report.'),
  ];
}

function jsonReport(id, label, route, fileName, detail, custom) {
  return { id, label, route, fileName, detail, language: 'json', custom };
}

function jsonPostReport(id, label, route, fileName, detail, body) {
  return { id, label, route, fileName, detail, language: 'json', method: 'POST', body, headers: { 'content-type': 'application/json' } };
}

function textReport(id, label, route, fileName, language, detail) {
  return { id, label, route, fileName, detail, language };
}

async function fetchReportContent(scan, report) {
  if (report.custom) return report.custom(scan);
  const route = typeof report.route === 'function' ? report.route(scan) : report.route;
  const body = typeof report.body === 'function' ? report.body(scan) : report.body;
  const response = await apiRequest(report.method || 'GET', route, body, report.headers || {});
  return formatReportContent(response.body || '', report.language);
}

function formatReportContent(content, language) {
  if (language !== 'json') return content;
  try {
    return JSON.stringify(JSON.parse(content), null, 2);
  } catch (error) {
    return content;
  }
}

async function buildFixProposalsArtifact(scan) {
  const eligible = (scan.findings || []).filter(finding => ['CRITICAL', 'HIGH', 'MEDIUM'].includes(finding.severity)).slice(0, fixBundleLimit());
  const proposals = [];
  const provider = defaultFixProvider();
  for (const finding of eligible) {
    try {
      const params = new URLSearchParams({ provider });
      const proposal = await apiJson('POST', `/api/scans/${scan.scan_id}/findings/${finding.id}/fix-proposal?${params}`);
      proposals.push(proposal);
    } catch (error) {
      proposals.push({ finding_id: finding.id, title: finding.title, error: error.message || String(error) });
    }
  }
  return JSON.stringify({
    scan_id: scan.scan_id,
    project_name: scan.project_name,
    generated_at: new Date().toISOString(),
    provider,
    limit: fixBundleLimit(),
    selected: eligible.length,
    proposals,
  }, null, 2);
}

function formatProposal(proposal) {
  const checks = (proposal.validation_checks || []).map(check => `# ${check.status}: ${check.name} - ${check.detail}`).join('\n');
  const commands = (proposal.validation_commands || []).map(command => `# - ${command}`).join('\n');
  const notes = (proposal.safety_notes || []).map(note => `# - ${note}`).join('\n');
  return [
    `# ${proposal.title}`,
    `# Priority: ${proposal.priority} | Risk: ${proposal.risk_score} | Effort: ${proposal.effort} | Confidence: ${proposal.confidence}`,
    '#',
    '# Validation checks:',
    checks || '# - none recorded',
    '#',
    '# Validation commands:',
    commands || '# - rerun scan and project tests',
    '#',
    '# Safety notes:',
    notes || '# - human review required',
    '',
    proposal.patch || '',
  ].join('\n');
}

async function showDocument(fileName, content, language) {
  const document = await vscode.workspace.openTextDocument({ content, language });
  await vscode.window.showTextDocument(document, { preview: false });
}

function apiJson(method, route, body, headers = {}) {
  return apiRequest(method, route, body, headers).then(response => {
    if (!response.body) return null;
    try {
      return JSON.parse(response.body);
    } catch (error) {
      throw new Error(`Invalid JSON response from ${route}: ${response.body.slice(0, 200)}`);
    }
  });
}

function apiRequest(method, route, body, headers = {}) {
  const target = new URL(route, `${apiBaseUrl()}/`);
  const client = target.protocol === 'https:' ? https : http;
  const payload = body ? Buffer.from(body) : null;
  const requestHeaders = { ...configuredHeaders(), ...headers };
  if (payload) requestHeaders['content-length'] = String(payload.length);

  return new Promise((resolve, reject) => {
    const request = client.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port,
      path: `${target.pathname}${target.search}`,
      method,
      headers: requestHeaders,
    }, response => {
      let data = '';
      response.setEncoding('utf8');
      response.on('data', chunk => data += chunk);
      response.on('end', () => {
        if (response.statusCode < 200 || response.statusCode >= 300) {
          const error = new Error(`HTTP ${response.statusCode}: ${data || response.statusMessage}`);
          error.statusCode = response.statusCode;
          reject(error);
          return;
        }
        resolve({ statusCode: response.statusCode, body: data });
      });
    });
    request.on('error', reject);
    if (payload) request.write(payload);
    request.end();
  });
}

function configuredHeaders() {
  const result = {};
  const extra = config().get('requestHeaders') || {};
  for (const [key, value] of Object.entries(extra)) {
    if (key && value !== undefined && value !== null && String(value) !== '') result[key] = String(value);
  }
  const bearerToken = config().get('bearerToken');
  if (bearerToken) result.authorization = `Bearer ${bearerToken}`;
  return result;
}

function showApiError(title, error) {
  output.appendLine(`${title}: ${error.stack || error.message || error}`);
  output.show(true);
  const suffix = error && error.statusCode === 401 ? ' Check SSO/auth/API header configuration for API access.' : '';
  vscode.window.showErrorMessage(`${title}: ${error.message || error}.${suffix}`);
}

function safeRisk(finding) {
  return finding.risk || { score: 0, tier: finding.severity || 'INFO', priority: 'P4', recommended_action: 'Review and triage.' };
}

class FindingsProvider {
  constructor(context) {
    this.context = context;
    this.scan = null;
    this.emitter = new vscode.EventEmitter();
    this.onDidChangeTreeData = this.emitter.event;
  }

  setScan(scan) {
    this.scan = scan;
    this.emitter.fire();
  }

  getTreeItem(element) {
    return element;
  }

  getChildren(element) {
    if (element) return [];
    if (!this.scan) return [new MessageItem('No scan loaded. Run Secure Review: Scan Workspace.')];
    if (!this.scan.findings || this.scan.findings.length === 0) return [new MessageItem('No findings reported.')];
    return this.scan.findings.map(finding => new FindingItem(finding));
  }
}

class MessageItem extends vscode.TreeItem {
  constructor(message) {
    super(message, vscode.TreeItemCollapsibleState.None);
    this.contextValue = 'message';
  }
}

class FindingItem extends vscode.TreeItem {
  constructor(finding) {
    const risk = safeRisk(finding);
    super(`${risk.priority} ${risk.score} ${finding.title}`, vscode.TreeItemCollapsibleState.None);
    this.finding = finding;
    this.contextValue = 'finding';
    this.description = `${finding.location.path}:${finding.location.line}`;
    this.tooltip = `${finding.message}\n${finding.rule_id}\n${finding.source}\n${risk.recommended_action || ''}`;
    this.command = { command: 'secureCodeReview.openFinding', title: 'Open Finding', arguments: [this] };
    this.iconPath = iconForPriority(risk.priority);
  }
}

function iconForPriority(priority) {
  if (priority === 'P0' || priority === 'P1') return new vscode.ThemeIcon('warning', new vscode.ThemeColor('problemsErrorIcon.foreground'));
  if (priority === 'P2') return new vscode.ThemeIcon('warning', new vscode.ThemeColor('problemsWarningIcon.foreground'));
  return new vscode.ThemeIcon('info', new vscode.ThemeColor('problemsInfoIcon.foreground'));
}

module.exports = { activate, deactivate };
