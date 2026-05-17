const vscode = require('vscode');
const http = require('http');
const https = require('https');
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
  context.subscriptions.push(vscode.commands.registerCommand('secureCodeReview.configureApi', configureApi));
  context.subscriptions.push(vscode.commands.registerCommand('secureCodeReview.health', checkHealth));
  context.subscriptions.push(vscode.commands.registerCommand('secureCodeReview.scanWorkspace', () => scanWorkspace(context)));
  context.subscriptions.push(vscode.commands.registerCommand('secureCodeReview.refreshFindings', () => refreshFindings(context)));
  context.subscriptions.push(vscode.commands.registerCommand('secureCodeReview.showLastScan', () => showLastScan(context)));
  context.subscriptions.push(vscode.commands.registerCommand('secureCodeReview.showRemediationPlan', () => showRemediationPlan(context)));
  context.subscriptions.push(vscode.commands.registerCommand('secureCodeReview.proposeFix', item => proposeFix(context, item)));
  context.subscriptions.push(vscode.commands.registerCommand('secureCodeReview.showRagContext', item => showRagContext(context, item)));
  context.subscriptions.push(vscode.commands.registerCommand('secureCodeReview.openFinding', item => openFinding(item)));
  context.subscriptions.push(vscode.commands.registerCommand('secureCodeReview.openWebApp', openWebApp));

  refreshFindings(context, { silent: true });
}

function deactivate() {}

function apiBaseUrl() {
  return vscode.workspace.getConfiguration('secureCodeReview').get('apiBaseUrl') || 'http://127.0.0.1:8000';
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
  await vscode.workspace.getConfiguration('secureCodeReview').update('apiBaseUrl', value.replace(/\/+$/, ''), vscode.ConfigurationTarget.Global);
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
  const configuredName = vscode.workspace.getConfiguration('secureCodeReview').get('projectName');
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
  const scan = await loadLastScan(context);
  if (!scan) {
    vscode.window.showInformationMessage('No scan loaded.');
    return;
  }
  const lines = [
    `# Secure Review Scan ${scan.scan_id}`,
    '',
    `Project: ${scan.project_name}`,
    `Target: ${scan.target_path}`,
    `Findings: ${scan.summary.total_findings}`,
    `Max risk: ${scan.summary.max_risk_score}`,
    `Average risk: ${scan.summary.avg_risk_score}`,
    `Priorities: ${JSON.stringify(scan.summary.priorities || {})}`,
    '',
    'Top findings:',
    ...scan.findings.slice(0, 20).map(f => `- ${f.risk.priority} ${f.risk.score} ${f.title} (${f.location.path}:${f.location.line})`),
  ];
  await showDocument('secure-review-scan.md', lines.join('\n'), 'markdown');
}

async function showRemediationPlan(context) {
  const scan = await loadLastScan(context);
  if (!scan) {
    vscode.window.showInformationMessage('No scan loaded.');
    return;
  }
  try {
    const plan = await apiJson('GET', `/api/scans/${scan.scan_id}/remediation-plan`);
    await showDocument('secure-review-remediation-plan.json', JSON.stringify(plan, null, 2), 'json');
  } catch (error) {
    showApiError('Could not load remediation plan', error);
  }
}

async function proposeFix(context, item) {
  const scan = await loadLastScan(context);
  const finding = await resolveFinding(scan, item);
  if (!scan || !finding) return;
  try {
    const proposal = await apiJson('POST', `/api/scans/${scan.scan_id}/findings/${finding.id}/fix-proposal`);
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

async function openFinding(item) {
  const finding = item && item.finding;
  if (!finding) return;
  const folder = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
  if (!folder) return;
  const fileUri = vscode.Uri.file(path.join(folder.uri.fsPath, finding.location.path));
  const document = await vscode.workspace.openTextDocument(fileUri);
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
  const picked = await vscode.window.showQuickPick(folders.map(folder => ({ label: folder.name, folder })), { title: 'Select workspace folder to scan' });
  return picked && picked.folder;
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
    label: `${finding.risk.priority} ${finding.risk.score} ${finding.title}`,
    description: `${finding.location.path}:${finding.location.line}`,
    detail: finding.message,
    finding,
  })), { title: 'Select finding' });
  return picked && picked.finding;
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
  const base = new URL(apiBaseUrl());
  const target = new URL(route, base);
  const client = target.protocol === 'https:' ? https : http;
  const payload = body ? Buffer.from(body) : null;
  const requestHeaders = { ...headers };
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

function showApiError(title, error) {
  output.appendLine(`${title}: ${error.stack || error.message || error}`);
  output.show(true);
  const suffix = error && error.statusCode === 401 ? ' Check SSO/auth configuration for API access.' : '';
  vscode.window.showErrorMessage(`${title}: ${error.message || error}.${suffix}`);
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
    const risk = finding.risk || { priority: 'P4', score: 0, tier: finding.severity || 'INFO' };
    super(`${risk.priority} ${risk.score} ${finding.title}`, vscode.TreeItemCollapsibleState.None);
    this.finding = finding;
    this.contextValue = 'finding';
    this.description = `${finding.location.path}:${finding.location.line}`;
    this.tooltip = `${finding.message}\n${finding.rule_id}\n${finding.source}`;
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
