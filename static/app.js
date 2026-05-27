const form = document.querySelector('#scan-form');
const statusEl = document.querySelector('#status');
const scanStateEl = document.querySelector('#scan-state');
const scanStateLabelEl = document.querySelector('#scan-state-label');
const scanStateDetailEl = document.querySelector('#scan-state-detail');
const scanStateElapsedEl = document.querySelector('#scan-state-elapsed');
const summaryEl = document.querySelector('#summary');
const findingsEl = document.querySelector('#findings');
const actionsEl = document.querySelector('#actions');
const healthEl = document.querySelector('#health');
const authUserEl = document.querySelector('#auth-user');
const scanButton = form.querySelector('button[type="submit"]');
const scanButtonLabel = scanButton ? scanButton.textContent : '';
let currentScan = null;
let serviceHealth = null;
let scanTimer = null;
let scanStartedAt = null;

fetch('/api/health').then(r => r.json()).then(data => {
  serviceHealth = data;
  const capabilityCount = (data.features || []).length;
  healthEl.innerHTML = data.ok
    ? `Service ready: ${capabilityCount} capabilities <button class="text-action" onclick="showSystemInfo()">System Info</button>`
    : 'Service unavailable';
}).catch(() => healthEl.textContent = 'Service unavailable');

fetch('/auth/me').then(r => r.ok ? r.json() : null).then(user => {
  if (!user) return;
  authUserEl.innerHTML = `${escapeHtml(user.display_name)} <a href="/auth/logout">Logout</a>`;
}).catch(() => {});

setScanState('idle', 'Scan not running', 'Ready to start a scan.');

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  statusEl.textContent = 'Scanning with source analyzers, dependency audit, secret scanning, risk scoring, memory update, and enterprise audit logging.';
  findingsEl.innerHTML = '';
  actionsEl.innerHTML = '';
  setScanState('running', 'Scan in progress', 'Running analyzers and preparing reports.');
  startScanTimer();
  if (scanButton) {
    scanButton.disabled = true;
    scanButton.textContent = 'Scanning...';
  }
  const body = new FormData(form);
  if (!body.get('archive')?.name) body.delete('archive');
  try {
    const response = await fetch('/api/scans', { method: 'POST', body });
    if (!response.ok) {
      const detail = await response.text();
      statusEl.textContent = `Scan failed: ${detail}`;
      setScanState('error', 'Scan failed', shortStatus(detail));
      return;
    }
    currentScan = await response.json();
    const bundlePath = currentScan.report_bundle && currentScan.report_bundle.bundle_dir;
    statusEl.textContent = bundlePath
      ? `Scan ${currentScan.scan_id} finished. Report bundle saved to: ${bundlePath}`
      : `Scan ${currentScan.scan_id} finished.`;
    setScanState('done', 'Scan is over', `Completed scan ${currentScan.scan_id}.`);
    renderScan(currentScan);
  } catch (error) {
    const detail = error && error.message ? error.message : String(error);
    statusEl.textContent = `Scan failed: ${detail}`;
    setScanState('error', 'Scan failed', shortStatus(detail));
  } finally {
    stopScanTimer();
    if (scanButton) {
      scanButton.disabled = false;
      scanButton.textContent = scanButtonLabel;
    }
  }
});

function setScanState(state, label, detail) {
  if (!scanStateEl) return;
  scanStateEl.className = `scan-state ${state}`;
  scanStateLabelEl.textContent = label;
  scanStateDetailEl.textContent = detail || '';
}

function startScanTimer() {
  scanStartedAt = Date.now();
  updateScanElapsed();
  stopScanTimer();
  scanTimer = window.setInterval(updateScanElapsed, 1000);
}

function stopScanTimer() {
  if (scanTimer) {
    window.clearInterval(scanTimer);
    scanTimer = null;
  }
}

function updateScanElapsed() {
  if (!scanStartedAt || !scanStateElapsedEl) return;
  scanStateElapsedEl.textContent = formatElapsed(Date.now() - scanStartedAt);
}

function formatElapsed(ms) {
  const totalSeconds = Math.max(0, Math.floor(ms / 1000));
  const minutes = String(Math.floor(totalSeconds / 60)).padStart(2, '0');
  const seconds = String(totalSeconds % 60).padStart(2, '0');
  return `${minutes}:${seconds}`;
}

function shortStatus(value) {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
  return text.length > 180 ? `${text.slice(0, 177)}...` : text;
}

function renderScan(scan) {
  const s = scan.summary;
  summaryEl.innerHTML = [
    metric('Total', s.total_findings), metric('Production', s.production_findings || 0), metric('Hygiene', s.hygiene_findings || 0),
    metric('Prod Max Risk', s.max_risk_score || 0), metric('Prod P0/P1', priorityCount(s, 'P0') + priorityCount(s, 'P1')), metric('Files', s.files_scanned),
    metric('Scopes', formatScopeCounts(s.scope_counts)), metric('New', scan.new_findings.length)
  ].join('');
  actionsEl.innerHTML = `
    <a class="link-button" href="/api/scans/${scan.scan_id}/sarif" target="_blank">SARIF</a>
    <a class="link-button secondary" href="/api/scans/${scan.scan_id}/report.html" target="_blank">HTML Report</a>
    <a class="link-button secondary" href="/api/scans/${scan.scan_id}/report.md" target="_blank">Markdown</a>
    <button class="ghost" onclick="showReportBundle('${scan.scan_id}')">Report Bundle</button>
    <button class="ghost" onclick="showSanitizedReport('${scan.scan_id}')">Sanitized Report</button>
    <button class="ghost" onclick="showRagMemory('${scan.scan_id}')">RAG Memory</button>
    <button class="ghost" onclick="showHermes('${scan.scan_id}')">Hermes</button>
    <button class="ghost" onclick="showGovernance('${scan.scan_id}')">Governance</button>
    <a class="link-button secondary" href="/api/scans/${scan.scan_id}/github-pr-comment" target="_blank">PR Comment</a>
    <button class="ghost" onclick="saveBaseline('${scan.scan_id}')">Save Baseline</button>
    <button class="ghost" onclick="showCompliance('${scan.scan_id}')">Compliance</button>
    <button class="ghost" onclick="showSecretPolicy('${scan.scan_id}')">Push Protection</button>
    <button class="ghost" onclick="showGithubPrReview('${scan.scan_id}')">GitHub PR</button>
    <button class="ghost" onclick="showCodeHostReview('${scan.scan_id}')">Code Hosts</button>
    <button class="ghost" onclick="showScannerMesh('${scan.scan_id}')">Scanner Mesh</button>
    <button class="ghost" onclick="showSonarQubeReport('${scan.scan_id}')">SonarQube</button>
    <button class="ghost" onclick="showScannerDepth('${scan.scan_id}')">Scanner Depth</button>
    <button class="ghost" onclick="showDependencyReview('${scan.scan_id}')">Dependencies</button>
    <button class="ghost" onclick="showFixBundle('${scan.scan_id}')">Fix Bundle</button>
    <button class="ghost" onclick="dryRunFixApply('${scan.scan_id}')">Fix Dry Run</button>
    <button class="ghost" onclick="showRemediationPlan('${scan.scan_id}')">Remediation</button>
    <button class="ghost" onclick="showAiScanReview('${scan.scan_id}')">AI Review</button>
    <button class="ghost" onclick="showIssuePlan('${scan.scan_id}')">Issue Plan</button>
    <button class="ghost" onclick="showChatNotification('${scan.scan_id}')">Chat Agent</button>
    <button class="ghost" onclick="showMessagingGateway('${scan.scan_id}')">Gateway</button>
    <button class="ghost" onclick="showTeamLearning()">Team Learning</button>
    <button class="ghost" onclick="showRecursiveLearning()">Recursive Learning</button>
    <button class="ghost" onclick="showTeamLearningBrief('${scan.scan_id}')">Learning Brief</button>
    <button class="ghost" onclick="showRecursiveLearningBrief('${scan.scan_id}')">Scanner Learning</button>
    <button class="ghost" onclick="showMemory()">Memory</button>
    <button class="ghost" onclick="showMemoryBrief('${scan.scan_id}')">Memory Brief</button>
    <button class="ghost" onclick="showRagStats()">Knowledge</button>
    <button class="ghost" onclick="showEnterprise()">Enterprise</button>`;
  findingsEl.innerHTML = scan.findings.map(renderFinding).join('') || '<section class="panel">No findings reported.</section>';
}

function formatRiskPoints(points) {
  const value = Number(points || 0);
  return value > 0 ? `+${value}` : String(value);
}
function metric(label, value) {
  return `<div class="metric"><strong>${value}</strong><span>${label}</span></div>`;
}

function priorityCount(summary, priority) {
  return (summary.priorities && summary.priorities[priority]) || 0;
}

function formatScopeCounts(scopes) {
  const entries = Object.entries(scopes || {});
  return entries.length ? entries.map(([key, value]) => `${key}:${value}`).join(' ') : 'none';
}

function renderFinding(f) {
  const tags = [...(f.cwe || []), ...(f.owasp || [])].map(t => `<span class="badge">${escapeHtml(t)}</span>`).join('');
  const guidance = (f.fix.guidance || []).map(item => `<li>${escapeHtml(item)}</li>`).join('');
  const riskFactors = ((f.risk && f.risk.factors) || []).map(item => `<li>${escapeHtml(item.label)} ${formatRiskPoints(item.points)}: ${escapeHtml(item.detail)}</li>`).join('');
  const risk = f.risk || { score: 0, tier: 'INFO', priority: 'P4', recommended_action: 'Review and triage.' };
  return `<article class="finding ${risk.tier.toLowerCase()}">
    <div class="finding-head"><h3>[${risk.priority} / ${risk.score}] ${escapeHtml(f.title)}</h3><span class="risk-pill">${escapeHtml(risk.tier)}</span></div>
    <div class="meta"><span>${escapeHtml(f.location.path)}:${f.location.line}</span><span>Scope ${escapeHtml(f.scope || 'production')}</span><span>${escapeHtml(f.rule_id)}</span><span>${escapeHtml(f.source)}</span><span>Severity ${escapeHtml(f.severity)}</span><span>Confidence ${escapeHtml(f.confidence)}</span>${tags}</div>
    <p>${escapeHtml(f.message)}</p>
    <p>${escapeHtml(risk.recommended_action)}</p>
    <details class="risk-details"><summary>Risk factors</summary><ul>${riskFactors || '<li>No risk factors recorded.</li>'}</ul></details>
    <p>${escapeHtml(f.explanation)}</p>
    <strong>${escapeHtml(f.fix.summary)}</strong>
    <ul class="fix-list">${guidance}</ul>
    <div class="decision-row">
      <select id="decision-${f.id}">
        ${['open','false_positive','accepted_fix','risk_accepted'].map(v => `<option ${f.decision === v ? 'selected' : ''} value="${v}">${v.replaceAll('_', ' ')}</option>`).join('')}
      </select>
      <input id="reason-${f.id}" placeholder="Decision reason" value="${escapeHtml(f.decision_reason || '')}" />
      <button class="ghost" onclick="saveDecision('${f.id}')">Save Decision</button>
      <select id="provider-${f.id}" title="LLM provider">
        <option value="offline">offline</option>
        <option value="ollama">ollama</option>
        <option value="openai">openai</option>
        <option value="openai_compatible">compatible</option>
      </select>
      <button class="ghost" onclick="showRagContext('${f.id}')">RAG</button>
      <button class="ghost" onclick="showAiFindingReview('${f.id}')">AI Review</button>
      <button class="ghost" onclick="proposeFix('${f.id}')">Propose Fix</button>
    </div>
    <pre class="proposal" id="proposal-${f.id}"></pre>
  </article>`;
}

async function saveBaseline(scanId) {
  const response = await fetch(`/api/scans/${scanId}/baseline`, { method: 'POST' });
  statusEl.textContent = response.ok ? 'Baseline saved for future scans.' : 'Could not save baseline.';
}

async function saveDecision(findingId) {
  const state = document.querySelector(`#decision-${findingId}`).value;
  const reason = document.querySelector(`#reason-${findingId}`).value;
  const response = await fetch(`/api/scans/${currentScan.scan_id}/decisions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ finding_id: findingId, state, reason })
  });
  statusEl.textContent = response.ok ? 'Decision saved.' : 'Could not save decision.';
}

async function proposeFix(findingId) {
  const provider = document.querySelector(`#provider-${findingId}`).value;
  const target = document.querySelector(`#proposal-${findingId}`);
  target.textContent = 'Generating proposal...';
  const response = await fetch(`/api/scans/${currentScan.scan_id}/findings/${findingId}/fix-proposal?provider=${provider}`, { method: 'POST' });
  if (!response.ok) {
    target.textContent = 'Could not generate proposal.';
    return;
  }
  const proposal = await response.json();
  target.textContent = formatProposal(proposal);
}

function formatProposal(proposal) {
  const checks = (proposal.validation_checks || []).map(item => `- ${item.status}: ${item.name} - ${item.detail}`).join('\n');
  const commands = (proposal.validation_commands || []).map(item => `- ${item}`).join('\n');
  const notes = (proposal.safety_notes || []).map(item => `- ${item}`).join('\n');
  return [
    `${proposal.summary}`,
    `Priority: ${proposal.priority} | Risk: ${proposal.risk_score} | Effort: ${proposal.effort} | Confidence: ${proposal.confidence}`,
    '',
    'Validation checks:',
    checks || '- none recorded',
    '',
    'Validation commands:',
    commands || '- rerun scan and project tests',
    '',
    proposal.patch,
    '',
    'Safety notes:',
    notes || '- human review required'
  ].join('\n');
}

async function showReportBundle(scanId) {
  const response = await fetch(`/api/scans/${scanId}/report-bundle`);
  if (!response.ok) {
    statusEl.textContent = 'Could not load report bundle manifest.';
    return;
  }
  const manifest = await response.json();
  statusEl.textContent = manifest.bundle_dir ? `Report bundle: ${manifest.bundle_dir}` : 'Report bundle manifest loaded.';
  showJsonPanel('Report Bundle', manifest);
}

async function showSanitizedReport(scanId) {
  const response = await fetch(`/api/scans/${scanId}/sanitized-report`);
  if (!response.ok) {
    statusEl.textContent = 'Could not load sanitized report.';
    return;
  }
  showJsonPanel('Sanitized Report', await response.json());
}

async function showRagMemory(scanId) {
  const response = await fetch(`/api/scans/${scanId}/rag-memory`);
  if (!response.ok) {
    statusEl.textContent = 'Could not load RAG memory.';
    return;
  }
  showJsonPanel('RAG Memory', await response.json());
}

async function showHermes(scanId) {
  const response = await fetch(`/api/scans/${scanId}/hermes`);
  if (!response.ok) {
    statusEl.textContent = 'Could not load Hermes orchestration.';
    return;
  }
  showJsonPanel('Hermes Orchestration', await response.json());
}

async function showGovernance(scanId) {
  const response = await fetch(`/api/scans/${scanId}/governance`);
  if (!response.ok) {
    statusEl.textContent = 'Could not load governance evidence.';
    return;
  }
  showJsonPanel('Enterprise Governance Evidence', await response.json());
}

async function showAiScanReview(scanId) {
  const response = await fetch(`/api/scans/${scanId}/ai-review?provider=offline&limit=25`);
  if (!response.ok) {
    statusEl.textContent = 'Could not load AI review.';
    return;
  }
  showJsonPanel('AI Finding Review', await response.json());
}

async function showAiFindingReview(findingId) {
  const provider = document.querySelector(`#provider-${findingId}`).value;
  const target = document.querySelector(`#proposal-${findingId}`);
  target.textContent = 'Generating AI review...';
  const response = await fetch(`/api/scans/${currentScan.scan_id}/findings/${findingId}/ai-review?provider=${provider}&include_prompts=true`);
  if (!response.ok) {
    target.textContent = 'Could not generate AI review.';
    return;
  }
  const review = await response.json();
  target.textContent = formatAiReview(review);
}

function formatAiReview(review) {
  const steps = ((review.remediation_suggestion && review.remediation_suggestion.steps) || []).map(item => `- ${item}`).join('\n');
  const commands = ((review.remediation_suggestion && review.remediation_suggestion.validation_commands) || []).map(item => `- ${item}`).join('\n');
  return [
    `AI scenario: ${review.scenario.label} (${review.scenario.confidence})`,
    '',
    'Explanation:',
    review.ai_explanation.text,
    '',
    'Remediation:',
    review.remediation_suggestion.text,
    '',
    'Steps:',
    steps || '- Review finding and apply the smallest safe change.',
    '',
    'Validation:',
    commands || '- Rerun scan and project tests.',
  ].join('\n');
}
async function showFixBundle(scanId) {
  const response = await fetch(`/api/scans/${scanId}/fixes/bundle?limit=10`);
  if (!response.ok) {
    statusEl.textContent = 'Could not build fix bundle.';
    return;
  }
  showJsonPanel('Secure Fix Bundle', await response.json());
}

async function dryRunFixApply(scanId) {
  const response = await fetch(`/api/scans/${scanId}/fixes/apply`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ dry_run: true, approved: true, limit: 10 })
  });
  if (!response.ok) {
    statusEl.textContent = 'Could not dry-run fix apply.';
    return;
  }
  showJsonPanel('Fix Apply Dry Run', await response.json());
}

async function showRemediationPlan(scanId) {
  const response = await fetch(`/api/scans/${scanId}/remediation-plan`);
  if (!response.ok) {
    statusEl.textContent = 'Could not load remediation plan.';
    return;
  }
  showJsonPanel('Remediation Plan', await response.json());
}
async function showIssuePlan(scanId) {
  const response = await fetch(`/api/scans/${scanId}/issue-plan`);
  if (!response.ok) {
    statusEl.textContent = 'Could not load Jira/Linear issue plan.';
    return;
  }
  showJsonPanel('Jira/Linear Issue Plan', await response.json());
}
async function showChatNotification(scanId) {
  const response = await fetch(`/api/scans/${scanId}/chat/notification`);
  if (!response.ok) {
    statusEl.textContent = 'Could not load Slack/Teams chat notification.';
    return;
  }
  showJsonPanel('Slack/Teams Chat Agent', await response.json());
}
async function showMessagingGateway(scanId) {
  const response = await fetch(`/api/scans/${scanId}/messaging-gateway`);
  if (!response.ok) {
    statusEl.textContent = 'Could not load messaging gateway report.';
    return;
  }
  showJsonPanel('Messaging Gateway', await response.json());
}
async function showCompliance(scanId) {
  const response = await fetch(`/api/scans/${scanId}/compliance`);
  showJsonPanel('Compliance Report', await response.json());
}

async function showSecretPolicy(scanId) {
  const response = await fetch(`/api/scans/${scanId}/secrets/policy`);
  if (!response.ok) {
    statusEl.textContent = 'Could not load push-protection policy.';
    return;
  }
  showJsonPanel('Push Protection', await response.json());
}

async function showCodeHostReview(scanId) {
  const response = await fetch(`/api/scans/${scanId}/code-hosts/review`);
  if (!response.ok) {
    statusEl.textContent = 'Could not build GitLab/Azure DevOps/Bitbucket review preview.';
    return;
  }
  showJsonPanel('GitLab/Azure DevOps/Bitbucket Review', await response.json());
}
async function showGithubPrReview(scanId) {
  const response = await fetch(`/api/scans/${scanId}/github/pr-review`);
  if (!response.ok) {
    statusEl.textContent = 'Could not build GitHub PR review preview.';
    return;
  }
  showJsonPanel('GitHub PR Review', await response.json());
}



async function showDependencyReview(scanId) {
  const response = await fetch(`/api/scans/${scanId}/dependencies/review`);
  if (!response.ok) {
    statusEl.textContent = 'Could not load dependency review.';
    return;
  }
  showJsonPanel('Dependency Review', await response.json());
}
async function showScannerMesh(scanId) {
  const response = await fetch(`/api/scans/${scanId}/scanner-mesh`);
  if (!response.ok) {
    statusEl.textContent = 'Could not load scanner mesh report.';
    return;
  }
  showJsonPanel('Scanner Mesh', await response.json());
}

async function showSonarQubeReport(scanId) {
  const response = await fetch(`/api/scans/${scanId}/sonarqube/report`);
  if (!response.ok) {
    statusEl.textContent = 'Could not load SonarQube report.';
    return;
  }
  showJsonPanel('SonarQube Quality Gate', await response.json());
}

async function showScannerDepth(scanId) {
  const response = await fetch(`/api/scans/${scanId}/scanner-depth`);
  if (!response.ok) {
    statusEl.textContent = 'Could not load scanner depth report.';
    return;
  }
  showJsonPanel('Scanner Depth', await response.json());
}
async function showRagContext(findingId) {
  const response = await fetch(`/api/scans/${currentScan.scan_id}/findings/${findingId}/rag-context`);
  if (!response.ok) {
    statusEl.textContent = 'Could not retrieve RAG context.';
    return;
  }
  const data = await response.json();
  showJsonPanel('Finding RAG Context', data);
}

async function showRagStats() {
  const response = await fetch('/api/rag/stats');
  showJsonPanel('Knowledge Index', await response.json());
}
async function showTeamLearning() {
  const response = await fetch('/api/team-learning/dashboard');
  if (!response.ok) {
    statusEl.textContent = 'Could not load team learning dashboard.';
    return;
  }
  showJsonPanel('Team Learning Dashboard', await response.json());
}

async function showTeamLearningBrief(scanId) {
  const response = await fetch(`/api/scans/${scanId}/team-learning`);
  if (!response.ok) {
    statusEl.textContent = 'Could not load scan learning brief.';
    return;
  }
  showJsonPanel('Scan Learning Brief', await response.json());
}
async function showRecursiveLearning() {
  const response = await fetch('/api/recursive-learning/dashboard');
  if (!response.ok) {
    statusEl.textContent = 'Could not load recursive scanner learning.';
    return;
  }
  showJsonPanel('Recursive Scanner Learning', await response.json());
}

async function showRecursiveLearningBrief(scanId) {
  const response = await fetch(`/api/scans/${scanId}/recursive-learning`);
  if (!response.ok) {
    statusEl.textContent = 'Could not load scan recursive learning.';
    return;
  }
  showJsonPanel('Scan Recursive Learning', await response.json());
}
async function showMemory() {
  const response = await fetch('/api/memory');
  showJsonPanel('Repository Memory', await response.json());
}

async function showMemoryBrief(scanId) {
  const response = await fetch(`/api/scans/${scanId}/memory-context`);
  if (!response.ok) {
    statusEl.textContent = 'Could not load repository memory context.';
    return;
  }
  showJsonPanel('Repository Memory Brief', await response.json());
}
async function showEnterprise() {
  const response = await fetch('/api/enterprise');
  showJsonPanel('Enterprise Configuration', await response.json());
}

async function showSystemInfo() {
  if (!serviceHealth) {
    const response = await fetch('/api/health');
    serviceHealth = await response.json();
  }
  showJsonPanel('System Info', serviceHealth);
}

function showJsonPanel(title, data) {
  const panel = document.createElement('section');
  panel.className = 'panel json-panel';
  panel.innerHTML = `<div class="finding-head"><h2>${escapeHtml(title)}</h2><button class="ghost" onclick="this.closest('section').remove()">Close</button></div><pre>${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
  findingsEl.prepend(panel);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[ch]));
}
