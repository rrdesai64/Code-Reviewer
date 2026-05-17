const form = document.querySelector('#scan-form');
const statusEl = document.querySelector('#status');
const summaryEl = document.querySelector('#summary');
const findingsEl = document.querySelector('#findings');
const actionsEl = document.querySelector('#actions');
const healthEl = document.querySelector('#health');
const authUserEl = document.querySelector('#auth-user');
let currentScan = null;

fetch('/api/health').then(r => r.json()).then(data => {
  healthEl.textContent = data.ok ? `Service ready: ${data.features.join(', ')}` : 'Service unavailable';
}).catch(() => healthEl.textContent = 'Service unavailable');

fetch('/auth/me').then(r => r.ok ? r.json() : null).then(user => {
  if (!user) return;
  authUserEl.innerHTML = `${escapeHtml(user.display_name)} <a href="/auth/logout">Logout</a>`;
}).catch(() => {});


form.addEventListener('submit', async (event) => {
  event.preventDefault();
  statusEl.textContent = 'Scanning with source analyzers, dependency audit, risk scoring, memory update, and enterprise audit logging.';
  findingsEl.innerHTML = '';
  actionsEl.innerHTML = '';
  const body = new FormData(form);
  if (!body.get('archive')?.name) body.delete('archive');
  const response = await fetch('/api/scans', { method: 'POST', body });
  if (!response.ok) {
    const detail = await response.text();
    statusEl.textContent = `Scan failed: ${detail}`;
    return;
  }
  currentScan = await response.json();
  statusEl.textContent = `Scan ${currentScan.scan_id} finished.`;
  renderScan(currentScan);
});

function renderScan(scan) {
  const s = scan.summary;
  summaryEl.innerHTML = [
    metric('Total', s.total_findings), metric('Max Risk', s.max_risk_score || 0), metric('Avg Risk', s.avg_risk_score || 0),
    metric('P0/P1', priorityCount(s, 'P0') + priorityCount(s, 'P1')), metric('Files', s.files_scanned), metric('New', scan.new_findings.length)
  ].join('');
  actionsEl.innerHTML = `
    <a class="link-button" href="/api/scans/${scan.scan_id}/sarif" target="_blank">SARIF</a>
    <a class="link-button secondary" href="/api/scans/${scan.scan_id}/report.html" target="_blank">HTML Report</a>
    <a class="link-button secondary" href="/api/scans/${scan.scan_id}/report.md" target="_blank">Markdown</a>
    <a class="link-button secondary" href="/api/scans/${scan.scan_id}/github-pr-comment" target="_blank">PR Comment</a>
    <button class="ghost" onclick="saveBaseline('${scan.scan_id}')">Save Baseline</button>
    <button class="ghost" onclick="showCompliance('${scan.scan_id}')">Compliance</button>
    <button class="ghost" onclick="showMemory()">Memory</button>
    <button class="ghost" onclick="showRagStats()">Knowledge</button>
    <button class="ghost" onclick="showEnterprise()">Enterprise</button>`;
  findingsEl.innerHTML = scan.findings.map(renderFinding).join('') || '<section class="panel">No findings reported.</section>';
}

function metric(label, value) {
  return `<div class="metric"><strong>${value}</strong><span>${label}</span></div>`;
}

function priorityCount(summary, priority) {
  return (summary.priorities && summary.priorities[priority]) || 0;
}

function renderFinding(f) {
  const tags = [...(f.cwe || []), ...(f.owasp || [])].map(t => `<span class="badge">${escapeHtml(t)}</span>`).join('');
  const guidance = (f.fix.guidance || []).map(item => `<li>${escapeHtml(item)}</li>`).join('');
  const riskFactors = ((f.risk && f.risk.factors) || []).map(item => `<li>${escapeHtml(item.label)} +${item.points}: ${escapeHtml(item.detail)}</li>`).join('');
  const risk = f.risk || { score: 0, tier: 'INFO', priority: 'P4', recommended_action: 'Review and triage.' };
  return `<article class="finding ${risk.tier.toLowerCase()}">
    <div class="finding-head"><h3>[${risk.priority} / ${risk.score}] ${escapeHtml(f.title)}</h3><span class="risk-pill">${escapeHtml(risk.tier)}</span></div>
    <div class="meta"><span>${escapeHtml(f.location.path)}:${f.location.line}</span><span>${escapeHtml(f.rule_id)}</span><span>${escapeHtml(f.source)}</span><span>Severity ${escapeHtml(f.severity)}</span><span>Confidence ${escapeHtml(f.confidence)}</span>${tags}</div>
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
  target.textContent = `${proposal.summary}\n\n${proposal.patch}\n\nSafety notes:\n- ${proposal.safety_notes.join('\n- ')}`;
}

async function showCompliance(scanId) {
  const response = await fetch(`/api/scans/${scanId}/compliance`);
  showJsonPanel('Compliance Report', await response.json());
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
async function showMemory() {
  const response = await fetch('/api/memory');
  showJsonPanel('Repository Memory', await response.json());
}

async function showEnterprise() {
  const response = await fetch('/api/enterprise');
  showJsonPanel('Enterprise Configuration', await response.json());
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
