# Secure Code Review Assistant

Production-shaped secure code review assistant built from the strategic upgrade roadmap.

## Implemented Phases

### Phase 1: Secure Review MVP

- FastAPI backend with browser UI
- ZIP upload or local repository path scanning
- Semgrep integration with local security rules
- Bandit integration for Python
- Python dependency vulnerability checks with `pip-audit`
- Dependency manifest hygiene checks for Python and Node projects
- Normalized findings with CWE/OWASP mapping, severity, confidence, explanation, and fix guidance
- Markdown and printable HTML reports

### Phase 2: Developer Workflow Integration

- SARIF export for GitHub Security and CI tools
- GitHub Actions workflow template
- Baseline save/compare to distinguish new, resolved, and unchanged findings
- False-positive / risk-accepted / accepted-fix decisions
- GitHub PR comment summary artifact
- CI CLI

### Phase 3: RAG And Repository Memory

- Local markdown knowledge base in `knowledge/`
- Lightweight lexical RAG index stored in `data/rag_index.json`
- RAG query endpoint for CWE/OWASP/security guidance
- Repository memory in `data/memory.json`
- Scan history, recurring rules, severity trends, and hotspot files

### Phase 4: Secure Refactoring

- Human-reviewed fix proposal endpoint
- Unified diff generation for common issue classes
- RAG-backed and optional LLM-backed safety notes
- No automatic code modification or merge behavior

### Phase 5: Local And Cloud LLMs

Supported providers:

- `offline`: deterministic local fallback, always available
- `ollama`: local model server at `OLLAMA_BASE_URL`
- `openai`: OpenAI Responses API using `OPENAI_API_KEY`
- `openai_compatible`: local or cloud OpenAI-compatible chat endpoint using `LLM_BASE_URL`

### Phase 6: Enterprise Capabilities

- Local RBAC configuration with admin, security reviewer, developer, and auditor roles
- SSO configuration placeholder
- Enterprise policy definitions
- Audit log in `data/audit.log`
- Compliance report endpoint mapped to OWASP/CWE and policies

## Run The Web App

```powershell
.\run.ps1
```

Open `http://127.0.0.1:8000`.

## Try The Sample Project

```powershell
.\scan.ps1 -Path "G:\My Software Projects\Code Reviewer - Codex\sample_project"
```

Or use the web form with the same path.

## CLI Examples

```powershell
.\.venv\Scripts\python.exe -m app.cli --path . --sarif-out secure-review.sarif --report-out secure-review.md --pr-comment-out pr-comment.md --compliance-out compliance.json --fix-proposals-out fix-proposals.json --fail-on high
```

Exit code `2` means findings met or exceeded the configured `--fail-on` threshold.

## LLM Configuration

```powershell
# OpenAI cloud provider
$env:OPENAI_API_KEY="your-key"
$env:OPENAI_MODEL="gpt-5.2"

# Ollama local provider
$env:OLLAMA_BASE_URL="http://127.0.0.1:11434"
$env:OLLAMA_MODEL="codellama"

# OpenAI-compatible endpoint
$env:LLM_BASE_URL="http://127.0.0.1:8001/v1"
$env:LLM_API_KEY="optional-key"
$env:LLM_MODEL="local-model"
```

The app falls back to `offline` guidance if a configured LLM provider is unavailable.

## Key API Endpoints

- `POST /api/scans`
- `GET /api/scans/{scan_id}/sarif`
- `GET /api/scans/{scan_id}/compliance`
- `POST /api/scans/{scan_id}/findings/{finding_id}/fix-proposal?provider=offline`
- `GET /api/rag/query?q=CWE-78`
- `POST /api/rag/reindex`
- `GET /api/memory`
- `GET /api/llm/providers`
- `GET /api/enterprise`
- `GET /api/audit`

## Safety Notes

Generated fixes are proposals only. Review diffs, run tests, rerun scans, and require human approval before accepting code changes.




## Phase A: Scanner Depth

Phase A adds deeper scanner orchestration while keeping external enterprise tools opt-in.

Implemented:

- Built-in Python AST analysis using the standard `ast` parser
- Expanded language-specific Semgrep rules for Python, JavaScript/TypeScript, Java, Go, Rust, YAML, and Dockerfile
- CodeQL adapter that activates only when `CODEQL_ENABLED=true` and the CodeQL CLI is installed
- SonarQube adapter that activates only when `SONAR_ENABLED=true`, `sonar-scanner` is installed, and server credentials are configured
- Tool status reporting for `python-ast`, `codeql`, and `sonarqube`

### Enable CodeQL

CodeQL CLI has been installed locally under `tools/codeql/`. To override or disable it, set:

```powershell
$env:CODEQL_ENABLED="auto" # auto, true, or false
$env:CODEQL_EXE="C:\path\to\codeql.exe" # optional if codeql is on PATH
$env:CODEQL_QUERY_SUITE="codeql-suites/code-scanning.qls"
$env:CODEQL_TIMEOUT_SECONDS="900"
```

The app creates temporary CodeQL databases under `data/codeql/`, which is ignored by Git. CodeQL query packs were installed into the user CodeQL cache with `codeql pack download`.

### Enable SonarQube

SonarScanner has been installed as a local npm dev dependency. Create a SonarQube/SonarCloud token, then set:

```powershell
$env:SONAR_ENABLED="auto" # auto, true, or false
$env:SONAR_SCANNER_EXE="C:\path\to\sonar-scanner.bat" # optional if on PATH
$env:SONAR_HOST_URL="https://sonarqube.example.com"
$env:SONAR_TOKEN="your-token"
$env:SONAR_PROJECT_KEY="secure-review-project"
$env:SONAR_TIMEOUT_SECONDS="600"
```

When disabled or unavailable, CodeQL and SonarQube report their status without failing the rest of the scan.

## Production SSO Enforcement

The app supports enforced OIDC and SAML login. When `AUTH_REQUIRED=true`, unauthenticated UI requests redirect to the configured SSO login route and unauthenticated API requests return `401`.

### Common Auth Settings

```powershell
$env:AUTH_REQUIRED="true"
$env:AUTH_MODE="oidc" # oidc or saml
$env:AUTH_SESSION_SECRET="replace-with-a-long-random-secret"
$env:PUBLIC_BASE_URL="https://secure-review.example.com"
$env:AUTH_COOKIE_SECURE="true"
$env:AUTH_COOKIE_SAMESITE="lax"
$env:AUTH_DEFAULT_ROLES="developer"
$env:AUTH_ADMIN_EMAILS="security-admin@example.com"
$env:AUTH_GROUP_ROLE_MAP="Security Team:security_reviewer;Auditors:auditor"
```

### OIDC Settings

Register this redirect URI with your identity provider:

`https://secure-review.example.com/auth/callback/oidc`

```powershell
$env:OIDC_CLIENT_ID="client-id"
$env:OIDC_CLIENT_SECRET="client-secret"
$env:OIDC_DISCOVERY_URL="https://issuer.example.com/.well-known/openid-configuration"
$env:OIDC_SCOPE="openid profile email"
```

### SAML Settings

Import the SP metadata into your identity provider:

`https://secure-review.example.com/auth/saml/metadata`

Configure the IdP ACS URL as:

`https://secure-review.example.com/auth/saml/acs`

```powershell
$env:AUTH_MODE="saml"
$env:SAML_IDP_ENTITY_ID="https://idp.example.com/entity"
$env:SAML_IDP_SSO_URL="https://idp.example.com/sso"
$env:SAML_IDP_SLO_URL="https://idp.example.com/slo"
$env:SAML_IDP_X509_CERT="-----BEGIN CERTIFICATE-----..."
$env:SAML_SP_ENTITY_ID="https://secure-review.example.com/auth/saml/metadata"
$env:SAML_WANT_ASSERTIONS_SIGNED="true"
```

For production, run behind HTTPS, set `AUTH_COOKIE_SECURE=true`, use a strong `AUTH_SESSION_SECRET`, and map IdP groups to local roles with `AUTH_GROUP_ROLE_MAP`.

## Phase B: Risk Scoring

Phase B adds deterministic, explainable risk prioritization on top of scanner severity.

Implemented:

- Per-finding risk score from 0-100
- Risk tier, priority label, recommended action, and factor breakdown
- Scoring factors for scanner severity, confidence, new-vs-baseline status, high-impact CWE/OWASP categories, exploitability keywords, scanner source, and sensitive/exposed file paths
- Risk-aware finding ordering in CLI and web scans
- Aggregate summary metrics: max risk score, average risk score, risk tiers, and priority counts
- Risk data in JSON scan output, SARIF properties, Markdown/HTML reports, GitHub PR comments, and compliance reports
- Enterprise policy check for unresolved P0 risk findings

Risk priority mapping:

- `P0`: score 85-100, release-blocking review
- `P1`: score 65-84, security review before merge or deployment
- `P2`: score 40-64, remediate in the current sprint
- `P3`: score 15-39, track as maintenance work
- `P4`: score 0-14, informational triage

## Phase C: RAG Expansion

Phase C expands the local RAG layer while keeping it deterministic and offline-friendly.

Implemented:

- Recursive markdown ingestion under `knowledge/`
- Rich knowledge chunk metadata with section names, chunk indexes, source paths, tags, and document titles
- Weighted retrieval across title, tags, metadata, and body text
- Tag-aware retrieval for CWE, OWASP, risk tier, and priority terms
- Finding-aware RAG context endpoint for scanner findings
- RAG index stats endpoint for corpus visibility
- Secure refactoring now retrieves guidance using the whole finding context, including CWE/OWASP and risk factors
- Web UI actions for knowledge index stats and per-finding RAG context
- Expanded built-in knowledge base for injection, secrets, supply chain, SSO, RBAC, and audit evidence

Useful endpoints:

- `GET /api/rag/query?q=CWE-78&limit=5&tags=CWE-78`
- `GET /api/rag/stats`
- `POST /api/rag/reindex`
- `GET /api/scans/{scan_id}/findings/{finding_id}/rag-context`

## Phase D: Repository Memory And Trends

Phase D expands repository memory from a simple snapshot into repeat-scan intelligence.

Implemented:

- Schema-versioned local memory stored in `data/memory.json`
- Per-repository scan history with finding, risk, P0/P1, and severity trend deltas
- Finding lifecycle memory with first seen, last seen, seen count, active/resolved status, and days open
- Current and cumulative hotspot files
- Current and cumulative recurring rules
- Top open risks ranked by risk score and recurrence
- Decision-aware memory context for secure refactoring prompts
- Repository recommendations based on P0/P1 counts, hotspots, recurrence, and worsening trends
- Web UI `Memory Brief` action for the current scan

Useful endpoints:

- `GET /api/memory`
- `GET /api/memory/summary`
- `GET /api/memory/repositories`
- `GET /api/memory/repositories/{repo_key}`
- `GET /api/scans/{scan_id}/memory-context`
