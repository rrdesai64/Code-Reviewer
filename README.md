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
- Semgrep multi-config support with `SEMGREP_CONFIGS` for organization rules or Semgrep registry packs
- CodeQL adapter with language detection, configurable query suites, extra query packs, and resource tuning
- SonarQube adapter that imports issues and quality gate failures when `SONAR_ENABLED=true`, `sonar-scanner` is installed, and server credentials are configured
- Tool status reporting for `python-ast`, `semgrep`, `codeql`, and `sonarqube`
- Dedicated SonarQube quality gate and scanner-depth reports in API, CLI, web UI, and CI artifacts

### Tune Semgrep

Semgrep uses the local `rules/semgrep-security.yml` file by default. Add extra configs or registry packs with semicolon-separated values:

```powershell
$env:SEMGREP_EXE="C:\path\to\semgrep.exe" # optional if semgrep is on PATH or in .venv
$env:SEMGREP_CONFIGS="p/security-audit;G:\security-rules\org-semgrep.yml"
$env:SEMGREP_TIMEOUT_SECONDS="300"
```

### Enable CodeQL

CodeQL CLI has been installed locally under `tools/codeql/`. To override, tune, or disable it, set:

```powershell
$env:CODEQL_ENABLED="auto" # auto, true, or false
$env:CODEQL_EXE="C:\path\to\codeql.exe" # optional if codeql is on PATH
$env:CODEQL_QUERY_SUITE="" # optional global override; defaults are language-specific
$env:CODEQL_QUERY_SUITE_PYTHON="" # optional per-language override
$env:CODEQL_EXTRA_QUERY_SUITES="codeql/python-queries:codeql-suites/python-security-and-quality.qls"
$env:CODEQL_THREADS="0" # 0 lets CodeQL choose; set a number for CI
$env:CODEQL_RAM="4096"
$env:CODEQL_BUILD_MODE="none" # optional; useful for some compiled-language scans
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
$env:SONAR_QUALITY_GATE_ENABLED="true"
$env:SONAR_QUALITY_GATE_WAIT="false" # set true in CI if you want sonar-scanner to wait for gate completion
$env:SONAR_QUALITY_GATE_TIMEOUT="300"
$env:SONAR_ISSUE_TYPES="VULNERABILITY,SECURITY_HOTSPOT,BUG,CODE_SMELL"
$env:SONAR_SEVERITIES="BLOCKER,CRITICAL,MAJOR" # optional
$env:SONAR_ISSUE_PAGE_SIZE="500"
$env:SONAR_TIMEOUT_SECONDS="600"
```

When disabled or unavailable, CodeQL and SonarQube report their status without failing the rest of the scan. Use `--sonarqube-out sonarqube-quality-gate.json` and `--scanner-depth-out scanner-depth.json` for standalone CLI artifacts, or open `/api/scans/{scan_id}/sonarqube/report` and `/api/scans/{scan_id}/scanner-depth` after a scan.

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

## Phase E: Secure Refactoring Expansion

Phase E expands secure refactoring from individual patch stubs into a safer remediation workflow.

Implemented:

- Rich fix proposals with priority, risk score, effort, confidence, validation checks, validation commands, RAG sources, and memory context
- Proposal guardrails that keep all changes human-reviewed and diff-only
- Language-aware patch comments/examples for Python and JavaScript/TypeScript findings
- Patch validation checks for target file existence, file scope, patch size, placeholders, and manual-only cases
- Scan-level remediation plan ordered by risk score and priority
- Remediation plan API and CLI export support
- Web UI `Remediation` action and richer proposal display
- `scan.ps1` now emits `remediation-plan.json` by default

Useful endpoints:

- `POST /api/scans/{scan_id}/findings/{finding_id}/fix-proposal`
- `GET /api/scans/{scan_id}/remediation-plan`

CLI export:

```powershell
.\scan.ps1 -Path "G:\Path\To\Repo" -RemediationPlanOut remediation-plan.json
```

## Phase F: IDE Experience

Phase F adds a dependency-light VS Code extension under `vscode-extension/` that connects to the stable local API.

Implemented:

- VS Code activity bar view for Secure Review findings
- Configurable backend URL via `secureCodeReview.apiBaseUrl`
- Command to scan the current workspace folder through `POST /api/scans`
- Findings tree with priority, risk score, location, and source navigation
- Commands for backend health, refresh findings, scan summary, remediation plan, RAG context, and fix proposals
- Human-reviewed fix proposal display with validation checks, validation commands, safety notes, and diff content
- Web app opener for deeper browser-based review
- Plain JavaScript extension with no build step or runtime npm dependencies

Extension folder:

```text
vscode-extension/
```

Development flow:

1. Start the backend from this project root:

```powershell
.\run.ps1
```

2. Open `vscode-extension/` in VS Code.
3. Run the extension in an Extension Development Host.
4. Use `Secure Review: Configure API URL` if the backend is not at `http://127.0.0.1:8000`.
5. Use `Secure Review: Scan Workspace` from the command palette or the Secure Review activity bar.

The extension does not apply patches automatically. It only displays remediation plans and fix proposal diffs for human review.

## SBOM Export, Policy, And Comparison

This phase adds first-class SBOM artifacts for supply-chain review.

Implemented:

- CycloneDX 1.5 JSON export for scanned Python and Node manifests
- SPDX 2.3 JSON export for the same component inventory
- `pip-audit` vulnerability findings attached to CycloneDX components through `vulnerabilities.affects`
- SBOM policy checks for critical package vulnerabilities, high vulnerability review, and unknown licenses
- SBOM comparison against a saved baseline scan or a specific scan ID
- CLI and PowerShell wrapper output for SBOM artifacts

Useful endpoints:

- `GET /api/scans/{scan_id}/sbom/cyclonedx`
- `GET /api/scans/{scan_id}/sbom/spdx`
- `GET /api/scans/{scan_id}/sbom/policy`
- `GET /api/scans/{scan_id}/sbom/compare`
- `GET /api/scans/{scan_id}/sbom/compare?baseline_scan_id={baseline_scan_id}`

CLI export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --cyclonedx-out cyclonedx-sbom.json --spdx-out spdx-sbom.json --sbom-policy-out sbom-policy.json --sbom-compare-out sbom-compare.json
```

PowerShell wrapper output:

```powershell
.\scan.ps1 -Path "G:\Path\To\Repo"
```

By default, `scan.ps1` now emits `cyclonedx-sbom.json`, `spdx-sbom.json`, `sbom-policy.json`, and `sbom-compare.json` along with the existing scan artifacts. Use `--fail-on-sbom-policy` in CI when you want unknown licenses or critical package vulnerabilities to fail the CLI run.

### SPDX Compliance Reports

SPDX now supports enterprise review artifacts beyond the raw SPDX JSON export.

Implemented for:

- Legal/license compliance: classifies approved, review-required, prohibited, and unknown licenses
- Supplier audits: reports supplier, originator, download location, homepage, package URL, and manifest evidence
- Open-source obligation reports: lists notice, license text, source availability, reciprocal license, and review actions
- Enterprise procurement requirements: produces `ready`, `review_required`, or `blocked` status with requirement-level pass/warning/fail evidence
- Formal software supply chain documentation: records SPDX 2.3 namespace, package count, relationships, annotations, manifests, scan ID, and tool metadata

Useful endpoint:

- `GET /api/scans/{scan_id}/sbom/spdx/compliance`

CLI export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --spdx-out spdx-sbom.json --spdx-compliance-out spdx-compliance.json --fail-on-spdx-compliance
```

`scan.ps1` now emits `spdx-compliance.json` by default. Unknown licenses, missing supplier evidence, reciprocal licenses, prohibited licenses, and vulnerable package components are surfaced for legal, supplier, security, or procurement review.

## Phase G: Advanced AI

Phase G adds optional advanced-AI capabilities while keeping the app usable on ordinary local hardware.

Implemented:

- Embeddings and semantic RAG search with a deterministic local hashing fallback
- Optional embedding providers for Ollama, OpenAI, and OpenAI-compatible runtimes
- Multi-agent secure review orchestration with risk triage, exploitability, remediation, and compliance agents
- Fine-tuned model experiment planning with chat JSONL dataset export and evaluation guidance
- Local runtime discovery for Ollama, OpenAI-compatible servers, LM Studio, vLLM, and llama.cpp-style endpoints
- GPU profiling and optimization recommendations using `nvidia-smi` and optional PyTorch detection
- Phase G CLI exports and API endpoints

Useful endpoints:

- `GET /api/advanced-ai/status`
- `GET /api/advanced-ai/runtimes`
- `GET /api/advanced-ai/gpu`
- `POST /api/rag/embeddings/reindex?provider=local&force=true`
- `GET /api/rag/semantic-query?q=dependency%20risk&limit=5`
- `GET /api/scans/{scan_id}/advanced-ai/report`
- `GET /api/scans/{scan_id}/advanced-ai/review`
- `GET /api/scans/{scan_id}/advanced-ai/finetune-experiment`
- `GET /api/scans/{scan_id}/advanced-ai/finetune-dataset`

CLI export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --advanced-ai-out advanced-ai.json --agent-review-out agent-review.json --embedding-index-out embedding-index.json --semantic-query "dependency vulnerability remediation" --semantic-search-out semantic-search.json --finetune-experiment-out finetune-experiment.json --finetune-dataset-out finetune-dataset.jsonl
```

Local runtime configuration:

```powershell
# Ollama generation and embeddings
$env:OLLAMA_BASE_URL="http://127.0.0.1:11434"
$env:OLLAMA_MODEL="codellama"
$env:OLLAMA_EMBEDDING_MODEL="nomic-embed-text"

# OpenAI-compatible local runtime such as LM Studio, vLLM, llama.cpp server, or compatible gateway
$env:LLM_BASE_URL="http://127.0.0.1:1234/v1"
$env:LLM_API_KEY="optional"
$env:LLM_MODEL="local-review-model"
$env:EMBEDDING_BASE_URL="http://127.0.0.1:1234/v1"
$env:EMBEDDING_MODEL="local-embedding-model"

# OpenAI cloud embeddings, only for repositories approved for external processing
$env:OPENAI_API_KEY="your-key"
$env:OPENAI_EMBEDDING_MODEL="text-embedding-3-small"
```

`scan.ps1` now emits `advanced-ai.json` by default. Fine-tune exports are dataset artifacts only; the app does not automatically submit training jobs or deploy fine-tuned models. Keep sensitive repositories on local embeddings/models unless external processing is explicitly approved.

## Roadmap Point 1: Secret Scanning And Push Protection

Point 1 adds a merge-blocking secret scanning layer while keeping local-first scanning as the default.

Implemented:

- Built-in regex secret scanner for hardcoded tokens, API keys, private keys, JWTs, database URLs with inline credentials, and generic secret assignments
- Secret values are redacted from findings; a secret-derived hash is used only inside stable fingerprints
- Optional external adapters for `gitleaks` and `trufflehog` when those CLIs are installed or configured
- Push-protection policy report that blocks open high/critical secret findings
- CLI artifact export with `--secret-policy-out`
- CI/pre-push failure mode with `--fail-on-secrets` exit code `5`
- Web/API access to the secret policy report
- `scan.ps1` now emits `secret-policy.json` by default

Useful endpoints:

- `GET /api/scans/{scan_id}/secrets/policy`
- `GET /api/scans/{scan_id}/push-protection`

CLI export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --secret-policy-out secret-policy.json --fail-on-secrets
```

PowerShell wrapper output:

```powershell
.\scan.ps1 -Path "G:\Path\To\Repo"
```

Configuration:

```powershell
$env:SECRET_SCAN_ENABLED="true"
$env:SECRET_SCAN_MAX_FILE_BYTES="1048576"
$env:SECRET_SCAN_EXTERNAL_ENABLED="auto"
$env:PUSH_PROTECTION_ENABLED="true"
$env:SECRET_POLICY_BLOCK_SEVERITY="HIGH"
$env:GITLEAKS_ENABLED="auto"
$env:GITLEAKS_EXE="C:\path\to\gitleaks.exe"
$env:TRUFFLEHOG_ENABLED="auto"
$env:TRUFFLEHOG_EXE="C:\path\to\trufflehog.exe"
```

For confirmed leaks, rotate credentials before closing the finding. Removing the value from the latest file is not enough if it was committed into repository history.

## Roadmap Point 2: GitHub PR-Native Review

Point 2 adds GitHub pull request review artifacts and optional publishing while keeping the default workflow safe and local-first.

Implemented:

- GitHub PR review payload generation from a saved scan
- Inline review comments for findings that map to added PR diff lines
- Summary-only fallback for findings outside the PR diff, below threshold, or above the inline limit
- Review gate status: `pass`, `warn`, or `fail`
- Optional GitHub review publishing through the Pull Request Reviews API
- Optional commit status publishing for the PR head SHA
- GitHub webhook signature verification with `X-Hub-Signature-256`
- Bot command parser for `/review`, `/full-review`, and `/fix-plan`
- CLI artifact export with `--github-pr-review-out`
- Web UI `GitHub PR` preview action
- `scan.ps1` now emits `github-pr-review.json` by default

Useful endpoints:

- `GET /api/integrations/github/status`
- `GET /api/scans/{scan_id}/github/pr-review`
- `POST /api/scans/{scan_id}/github/pr-review`
- `POST /api/integrations/github/webhook`

CLI dry-run export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --github-pr-review-out github-pr-review.json --github-pr-repository owner/repo --github-pr-number 123 --github-pr-diff pr.diff
```

CLI publish, once credentials are configured:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --github-pr-review-out github-pr-review.json --github-pr-repository owner/repo --github-pr-number 123 --github-pr-publish --github-pr-publish-status
```

Configuration:

```powershell
$env:GITHUB_TOKEN="github_pat_or_app_token"
$env:GITHUB_REPOSITORY="owner/repo"
$env:GITHUB_PR_NUMBER="123"
$env:GITHUB_DRY_RUN="true"
$env:GITHUB_FETCH_PR_DIFF="false"
$env:GITHUB_REVIEW_EVENT="COMMENT" # COMMENT, REQUEST_CHANGES, APPROVE, or auto
$env:GITHUB_MAX_INLINE_COMMENTS="25"
$env:GITHUB_MIN_INLINE_RISK="40"
$env:GITHUB_PUBLISH_STATUS="false"
$env:GITHUB_WEBHOOK_SECRET="long-random-webhook-secret"
```

For production, keep `GITHUB_WEBHOOK_ALLOW_UNSIGNED=false`, configure a GitHub webhook secret, and start with dry-run artifacts before enabling `--github-pr-publish`. GitHub inline review comments require mapping findings to positions in the PR diff, so findings outside changed lines remain in the review summary.

## Roadmap Point 3: Unified Scanner Ingestion Layer

Point 3 adds a scanner mesh so each analyzer feeds one normalized finding schema instead of keeping separate per-tool shapes.

Implemented:

- Shared ingestion module for Semgrep, Bandit, pip-audit, CodeQL SARIF, SonarQube issues, external SARIF, and Snyk-ready JSON payloads
- Preserved scanner identity through `source`, `scanner_metadata.scanner_source`, `scanner_metadata.scanner_family`, raw severity, tool name, and normalization version
- Enriched finding fields for `exploitability`, `reachability`, `policy_impact`, and `remediation`
- Post-dedupe enrichment for built-in AST, dependency manifest, and secret findings so all findings expose the same metadata surface
- External SARIF import through the CLI with repeatable `--sarif-in` flags
- Scanner mesh status and per-scan coverage reports in API, CLI, and web UI
- `scan.ps1` now emits `scanner-mesh.json` by default and accepts optional SARIF imports with `-SarifIn`

Useful endpoints:

- `GET /api/scanner-mesh/status`
- `GET /api/scans/{scan_id}/scanner-mesh`

CLI export and SARIF import:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --sarif-in codeql.sarif --scanner-mesh-out scanner-mesh.json
```

PowerShell wrapper:

```powershell
.\scan.ps1 -Path "G:\Path\To\Repo" -SarifIn @("codeql.sarif", "third-party.sarif")
```

The scanner mesh is the integration point for future Snyk/GitHub code-scanning/Semgrep Platform ingestion. New adapters should convert into `Finding` through `app.ingestion.normalize_finding()` so policy, risk scoring, SBOM, PR review, and enterprise reporting see one consistent contract.

## Roadmap Point 4: Dependency Review With Reachability And Risk Scoring

Point 4 adds dependency-aware triage on top of SBOM and scanner findings. The app now reviews package inventory, vulnerability findings, source usage evidence, fix availability, and dependency scope together.

Implemented:

- Dependency review report for Python and Node components discovered from `requirements*.txt`, `pyproject.toml`, `package.json`, and `package-lock.json`
- Source-level reachability evidence for Python imports and JavaScript/TypeScript `import` / `require()` usage
- Component risk scoring with vulnerability severity, direct/transitive status, runtime/dev scope, source reachability, fix availability, and license review signals
- Dependency finding enrichment so `pip-audit`, Snyk-ready, and dependency manifest findings carry `dependency_*` metadata into scanner mesh, reports, PR review, and enterprise policy outputs
- Risk scoring adjustments for reachable runtime dependencies and lower-priority transitive/dev-only dependency signals
- Dependency policy gates for reachable critical vulnerabilities, reachable high vulnerabilities, unknown reachability, and missing fix versions
- CLI, API, PowerShell wrapper, and web UI access to dependency review results

Useful endpoint:

- `GET /api/scans/{scan_id}/dependencies/review`

CLI export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --dependency-review-out dependency-review.json --fail-on-dependency-policy
```

PowerShell wrapper:

```powershell
.\scan.ps1 -Path "G:\Path\To\Repo"
```

`scan.ps1` now emits `dependency-review.json` by default. Reachability is heuristic and conservative: source import evidence is high confidence, direct runtime manifests are medium confidence, and lockfile-only/transitive packages remain review items until the parent dependency path is known.

## Roadmap Point 5: SonarQube Issue And Quality Gate Ingestion

Point 5 makes SonarQube a first-class governance signal instead of a passive external scan. Issues and failing quality gate conditions are normalized into findings, and the scan keeps an auditable quality gate report.

Implemented:

- SonarQube issue ingestion for vulnerabilities, security hotspots, bugs, and optional code smells
- Quality gate retrieval from `/api/qualitygates/project_status` after scanner execution
- Failing quality gate conditions converted into normalized `sonarqube` findings with `scanner_metadata.sonar_kind=quality_gate`
- Per-scan SonarQube report with issue counts, quality gate status, failing conditions, policy blockers, and recommended action
- CLI export with `--sonarqube-out` and optional `--fail-on-sonarqube-gate`
- API endpoint and web UI button for the SonarQube quality gate report
- `scan.ps1` and GitHub Actions artifact output for `sonarqube-quality-gate.json`

Useful endpoint:

- `GET /api/scans/{scan_id}/sonarqube/report`

CLI export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --sonarqube-out sonarqube-quality-gate.json --fail-on-sonarqube-gate
```

`SONAR_HOST_URL`, `SONAR_TOKEN`, and `SONAR_PROJECT_KEY` must match the SonarQube/SonarCloud project that receives the scanner upload. If SonarQube is unavailable, the app records the adapter status and continues the local scan.

## Roadmap Point 6: Semgrep/CodeQL Depth Improvements

Point 6 deepens local and semantic scanner coverage while preserving the app's local-first center of gravity. Semgrep can run multiple configs, CodeQL can run tuned query suites, and the app reports scanner coverage gaps explicitly.

Implemented:

- Semgrep execution now supports `SEMGREP_EXE`, `SEMGREP_CONFIGS`, `SEMGREP_TIMEOUT_SECONDS`, and metrics-off local scans
- CodeQL execution now supports per-language defaults, extra query suites, thread/RAM tuning, optional build mode, and richer per-language status
- Scanner-depth report with Semgrep rule inventory, severity counts, top rules, CodeQL language coverage, and coverage gaps
- CLI export with `--scanner-depth-out`
- API endpoint and web UI button for scanner-depth reports
- `scan.ps1` and GitHub Actions artifact output for `scanner-depth.json`

Useful endpoint:

- `GET /api/scans/{scan_id}/scanner-depth`

CLI export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --scanner-depth-out scanner-depth.json
```

Treat scanner-depth `partial` status as a coverage warning: it means the scan ran, but one or more configured scanner layers did not complete for the detected languages.

## Roadmap Point 7: Safe One-Click Fix Workflow

Point 7 turns fix proposals into a controlled one-click workflow while keeping the app security-first. The default path is still dry-run and review-first; real source edits require explicit approval and the `FIX_APPLY_ENABLED=true` runtime gate.

Implemented:

- Scan-level secure fix bundle that collects prioritized fix proposals, validation checks, safety notes, and combined eligible patch text
- Controlled apply workflow with dry-run output by default
- Non-dry-run apply requires `approved=true`, `dry_run=false`, and `FIX_APPLY_ENABLED=true`
- Apply eligibility gates for mechanical confidence, blocked validation checks, manual guidance stubs, TODO/placeholders, missing files, and overlapping same-file edits
- Safe dependency upgrade patching for vulnerable Python requirements when scanner metadata includes a fixed version
- File backups under `.secure-review-backups/{scan_id}/` before approved source writes
- Enterprise permission `fix:apply` for admins and security reviewers, plus audit logging for bundle and apply requests
- CLI, API, PowerShell wrapper, and web UI access to fix bundles and dry-run apply reports

Useful endpoints:

- `GET /api/scans/{scan_id}/fixes/bundle`
- `POST /api/scans/{scan_id}/fixes/apply`

CLI dry-run bundle and apply preview:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --fix-bundle-out fix-bundle.json --fix-apply-out fix-apply-dry-run.json
```

Approved local apply, only when you intentionally enable it:

```powershell
$env:FIX_APPLY_ENABLED="true"
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --apply-fixes --fix-apply-approved --fix-apply-out fix-apply.json
```

PowerShell wrapper:

```powershell
.\scan.ps1 -Path "G:\Path\To\Repo"
```

`scan.ps1` now emits `fix-bundle.json` and `fix-apply-dry-run.json` by default. Treat the dry-run report as the review artifact; approved apply should be reserved for local branches or disposable worktrees where backups and validation commands can be reviewed immediately.


## Roadmap Point 8: IDE/CLI Parity

Point 8 makes the VS Code extension a practical peer to the CLI for developer review work. The IDE now exposes scan execution, finding triage, report viewing, safe fix workflows, and evidence export without forcing developers to leave the editor for routine tasks.

Implemented:

- VS Code command palette and activity-bar commands for workspace scans, health checks, refresh, baseline save, and web app launch
- Finding tree with source navigation, RAG context, fix proposals, and finding decision updates
- Report picker for scanner mesh, dependency review, SonarQube quality gate, scanner depth, secret policy, push protection, CycloneDX, SPDX, SPDX compliance, SBOM policy, SBOM comparison, GitHub PR review, PR comment, remediation plan, memory context, advanced AI report, compliance, SARIF, Markdown, and HTML
- Safe fix workflow parity through IDE-accessible fix proposals, fix bundles, and dry-run fix apply reports
- Evidence bundle export to `.secure-review-artifacts/{scan_id}` using the same core artifacts emitted by `scan.ps1` and `app.cli`
- Extension settings for backend URL, optional bearer token, extra request headers, default fix provider, and fix bundle limit
- Backend health metadata now advertises `ide-cli-parity`, `vscode-extension-parity`, and `ide-evidence-export`

Development check:

```powershell
cd vscode-extension
npm run check
```

The IDE path intentionally keeps real source modification out of the default workflow. The extension can request fix proposals and dry-run apply reports, while non-dry-run apply remains guarded by backend permissions and `FIX_APPLY_ENABLED=true`.
