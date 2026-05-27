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

`run.ps1` and `scan.ps1` both load `.env` before starting the app or CLI scan, so scanner settings such as CodeQL, SonarQube/SonarCloud, govulncheck, and secret-scanner paths stay consistent between web and command-line workflows.

Generated runtime data defaults to `E:\secure-review` when no output root is configured. Set `SECURE_REVIEW_OUTPUT_ROOT`, `SECURE_REVIEW_DATA_DIR`, and `REPORT_BUNDLE_DIR` in `.env` if you want a different drive.

## Bulk Clone Repositories

Create a private `repo-list.txt` with one GitHub URL per line, optionally followed by branch and Sonar project key:

```text
# repository_url,branch,sonar_project_key
https://github.com/example-org/example-service.git,,adsflaunt-enterprises_example-org__example-service
https://github.com/example-org/example-api.git,main,adsflaunt-enterprises_example-org__example-api
```

Then clone each repository into an isolated scan workspace:

```powershell
.\clone-repos.ps1 -List .\repo-list.txt -OutDir .\scan-workspace\repos
```

Existing repositories are skipped by default. Add `-UpdateExisting` to fetch and fast-forward existing checkouts, `-Depth 1` for shallow clones, or `-DryRun` to preview the planned directories. The script writes `clone-summary.json` under the output directory for auditability.

If the first clone run fills a disk, resume into a different drive while reusing completed checkouts from the old directory:

```powershell
.\clone-repos.ps1 -List .\repo-list.txt -OutDir "E:\secure-review\repos" -ResumeFromDir .\scan-workspace\repos -Depth 1
```

To verify supply-chain scanner coverage, collect root-level manifest and lock files from the cloned repositories:

```powershell
.\collect-supply-chain-footprints.ps1 -List .\repo-list.txt -ReposDir .\scan-workspace\repos -OutDir .\scan-workspace\supply-chain-footprints
```

The collector copies files such as `package.json`, `package-lock.json`, `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `go.mod`, `go.sum`, `pom.xml`, Gradle manifests, `Cargo.toml`, `Cargo.lock`, and common ecosystem lockfiles from each repository root. It writes `footprint-index.json` with per-file SHA-256 hashes, sizes, source paths, and copied evidence paths.

Run scans for every cloned repository while applying each repo's Sonar project key from the third manifest column:

```powershell
.\scan-repos.ps1 -List .\repo-list.txt -ReposDir .\scan-workspace\repos -ReportsDir .\reports
```

With the default output root, `-ReportsDir .\reports` resolves to `E:\secure-review\reports` so bulk scan reports do not fill the project drive.

When repositories are split across drives, pass both roots and put reports on the drive with enough space:

```powershell
.\scan-repos.ps1 -List .\repo-list.txt -ReposDir .\scan-workspace\repos,"E:\secure-review\repos" -ReportsDir "E:\secure-review\reports"
```

Use `-DryRun` first to verify paths and Sonar keys without scanning.

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
- Expanded language-specific Semgrep rules for Python, JavaScript/TypeScript, Java, Go, Rust, YAML, and Dockerfile, including unsafe deserialization, TLS bypass, weak hash, SQL formatting, container privilege, and unpinned base-image patterns
- Semgrep multi-config support with `SEMGREP_CONFIGS` for organization rules or Semgrep registry packs
- CodeQL adapter with language detection, configurable query suites, extra query packs, resource tuning, no-build defaults for interpreted languages, and optional per-language build commands
- SonarQube/SonarCloud adapter that imports issues and quality gate failures when `SONAR_ENABLED=true`, `sonar-scanner` is installed, and server credentials are configured
- Project-local Gitleaks and TruffleHog adapters under `tools/gitleaks/` and `tools/trufflehog/` for external secret-scanning depth
- Project-local Go toolchain for CodeQL Go scans, Go module inventory from `go.mod`/`go.sum`, Go import reachability, and optional `govulncheck` vulnerability ingestion
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
$env:CODEQL_BUILD_MODE="none" # optional global override; Python/JavaScript/Ruby default to no-build automatically
$env:CODEQL_BUILD_MODE_PYTHON="none" # optional per-language override
$env:CODEQL_BUILD_COMMAND_JAVA_KOTLIN="mvn -DskipTests package" # optional for compiled languages
$env:CODEQL_TIMEOUT_SECONDS="900"
```

The app creates temporary CodeQL databases under `data/codeql/`, which is ignored by Git. CodeQL query packs were installed into the user CodeQL cache with `codeql pack download`.

### Enable SonarQube Or SonarCloud

SonarScanner has been installed as a local npm dev dependency. Create a SonarQube/SonarCloud token, then set:

```powershell
$env:SONAR_ENABLED="auto" # auto, true, or false
$env:SONAR_SCANNER_EXE="C:\path\to\sonar-scanner.bat" # optional if on PATH
$env:SONAR_HOST_URL="https://sonarqube.example.com" # use https://sonarcloud.io for SonarCloud
$env:SONAR_TOKEN="your-token"
$env:SONAR_PROJECT_KEY="secure-review-project"
$env:SONAR_ORGANIZATION="your-sonarcloud-organization" # required for SonarCloud, optional for self-hosted SonarQube
$env:SONAR_PROJECT_NAME="Secure Review Project" # optional display name
$env:SONAR_SOURCES="." # optional source root inside the scanned repository
$env:SONAR_EXCLUSIONS="**/.venv/**,**/node_modules/**,**/dist/**,**/build/**" # optional
$env:SONAR_QUALITY_GATE_ENABLED="true"
$env:SONAR_QUALITY_GATE_WAIT="false" # set true in CI if you want sonar-scanner to wait for gate completion
$env:SONAR_QUALITY_GATE_TIMEOUT="300"
$env:SONAR_ISSUE_TYPES="VULNERABILITY,SECURITY_HOTSPOT,BUG,CODE_SMELL"
$env:SONAR_SEVERITIES="BLOCKER,CRITICAL,MAJOR" # optional
$env:SONAR_ISSUE_PAGE_SIZE="500"
$env:SONAR_TIMEOUT_SECONDS="600"
$env:SONAR_EXTRA_ARGS="-Dsonar.verbose=false" # optional semicolon-separated raw scanner args
```

For SonarCloud, `SONAR_ORGANIZATION` must match the organization key shown in the SonarCloud organization URL/settings. The app now fails fast with a clear adapter status when that value is missing instead of running a doomed upload.

### Go, CodeQL, And govulncheck

Go is installed project-locally under `tools/go/` and is added only to scanner subprocess environments. This avoids changing the system PATH while allowing CodeQL Go autobuild and Go dependency tooling to run.

```powershell
$env:GO_EXE="G:\My Software Projects\Code Reviewer - Codex\tools\go\bin\go.exe" # optional override
$env:GOVULNCHECK_ENABLED="auto" # auto, true, or false
$env:GOVULNCHECK_EXE="G:\My Software Projects\Code Reviewer - Codex\tools\go-tools\bin\govulncheck.exe" # optional override
$env:GOVULNCHECK_TIMEOUT_SECONDS="300"
```

Go dependency review now reads `go.mod` and `go.sum`, emits Go components into CycloneDX/SPDX, maps Go imports for reachability evidence, and ingests `govulncheck` findings as `golang` SCA vulnerabilities when the tool completes.

### External Secret Scanners

Gitleaks and TruffleHog are installed project-locally and are picked up automatically before PATH lookup:

```powershell
$env:GITLEAKS_ENABLED="auto" # auto, true, or false
$env:TRUFFLEHOG_ENABLED="auto" # auto, true, or false
$env:SECRET_SCAN_EXTERNAL_ENABLED="auto" # set false to use only the built-in scanner
$env:GITLEAKS_EXE="G:\My Software Projects\Code Reviewer - Codex\tools\gitleaks\gitleaks.exe" # optional override
$env:TRUFFLEHOG_EXE="G:\My Software Projects\Code Reviewer - Codex\tools\trufflehog\trufflehog.exe" # optional override
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
- Scope-aware finding classification for `production`, `test`, `docs`, `example`, `config`, `dependency`, and `generated` paths
- Production gate metrics that exclude ordinary test/docs/example hygiene findings from the main max risk score, priority counts, PR gates, and CLI `--fail-on` checks
- High-confidence or critical secrets still remain blocking regardless of whether they appear in tests, docs, examples, or production code
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
- Report picker for scanner mesh, dependency review, SonarQube quality gate, scanner depth, quarantine policy, sanitized report lake records, RAG memory records, Hermes orchestration, messaging gateway, enterprise governance evidence, secret policy, push protection, CycloneDX, SPDX, SPDX compliance, SBOM policy, SBOM comparison, GitHub PR review, PR comment, remediation plan, memory context, recursive scanner learning, advanced AI report, compliance, SARIF, Markdown, and HTML
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
## Roadmap Point 9: Issue Planning With Jira/Linear

Point 9 turns prioritized remediation into issue-tracker work items while preserving the app's security-first default: dry-run artifacts first, real publishing only after credentials and explicit publish controls are enabled.

Implemented:

- Jira Cloud issue payload generation for prioritized open findings
- Linear issue payload generation through the Linear GraphQL API
- Shared issue plan artifact with finding context, risk, validation commands, labels, dedupe key, and provider payloads
- Dry-run by default for both providers, with real creation gated by `publish=true` plus provider dry-run disabled
- API status, preview, and publish endpoints with audit logging
- CLI export with `--issue-plan-out` and optional `--issue-plan-publish`
- Browser UI and VS Code report access for `issue-plan.json`
- `scan.ps1` and GitHub Actions artifact output for `issue-plan.json`

Useful endpoints:

- `GET /api/integrations/issues/status`
- `GET /api/scans/{scan_id}/issue-plan`
- `POST /api/scans/{scan_id}/issue-plan`

CLI dry-run export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --issue-plan-out issue-plan.json --issue-plan-provider all --issue-plan-min-priority P2
```

CLI publish, once credentials are configured and you intentionally disable provider dry-run:

```powershell
$env:JIRA_DRY_RUN="false"
$env:LINEAR_DRY_RUN="false"
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --issue-plan-out issue-plan.json --issue-plan-publish
```

Jira configuration:

```powershell
$env:JIRA_ENABLED="auto"
$env:JIRA_BASE_URL="https://your-company.atlassian.net"
$env:JIRA_EMAIL="you@example.com"
$env:JIRA_API_TOKEN="jira-api-token"
$env:JIRA_PROJECT_KEY="SEC"
$env:JIRA_ISSUE_TYPE="Task"
$env:JIRA_LABELS="secure-review,security"
$env:JIRA_DRY_RUN="true"
```

Linear configuration:

```powershell
$env:LINEAR_ENABLED="auto"
$env:LINEAR_API_KEY="lin_api_key"
$env:LINEAR_TEAM_ID="team-uuid"
$env:LINEAR_LABEL_IDS="label-uuid-1,label-uuid-2"
$env:LINEAR_PROJECT_ID="project-uuid"
$env:LINEAR_DRY_RUN="true"
```

For production, keep provider dry-run enabled until teams have reviewed the generated payload shape. Publishing requires `enterprise:write` through the API and should run from a controlled service account whose Jira/Linear permissions are scoped to the target project or team.
## Roadmap Point 10: Slack/Teams Agent

Point 10 adds a controlled chat-ops layer for secure review notifications and lightweight agent commands. The implementation keeps the same local-first posture as the rest of the app: generate inspectable chat payloads by default, then publish only when credentials and dry-run gates are intentionally configured.

Implemented:

- Slack Block Kit notification payloads for scan summaries and top findings
- Microsoft Teams Adaptive Card notification payloads for scan summaries and top findings
- Dry-run by default for Slack and Teams webhook publishing
- Slack slash-command endpoint with `X-Slack-Signature` verification
- Teams command endpoint with a shared secret header for bot/proxy integrations
- Shared command parser for `help`, `status`, `latest`, `review`, and `plan`
- API status, preview, publish, and command endpoints with audit logging
- CLI export with `--chat-notification-out` and optional `--chat-publish`
- Browser UI and VS Code report access for `chat-notification.json`
- `scan.ps1` and GitHub Actions artifact output for `chat-notification.json`

Useful endpoints:

- `GET /api/integrations/chat/status`
- `GET /api/scans/{scan_id}/chat/notification`
- `POST /api/scans/{scan_id}/chat/notification`
- `POST /api/integrations/slack/command`
- `POST /api/integrations/teams/command`

CLI dry-run export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --chat-notification-out chat-notification.json --chat-provider all --chat-include-findings 10
```

CLI publish, once webhooks are configured and you intentionally disable provider dry-run:

```powershell
$env:SLACK_DRY_RUN="false"
$env:TEAMS_DRY_RUN="false"
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --chat-notification-out chat-notification.json --chat-publish
```

Slack configuration:

```powershell
$env:SLACK_ENABLED="auto"
$env:SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
$env:SLACK_SIGNING_SECRET="slack-signing-secret"
$env:SLACK_ALLOW_UNSIGNED="false"
$env:SLACK_DRY_RUN="true"
$env:SLACK_CHANNEL="#security-review"
$env:SLACK_USERNAME="Secure Review"
```

Teams configuration:

```powershell
$env:TEAMS_ENABLED="auto"
$env:TEAMS_WEBHOOK_URL="https://your-teams-webhook-url"
$env:TEAMS_COMMAND_SECRET="long-random-shared-secret"
$env:TEAMS_ALLOW_UNSIGNED="false"
$env:TEAMS_DRY_RUN="true"
```

For Slack slash commands, point the Slack app command URL to `/api/integrations/slack/command` and set `SLACK_SIGNING_SECRET`. For Teams, use an Azure Bot, workflow, or secure relay that forwards command payloads to `/api/integrations/teams/command` with `x-secure-review-teams-secret`. Keep unsigned commands disabled in production.
## Secure Review Messaging Gateway

The first-party messaging gateway replaces external gateway framework dependency risk with local, auditable adapters. The initial channel set is Slack, Microsoft Teams, Email, and Telegram. It is notification/control-plane only: it can prepare or publish scan updates and answer safe read-only commands, but it cannot mutate scanner rules, suppressions, parser code, scanner config, or repository files.

Implemented:

- Shared gateway event model, channel registry, delivery artifacts, and governance-audited event log
- Slack, Teams, Email, and Telegram outbound payloads
- Dry-run by default for every channel through `GATEWAY_DRY_RUN`
- Inbound webhook normalization for Slack, Teams, Telegram, and Email relay payloads
- Safe read-only commands: `help`, `status`, `latest`, `scan <scan_id>`, and `explain <scan_id> <finding_id>`
- Strict inbound allowlists by default through `GATEWAY_ALLOWED_USERS` or `GATEWAY_<CHANNEL>_ALLOWED_USERS`
- API, CLI, browser UI, VS Code report picker, report bundle, disposable VM export, and GitHub Actions artifact support for `messaging-gateway.json`

Useful endpoints:

- `GET /api/gateway/status`
- `GET /api/gateway/channels`
- `GET /api/gateway/events`
- `POST /api/gateway/send`
- `POST /api/gateway/webhook/{channel}`
- `GET /api/scans/{scan_id}/messaging-gateway`
- `POST /api/scans/{scan_id}/messaging-gateway`

CLI dry-run export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --messaging-gateway-out messaging-gateway.json --gateway-channels all
```

CLI publish, once credentials are configured and dry-run is intentionally disabled:

```powershell
$env:GATEWAY_DRY_RUN="false"
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --messaging-gateway-out messaging-gateway.json --gateway-publish
```

Core configuration examples:

```powershell
$env:GATEWAY_DRY_RUN="true"
$env:GATEWAY_ALLOWED_USERS="trusted-user-id,security-lead@example.com"
$env:GATEWAY_SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
$env:GATEWAY_SLACK_SIGNING_SECRET="slack-signing-secret"
$env:GATEWAY_TEAMS_WEBHOOK_URL="https://your-teams-webhook-url"
$env:GATEWAY_TEAMS_COMMAND_SECRET="long-random-shared-secret"
$env:GATEWAY_SMTP_HOST="smtp.example.com"
$env:GATEWAY_EMAIL_FROM="secure-review@example.com"
$env:GATEWAY_EMAIL_TO="security-team@example.com"
$env:GATEWAY_TELEGRAM_BOT_TOKEN="123456:token"
$env:GATEWAY_TELEGRAM_CHAT_ID="123456789"
```

## Roadmap Point 11: GitLab, Azure DevOps, And Bitbucket

Point 11 extends PR/MR review publishing beyond GitHub while keeping one common review artifact and provider-specific payloads for each code host. Publishing remains dry-run by default.

Implemented:

- GitLab merge request note payloads and optional commit status payloads
- Azure DevOps pull request thread payloads and optional pull request status payloads
- Bitbucket Cloud pull request comment payloads and optional build status payloads
- Bitbucket Server/Data Center comment/status path support through `BITBUCKET_DEPLOYMENT=server`
- Shared code-host review artifact with risk status, top findings, provider configuration status, and publish results
- API status, preview, and publish endpoints with audit logging
- CLI export with `--code-host-review-out` and optional `--code-host-publish`
- Browser UI and VS Code report access for `code-host-review.json`
- `scan.ps1` and GitHub Actions artifact output for `code-host-review.json`

Useful endpoints:

- `GET /api/integrations/code-hosts/status`
- `GET /api/scans/{scan_id}/code-hosts/review`
- `POST /api/scans/{scan_id}/code-hosts/review`

CLI dry-run export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --code-host-review-out code-host-review.json --code-host-provider all --code-host-include-findings 25
```

CLI publish, once credentials are configured and provider dry-run is intentionally disabled:

```powershell
$env:GITLAB_DRY_RUN="false"
$env:AZURE_DEVOPS_DRY_RUN="false"
$env:BITBUCKET_DRY_RUN="false"
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --code-host-review-out code-host-review.json --code-host-provider gitlab --code-host-publish --code-host-publish-status
```

GitLab configuration:

```powershell
$env:GITLAB_ENABLED="auto"
$env:GITLAB_API_URL="https://gitlab.com/api/v4"
$env:GITLAB_TOKEN="gitlab-token"
$env:GITLAB_PROJECT_ID="group/project-or-numeric-id"
$env:GITLAB_MR_IID="123"
$env:GITLAB_COMMIT_SHA="commit-sha"
$env:GITLAB_DRY_RUN="true"
$env:GITLAB_PUBLISH_STATUS="false"
```

Azure DevOps configuration:

```powershell
$env:AZURE_DEVOPS_ENABLED="auto"
$env:AZURE_DEVOPS_ORG="your-org"
$env:AZURE_DEVOPS_PROJECT="your-project"
$env:AZURE_DEVOPS_REPOSITORY_ID="repo-id-or-name"
$env:AZURE_DEVOPS_PR_ID="123"
$env:AZURE_DEVOPS_PAT="azure-devops-pat"
$env:AZURE_DEVOPS_DRY_RUN="true"
$env:AZURE_DEVOPS_PUBLISH_STATUS="false"
```

Bitbucket Cloud configuration:

```powershell
$env:BITBUCKET_ENABLED="auto"
$env:BITBUCKET_DEPLOYMENT="cloud"
$env:BITBUCKET_TOKEN="bitbucket-access-token"
$env:BITBUCKET_WORKSPACE="workspace"
$env:BITBUCKET_REPO_SLUG="repo-slug"
$env:BITBUCKET_PR_ID="123"
$env:BITBUCKET_COMMIT_SHA="commit-sha"
$env:BITBUCKET_DRY_RUN="true"
$env:BITBUCKET_PUBLISH_STATUS="false"
```

For Bitbucket Server/Data Center, set `BITBUCKET_DEPLOYMENT=server`, `BITBUCKET_API_URL=https://bitbucket.example.com/rest/api/1.0`, `BITBUCKET_PROJECT_KEY`, and `BITBUCKET_REPO_SLUG`. Start with dry-run artifacts, then enable one provider at a time with a scoped service account token.

## Roadmap Point 12: Team Learning And Security Campaign Dashboard

Point 12 adds the team-level learning layer that turns repeated scan evidence into coaching themes, security campaigns, and trend signals. It stays local-first: dashboard metrics are derived from stored scan history, repository memory, decisions, and campaign records under `data/`.

Implemented:

- Team learning dashboard with risk cards, recurring patterns, scanner gaps, trend direction, and learning recommendations
- Security campaign store for planned, active, paused, and completed remediation campaigns
- Campaign recommendations for secrets, dependencies, injection risk, hotspot files, and scanner coverage gaps
- Scan-level learning brief for the latest evidence from a single scan
- API endpoints protected by existing enterprise/read-write permissions and audit logging
- CLI export with `--team-learning-out` and `--team-learning-limit`
- Browser UI and VS Code report access for `team-learning-dashboard.json`
- `scan.ps1` and GitHub Actions artifact output for `team-learning-dashboard.json`

Useful endpoints:

- `GET /api/team-learning/dashboard`
- `GET /api/team-learning/campaigns`
- `POST /api/team-learning/campaigns`
- `GET /api/scans/{scan_id}/team-learning`

CLI export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --team-learning-out team-learning-dashboard.json --team-learning-limit 100
```

Create a campaign through the API:

```json
{
  "title": "Secrets exposure reduction",
  "focus_area": "secrets",
  "owner": "AppSec",
  "status": "planned",
  "target_reduction_percent": 80,
  "rule_ids": ["gitleaks.generic-api-key"],
  "repository_keys": ["payments-service"]
}
```

Use the dashboard as a security-management artifact, not only a scanner artifact. The intended workflow is scan, review recurring patterns, open a focused campaign, verify improvement with later scans, and keep accepted-risk decisions auditable.

## Recursive Scanner Learning

Recursive scanner learning turns stored scan evidence into proposed scanner improvement recommendations. It is intentionally read-only: the app does not rewrite Semgrep rules, parser code, CodeQL/Sonar configuration, or suppression settings automatically.

Implemented:

- Evidence collection for noisy rules, parser gaps, scope classification conflicts, scanner environment failures, false-positive patterns, recurring vulnerable dependency families, finding decisions, and report section usage
- Scanner improvement recommendations with `status=proposed`, `requires_human_approval=true`, and `auto_apply=false`
- Human approval workflow guidance for rule/config/parser changes
- Benchmark promotion gates requiring before/after evidence, lower noise, and no loss of known true positives
- API, CLI, browser UI, and report bundle artifact support through `recursive-learning.json`

Useful endpoints:

- `GET /api/recursive-learning/dashboard`
- `GET /api/scans/{scan_id}/recursive-learning`

CLI export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --recursive-learning-out recursive-learning.json --recursive-learning-limit 100
```

PowerShell wrapper:

```powershell
.\scan.ps1 -Path "G:\Path\To\Repo"
```

`scan.ps1` now emits `recursive-learning.json` by default with the other review artifacts.

Recommended workflow: collect scan evidence, review generated scanner improvement recommendations, approve candidate changes manually, test them against benchmark repositories, and promote them into the main rule pack only if false-positive noise drops without losing true positives.

## Quarantine Registry

Step 1 of the disposable-VM and agent-learning architecture adds a local quarantine registry for repositories that must be treated as hostile input before any future scanner worker or Hermes agent touches them.

Implemented:

- Registry path: `SECURE_REVIEW_DATA_DIR\quarantine-registry.json`
- Built-in quarantined entry for `https://github.com/samratashok/nishang`
- Deny-by-default controls for raw-code access, host execution, and agent learning
- Report-only guidance for sanitized, inert artifacts after explicit approval
- Recursive-learning exclusion for quarantined scans
- CLI host-scan blocking for quarantined targets with exit code `13`
- `quarantine-policy.json` in `scan.ps1`, bulk scan outputs, report bundles, and the VS Code report picker

Useful endpoints:

- `GET /api/quarantine/registry`
- `POST /api/quarantine/lookup`
- `POST /api/quarantine/registry`
- `GET /api/scans/{scan_id}/quarantine-policy`

CLI export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --quarantine-policy-out quarantine-policy.json
```

Example entry:

```json
{
  "repository": "https://github.com/example/danger-lab",
  "status": "quarantined",
  "reason": "Known hostile test corpus.",
  "tags": ["malware", "report-only"]
}
```

## Disposable VM Scan Worker

Step 2 adds a disposable VM worker preparation layer. It does not execute unknown repository code on the host. Instead, it creates a job package for an isolated guest, with a manifest, Windows Sandbox config, guest runner, launcher script, and strict artifact export allowlist.

Implemented:

- Disposable VM job manifests under `SECURE_REVIEW_DATA_DIR\vm-worker\jobs`
- Windows Sandbox `.wsb` job generation
- Read-only host mounts for the app and repository source
- Guest scratch copy before scanning
- Scanner output written inside the guest first
- Export allowlist for report artifacts only, including `scan.json`, SARIF, SBOM/SPDX, recursive learning, benchmark gate, quarantine policy, sanitized report lake records, RAG memory records, and worker status/log
- Offline network mode through Windows Sandbox networking disablement
- `scanner-only` and `full` network policy metadata for future firewall-backed workers
- Explicit approval requirement before preparing a VM job for quarantined repositories

Useful endpoints:

- `GET /api/vm-worker/status`
- `GET /api/vm-worker/jobs`
- `GET /api/vm-worker/jobs/{job_id}`
- `POST /api/vm-worker/jobs`

Prepare a disposable VM scan job:

```powershell
.\prepare-vm-scan-job.ps1 `
  -RepoPath "E:\secure-review\repos\owner__repo" `
  -RepoUrl "https://github.com/owner/repo" `
  -OutputRoot "D:\secure-review" `
  -ReportsDir ".\reports" `
  -NetworkPolicy offline `
  -JsonOut "D:\secure-review\vm-job-owner-repo.json"
```

For a quarantined repository, preparation requires explicit approval:

```powershell
.\prepare-vm-scan-job.ps1 `
  -RepoPath "E:\secure-review\repos\samratashok__nishang" `
  -RepoUrl "https://github.com/samratashok/nishang" `
  -OutputRoot "D:\secure-review" `
  -ApprovedQuarantine `
  -NetworkPolicy offline `
  -JsonOut "D:\secure-review\vm-job-nishang.json"
```

Use `-Launch` only after reviewing the generated job manifest and `.wsb` file. Closing the Windows Sandbox window discards the guest state.

## Sanitized Report Lake

Step 3 adds a sanitized report lake for future Hermes/RAG memory work. It is populated from saved `ScanResult` objects only; it does not open cloned repositories, execute code, or parse raw report files.

Implemented:

- Lake path: `SECURE_REVIEW_DATA_DIR\report-lake\scans`
- Automatic sanitized lake record after each API or CLI scan
- `sanitized-report.json` in `scan.ps1`, bulk scan outputs, disposable VM exports, report bundles, GitHub Actions artifacts, browser UI, and VS Code report picker
- Redaction for obvious secret-like strings before persistence
- No raw source code, patches, or full local target paths in lake records
- Quarantine and learning-eligibility labels for every record
- Reindex endpoint for rebuilding sanitized records from saved scans without touching repos

Useful endpoints:

- `GET /api/report-lake/status`
- `GET /api/report-lake/scans`
- `POST /api/report-lake/reindex`
- `GET /api/report-lake/scans/{scan_id}`
- `GET /api/scans/{scan_id}/sanitized-report`

CLI export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --sanitized-report-out sanitized-report.json
```

Hermes and future language agents should treat `learning_eligibility` as mandatory policy input. Quarantined or watched scans can be retained as inert governance evidence, but they must not be used for autonomous RAG ingestion, fine-tuning, or scanner promotion.

## RAG Memory Schema

Step 4 adds a dedicated RAG memory schema and index fed by the sanitized report lake. It keeps repository scan experience separate from the static markdown knowledge base, and every memory item carries eligibility and safety labels for future Hermes agents.

Implemented:

- Memory path: `SECURE_REVIEW_DATA_DIR\rag-memory`
- Schema endpoint describing required item fields, allowed item types, safety labels, and eligibility gates
- Automatic per-scan `rag-memory.json` after API or CLI scans
- Retrieval index with `scan-summary`, `finding-pattern`, `rule-pattern`, `dependency-signal`, and `scanner-status` items
- Query endpoint over retrieval-eligible sanitized memory items
- Quarantine/watch records skipped for retrieval by default
- `rag-memory.json` in `scan.ps1`, bulk scan outputs, disposable VM exports, report bundles, GitHub Actions artifacts, browser UI, and VS Code report picker

Useful endpoints:

- `GET /api/rag-memory/schema`
- `GET /api/rag-memory/status`
- `GET /api/rag-memory/items`
- `GET /api/rag-memory/scans`
- `GET /api/rag-memory/query?q=dependency%20risk`
- `POST /api/rag-memory/reindex`
- `GET /api/scans/{scan_id}/rag-memory`

CLI export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --rag-memory-out rag-memory.json
```

This layer is retrieval memory, not autonomous scanner learning. It can help future Python, Go, and other Hermes agents understand recurring sanitized patterns, but scanner/rule updates still require human approval and benchmark gates.

## Hermes Orchestrator

Step 5 adds the production Hermes orchestration core. Hermes consumes only sanitized RAG memory, plans review tasks, dispatches deterministic governance agents, records durable runs, and produces auditable recommendations without reading source code or mutating scanners, rules, suppressions, fixes, or repositories.

Implemented:

- Durable run store: `SECURE_REVIEW_DATA_DIR\hermes\runs`
- Policy gate that blocks missing, quarantined, watch-policy, or safety-violating memory
- Built-in deterministic agents:
  - `hermes-risk-governor`
  - `hermes-supply-chain-governor`
  - `hermes-scanner-coverage-governor`
  - `hermes-remediation-governor`
  - `hermes-compliance-governor`
- Task planning for release readiness, risk triage, supply-chain review, remediation routing, scanner coverage, and scanner improvement candidates
- Audit-safe synthesis with blockers, review-required items, next actions, and benchmark/human-approval gates
- `hermes-orchestration.json` in `scan.ps1`, bulk scan outputs, disposable VM exports, report bundles, GitHub Actions artifacts, browser UI, and VS Code report picker

Useful endpoints:

- `GET /api/hermes/status`
- `GET /api/hermes/runs`
- `GET /api/hermes/runs/{run_id}`
- `POST /api/hermes/runs`
- `GET /api/scans/{scan_id}/hermes`

CLI export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --hermes-out hermes-orchestration.json
```

Hermes is production-grade orchestration, not autonomous mutation. Its outputs are planning and governance artifacts; any code fix, scanner tuning, rule promotion, suppression, or parser change must still go through human approval and benchmark validation.

## Hermes Python Security Specialist

Step 6 adds the first language-specialist Hermes agent: `hermes-python-security-specialist`. It follows the local Hermes agent contract and the upstream [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent) security posture, while deliberately avoiding a broad runtime dependency import for this project.

Implemented:

- Python-specific task planning for finding patterns, dependency signals, scanner status, and release-readiness runs
- Language-aware triage for command execution, unsafe deserialization, SQL injection, path traversal, TLS bypass, secret handling, debug-mode, dependency, and locking-range signals
- Python supply-chain review for `pip-audit`, `requirements.txt`, `pyproject.toml`, Poetry, Pipfile, vulnerable package, and dependency-hygiene evidence
- Python scanner coverage checks for Bandit, pip-audit, Python AST, Semgrep, CodeQL, and SonarQube status signals
- Review-only remediation routing with validation commands such as `python -m compileall .`, `pip-audit`, `bandit -r .`, and `pytest`
- No raw repository reads, no source execution, no external calls, no file edits, no dependency installation, and no automatic rule/scanner changes

Hermes upstream review notes:

- `NousResearch/hermes-agent` was reviewed as the framework reference for agent registry, memory, skills, tool routing, and messaging concepts.
- Its security policy treats OS/container isolation as the real security boundary, so this app keeps language agents inside the existing sanitized-memory-only governance layer and relies on disposable VM workers for hostile repositories.
- Its current direct pinned core dependencies were checked with `pip-audit --no-deps`; no known vulnerabilities were reported for that direct pinned set at review time.
- The upstream package itself was not added to `requirements.txt` because this Python specialist does not need its full CLI, messaging gateway, terminal backends, skill hub, scheduler, provider, or optional tool dependency surface.

The Python specialist is included automatically in `hermes-orchestration.json`, `/api/hermes/status`, `/api/hermes/runs`, and `/api/scans/{scan_id}/hermes` whenever eligible sanitized RAG memory contains Python evidence.

## Benchmark Gate

Step 7 adds a hard promotion gate for recursive scanner learning. Recommendations can still be generated as `proposed`, but they cannot influence future scanner/rule recommendations unless they become active through the full benchmark path.

Implemented:

- Benchmark corpus: `benchmarks/language-corpus.json`
- Per-language benchmark expectations for Python, Go, JavaScript, TypeScript, Java, Rust, PHP, Ruby, C#, YAML, Dockerfile, and Terraform
- Required benchmark case types for every language:
  - `rule-regression`
  - `false-positive`
  - `fix-validation`
- Promotion states:
  - `proposed`
  - `reviewed`
  - `benchmarked`
  - `approved`
  - `active`
- Stateful benchmark lesson store: `SECURE_REVIEW_DATA_DIR\benchmark-gate\lessons.json`
- Recursive-learning recommendations now carry benchmark promotion metadata and `learning_influence_allowed`
- Only active lessons with passing benchmark evidence and human approval are exposed as approved learning influences
- `benchmark-gate.json` in `scan.ps1`, bulk scan outputs, report bundles, GitHub Actions artifacts, and the VS Code report picker

Useful endpoints:

- `GET /api/benchmark-gate/status`
- `GET /api/benchmark-gate/corpus`
- `GET /api/benchmark-gate/lessons`
- `POST /api/benchmark-gate/lessons`
- `POST /api/benchmark-gate/lessons/{lesson_id}/transition`
- `GET /api/scans/{scan_id}/benchmark-gate`

CLI export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --benchmark-gate-out benchmark-gate.json
```

Benchmark evidence must show all known true positives were preserved, false-positive noise did not increase after review, fix validation passed, and scanner status did not fail or silently skip required coverage. The gate does not rewrite scanner rules, parser code, configs, suppressions, or repository files.

## Enterprise Governance

Step 9 adds the team-governance layer around Hermes, RAG memory, and Benchmark Gate approvals. The goal is traceability: what agent ran, what evidence it used, who approved scanner-learning lessons, why a lesson moved forward, which memory version was used, and how to export this for review.

Implemented:

- Governance event log: `SECURE_REVIEW_DATA_DIR\governance\events.jsonl`
- Audit events for every Hermes agent action and policy block
- Benchmark Gate promotion evidence with `promotion_reason`, reviewer, benchmark, approver, and activation history
- RAG memory version snapshots under `SECURE_REVIEW_DATA_DIR\rag-memory\versions`
- Active memory version registry: `SECURE_REVIEW_DATA_DIR\rag-memory\versions.json`
- Memory rollback endpoint that restores sanitized RAG memory and rebuilds the retrieval index
- Scan-level and enterprise-level governance evidence exports
- `governance-evidence.json` in `scan.ps1`, bulk scan outputs, disposable VM exports, report bundles, GitHub Actions artifacts, browser UI, and the VS Code report picker

Useful endpoints:

- `GET /api/enterprise/governance`
- `GET /api/enterprise/governance/events`
- `GET /api/enterprise/governance/evidence`
- `GET /api/scans/{scan_id}/governance`
- `GET /api/rag-memory/versions`
- `POST /api/rag-memory/versions/{version_id}/rollback`

Rollback request:

```json
{
  "reason": "Rollback to the last reviewed sanitized memory version."
}
```

CLI export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --governance-out governance-evidence.json
```

## AI Finding Review Layer

The app already had local/cloud LLM plumbing, RAG, multi-agent reports, and fix proposals. This layer adds a first-class per-finding AI review artifact: each finding gets a dynamically generated vulnerability explanation prompt and remediation suggestion prompt based on the scanner source, CWE/OWASP tags, risk score, reachability, RAG context, repository memory, and detected vulnerability scenario.

Implemented:

- Dynamic prompt templates for vulnerability explanations and remediation suggestions
- Scenario classification for secrets, vulnerable dependencies, command injection, SQL injection, XSS, path traversal, SSRF, deserialization, auth/access control, crypto, insecure transport, debug/configuration, IaC/container, CI/CD supply chain, and generic secure coding findings
- Offline deterministic template fallback plus optional Ollama, OpenAI, and OpenAI-compatible LLM providers
- Per-finding endpoint with prompt-template output for auditability
- Scan-level AI review artifact for top open findings
- Browser UI, CLI, VS Code, `scan.ps1`, and GitHub Actions artifact support for `ai-review.json`

Useful endpoints:

- `GET /api/finding-ai/status`
- `GET /api/scans/{scan_id}/ai-review`
- `GET /api/scans/{scan_id}/findings/{finding_id}/ai-review`

CLI export:

```powershell
.\.venv\Scripts\python.exe -m app.cli --path "G:\Path\To\Repo" --ai-review-out ai-review.json --ai-review-provider offline --ai-review-limit 25 --ai-review-include-prompts
```

Provider options match the existing LLM layer: `offline`, `ollama`, `openai`, and `openai_compatible`. Keep `offline` for sensitive repositories unless an external provider is explicitly approved.
## Web Scan Report Bundles

Dashboard scans now write a human-shareable report bundle automatically after each completed scan. The default folder layout is:

```text
reports\<repo-name>\<scan-id>\
```

Each bundle includes `manifest.json`, `scan.json`, `secure-review.md`, `secure-review.html`, `secure-review.sarif`, `dependency-review.json`, `ai-review.json`, `recursive-learning.json`, `benchmark-gate.json`, `messaging-gateway.json`, `governance-evidence.json`, `quarantine-policy.json`, `sanitized-report.json`, `rag-memory.json`, `hermes-orchestration.json`, SBOM/SPDX/compliance artifacts, scanner depth, secret policy, remediation, issue planning, chat/code-host previews, and safe fix dry-run artifacts.

The dashboard shows the saved bundle path after the scan and includes a `Report Bundle` action that opens the manifest. Set `REPORT_BUNDLE_DIR` in `.env` to place bundles somewhere else, for example:

```env
REPORT_BUNDLE_DIR=G:\Secure Review Reports
```
