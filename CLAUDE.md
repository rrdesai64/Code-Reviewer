# Code-Reviewer

Secure code review assistant (FastAPI). This file is the working context for an
AI session: how the system fits together, the conventions to keep, the test
story, and the open threads. Read it before making changes.

## What this is

A **tool orchestrator**, not a native rule engine. `app/scanner.py` runs
several detection passes, normalizes everything into one `Finding` model, and
layers reporting, baseline diffing, RAG, secure-refactor proposals, RBAC, and
SSO on top. Detection comes from Semgrep, Bandit, and pip-audit; two in-house
pieces add what those miss.

## Layout

```
app/
  scanner.py            # orchestrator: run_scan() runs all passes -> Finding[]
  catalog_scan.py       # NATIVE byte-level scanner (catalog binary_scan lane)
  catalog_knowledge.py  # SHARED knowledge layer: the only catalog reader
  ai.py                 # explain()/suggest_fix(): grounds findings via the catalog
  models.py             # pydantic Finding / Location / FixSuggestion / ScanResult / ...
  llm.py                # provider abstraction (offline / openai / ollama / compatible)
  rag.py                # lexical knowledge index over knowledge/*.md
  refactor.py           # human-reviewed fix proposals (deterministic patch + LLM note)
  memory.py             # per-repository scan memory / hotspots
  storage.py            # scan persistence, baseline compare, decisions
  enterprise.py         # RBAC roles/users, audit log, compliance report
  auth.py               # config, claims->roles, OIDC/SAML, enforcement middleware
  reporting.py, sarif.py, main.py, cli.py
rules/
  semgrep-security.yml      # 6 custom Semgrep rules
  code_review_rules.yaml    # the 150-rule catalog (knowledge + binary_scan spec)
knowledge/security_kb.md    # RAG knowledge base
tests/                      # pytest suite (138 tests); tests/conftest.py has fixtures
conftest.py                 # ROOT: puts repo root on sys.path for tests
requirements.txt / requirements-dev.txt
run.ps1 / scan.ps1
```

## Mental model

`run_scan()` runs four passes, each returning `app.models.Finding` objects that
flow through dedup -> summary -> baseline/decisions unchanged:

1. `run_semgrep` — Semgrep + `rules/semgrep-security.yml`
2. `run_bandit` — Bandit's Python rules
3. `run_catalog_native` — our byte-level scanner (see below)
4. `run_dependency_checks` — pip-audit + manifest hygiene

**Analysis lanes** (how to route any new rule):
`cheap` (pattern, binary_scan) | `structural` (ast, metric) |
`deep` (dataflow, interprocedural) | `external` (external_db / CVE feed).

## The catalog and its two roles

`rules/code_review_rules.yaml` (150 rules, CWE/OWASP-tagged). It is **not** a
parallel detection engine and **not** a source to generate Semgrep rules from
(no pattern syntax; half the rules have no expressible pattern; the rest
duplicate the Semgrep registry). Its real roles:

1. **Live spec for the native byte-level scanner** (`catalog_scan.py`). Detection
   logic is Python; metadata (severity, CWE, OWASP, text) comes from the catalog.
   Covers encoding/Unicode/lexical issues Semgrep & Bandit structurally cannot
   see: invalid UTF-8, BOM, Trojan-source bidi (ENC-005), homoglyph identifiers
   (ENC-006), zero-width/NBSP, null bytes, mixed tab/space indent, trailing
   whitespace after a line-continuation.
2. **Knowledge/taxonomy layer** (`catalog_knowledge.py`) behind `ai.py`, used to
   explain *every* finding regardless of which tool produced it.

For pattern-lane breadth, prefer enabling Semgrep **registry** rules and use the
catalog as a coverage checklist; for the deep lane (races, authz, null-contract
mismatches) the catalog is a prompt scaffold for the LLM.

## Conventions (keep these)

- **One catalog reader.** `catalog_knowledge.py` is the single source. Do not
  re-load the YAML elsewhere; call `kb.get_rule / match_rule / all_rules /
  rules_for_detection / build_explanation / build_fix`.
- **Logic in code, metadata in YAML.** A new byte-level check = a detector fn +
  `DETECTORS` entry in `catalog_scan.py` **and** a catalog rule with
  `detection: binary_scan`.
- **Findings are always `app.models.Finding`.** Severity uppercase; CWE as
  `["CWE-N"]`; `source` identifies the producer (`semgrep`, `bandit`,
  `pip-audit`, `catalog-native`, `dependency-manifest`).
- **Cross-platform tools.** Use `scanner.resolve_tool(name)` (venv `Scripts/*.exe`
  on Windows, `bin/*` on POSIX, then PATH). Never reintroduce hardcoded `.exe`
  paths — that silently breaks scans on WSL/Linux.
- **Tests must isolate data paths.** `storage.py`, `enterprise.py`, `rag.py`,
  `memory.py` write to `data/` via module-level path constants. Tests redirect
  these to tmp via fixtures (`isolate_storage`, `isolate_enterprise`,
  `isolate_rag`, `isolate_memory`) — never let a test touch the real `data/`.
- **Tests never hit the network.** Stub `llm.post_json`; use the `offline`
  provider for refactor/LLM paths.

## Testing

- Run: `pip install -r requirements.txt -r requirements-dev.txt && python -m pytest`
- Expected: **138 passed** (suite is offline and hermetic).
- The suite does NOT require semgrep/bandit/pip-audit to be installed — those
  passes degrade to `not installed` and the native catalog scanner supplies the
  findings the tests rely on (a planted ENC-009 curly-quote -> HIGH).
- Coverage by area: catalog/knowledge/native-scanner, scanner tool-resolution,
  storage, sarif, reporting, enterprise, auth (pure logic + request guards),
  llm (all providers, stubbed), rag, memory, refactor, the full FastAPI route
  surface via `TestClient` (incl. SSO enforcement redirects), and a CLI smoke.
- `tests/conftest.py` holds shared fixtures (`make_finding`, `make_scan`, and
  the four `isolate_*` fixtures + `clean_auth_env`). Root `conftest.py` only
  fixes `sys.path`. `tests/` has no `__init__.py` (intentional).

## Environment note (Windows vs WSL)

The venv executable layout differs (`Scripts/*.exe` vs `bin/*`) and
`resolve_tool` handles it, but on WSL the external tools must be installed in
the active venv or on PATH — otherwise those passes report `not installed` and
only catalog-native findings appear.

## Open threads / next steps

- **`applies_when` tightening.** Catalog `["*"]` rules are over-broad (e.g. SQL
  injection nominally "applies" to a Dockerfile). Low priority while detection
  is delegated; relevant if native dataflow rules are added. Design triggers
  (`imports` / `calls` / `constructs`) against the scanner's detection surface.
- **Robust matching upgrade.** `kb.match_rule` is a heuristic (exact id ->
  shared CWE -> whole-word keyword, with a language tiebreak). For findings you
  care about, add an explicit `maps_to: [SEC-002]` on the Semgrep/Bandit rule
  rather than relying on inference.
- **IdP integration tests.** Route tests cover SSO *enforcement* (401 / 303
  redirects) and metadata, but NOT the OIDC token exchange or SAML assertion
  consumption (`/auth/callback/oidc`, `/auth/saml/acs`) — those need a mocked
  IdP issuing signed responses.
- **ENC-008** (encoding-declaration mismatch) intentionally not implemented in
  the native scanner — hard to do without false positives.
- **RAG seeding.** The catalog could seed `knowledge/` / the RAG index.
- **No live CVE feed.** `DEP-*` catalog rules are `external_db`; real data needs
  OSV/GitHub Advisory. pip-audit already covers Python deps.

## Gotchas already learned (don't re-discover)

- Keyword matching must be **whole-word**, not substring (`unknown` != `known`).
- **CWE taxonomy near-miss:** tools tag `eval` as CWE-94 while the catalog uses
  CWE-95; the matcher rescues via a whole-word keyword pass.
- Byte-level detectors must read **raw bytes** (`read_bytes`), never parsed
  source — a tokenizer normalizes away the very characters they detect.
- The matcher is a *knowledge* layer: a wrong match degrades an explanation, it
  never causes a wrong detection.
- `auth.py` needs `httpx` (authlib's Starlette client); it is pinned in
  requirements.txt. Without it, `app.auth` (and thus `app.main`) fails to import.
