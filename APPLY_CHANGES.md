# Apply changes — runbook

These changes were produced in a chat session and downloaded by the user. They
add a native byte-level scanner, a shared catalog knowledge layer, catalog-
grounded explanations, a cross-platform tool fix, and a full pytest suite (138
tests). Your job: place each file, install deps, run the suite against THIS
environment, fix any environment-specific issues, confirm green, then commit.

Read `CLAUDE.md` first for architecture and conventions.

## 0. Branch

```
git checkout -b feature/catalog-scanner-and-tests
```

## 1. Add NEW files (create at these exact paths)

App / rules:
- `app/catalog_scan.py`
- `app/catalog_knowledge.py`
- `rules/code_review_rules.yaml`

Project root:
- `CLAUDE.md`
- `APPLY_CHANGES.md` (this file; optional to commit)
- `requirements-dev.txt`
- `conftest.py`  ← the SMALL one: only inserts the repo root on `sys.path`
                   (~4 lines). Do NOT confuse with the fixtures file below.

Tests (new `tests/` directory; do NOT add `tests/__init__.py`):
- `tests/conftest.py`  ← the LARGE one: `make_finding`, `make_scan`, and the
                         `isolate_storage/_enterprise/_rag/_memory` + `clean_auth_env`
                         fixtures. (Two files are named conftest.py — root vs tests/.)
- `tests/test_catalog.py`
- `tests/test_catalog_knowledge.py`
- `tests/test_catalog_scan.py`
- `tests/test_scanner.py`
- `tests/test_storage.py`
- `tests/test_sarif.py`
- `tests/test_reporting.py`
- `tests/test_enterprise.py`
- `tests/test_auth.py`
- `tests/test_llm.py`
- `tests/test_rag.py`
- `tests/test_memory.py`
- `tests/test_refactor.py`
- `tests/test_main.py`
- `tests/test_cli.py`

## 2. REPLACE existing files (use the latest downloaded version of each)

- `app/scanner.py`   — adds `resolve_tool()` (cross-platform), the
                       `run_catalog_native` pass in `run_scan()`, and passes
                       `cwe` into `suggest_fix`.
- `app/ai.py`        — now a thin consumer of `catalog_knowledge`.
- `app/reporting.py` — fixes an invalid escape (`'\|'` -> `r'\|'`).
- `requirements.txt` — adds `httpx==0.28.1` and `PyYAML==6.0.2`.

If any file was downloaded more than once across the session, use the most
recent version. Verify each replacement is the intended one before overwriting.

## 3. Sanity-check placement

```
git status            # expect new app/ + rules/ + tests/ files and 4 modified
python -c "import ast,glob; [ast.parse(open(f).read()) for f in glob.glob('app/*.py')+glob.glob('tests/*.py')]" && echo "all parse"
```

## 4. Install dependencies

```
pip install -r requirements.txt -r requirements-dev.txt
```

- If a pin conflicts with what is already installed (most likely `httpx`),
  reconcile to the version this environment actually uses and update
  `requirements.txt` to match — do not force a downgrade that breaks other deps.
- `python3-saml` needs native xmlsec libs. If install fails, the auth tests will
  skip cleanly (they use `importorskip`); everything else still runs.

## 5. Run the suite

```
python -m pytest -q
```

Expected: **138 passed** (or a small number skipped if `python3-saml`/`httpx`
are unavailable). The suite is offline and hermetic and does NOT require
semgrep/bandit/pip-audit to be installed — those passes report `not installed`
and the native catalog scanner provides the findings the tests use.

If there are FAILURES, they are almost certainly environment-specific:
- import errors for `app.auth` / `app.main` -> a missing dep (`httpx`,
  `python-multipart`, `authlib`, `python3-saml`); install it.
- version-pin mismatches -> align `requirements.txt` to the installed version.
- Do not weaken assertions to make tests pass; fix the environment instead.

## 6. Optional end-to-end sanity

```
python -m app.cli --path . --fail-on high   # exit code 2 if HIGH+ findings exist
```

## 7. Review, commit, push

```
git add -A
git diff --cached --stat
git commit -m "Add native byte-level scanner, catalog knowledge layer, and full test suite (138 tests)"
git push -u origin feature/catalog-scanner-and-tests
```

Open a PR. Do not push directly to the default branch.
