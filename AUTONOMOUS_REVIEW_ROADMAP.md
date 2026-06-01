# Autonomous Review Roadmap — Soundness Verification (Inside-Out + Outside-In)

What this is: the build roadmap for the Code-Reviewer **as a component of an
autonomous software-development app**, not as a standalone product. The agents
generate runnable apps; this component verifies they're *sound* from two
viewpoints — inside-out (SAST, reads the source) and outside-in (runtime + DAST,
tests the running app) — and serves three roles: **gate**, **auto-fix loop**, and
**feedback source**.

This supersedes the product-framed `CORRELATION_LAYER_ARCHITECTURE.md` for this
purpose. The engineering specs still apply, repurposed: `PHASE1_CORRELATION_CORE_SPEC.md`
and `PRIORITIZATION_DESIGN.md` (now for *machine* consumption, not human triage);
`DAST_CONSUMPTION_SPEC.md` (Phase 4). The PR-sliver spec is a human surface and is
not used here.

## Guiding facts (the reasons the order is what it is)
- **SAST is universal & deterministic** → it works on every app type the agents
  emit and gives `file:line` → it is the backbone and the auto-fix engine.
- **DAST is web-only, non-deterministic, and maps endpoints→code imperfectly** →
  it is a verification *gate*, never a naive auto-fix driver, and it needs the app
  built and running first.
- **The consumer is a machine** → output must be structured, deterministic, and
  carry actionable fix guidance; precision controls loop safety (a false positive
  makes an agent "fix" a non-bug).

---

## Phase 0 — Current state (foundation; do not rebuild)

Inside-out **detection** is largely done: SAST/SCA/secrets fleet (Semgrep, Bandit,
CodeQL, SonarQube, pip-audit, govulncheck, ShellCheck, SQL-artifact, native
byte-level catalog, secrets, SARIF import), the 150-rule catalog + knowledge
layer, fix proposals, 221 tests + CI, the coverage map (148/150). The gap is not
detection — it's that the tool is shaped for humans, not for an orchestrator.

---

## Phase 1 — Make it a clean machine component (inside-out; enables gate + feedback)

Goal: the orchestrator/agents call it programmatically and get deterministic,
structured results.

Build:
- **Contract**: input = path/commit; output = structured findings (location,
  vuln class, severity, **catalog-grounded fix guidance**, priority) as
  machine-readable data (JSON/SARIF) — no human formatting required.
- **Consolidation + prioritization**: implement `PHASE1_CORRELATION_CORE_SPEC.md`
  + `PRIORITIZATION_DESIGN.md`, repurposed — give agents a deduped, ranked set so
  they don't chase duplicates or low-value findings.
- **Determinism + precision hardening**: line-insensitive fingerprints
  (flaky findings → flaky loop); conservative rules (false positives misdirect
  agents). This is the single most important quality bar for loop safety.
- **Gate decision**: policy/thresholds → `pass | block` + machine-readable reasons.

Why first: all three roles depend on this contract existing.
Done when: the orchestrator can call the component on a path and receive a
deterministic, ranked, structured findings set + a gate verdict.

---

## Phase 2 — Close the inside-out auto-fix loop (inside-out; the auto-fix role)

Goal: findings flow back to the coding agents and get fixed, verifiably.

Build:
- **Agent-shaped fix output**: structured remediation per finding (not human
  prose), derived from the catalog knowledge layer.
- **Loop protocol**: scan → emit findings+fixes → orchestrator routes to agent →
  agent edits → **re-scan → verify the finding is resolved AND no new findings
  introduced**.
- **Convergence/termination**: max iterations, anti-oscillation, and a clear
  "could not resolve" outcome the orchestrator can act on.
- **Regression check**: a fix must not break the app's own tests.

Why here: completes the inside-out version of all three roles, deterministically,
on every app type the agents generate. This is the universal backbone.
Done when: an introduced issue is detected, fixed by an agent, and confirmed
resolved by re-scan without regressions, automatically.

---

## Phase 3 — Outside-in foundation: build/run + functional soundness (outside-in; web first)

Goal: stand the generated app up and check it behaves — the prerequisite for any
outside-in testing.

Build:
- **Sandboxed build-and-run harness** for generated web apps (container).
- **Smoke/integration checks**: does it start, do endpoints respond, basic
  behavioral soundness.
- **Runtime posture checks**: security headers, debug mode off, expected exposed
  surface only.

Why before DAST: you cannot test from outside an app you cannot run; and "does it
even run correctly" is the first outside-in question. Valuable beyond security
(functional soundness). Scope: web services.
Done when: a generated web app can be built, run in a sandbox, and pass/fail a
structured functional+posture soundness check.

---

## Phase 4 — Outside-in security: DAST as a gate (outside-in; web only)

Goal: confirm the *running* web app holds up from the outside.

Build:
- Run DAST (ZAP/Nuclei) against the Phase-3 running app.
- Consume output per `DAST_CONSUMPTION_SPEC.md`; map endpoints→code best-effort.
- Feed results as a **verification gate + feedback**, NOT into the naive auto-fix
  loop (non-determinism + imperfect mapping). A SAST-suspected + DAST-confirmed
  finding → high-confidence block.

Why here: it's the security layer on top of the functional outside-in foundation,
and the hardest signal to trust autonomously — so it follows the deterministic
inside-out core.
Done when: the running web app is DAST-scanned, findings are mapped to code where
possible, and a confirmed-exploitable issue produces a high-confidence gate
failure with the proof attached.

---

## Phase 5 — Unify into a soundness verdict + harden

Goal: one verdict the orchestrator consumes, and a component that improves with use.

Build:
- **Unified soundness verdict** per generated app: `sound | unsound` + ranked
  issues + confidence, with correlation spanning inside-out and outside-in (a
  SAST+DAST cluster = strongest signal).
- **Feedback-driven tuning**: loop outcomes (what agents actually fixed vs what
  recurred) refine precision and rule weighting over time.
- **Per-runtime expansion**: add outside-in providers for mobile/enterprise
  *only when those output paths mature and are runnable in the loop*.

Why last: polish/scale once both viewpoints work.

---

## Sequencing discipline (what not to do)

- Don't begin the outside-in track (3–4) until the inside-out loop (1–2) is solid
  and deterministic.
- Keep DAST out of the auto-fix path; it gates and informs, agents fix via the
  inside-out loop.
- Outside-in is web-only initially; defer mobile/enterprise dynamic testing.
- Don't expand SAST breadth speculatively — coverage is near-complete. The payoff
  now is the contract, the loop, and determinism, not more rules.
- One phase at a time; each on its own branch, tests green before merge, dogfooded.

## Verification recipe (per phase)
- P1: call the component twice on the same input → identical structured output +
  gate verdict (determinism); known issue appears ranked with fix guidance.
- P2: inject a known issue → loop detects, agent fixes, re-scan confirms resolved,
  app tests still pass.
- P3: a generated web app builds, runs, and yields a functional+posture verdict.
- P4: a deliberately vulnerable generated app is built, run, DAST-scanned, and the
  confirmed issue maps to code and trips the gate.
- P5: a SAST+DAST-confirmed issue surfaces as the top-ranked item in a single
  soundness verdict.
