# Build Spec — Phase 4: Outside-In Security (DAST as a Gate)

Purpose: run DAST against the **Phase-3 sandboxed running app**, map each dynamic
finding back to a line of source code, and fold it into the same ranked, gated
soundness verdict as everything else. The marquee outcome: a finding that SAST
*suspected* and DAST *confirmed exploitable* becomes the highest-confidence P0.

Read first: `AUTONOMOUS_REVIEW_ROADMAP.md` (this is Phase 4), and confirm the
Phase-3 contracts in `runtime_plan.py`, `runtime_worker.py`, `runtime_smoke.py`.
Reuse `PHASE1_CORRELATION_CORE_SPEC.md` (consolidation/contract) and
`PRIORITIZATION_DESIGN.md` (scoring). Build only after Phase 3 is solid.

## Key context vs the standalone framing
This runs **inside the autonomous loop**: the system already builds and runs the
*generated* app in a sandbox (Phase 3B) and probes it on loopback (Phase 3C). So
DAST here scans **that same sandboxed, loopback instance** — it is not a sensor in
anyone's production, and not a scan of arbitrary external targets. The Phase-3
safety guardrails carry over unchanged (sandboxed execution, loopback-only target,
quarantine gating, `allow_remote_base_url` required for any non-loopback host).

## Scope

In: a `DASTProvider` that (a) runs a DAST tool (ZAP/Nuclei) against the Phase-3
running sandbox app, OR (b) ingests an externally-produced DAST report
(SARIF/ZAP/Nuclei JSON) when one is supplied; normalizes to canonical `Finding`s;
resolves endpoints to code; and feeds them into consolidation as a gate signal.

OUT (non-goals):
- No production sensors, no eBPF, no scanning of arbitrary/remote targets. The
  target is the sandboxed loopback app from Phase 3 (or a supplied report).
- DAST findings are **never** wired naively into the auto-fix loop (Phase 2) —
  they gate and inform; fixes flow through the deterministic inside-out loop.
- No bespoke DAST engine — use ZAP/Nuclei (or a supplied report).

---

## 1. Input: run-against-sandbox or ingest-report

`DASTProvider` supports two input modes behind one interface:
- **Run mode**: against the Phase-3 running app's loopback `base_url`, invoke the
  DAST tool (ZAP baseline/full or Nuclei). Honor the Phase-3 guardrails: only when
  there is a running sandbox instance and a loopback target; respect quarantine
  and `allow_remote_base_url`.
- **Ingest mode**: parse a supplied report. Auto-detect by shape — SARIF (reuse the
  existing SARIF importer), OWASP ZAP JSON/XML (alerts: url, method, param, risk,
  cweid, evidence, request/response), Nuclei JSONL (template-id, matched-at URL,
  severity, request/response).
Each parser maps tool fields → a normalized `Finding` (section 3). Start with
whichever DAST tool you actually run in the loop; add formats on demand.

---

## 2. The hard part — endpoint to code mapping

DAST findings are located by **URL + method + parameter**, not `file:line`. The
core work is resolving that to a source location so a DAST finding can cluster
with SAST. Best-effort and layered; **degrade gracefully** — never drop an
unmappable finding.

Resolver strategies, in order of accuracy:
1. **OpenAPI/Swagger spec** (if generated): `path + method` -> `operationId`/handler
   -> source -> `file:line`.
2. **Framework route table**: parse route definitions for the framework the agent
   generated (FastAPI/Flask decorators, Express routes, Spring annotations, Rails
   routes) -> handler -> `file:line`. Most accurate; implement the frameworks your
   agents actually emit.
3. **Heuristic string search**: grep the source for the route literal
   (`"/api/orders"`) to locate the handler. Crude fallback.
4. **Unresolved**: keep the finding at endpoint granularity (section 3). Still
   gated and shown; just can't cluster with file-level findings.

`EndpointResolver.resolve(method, url) -> Optional[Location]`. First hit wins;
else None. Conservative: a wrong mapping that pins a DAST finding to the wrong
line is worse than leaving it endpoint-level — and in an autonomous loop a wrong
map could misdirect a downstream fix.

---

## 3. Finding model additions

Extend per the PRIORITIZATION_DESIGN pattern (optional, backward-compatible):

```python
class DynamicEvidence(BaseModel):
    method: str
    url: str
    param: str | None = None
    payload: str | None = None
    request_excerpt: str | None = None
    response_excerpt: str | None = None
    status_code: int | None = None
```

On `Finding`:
- `dynamic: DynamicEvidence | None = None`  — the proof, always preserved.
- `source = "dast:<tool>"` (e.g. `dast:zap`).

On `Reachability` (add one field):
- `confirmed_exploitable: bool = False` — DAST observed it, not inferred. The
  **strongest** reachability signal; observation beats static taint.

Location handling:
- **Resolved** -> set `location` to the real `file:line`; keep `dynamic` for proof.
- **Unresolved** -> `location.path = f"[endpoint] {method} {url}"`, `line = 0`, and
  `context.path_class = "endpoint"` so consolidation keeps it in its own bucket and
  never cross-merges it with file findings.

---

## 4. Consolidation interplay (the value)

When a resolved DAST finding shares `(normalized_path, proximate_line, vuln_class)`
with a SAST finding, they cluster (existing Phase-1 logic):
- `corroborating_tools` gains a DAST source.
- The cluster carries `reachability.confirmed_exploitable = True`.

That cluster — statically flagged **and** dynamically confirmed exploitable — is
the highest-confidence issue the system can produce. Surface the DAST `dynamic`
evidence (request/response proof) on the representative so the gate reason is
self-justifying. Unresolved DAST findings stay in their `path_class="endpoint"`
group, gated on their own.

---

## 5. Prioritization & gate impact

Extend the reachability factor in PRIORITIZATION_DESIGN:
- `confirmed_exploitable` (DAST) -> larger boost than static dataflow (suggested
  +35 vs +25; tune). A cluster with both static taint and `confirmed_exploitable`
  is the canonical P0, and `confirmed_exploitable` satisfies the P0 reachability
  guard on its own.
- In the soundness verdict, a confirmed-exploitable issue is a **block** with a
  reason that names the proof (`"dynamically confirmed exploitable (zap: POST
  /api/orders, param id)"`).

---

## 6. Pipeline placement

DAST runs **after** Phase 3 has built and started the app in the sandbox:
```
... -> runtime build/run (3B) -> smoke+posture (3C) -> DAST against loopback app (4)
     -> normalize -> EndpointResolver -> consolidate (with SAST) -> prioritize -> verdict
```
`DASTProvider` is a `DetectionProvider`; its findings join the same
`consolidate -> enrich -> prioritize` flow. Resolve endpoints before consolidation
so resolved locations are available to cluster on.

---

## 7. Tests (hermetic/offline)

- **Parsers**: sample ZAP JSON / Nuclei JSONL / DAST SARIF -> normalized `Finding`s
  with `dynamic` populated.
- **Resolver**: OpenAPI path -> handler file:line; route-table -> handler; heuristic
  match; unmapped -> endpoint-level with `path_class="endpoint"`.
- **Consolidation**: DAST finding resolving to the same file/line/class as a SAST
  finding -> one cluster, `confirmed_exploitable=True`, both tools in
  `corroborating_tools`; an unresolved/wrong one -> NOT merged onto a file.
- **Gate/priority**: `confirmed_exploitable` outranks static dataflow; a SAST+DAST
  cluster -> P0 block with the proof in the reason.
- **Guardrails**: run mode refuses a non-loopback target without
  `allow_remote_base_url`; refuses when no sandbox instance is running.
- Use fixtures/canned reports — no live targets or network in tests.

---

## 8. Open decisions

1. **First DAST tool & frameworks.** Implement the one DAST tool you run in the
   loop and route resolution for the frameworks your agents actually generate.
2. **confirmed_exploitable weight.** Start +35; calibrate so SAST+DAST reliably
   lands P0 without flooding it.
3. **ZAP baseline vs full scan.** Baseline (passive + a few active) is faster and
   more deterministic in a loop; full active scan is slower/noisier. Prefer
   baseline first.
4. **Endpoint-level finding presentation** in the verdict (separate "endpoint
   findings" group vs inline).

## 9. Sequencing / discipline

Build after Phase 3 is solid. Run only against the sandboxed loopback app (reuse
Phase-3 guardrails) or ingest a supplied report — never a production sensor, never
an arbitrary remote target. Gate and inform; do not feed DAST findings into the
naive auto-fix path. Branch, tests green, dogfood.
