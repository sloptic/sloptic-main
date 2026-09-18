# Sloptic v3.0 sprint

Internal planning doc. Sibling of `V2_ROADMAP.md`, which holds the versioning contract this sprint obeys.
Written 2026-09-14, after sloptic.org was publicized on 09-08.

## Sprint goal

**One ruler change, measured twice: land every score moving fix and every new probe, run the corpus, audit
what the new probes fire, fix it, run again, freeze both curves, publish 3.0.0.**

One sentence because the goal is the thing that decides what gets cut when the sprint runs long. Anything
that does not serve "both curves frozen and 3.0.0 published" is out, however good it is.

## Why a sprint rather than a release train

The instinct to ship small and often is right almost everywhere and wrong here, for a reason worth being
explicit about: **the expensive step is measurement, not code.**

- A full corpus run is 146 machine hours over 38 wall hours at concurrency 4. Two of them plus their passive
  counterparts is roughly a week of a four core box.
- Every score moving change invalidates the frozen curve, and a curve can only be rebuilt by a full run.
- So N changes shipped separately cost N runs. Batched, they cost one measurement cycle.

That is what forces a sprint boundary. It is not a preference for big batches, it is that the batch size is
set by the cost of the oracle.

**The planning consequence, and the thing that surprised us:** code time compresses hard with an AI pair,
measurement time does not compress at all. A deterministic probe is an afternoon. The run behind it is three
days no matter who wrote the probe. So the critical path is the runs and the audit, and the correct response
is to put MORE into each run rather than fewer, which is the opposite of what small batch thinking suggests.

## Definition of done

**Sprint level.** Both curves frozen (full and passive), `3.0.0` tagged and on PyPI, sloptic.org moved to the
new pin, and the report card carrying a visible ruler label so a stored 2.x grade does not silently read as
current.

**Item level**, inherited from `claude.md` doctrine rather than invented here. A probe is not done when it
fires. It is done when:

1. It passes the intent independence wedge: there is no legitimate app for which the failing behaviour is
   correct.
2. Its oracle rests on a signature only the flaw can emit. Reflecting our own payload back is not evidence.
3. It has a precision guard and a CI lock, so a future change cannot silently widen it.
4. It has tests, and the suite is green.
5. It survived the audit pass on real corpus fires. **A probe that has only ever run on fixtures is not
   done**, it is untested at population scale, which is where every FP class we have ever had came from.

## The one hard sequencing constraint

Everything else is free ordering. This is not:

> **New detection must land before the DISCOVERY run. Pure fixes only need to land before the FINAL run.**

Because the discovery run exists to surface FP classes at scale, and only probes that fire can produce them.
A probe landing after that run needs a third run, which is three more days of box time. Fixes that remove or
reclassify (the cap, the onset, the 404 gate) generate no fires, so they can land later without costing a
run.

## Backlog

### Done (landed before the sprint proper, both diagnostic, neither moves a score)

- **Host speed on every record.** `benchmark_index` + `benchmark_index_spread` (commit `a241dac`). Nothing in
  Lighthouse normalizes for host load: under the default `simulate` throttling the real browser is never CPU
  throttled, so the trace carries the box's actual contention and Lantern scales it by a fixed 4x. Without
  this a perf shift between corpora cannot be told apart from a busier box.
- **Death location on every DNF.** `timeout_phase` / `timeout_probe` / `timeout_progress` (commit `b194184`).
  The 900s tail is 19.7% of a run's machine time and had two competing explanations, neither sizeable while
  the child process was SIGKILLed with its knowledge inside it.

Both had to precede the discovery run or that run produces another corpus that cannot answer the questions
being asked of it. **That is the general rule: instrumentation lands before the measurement it serves.**

### Committed: must be in the discovery run

New detection. Each is deterministic, so no model enters the grader.

| # | item | why it passes the wedge | size | status |
|---|---|---|---|---|
| 1 | Provider key in the client bundle (Groq/xAI/HF/Replicate + Anthropic split) plus live Gemini validation for `AIza` | no app intends to ship a credential that bills its owner | S | **DONE** `sec-secrets-003` |
| 2 | Supabase Storage bucket listing open to anonymous | storage policies are separate from table RLS, so not redundant with `sec-backend-001`; zero coverage today | S | **DONE** `sec-backend-004` |
| 3 | System prompt in the client bundle | structural detection (a provider SDK call with a literal `role: "system"`), never semantic | S | todo |
| 4 | Scaffold text on a LINKED route | string match only; the moment it asks "is this page finished" it judges intent and fails the wedge | S | **DONE** `qa-scaffold-001` |
| 5 | Session token in a URL query string | confirmed uncovered; leaks via referrer, history and logs, and no spec makes it correct | S | **DONE** `sec-session-006` |
| 6 | CVE-2025-29927 Next.js middleware auth bypass (`x-middleware-subrequest`) | a route auth-gated to anon becomes reachable with an internal header; no app intends that | M | **ALREADY BUILT** `sec-authbypass-001` (predicate `middleware_auth_bypass`, repriced to 90) — the roadmap note calling it dark described intent, not the code |

**CVE-2025-48757 (Supabase anon-RLS) DROPPED as redundant** (2026-09-15, verified against the disclosure).
It is "missing RLS lets anon or any authed user read protected rows", which is exactly what `sec-backend-001`
(anon read) and `sec-backend-002` (authed read) already do, and they prove it by reading a real row rather
than matching a version. A separate signature probe would only duplicate the finding. So "two CVE probes" is
one, and the storage listing (item 2) is the genuinely uncovered BaaS surface.

**System prompt in the bundle (item 3) DROPPED** (2026-09-15, Ian agreed). It is a marker for things now detected directly: a direct client-to-provider call ships the KEY too (caught at 70-92 by `sec-secrets-003` and the provider patterns), and the only additive slice, a backend that honors a client-supplied system prompt, needs an ACTIVE inference request to prove and belongs with the unmetered-inference stretch item, not a cheap string match.

**So the discovery-run new-detection set is fully landed: two built this sprint (`sec-secrets-003`, `sec-backend-004`), two more built this sprint (`qa-scaffold-001`, `sec-session-006`), one already in the tree (`sec-authbypass-001`), two dropped as redundant or weak (CVE-2025-48757, system-prompt).**

### Committed: must be in the discovery run (added 2026-09-15, from the sloptic-web report)

- **Redirect settling + http fallback at the deployer** (`_settle_origin`, `_http_variant`). A same-host
  http->https upgrade is adopted as the graded origin, and an https target whose connection fails outright
  falls back to http once. This is here rather than with the pure fixes because it is SCORE MOVING for a real
  slice: ~154 corpus origins are http, only 13 are true http-only (they fire sec-tls-001), so ~a hundred
  redirect to https and were being UNDER-graded (base_url stuck on http, redirect-averse probes saw 301s).
  Rebasing grades them at their real https origin, which changes their scores, so it must be in the corpus
  the curve is frozen from. It also fixes the hosted worker's origin-scope DNF (the port changed 80->443) and
  records `observed_surface.graded_origin` so a record says which scheme answered. The web session's three
  asks resolve to this: sec-tls-001 already fires on http (penalty 30, confirmed), and the redirect-DNF they
  saw was origin-scope specific, not a corpus DNF (the corpus http DNFs are dead ports, a ConnectError, not
  redirects).

### Committed: must be in the final run

Fixes. These reclassify or remove rather than fire, so they do not need the discovery run to audit them.

- **The inert injection request cap.** `_INJECT_MAX_REQUESTS = 150` is read on the main thread but tallied in
  worker threads where the context var is empty, so it has never fired in the fan out it was written to bound.
- **Challenge onset in pooled probes.** Must land WITH the run, never before: the corpus was measured with the
  same blind spot, so correcting it alone makes new grades incomparable to the curve they rank against.
- **The 404 gate, three layers.** Certain (4xx root plus platform error headers), divergence (the existing
  `discovery._CATCHALL_PROBE` wired to gradeability instead of only finding suppression), and render (SPAs
  serve identical HTML for every path by design, so only the rendered DOM separates a real SPA from a sink).
- **Browser navigation scoping** via `resource_type == "document"`, subresources stay unscoped.
- **A discovery budget plus pipe.** Generalize the crawler wedge pattern: `render_routes` already has a 150s
  budget, streams routes back as they complete, and SIGKILLs on expiry, and it accepts a `hard_deadline`
  parameter **no caller passes**. X wants sizing from the discovery run's `timeout_phase` data, not a guess.
- **The a11y axis promotion** plus the qa-seo relabel. Total preserving, so it needs no re-grade and does not
  gate either run, but it must precede the re-pricing pass so pricing sees four axes rather than three.
- **LANDED 2026-09-17 (the final-run mechanism set):** pool context propagation — the fan-out pools submit
  through a fresh copy of the submitting context, so the 150-request cap FIRES in the fan-out and challenge
  onset registers from pooled probes (net's onset became a shared first-writer recorder; a per-submit copy,
  never one shared Context, since Context.run is single-entry and a shared one killed every concurrent send);
  a per-probe wall clock (default 120s, env SLOPTIC_PROBE_TIMEOUT, catalog max_seconds) that abandons a hung
  probe into blocked_probes for the retry pass — browser probes exempt, because Playwright's sync API is
  thread-affine; and browser top-level navigation scoping via resource_type == "document" (subresources stay
  unscoped). **The a11y axis promotion also landed (`53384e9`): accessibility is now its own axis (qa-a11y-001,
  qa-a11y-002, and qa-seo-001 moved from bundle qa, seo's category relabeled mobile-visibility since it scores
  a missing viewport, not marketing). Total-preserving by construction (the damper groups by category, not
  bundle), so it needs no re-grade, verified on the reference app and locked by a dedicated test.** With that,
  every pre-repricing mechanism is in and the re-pricing pass is unblocked — it now prices four axes, not three.
- **a11y RE-PRICED 2026-09-18: KEPT at 20/12/7/3 (Ian, locked).** The v11 calibration holds post-promotion
  (critical = half the security ceiling; a11y is the smallest axis at ~18%, decorrelated at 0.18), so the
  tiers do not change. Two non-score-moving fixes landed alongside: the report-card evidence line now names
  the failing rules/impacts (`0c9e940`), and the off-score advisory set is persisted on CLEAN a11y outcomes
  (`28698e1`) so the final run can measure whether any advisory rule (target-size the only real-barrier
  candidate) earns promotion. The v3.1 probe candidates (DB connection string in the bundle, Neon Data API
  RLS generalization, Svelte fingerprint) are logged to memory, deferred so v3.0's discovery run stays valid.
- **RULER LABEL LANDED 2026-09-18 (`6ad8d4f`), DoD item 4 done.** Every grade record now stamps `ruler`
  (full 2026.3 · passive-2026.1) from `sloptic/ruler.py`, and the card reads it from the record (never the
  current curve), so a stored 2.x grade renders "Ruler unspecified -- not comparable" instead of borrowing
  3.x. **FREEZE CHECKLIST GAINS A STEP: bump `sloptic/ruler.py` FULL/PASSIVE together with the curve files in
  validation/ and the pyproject version -- test_ruler.py fails CI if the constant drifts from the frozen
  curve.**
- **FP backlog** — AUDITED 2026-09-17, each on its own merits against the v24 fires. Only ONE was a real
  actionable FP:
  - **base44 endpoint attribution — REAL FP, FIXED (`5c67dee`).** 4 base44 apps carried 131-221 phantom
    endpoints, all the identical `/api/apps/{app_id}/entities/...` SDK scaffold (the platform's, not the
    team's), unreachable without the real UUID, all 404, all counted as reached surface (404 < 500) ->
    surface_size ~450. discovery now drops any endpoint whose CONCRETE path still carries an unresolved
    `{placeholder}` (openapi concretizes declared params, so a surviving brace is an unresolvable template).
    No finding moved; the phantom surface is gone.
  - **secretscan recall — already done, verified.** The provider patterns (`gsk_`/`xai-`/`hf_`/`r8_` + the
    `sk-ant-` split) are in `secretscan.py`; this overlapped the sec-secrets-003 work and needs nothing more.
  - **perf-load-001 edge gate — NO FP.** All 4 v24 fires are legitimate: 2 self-hosted nginx apps that 5xx
    under load, and 2 (pythonanywhere-free, a raw-nginx VPS) that drop a 20-request burst though they answer
    a lone request in ~0.4s. All four respond 200 at baseline, none is behind a CDN the gate missed, and the
    design deliberately keeps self-hosted PaaS live (the team owns its capacity). Priced 50 (drops) / 60
    (5xx). Working as intended.
  - **dead-controls (qa-deadctrl-001) — SOUND at ~95%.** The 223 fires are dominated by real dead CTAs (dead
    "sign in"/"log in"/"get started" buttons — the AI-shell tell). The 49 `(unlabeled)` fires spread across
    normal apps (real dead icon buttons co-occurring with real dead CTAs), not clustered on canvas apps. The
    one true confounder (canvas/WebGL draw, already in the tp_definition) is ~2 apps; a canvas-pixel watcher
    is a risky browser change for a 2-app gain right before the freeze -- not taken.
  - **http-correctness — NO score FP.** qa-http-001 fires at penalty 0 (not scored). qa-http-002 (charset,
    9 fires) spot-checked live: getsentinel.co and calebgoodman both serve text/html with no header charset
    and no meta charset in the first 1KB -- real, and the meta-in-first-1KB hardening holds.
- **LANDED 2026-09-17, from the v24 NEW-PROBE audit + the 12.5 shell cluster:**
  `sec-session-006` filters candidate URLs to the graded origin (both v24 fires were third-party params: a
  Loom `sid`, a Mapbox `access_token`) and excludes `pk.` publishable keys; `qa-scaffold-001` requires 2+
  DISTINCT bracket placeholders (backtrack-ten's single `[Your Name]` was deliberate example copy); the 404
  gate's platform signatures landed in `_dead_shell_reason` — Netlify "No Server Found", GitHub Pages
  "There isn't a GitHub Pages site here", and the untouched Vite starter, all served at HTTP 200. **The 12.5
  cluster decomposed on inspection: envi-seven is a REAL one-page app and stays graded** — the assumption
  that all five were shells died when fetched. Remaining 404-gate work: title-only shells (idea-forge) need
  the render layer.
- **LANDED 2026-09-17, the 404 gate's RENDER layer (`8c0a917`):** a non-canvas host whose entry renders under
  24 visible chars AND captured no forms/endpoints is recorded `render_state = "empty"` and excluded from the
  curve by `is_shell_only`, the same way a Streamlit canvas shell is -- a probabilistic shell CLASSIFICATION,
  never a dead-url DNF (a slow-hydrating real SPA can render short too). idea-forge-web renders only its
  `<title>` "Idea Forge" (10 chars) and scored a phantom 12.5; envi-seven (514 chars of real copy) is spared.
  This completes the 404 gate's three layers (certain platform-signature, divergence, render).

- **LANDED 2026-09-17, from the v24 injection audit (classics at 55% precision: 5 real / 6 false):**
  sqli boolean gets a negative control (FALSE must collapse onto the benign baseline) plus an SSE
  generator-stream skip (`8aab72b`); csrf treats a cross-host redirect as a bounce and records the
  redirect Location so 3xx fires are auditable (`4a8fb48`); hosthdr never fires on a 4xx/5xx reflection
  (`5cefc40`). Replay evidence in the audit: mesh-3d answered all payloads identically, cognify was an
  LLM SSE stream, governancex 307'd to its canonical domain, bye-buy's S3 404 echoed the bucket name.

### Stretch: in if the sprint is running ahead, out without argument if not

- Unmetered inference endpoint. Needs the full active battery escalation ladder (free variants first, stop at
  the first throttle, hard cap 15) and a consent story, and it must never enter the passive 44 because it
  spends the target's money.
- First paint permissions. The audits ship in our pinned Lighthouse but we run `--only-categories=performance`,
  so collecting them means adding a category, which touches the perf axis and wants its own care.
- WCAG reflow. Resize-text is explicitly a later, noisier, separate probe.
- Browser driven create-and-read-back, the keystone capability against the access control 0% gap. This is a
  capability, not a probe, and it is the most likely thing to eat the sprint if allowed in.

### Out of scope, named so it stays out

Supabase Realtime (demoted: same RLS precondition `sec-backend-001` already catches, worth an escalator later
but not recall). Prompt injection resistance, hallucinated output, model choice: all fail the wedge. Char
handling. Repo grading on the Dell, which needs the apt-Docker plus gVisor migration and is infrastructure,
not this sprint.

## Capacity

| | machine hours | wall at conc 4 | wall at conc 2 |
|---|---:|---:|---:|
| full run | 146.0 | 38.0h | 73.0h |
| passive run | 72.7 | 19.7h | 36.4h |

Discovery run is full only (passive probes are a subset, so a separate passive discovery run buys nothing).
The final pass runs both, for the two curve freezes. **Roughly 7.6 days of box time at concurrency 4.**

**Run at concurrency 4 with the grader down.** Every prior corpus used 4, and changing concurrency changes
cores per grade, which changes observed CPU task durations, which Lantern multiplies by a fixed 4x into the
perf score. Changing the measurement environment in the same sprint that changes the probes means a perf
shift cannot be attributed to either. If the site must stay up, concurrency 2 **pinned** with
`taskset -c 0,1`, because CPU affinity is inherited across fork and exec and two unpinned grades will spill
across all four cores anyway. Concurrency 2 unpinned is the worst option: slower than 4 and not comparable to
history.

## Risks

| risk | why it bites | mitigation |
|---|---|---|
| New probes bring new FP classes | Every FP class we have had came from population scale, not fixtures | That is what the discovery run and audit are FOR; do not skip straight to one run |
| Scope creep via the stretch list | Read-back in particular is a capability that can absorb the whole sprint | Stretch items are out by default, in only if ahead |
| Grade discontinuity at the switchover | 2.x stored reports are not comparable to 3.x, and will silently look current | Ruler label on the report card, or re-grade stored results. Decide early, it is web side work |
| Perf inflation on live grades | A live grade gets the whole box; the curve population got a quarter of it, so live apps may score better on perf than the curve they rank against, a bias in the app's favour | The A/B below, before the freeze |
| Pricing notes are stale | The `qa-deploy-001` PROVISIONAL comment is a leftover, not open work | Re-verify against reality before anything goes on a list; do not quote the old notes |

## Open questions to settle inside the sprint

1. **The perf contention A/B.** Grade ~30 apps at concurrency 4, then the same 30 at concurrency 1, compare
   median Lighthouse performance. `benchmark_index` is now on the record, so the host speed difference is
   visible directly rather than inferred. An hour or two. If it is a wash, disregard forever; if not, it is a
   curve design input and you want it before the freeze, not after.
2. **X for the discovery budget.** Read it off the discovery run's `timeout_phase` distribution.
3. **Is the DNF tail discovery or fan out?** Same source. Settles whether the cap or the budget is the bigger
   capacity win, and neither number should be quoted until it does.
