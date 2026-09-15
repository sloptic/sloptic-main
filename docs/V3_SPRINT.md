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
| 4 | Scaffold text on a LINKED route | string match only; the moment it asks "is this page finished" it judges intent and fails the wedge | S | todo |
| 5 | Session token in a URL query string | confirmed uncovered; leaks via referrer, history and logs, and no spec makes it correct | S | todo |
| 6 | CVE-2025-29927 Next.js middleware auth bypass (`x-middleware-subrequest`) | a route auth-gated to anon becomes reachable with an internal header; no app intends that | M | todo |

**CVE-2025-48757 (Supabase anon-RLS) DROPPED as redundant** (2026-09-15, verified against the disclosure).
It is "missing RLS lets anon or any authed user read protected rows", which is exactly what `sec-backend-001`
(anon read) and `sec-backend-002` (authed read) already do, and they prove it by reading a real row rather
than matching a version. A separate signature probe would only duplicate the finding. So "two CVE probes" is
one, and the storage listing (item 2) is the genuinely uncovered BaaS surface.

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
- **FP backlog**: base44 endpoint attribution, secretscan recall (overlaps item 1 above), perf-load-001's edge
  gate, and dead-controls plus http-correctness, never audited on their own merits.

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
