# claude.md — the fuzz runner

Conventions and hard-won decisions for this project. This file governs everything at or below
`fuzz-runner/`. The league's root `claude.md` governs the league; where they disagree about code in this
directory, this file wins.

Read `FUZZ_RUNNER_SPEC.md` for architecture and `format_spec.md` §4 for the scoring contract. This file is the
*why*: the decisions that are expensive to rediscover, and the mistakes that are expensive to repeat.

---

## 1. What this project is

**A standalone, universal, black-box web-application resilience grader.** It takes a URL, probes the deployed
app over HTTP, and emits a score. It never reads source.

**HackLet League is a consumer, not the owner.** The league is the most prominent user and the reason this
exists, but the runner is its own product with its own users (MLH-style hackathons, and eventually anyone who
wants a durability check on a deployed app). Nothing in here may assume league-specific context. Where league
behaviour is needed, it goes behind a flag (`--controlled-deploy`) or an applicability gate, never into the
core.

**The moat is the score, not the check count.** Anyone can add probes. What is hard is a number that means
something: calibrated, precise, reproducible, and defensible to somebody who disagrees with it.

**Target coverage: ~95% of the intent-independent, observable surface.** Humans carry intent. That boundary is
the whole design and §3 makes it operable.

**Black-box and runtime is the differentiator.** Every comparable tool in this space (Larridin's AI Slop Index,
SlopCodeBench, SlopGuard, EQ-Bench's Slop Score) is static: repos, PRs, diffs, text. This one grades a running
deployment. Do not drift toward source analysis. It is a different product and a crowded one.

## 2. The score

**Deduction-only. Lower is better. 0 is perfect. Unbounded above.** A probe either detects slop and adds its
penalty, or it does not and adds nothing. There are no points for passing.

This is not a stylistic choice, it honours the attacker/defender asymmetry: defending seven of eight SQL sinks
is still a breach, so the seven add nothing and the one adds full penalty. It also resolves
parameterized-SQL-invisibility structurally — a defended hidden sink and an absent one both score zero, which
is correct, because neither is vulnerable.

**Never claim "defended."** The score cannot distinguish "protected" from "absent," and saying otherwise is a
false assurance. The spec forbids it.

**It is named for AI slop.** Not for security holes specifically. The name is about the whole texture of
carelessly-generated software, which is why **hygiene is signal rather than noise**: missing headers, broken
links, absent alt text and soft 404s all belong in the number. A slop score of 0 must mean "you are on top of
things, you even nailed the boring hygiene." Do not re-price hygiene down to make scores look kinder. This was
proposed once and was actively wrong.

**Penalties are risk-priced by real-world frequency**, calibrated against measured vibe-coded-app rates:
access control ~36%, secrets/crypto ~21%, injection ~18% anchor the top. Security ceiling is 40.

**Per-axis decomposition** (security / qa / performance), no 0–100 normalization. Normalizing was tried and
reverted: it reintroduces a denominator that makes scores incomparable across apps with different applicable
surface.

## 3. The intent-independence litmus

Before adding any probe, ask: **"Is there a legitimate app for which this failing behaviour is actually
correct?"** If yes, the probe is out, or it needs a gate that excludes that app.

Worked examples that shaped the boundary:

- An anon-readable table is *correct* for a public profile directory or a product catalogue. So the gate is
  **column sensitivity, never the table name** (§5).
- `*` returning every row is how plenty of search boxes are designed. So the wildcard differential is
  corroboration only and never fires alone.
- A missing `Secure` cookie flag is untestable over plain HTTP, because the browser would refuse to send the
  cookie back and auth would break. So it is gated on `served_over_https`.
- "Has an API but data-integrity never ran" fires on 59.9% of the corpus. A rule that fires on everything says
  nothing, so it is deliberately excluded from the untested-families gate.

**Authorization semantics stay human.** Whether *this* user should see *that* record is intent. Whether an
anonymous stranger can read a table with `contact_email` in it is not.

## 4. Evidence over heuristic

A finding must rest on a signature **only the flaw can emit**. Reflecting our own payload back is not
evidence.

- `sec-lfi-001` matches `/etc/passwd`'s root line, never the path we requested.
- `sec-filterinj-001` matches `title.ilike.%` in a parse error. Our payload is a comma and a benign token, so
  that string can only be the app's own filter template.
- `sec-domxss-001` requires the payload to **execute** in the DOM, not merely appear in the response.
- `_SSRF_INBAND` signatures are chosen so they never appear in the request URL. `computeMetadata` was
  deliberately rejected as a signature because it *is* in the path we send.

**Corollary: a baseline must be clean.** An app that answers every request with filter grammar (a chatty
framework, a strict validator) carries no signal, and firing on it would report every such app as vulnerable.
Check the benign case first and read N/A when it is dirty.

## 5. N/A is a verdict, and it must say WHY

**A probe that cannot test must return `None`, never `False`.** A false "clean" is a missed finding wearing a
pass.

**And it must set `ctx.evidence["na_reason"]`.** This is the most expensive lesson in the project's history.
`aggregate.py` surfaces per-kind N/A reasons for any kind that went entirely N/A, and for a long time the
session cluster surfaced nothing because every precondition returned a bare `None`.

The cost, measured on the v10 corpus (865 apps): the session probes ran on 31 apps, and **177 of the 204 apps
carrying both a login and a signup reported N/A with no recorded reason.** Two causes were indistinguishable
in that data, and they demand opposite responses:

- registration failed → a hole in our auth lanes, ours to fix
- registered fine, session is not in a cookie → the localStorage/Bearer cohort, which `sec-session-005` already
  handles correctly, so not a hole at all

**Rule: if a predicate has more than one `return None` path, each one gets a distinct reason string.** Not
merely a reason — a *different* one. Three identical messages satisfy "has a reason" and still leave the
aggregate unable to tell a bug from correct behaviour. There is a test that asserts distinctness for the
session cluster; copy that pattern.

`access-control` ran on only 20% of v10 and is the prime suspect for the same defect. Audit it.

## 6. Precision and recall are different games

- **Precision is the adoption gate.** A false positive is loud, immediate and self-correcting, because a human
  disputes it. The runner crossed the usable threshold at roughly 3% residual FP.
- **Recall is the authority-retention game.** A false negative is silent, delayed and retroactive. It voids the
  *meaning* of a passing grade, which is the entire product. "It passed us and we got popped" kills a
  durability credential.
- Both matter. The marginal effort now goes to recall, but only for **provable, observable,
  intent-independent** misses. Intent-dependent misses are by design.

**FPs and FNs live in targeting and scope, not in probe logic.** The audit that established this found the
probe predicates were mostly right and the failures were about *where* they were pointed. Look there first.

**The FP taxonomy — three independent axes, and every FP is on one:**

1. **Scope** — the team's code or the platform's? An app on a hosting platform's subdomain may serve the
   *platform's* login form, and an XSS there is not the team's finding.
2. **Reproducibility** — a stable property, or a transient artifact?
3. **Causality** — did the tested flaw cause the signal, or did a confound? A proxy 500 read as a crash; an
   LLM echoing our payload read as XSS.

Scope is the hardest and it is fundamentally an arbitrary-URL problem. A controlled deploy dissolves it for
free, because you own the platform and can separate it from the submission. Narrow each axis, never claim to
have closed it. The human is the designed last line.

## 7. Attribution: findings must move for their own reasons

A consumer will harden one thing and expect the score to move by exactly that thing. supavulnbase's hardened
reference is built as an ablation harness for precisely this: `HARDEN_CLASS` fixes one flaw class so the
differential is attributable to that class alone.

**This constrains us.** Two rules fell out of it:

**Variant groups collapse to one finding, so a delta is the group maximum and not the sum.** `sec-secrets-001`
and `-002` share a group, so fixing secrets drops 35, not 70. `qa-a11y-001` and `-002` drop 30, not 60. Naive
penalty summing across the catalogue gives 2228; the collapsed ceiling is 1901. Anyone predicting deltas by
summing will conclude we under-report by ~15%.

**A probe with several firing shapes needs a fixed, documented precedence.** `sec-backend-003` fires from
either the PostgREST OpenAPI root or a verbose write error. The write shape is *not* independent of RLS state
(a terse 42501 is RLS refusing; a 23502 with `Failing row contains` is RLS passing and a constraint refusing).
Checking the root first makes the finding immune to the RLS dial. Had it consulted the write first, hardening
RLS would silence a schema-disclosure finding and the RLS delta would read 52 instead of 40 — measuring our
coupling instead of their fix. There is a 2×2 test pinning this. Keep it.

## 8. Measurement must survive a loaded host

Scores are compared across machines and runs, so anything wall-clock is a threat to comparability.

- **Structural beats timed.** Five of twelve perf probes are pure counts (bytes, requests, headers) and have
  zero host exposure. Prefer that shape.
- **`perf-loadtime-001` is the model to copy**: it does not measure wall-clock at all. It computes
  `ttfb + weight/bandwidth + requests×rtt` against a fixed published profile (1 vCPU, 12 Mbps, 50 ms RTT), so
  it is host-independent by construction.
- **Timed probes sample.** `sample_ttfb` is median-of-3. FCP is median-of-3. CWV is **best-of-3** (`min()`)
  against Google "poor" thresholds, with a 4× CDP CPU throttle — so an app must be poor even on its best run,
  and variance can only ever help the player.
- **`perf-ttfb-001` is the outstanding exception**: a raw single `resp.elapsed`. Its own comment admits
  production should sample N. Fix it.

**Player-favourable variance is the rule.** Where measurement is uncertain, the uncertainty goes to the
player's benefit. It makes a disputed finding defensible.

## 9. Recurring bug families

**Sub-path rebasing.** The single most repeated bug in this codebase. An app served at `/app` means `/.env`
must be fetched as `/app/.env`. Helpers exist — `_at`, `_under`, `_relative_to` — and every new constructed
path must use them. A probe that resolves against the origin reports a sub-path app clean while a critical leak
sits one prefix away. supavulnbase exists partly to catch this; `:8091` is the root-served twin for exactly
this comparison.

**Reach, not detection, is usually the bottleneck.** Proven repeatedly: `api_sqli` fires instantly when handed
`/api/products/search?q=`. Before building a detector, check whether the target is even in the surface.
Discovery mechanisms that earned their place: bundle literal mining, conventional API names, search-sibling
guessing, create+read pairs, BaaS gateway registration.

**Self-as-oracle.** Register throwaway accounts; mint two identities for IDOR. Never change the session's own
credentials — password-change and reset forms are withheld, because the grader must not lock itself out.

**BaaS auth is not the app's auth.** The bolt/Supabase cohort authenticates by JWT in localStorage with a
Bearer header, not by cookie. That is why the whole auth cluster went dark once, and why `sec-session-005`
exists. Registration goes to `POST <gateway>/auth/v1/signup`.

**Anon WRITE is the RLS oracle, and it creates no rows.** `POST {}` and read the SQLSTATE: `23502`/`22xxx`
means the write passed RLS and a constraint caught it; `42501` means RLS refused; `PGRST204`/`42P01` is
inconclusive. Prefer it over read-based inference — it is the unambiguous half.

**Column sensitivity, never the table name.** A table *named* `profiles` is not evidence its rows are private.
Using the table-name half of the gate produced a 40-point false positive against a declared control on the
hardened reference, and four more in the corpus. `_sensitive_columns` (columns only) gates anon reads;
`_sensitive_leak` (name or columns) is only for the *differential* callers, where anon-denied is already
established. Known trade-off, recorded rather than hidden: a sensitive table with bland column names
(`payments(id, amount, status)`) now reads clean. Column names are the only evidence that survives contact with
a hardened app.

**Write-first ordering masks, it does not suppress.** The anon-write check runs before the anon-read check so a
public-by-design table is not reported. But ordering only changes *which* fires first; when the write half is
fixed, control still falls through to the read path. If you need suppression, gate it. Do not rely on order.

**"Retained is not sent."** httpx stores a `Secure` cookie received over http but never transmits it. Neither
"httpx drops it" nor "httpx sends it" is correct, and both have been believed here.

## 10. How not to fool yourself

The failures that cost the most time were not code bugs. They were reasoning errors about our own data.

**An untested-family rate is a claim about the RUN before it is a claim about the population.** The coverage
gate reported "has a login/signup but no session probe ran" on 36.3% of v10 and it was read as a property of
the apps. Check the invocation first.

**But do not invert that into inferring the invocation from the data.** `--browser-auth` was assumed off
because coverage looked like it was off. It was on. The record stores `browser` but not `browser_auth`, so the
flag is unknowable from the JSONL. Ask, don't deduce.

**The invocation is not recorded, and this has cost an answer three times** (`--browser-auth`, `--concurrency`,
host/Python/Playwright versions). Nothing in a result row says how the run was invoked. Stamping a provenance
block — run id, flags, hostname, CPU, Python and Playwright versions — is outstanding work and it subsumes
several separate requests.

**Do not extrapolate from incomplete data.** A partial run is a partial run. `perf-cwv-002` "corpus-wide
inflation" turned out to be sampling noise: on 847 paired apps it was kept 157 / lost 40 / gained 28, net −12.

**Reconstruct an external study's denominator before comparing to it.** Escape.tech's scan of 5,600 deployed
vibe-coded apps reports 7.1% exposed secrets. Against our raw 865 that reads as 24× under-counting. But only
9.5% of our corpus emits any managed-BaaS traffic and 40% has no endpoint at all. Conditioned on the
population that *can* leak, backend/RLS exposure is 15.9% — the same order as their ~33% serious-flaw rate.
The aggregate gap was denominator, not recall.

**A detector that finds nothing has two explanations, and they are separable offline.** Zero `service_role`
keys across 68 Supabase apps looked like a recall bug. Decoding the `role` claim of every JWT the findings
recorded gave anon 8, authenticated 2, service_role 0 — population truth. Hackathon builds ship the anon key,
which is designed to be public, and never mint a service_role into the client. Check the recorded evidence
before assuming a bug.

**Hypotheses tested and refuted. Do not re-run these:**

- *`--browser-auth` was off for v10* — it was on.
- *`--concurrency 5` starved `register_in_browser`'s 45 s budget* — five concurrent browser-auth grades against
  one target returned byte-identical results.
- *GoTrue was rate-limiting our throwaway signups* — a signup returned HTTP 200.
- *SPA stack bias depressed security findings* — security median identical (14.0) at 53% vs 67% coverage.
- *A Playwright/Chromium bump moves scores* — 1.60 → 1.61 left a grade byte-identical.
- *Form mis-attribution explained a phantom login* — `/about` really does carry an email+password modal.

**Read the applied diff.** A scripted text-range edit once deleted a block of constants and broke 12 tests; a
comment once swallowed `"dom-xss"` off a gate list. Both were caught by reading the diff, not by intent.

**Do not edit while the suite runs.** It went stale four times in one session.

## 11. Validation layers

No single target validates this thing. Five layers, each answering a different question:

1. **The reference pair** (`references/vulnerable` 649 vs `references/hardened` 0) — does it discriminate at
   all? Note what that 0 means: `hardened/app.py` is a hand-rolled server that satisfies every probe by
   construction. It proves the probes are satisfiable, not that a real app scores 0.
2. **The local vulnerable corpus** (DVWA, Juice Shop, VAmPI, bWAPP) — probe recall on known flaws. Every port
   binds to `127.0.0.1` only. **Never expose this corpus to a network.**
3. **OopsSec Store** — a real app with its own backend.
4. **supavulnbase** — the Next.js + Supabase + PostgREST + RLS stack most hackathon submissions actually use,
   with a machine-readable answer key at `{basePath}/__manifest`, declared controls that must stay silent, and
   a hardened ablation twin. The most valuable single target. Run its `verify.sh` first: if the fixture does
   not match its own answer key, a grader "miss" is the fixture's fault.
5. **GapBench** — third-party recall benchmark. Throttle, be polite, and **never build anything that defeats
   its bot challenge.** Detection evasion is out of scope for this project, permanently.
6. **The Devpost corpus** (60 curated hackathon slugs) — population coverage at scale.

**The corpus tests POPULATION, not PROBE coverage.** The authed, same-origin and stateful probes (idor,
integrity, race, upload, stored-xss) are dark on it — a thousand-app run cannot tell you whether one of them
silently regressed, because nothing fires. Probe recall is the synthetic-target job. The two are complementary
halves of "comprehensive," not substitutes. Drop known-vulnerable and known-clean anchors *into* corpus runs so
the dark probes stay observably firing.

**Run cadence.** A full corpus re-grade is 6–10 hours, so fixes are stacked into sprints — one run per batch,
not per fix. Validating a batch can use a sampled or affected-subset run; a full run is for calibration.
Re-derive the Attack Surface tertiles after every calibration run: they are a property of the corpus and the
catalogue together.

## 12. Non-negotiables

**Only fuzz targets you own or are authorized to test.** This is not advisory. The runner sends injection
payloads, traversal attempts, SSRF probes, concurrent bursts (20 requests × 3) and credential-shaped
rate-limit tests. Pointing that at somebody else's deployment without authorization is unauthorized testing.

**Never publish grading output.** A results file names real third-party apps and carries, per finding, a
paste-to-reproduce request against a live deployment. The v9/v10 corpus runs held 1,709 named Devpost projects
and 8,825 repro blocks, and they reached a public repo through `rsync` + `git add -A` before anyone noticed.
`.gitignore` in *this* directory is the source of truth for both repos, because rsync overwrites the mirror's
copy. `*.jsonl` and deliberately not `*.json` — `validation/benchmark-curve.json` is the frozen curve and must
stay tracked.

**Never commit the hidden probe pool.** `**/hidden/` and `catalog-hidden/` are gitignored as a backstop; the
real boundary is a separate private repo.

**Hand the subject a private report.** The product guardrail is upside-only: a grade that is not requested is
not published. This is a design constraint, not a policy preference, and §13 turns on it.

**Never change the target's own credentials.** Password-change and reset forms are withheld from the form
pool.

**The SSRF guard on bundle-derived origins gets NARROWED, never removed.** Follow an origin only where the
target already is: same host any port, or loopback for loopback.

## 13. The current mandate: make this a product

The runner is a CLI and a library. The work now is to make it **its own web application**, so it stands up
independently and the league becomes one consumer among several.

**The authorization problem is the whole design, not a feature.** A public "paste a URL and we will fuzz it"
service is an abuse vector and legally fraught, for the reasons in §12. Ownership verification must gate every
scan, before anything else is built:

- a DNS TXT record, or a token at a well-known path, or a meta tag, or OAuth against the hosting platform
- re-verified per scan, not once per account
- loopback and private ranges refused outright, so the service cannot be used to reach inside someone's network
- the existing SSRF guard reviewed again in this context, because a hosted service turns a same-host follow
  into a much sharper capability

Get this right first. Everything else is downstream of it, and a version without it should not exist even
internally.

**Then, roughly in order:** a queue (a grade is ~2 minutes and holds a browser, so it is not a request/response
operation), per-account quotas and rate limits, a report view that is **private by default** with explicit
opt-in to share, re-scan and history so a builder can watch the number fall, and an API for consumers like the
league.

**What must not change while doing it:** the score's meaning, the catalogue's calibration, the deduction-only
contract, and every non-negotiable in §12. If the web app wants a friendlier number, it presents the existing
one differently. It does not get a different score.

**Open decisions:**

- **The name is unresolved.** `slop-o-meter` was proposed and the space is crowded: a GitHub org of that exact
  name measuring "software slop," `slopometer.com` (an AI code scanner), `slop-o-meter.dev`, `slopometer.ai`
  (grading on "SlopScale™"), and a Chrome extension. Adjacent metric names are taken too: EQ-Bench's Slop
  Score, Larridin's AI Slop Index, SlopCodeBench, SlopGuard. A credential's value is being unambiguously
  attributable, and "which slop-o-meter?" destroys that. **Note that every one of those is static analysis of
  source, repos, PRs or text. This is the only one that grades a running deployment** — the product name
  should probably lead with that rather than joining the slop crowd. Keeping `slop score` as the internal
  metric name is fine and cheap; it is canonical in `format_spec.md` §4 and cascaded through roughly ten
  documents.
- Hosting, tenancy and whether reports are ever public by design.
- How the league consumes it: the same HTTP API as anyone else, or an in-process path.

## 14. Operational

- `uv sync --group browser` — `browser` is a dependency **group**, not an extra. `--extra browser` fails.
- `uv run playwright install chromium`. **Playwright floor is 1.61**, the release that added Ubuntu 26.04;
  1.60 cannot fetch a browser there at all. A machine with a system Chrome hides this via
  `_LAUNCH_ORDER`'s channel fallback, so a fresh clone is the real test.
- `uv run pytest -q` before every commit. Run it in the background and do not edit while it runs.
- One commit per change. Commit messages end with the `Co-Authored-By` trailer.
- **Two repos.** This directory is the source of truth; it rsyncs to a standalone public mirror. Root-level
  league docs (`format_spec.md`, `FUZZ_RUNNER_SPEC.md`) are excluded from that sync, as is all grading output.
  `FUZZ_RUNNER_SPEC.md` has significant drift between the league root and the mirror with no sync path — an
  outstanding problem, and it matters more once this is an independent project.
- No `OPENROUTER_API_KEY` is needed for `--url-only` grading; url-ingest skips the plan/deploy path entirely.
  The LLM is scoped to discovery seeding and an off-score coverage audit, and **never touches the number**.
