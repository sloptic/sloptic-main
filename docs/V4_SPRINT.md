# Sloptic v4.0 sprint

Internal planning doc. Successor to `V3_SPRINT.md`, whose versioning contract and sequencing rule still hold.
Written 2026-09-24, as 3.0.0 goes out.

## Target

**Ship 4.0.0 in early December 2026. Fallback: early January 2027.** One ruler move: full `2026.4 -> 2026.5`,
passive `passive-2026.2 -> passive-2026.3`.

Why December, briefly:

- **Between seasons.** The fall hackathon season ends mid November and spring starts in January. Never move the
  ruler while an event is being graded, or one event's leaderboard ends up on two rulers.
- **A fresher corpus.** A November discovery run can fold in fall 2026 events, so the curve stays current.
- **3.0 has to live first.** Launch surfaces live product bugs, and real usage should shape what 4.0 is.

## Two tracks

The rule that sorts every idea: **if it changes which probes fire, a penalty, eligibility, or the passive
battery, it moves the ruler and waits for 4.0.** Everything else ships whenever it is ready.

- **Fast track (3.x, ruler unchanged):** card copy and evidence, stats and tooling, grader throughput and
  telemetry, off score diagnostics, sloptic-web features. Ship weekly if you like.
- **Slow track (4.0 queue):** new scored probes, repricing, fixes that change fires, battery changes. Batched,
  because N ruler moves cost N measurement cycles and a moving ruler erodes the credential.

When an idea shows up, it goes on this page immediately. Captured, not shipped.

## Measurement runs with the grader down (decided)

From 3.0 the Dell also serves sloptic.org, and v4's roughly 7.6 days of box time (two full runs plus a
passive run, per the v3 capacity table) needs the whole box. **Decided 2026-09-24: the grader goes down for
corpus runs, intentionally**, exactly as in v3. That keeps every run at concurrency 4 on the same box, so the
curves stay comparable with history and perf_norm's bi_ref stays valid. It is also one more reason the runs
belong in a quiet window between seasons, not mid event.

## Timeline

| when | what |
|---|---|
| Sep 26-27 | 3.0.0 live, sloptic.org on the new pin |
| October | live usage, fast track releases, queue grows. **Scope freeze Oct 31** |
| early Nov | fall 2026 slugs added to the corpus; all new detection lands; discovery run |
| mid Nov | audit the discovery fires, fix what they surface |
| late Nov | final full run, then the passive run |
| early Dec | freeze `2026.5` + `passive-2026.3`, publish 4.0.0 |

## Fast track backlog (ship anytime as 3.x)

1. **Explain the perf score on the card.** Pull the top savings from the Lighthouse report we already fetch.
   Lighthouse 13 removed the old opportunity audits, so use the ids verified present in our pinned 13.4.1:
   `lcp-breakdown-insight` (splits a slow LCP into server, load delay, render delay: the best single
   explainer), `unused-javascript`, `render-blocking-insight`, `legacy-javascript-insight`,
   `image-delivery-insight`, `third-parties-insight`, `bootup-time`. The old ids
   (`render-blocking-resources`, `legacy-javascript`, `uses-responsive-images`, `third-party-summary`) no longer
   exist and would silently read nothing.
2. **Timeout tail telemetry.** Record `timings.discover_s / lighthouse_s / probes_s` plus per probe wall
   seconds (deltas between the child's per probe start messages, `deploy_and_grade.py` `_progress_sink`). Off
   score. If the v26 run log was captured, mine its discovery and Lighthouse lines first; that answers the
   question with zero code. See the v25 timeout tail memory: 115 timeouts, 6.2% of deployed, shaped as scale
   times latency.
3. **Relabel the Vercel surge challenge on the card.** An `x-vercel-mitigated` challenge mid grade is
   Vercel's bot protection throttling the grader, not the app blocking users. Card label only; changing
   eligibility would move it to the slow track.
4. **Svelte fingerprint** (`/_app/immutable/`, `__sveltekit_`) for the report label. Off score.
5. **sloptic-web handoff:** hide the evidence of exposure and backend findings until ownership is verified.
   That is the website's job; this repo only needs to keep the evidence fields separable.

## Slow track queue (4.0)

### New detection (must land before the discovery run)

1. **DB connection string in the client bundle.** `postgres(ql)?://user:PASS@host`, `mysql://`,
   `mongodb+srv://`, `redis://`, requiring `:password@`. Verified gap: `secretscan._PROVIDER` has no connection
   URI pattern. Wedge clean, deterministic, catastrophic. A live Neon footgun (the serverless driver runs over
   HTTP, so teams ship `DATABASE_URL` under `VITE_` or `NEXT_PUBLIC_`). Strongest candidate.
2. **PostgREST generalization of `sec-backend-001`.** Today it gates on the `.supabase.co` host regex
   (`probes.py:3184`, `_SUPABASE_URL`). Key on the `/rest/v1/` PostgREST signature instead and one probe covers
   Neon's Data API, self hosted PostgREST, and Supabase. This is "Neon support" for the data plane.
3. **Lighthouse Best Practices, a scored slice.** `geolocation-on-start`, `notification-on-start`,
   `paste-preventing-inputs` (now all editable inputs, not just passwords), `deprecations`. All four verified
   present in 13.4.1. Adding the category is one CLI flag but lengthens the most expensive step per app, so
   measure runtime on a sample first. All are passive, so the passive battery grows.

### Score moving fixes (can land before the final run)

4. **One root cause, two charges.** `qa-email-001` (72) and `qa-reset-001` (60) both fire when an app has no
   real mail provider (loomai paid both in v26). Decide whether one dominates or they share a variant group.
   Both remain true positives per the 2026-09-24 decision; this is only about double counting.
5. **Streamlit render flip.** Streamlit apps move in and out of the curve between runs depending on whether
   the render lands (v26: lifelens 0 -> 122, zamexo 111 -> 0). Make inclusion deterministic.
6. **Timeout tail recovery**, once the telemetry says which half dominates: per target caps on the fan out
   probes, cheaper browser probes (reuse the two account IDOR registration, budget the stale UI render), or a
   higher grade timeout. Changes curve membership, so it waits.
7. **Wrong owner leftovers.** `figma.fun` (1 app, unclassified). Proactively `apps.apple.com` and `npmjs.com`,
   the same classes as the v26 additions.

### Stretch (carried from v3: in if running ahead, out without argument if not)

- **Unmetered inference.** Never passive: it spends the target's money.
- **Browser driven create-and-read-back.** The keystone capability against the access control gap. The most
  likely thing to eat the sprint.
- **WCAG reflow.**
- **Lighthouse median of 5** to cut the flicker at the 90 line (~15% of perf verdicts flip run to run). Costs
  Lighthouse runtime, so weigh it against the timeout tail.

## Decided, do not reopen

- **No Vercel pacing** (2026-09-22). Their WAF is good; the soft late challenge is accepted.
- **`sec-exposure-001/002/003` and `sec-backend-001` stay active** (2026-09-24). Detecting a served `.env`
  requires fetching a path nothing links to, which is recon against apps the requester may not own: trivial to
  find, catastrophic to leave, so it stays behind attestation. `sec-backend-001` also writes (an anonymous
  INSERT), so it could never be passive as shipped.
- **Supabase default mailer fires are true positives** (2026-09-24). Users care that the email never came,
  not why. Configuring a real provider is the team's job.
- **Lighthouse imports we pass:** the accessibility category (same axe engine as `qa-a11y-001`); the Best
  Practices audits we already score (`csp-xss`, `has-hsts`, `clickjacking-mitigation`, `origin-isolation`,
  `is-on-https`, `errors-in-console`); `trusted-types-xss` (almost nobody ships it, so it would be a flat
  tax); `third-party-cookies` (usually embeds, a wrong owner problem); `bf-cache` (fails the wedge, banking
  apps legitimately send `no-store`); the SEO category; CrUX field data; a desktop preset; INP. **Never
  `valid-source-maps`**: it rewards shipping source maps, which `sec-exposure-006` penalizes.

## Sequencing (inherited from v3)

**New detection lands before the discovery run. Pure fixes only need to land before the final run.** Plus
the new rule for a live product: no ruler move while an event is being graded.
