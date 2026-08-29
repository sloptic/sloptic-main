# Sloptic v2.0 foundation and roadmap

Internal planning doc (league repo only, NOT synced to the public mirror). Captures the plan
agreed 2026-07-31 so it survives context compaction. Sequence at the bottom.

## The versioning contract (the decision rule)

Two Sloptic scores are comparable only within the same **(software major version, frozen curve)**
pair. The major/minor boundary is one question:

> Does the change alter what the number MEASURES, or just make the existing number more correct?

- Precision + honesty fixes preserve the contract -> **minor** (v1.x), curve re-freeze optional.
- New SCORED dimensions redefine the contract -> **major** (v2.0), needs a new curve, because a
  v1 app and a v2 app are penalized on different axes and the numbers stop being the same currency.
- Advisory / off-score additions and test-only anchors are version-light (don't touch the contract).

Curve axis is CalVer (`2026.N`), a frozen data artifact in `validation/benchmark-curve.json`.
v1.1 -> re-freeze `2026.2` (optional; injection FPs were few). v2.0 -> new curve `2026.3` after a
full re-grade with the new probes.

## v1.1 (ship first, do NOT fold into v2.0)

Makes the existing score correct + honest; no new scored dimensions.

**STATUS: SHIPPED to PyPI. v1.1 (injection hardening + the four honesty fixes below + platform_id + the
passive/active `--passive-only` split), v1.1.1 (pip-first README + the first pip-installable package via
hatchling + force-included catalog), and v1.2 (bot-challenge / interstitial guard) are all published; curve
stays 2026.1. sloptic.org is live. The TODO markers below are the historical record of what got done.**

- **Injection hardening (DONE, committed both repos, suite green 870):** cmdi/ssti/lfi/xxe/upload
  moved from LLM-fakeable arithmetic markers to salted `sha256` hash oracles + dose-response +
  liveness gates. See [[probe-technique-coverage]] memory "HASH-ORACLE STANDARD".
- **cmdi v15 FP fix = already delivered.** The two v15 FPs (brightbet marker-echo, tanishadharmik
  time-based) are killed by the hash + dose-response + `_endpoint_is_live` gate. v16 confirms.
- **parity.py honesty fix (TODO):** it prints `BLIND SPOTS (none ...)` when a stack has no expected
  labels -> a silent clean report on an unchecked condition (the exact failure class we've been
  killing). Make it print "cannot assess, no ground-truth labels for this stack." ALSO: the stack
  table has collapsed to one row, so cross-stack parity is not being measured; the SPA-vs-server-forms
  comparison that confirmed uniform false negatives is gone. Find whether that analysis fell out when
  url-ingest changed and restore it.
- **CORPUS_REPORT 4.4 denominator fix (TODO):** the report divides backend-tier counts by 1537, but
  the tiers come from 1066 apps with observed runtime traffic and sum to 1485 (apps are multi-tier).
  "only 11% have an own injectable backend" is 175 over the wrong denominator. Correct to 175/1066 =
  16.4% and STATE that tiers overlap (they are not shares of a whole). 4.4 is the strongest section
  and the table as printed dies when someone sums the column.
- **RELEASE_NOTES softening (TODO):** guarantees are currently "stability and precision." precision.py
  reports 9164/10513 findings unaudited (72% of damped in-score penalty), 599 vouched. Reword to
  "stability guaranteed; precision vouched on the classes with rules, unaudited elsewhere," and add
  that the unaudited mass is dominated by deterministic presence checks where FP risk is structurally
  low, the audit cannot distinguish "no rule needed" from "no rule written" but we can.
- Then run **v16** re-grade -> confirm cmdi FPs gone + no regression -> re-freeze `2026.2` (or keep
  `2026.1`) -> tag **v1.1**.

## The rank-variance measurement (already done; tool persisted)

`scripts/rank_variance.py` (run: `uv run --with numpy python scripts/rank_variance.py <jsonl> --corr`).
Leave-one-out re-ranking off recorded penalties. Findings on multihacksfinalv15 (1530 scored apps):

- **Carriers of the ordering** (footrule = avg |rank shift| when removed): qa-a11y-001 (158),
  sec-ratelimit-001 (129), perf-cwv-002 (125), qa-a11y-002 (120) dominate; then qa-http-001 (59),
  perf-compress-001 (53), perf-cwv-001 (52), sec-exposure-006 (50), qa-crash-010 (50),
  qa-deadctrl-001 (48), perf-weight-001 (31). ~11-14 probes carry the ranking; the rest is gate or tax.
- **Prevalence must be DECOMPOSED into applicability x conditional-fire.** sec-ratelimit-001 is
  40.9% applicable x 99.7% fires-when-applicable, NOT a 41% fire probe. The script prints both columns.
- **"98% = constant tax" confirmed:** sec-headers-002 = 98% prev, mean penalty 7.83 (largest of any
  probe) but std 1.16, footrule 4.76. Taxes everyone, separates no one. Same for sec-headers-001/004/005.
- **Carriers are healthily decorrelated** (mean pairwise |r| 0.03-0.17). Only real redundancy: perf
  cluster cwv-002/weight-001/cwv-001 (r 0.37-0.50) ~= 1.5 effective axes. qa-a11y-001 vs qa-a11y-002
  correlate only 0.29 -> a11y is genuinely two independent axes.
- **ADMISSION TEST for any new probe** (run it on the corpus first, THEN judge): mid applicability
  AND high per-app std AND low |r| with the existing carriers. Prevalence alone is necessary, not
  sufficient. A 35%-prevalence probe that co-fires with an existing carrier adds a constant to that
  axis, not new ordering. footrule is first-order (damping applied after scoring), trust it as a
  ranking of carriers, not exact displacement.

## v2.0 FOUNDATION: the LLM-echo authoring invariant (first commits)

Some injection targets have a model in the response path; a model has no constrained response space,
so there is NO evidence signature it cannot produce (cmdi canaries echoed, {{7*7}} computed, SQL
errors described in prose, root:x:0:0 hallucinated). This breaks causal specificity as an authoring
invariant. Adopt this template for EVERY content-oracle probe, land it before the new families so they
inherit it:

1. **Determinism gate (precondition, LLM-agnostic):** send each request twice; if two identical
   requests differ substantively, the endpoint is nondeterministic and NO content oracle is valid on
   it -> can't-assess, not a fire. IMPLEMENTATION NUANCE: "substantively differ" must tolerate benign
   nondeterminism (CSRF tokens, timestamps, request-ids, nonces) -> diff the injection-relevant region
   or normalize known-volatile tokens, else deterministic-but-nonced endpoints get wrongly gated out.
2. **Paired canary:** send the payload with injection syntax, then the canary as a bare literal with
   no injection syntax. Both return = reflection. Only-with-syntax = execution.
3. **Computational asymmetry = the HASH we already shipped.** Do NOT revert to `echo $((...))`: the
   hash strictly dominates large arithmetic (a model cannot hash a fresh salt; it CAN sometimes land a
   big product). base64-decode-of-random-bytes is the same spirit (fine as an alternate).
4. **SSTI engine fingerprint (add):** `{{7*'7'}}` -> 7777777 in Jinja2, 49 in Twig. Evidence of a
   specific ENGINE, not just arithmetic. Pairs with the hash: hash proves execution, 7*'7' identifies
   the engine.
5. **OOB: parked** (egress-blocked sandboxes + static sites can't reach a collector; only covers the
   own-backend tier). Matches the cmdi decision (OOB off, SSRF-misattribution risk).

## v2.0 FAMILY 1: "works on my machine" deploy-time gates (highest ROI)

Gates, not middle-band; judge on "catches a real, currently-invisible, DECORRELATED failure," not
fire-rate. These fire on the deployed-but-dead population, orthogonal to the a11y/perf/headers carriers,
so they add genuinely new ordering. This is the sharpest expression of Sloptic's "meeting the moment"
thesis (vibe-coded, deploy-and-never-test-in-prod).

- **localhost / private-IP backend reference** (STRONGEST; already collected off-score -> promote):
  bundle refs or observed runtime requests to localhost / 127.0.0.1 / 0.0.0.0 / RFC1918. `localhost:8000`
  appears 12x in top opaque hosts. Front page renders, app is dead for every visitor.
- **`https://undefined/api/...`**: unset `NEXT_PUBLIC_`/`VITE_` at build time. Cheap substring match.
- **Plain HTTP, no TLS**: HSTS (sec-headers-003) and mixed-content (sec-mixed-001) both miss a no-TLS
  origin. CAVEAT: gate to deployed public origins so a legitimate localhost/preview isn't punished.
- **OAuth redirect_uri at localhost/preview**: initiate the flow, do not complete it, read the param
  off the authorization URL; if it points where the deployed app is not, sign-in is dead in prod. Zero
  payload. CAVEAT: judge redirect_uri host vs the app's own origin.
- **Redirect loops**: follow with a cap; exceeding it = unusable, plausibly explains some 720s timeouts.
- **Linked route 5xx**: extend qa-links-001 (currently 4xx dead ends, 36 fires) to treat 5xx as
  in-scope; a 500 on a linked route outranks a bad href (documented cause: missing runtime env var).

## v2.0 FAMILY 2: WCAG-backed a11y (well-grounded; add the DECORRELATED subset only)

WCAG criteria VERIFIED (2026-07-31): 2.1.1 Keyboard (A), 1.4.4 Resize Text (AA), 1.4.10 Reflow (AA,
2.1), 2.5.8 Target Size Min (AA, 2.2), 2.4.11 Focus Not Obscured Min (AA, 2.2), 2.5.7 Dragging (AA, 2.2).
Legal framing VERIFIED: Section 508 = WCAG 2.0 AA (federal); DOJ ADA Title II 2024 rule = WCAG 2.1 AA
(state/local GOV only). So 2.5.8/2.4.11 (2.2) are in no US standard. Nuance: 1.4.10/1.4.12 are 2.1 so
they ARE bound by Title II for public entities, moot for Sloptic (grades private apps). CITE AS WCAG
STANDARD, NOT LAW (several widely cited sources get this wrong).

Candidate checks: keyboard operability (div+click, no tabindex/role) [Level A -> price at 30, same tier
as alt/labels], reflow@400% + resize-text@200% (Playwright narrow viewport), target size 24x24 CSS px
(respect exceptions: inline, UA-controlled, essential, equivalent elsewhere, or 24px spacing; padding
counts), focus-not-obscured (sticky header over focused element), dragging alternative, ARIA validity
(aria-labelledby -> nonexistent id, invalid role, required attr missing for role, aria-hidden on a
focusable el -- WebAIM 2026: ARIA +28%/yr, ~133 attrs/page, ARIA pages had MORE errors), heading
structure (>1 h1 = 18.1% of pages; skipped levels = 94.9% of pages with h6).

CAUTIONS (from the measurement):
- a11y is ALREADY the #1 and #4 carrier. Two risks: (a) COMPOSITION -- more a11y probes raise a11y's
  share of total penalty mass (composition audit already ~31%), a fairness question separate from
  ordering; (b) axe-core OVERLAP -- qa-a11y-001 IS axe-core (already flags button-name, some ARIA,
  some contrast).
- So: run each check, measure footrule + |r| vs qa-a11y-001/002, KEEP THE DECORRELATED ONES (heading
  structure, broken aria refs, invalid role, target size, focus-obscured, reflow are mostly not in axe
  defaults; keyboard/ARIA partially are), and VARIANT-GROUP them under qa-a11y so a11y fires as one
  bounded axis, not 10 stacking penalties.
- Sequence: static/cheap first (multiple-h1, skipped-heading, missing aria target, invalid role,
  div-click-no-role); Playwright-measured second (reflow@400%, target size, focus-obscured, dragging).

## v2.0 FAMILY 3: tool-consensus (advisory until fired; off-score, version-light)

Check FIRST: qa-console-001 fired only 39x -> likely filtering to uncaught exceptions and DROPPING CSP
violations + React warnings + hydration errors. Two probes below depend on widening it.
- img without explicit width/height (direct CLS mechanism).
- font-display unset (invisible text during webfont load, FOIT).
- CSP present but blocking own resources (CSP header + CSP violations in console) -- needs the console fix.
- Hydration mismatch (Next-specific console error) -- needs the console fix.
- Dead declarations, widen qa-chunk-001 (11 fires): PWA manifest icons that 404, apple-touch-icon
  unresolved, .well-known referenced but missing.
- Loading state that never resolves (spinner still present after 30s) -- intent-independent, the visible
  symptom of Family 1.

## v2.0 FAMILY 4: modern web-quality standards (published-standard footing, like WCAG)

Cite the standard, not our judgment (OWASP Secure Headers Project; Lighthouse's own audit taxonomy). Non-AI,
intent-independent, chosen for DECORRELATION from the existing carriers. All SCORED -> each must clear
`rank_variance.py` (footrule up, |r| down) before it stays; the perf ones especially, since the
cwv/weight/compress cluster is already ~1.5 effective axes, so they must prove they are not re-measuring
"heavy page."

Security (OWASP Secure Headers):
- **Subresource Integrity (SRI)** -- STANDOUT. A third-party `<script src>` / `<link>` without an
  `integrity=` hash is an unguarded supply-chain risk. Intent-independent, anchorable (script with/without
  the hash), CONDITIONALLY prevalent (applies only to apps loading third-party resources) -> the middle-band,
  decorrelated shape we want. Strongest single new security probe.
- **Permissions-Policy** missing/over-permissive -- anchorable but likely near-universally absent -> a
  low-variance TAX; price it small (like the header family), do not expect discrimination. Same for
  **COOP/COEP/CORP** (cross-origin isolation): correct + standardized but so rarely set they are a constant.

Performance (Lighthouse audit taxonomy):
- **Next-gen image formats** (`uses-webp-images`): JPEG/PNG served where WebP/AVIF would cut bytes. Common,
  and decorrelated from the existing perf carriers because it is FORMAT, not size or timing.
- **Render-blocking resources** (`render-blocking-resources`): synchronous CSS/JS in `<head>` blocking first
  paint. Mostly static-analyzable from the served HTML.
- **Unminified CSS/JS** (`unminified-css` / `unminified-javascript`): whitespace/newline-ratio heuristic; a
  distinct hygiene signal from the dev-build probe.

DEPRIORITIZED for this population: a full TLS/transport-quality axis (SSL-Labs style) is intent-independent
and a genuinely new axis, but at 65% Vercel/Netlify/Cloudflare the TLS is platform-default and uniform ->
~zero variance here. `security.txt` / robots.txt validity = low-prevalence gates, not differentiators.

## Never-applied probes (audit + anchor; version-light)

- qa-race-001/002 never applied across 1537 apps -- CORRECT behavior, not a gap: the stack allocates
  ids atomically/collision-free (Postgres IDENTITY, Supabase gen_random_uuid, Prisma cuid, Firebase
  push, Mongo ObjectID). Audit the gate (`--audit qa-race-001`) to confirm it demands only a discovered
  create endpoint + session (not something narrower). If honest, this is a FINDING about the stack for
  the writeup.
- IDOR family never applied: needs two accounts + two sessions (hardest for a black-box grader). Both
  families need one honest fire on supavulnbase (already seeds multiple users with overlapping records)
  -- add a deliberate NON-ATOMIC allocation endpoint there so the race probes stop being an assumption.

## Sequence

0. **v1.1 / 1.1.1 / 1.2 -- DONE, shipped to PyPI, curve 2026.1. sloptic.org live. v2.0 opens now.**
1. v2.0 foundation: LLM-echo authoring template (determinism gate + keep hash + paired canary +
   7*'7' engine tag). Contract-preserving (could even be a v1.3).
2. Family 1 deploy gates (highest ROI, decorrelated).
3. Family 4 security: **SRI** (+ Permissions-Policy priced as a tax).
4. Family 4 perf: **next-gen images + render-blocking** (+ unminified) -- validate each against the perf
   cluster before keeping.
5. Family 2 decorrelated static a11y (variant-grouped), then browser a11y.
6. Family 3 advisory + the console-capture check.
7. race/IDOR anchors on supavulnbase.
8. Full re-grade -> new curve **2026.3** -> **tag v2.0**.

Every new SCORED probe must pass the admission test (`scripts/rank_variance.py`) on the corpus before
it stays in the score, and must be CI-locked with a vulnerable/hardened anchor pair (the wedge test).

## Coverage backlog (post scoring-v2)

New probe families to add after the authority-anchored severity migration (docs/SCORING_V2_SPEC.md):

1. **PostgREST filter injection** (CWE-943): validated against the supavulnbase fixture (inj-001 / ctl-012 /
   hardened-8092). Predicate + three-shot count oracle + fingerprint gate + tp_definition. Self-contained, ready.
2. **Email-verification driver** (a 6th register lane) + 2 probes: (a) app promises verification but no email
   within X seconds; (b) the verification link establishes no session. Infra-gated: needs a throwaway domain +
   inbound-parse receiver (NOT sloptic.org). Respect captcha / SSO (do not defeat them).
3. **Rate-limit coverage expansion** (CWE-770 / CWE-799): today sec-ratelimit-001 tests only the LOGIN surface.
   The broader class is abuse-resistance across many surfaces -- signup/contact spam, OTP/email flooding,
   scraping, enumeration, and the headline case for an AI corpus: **cost amplification** (an unthrottled endpoint
   that calls a paid LLM API = a direct financial DoS). A probe that finds an expensive/send-email/LLM-proxy
   endpoint and confirms no throttle. Higher potential severity than the login case (VRT-override candidate).
