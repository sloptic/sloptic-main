# Sloptic web (sloptic.org) — build handoff + spec

Brief for the session that builds the public web product. Written 2026-08-01, league repo (internal). The
grader repo's `claude.md` is grader-only; this is the web product's context. Copy the appendix into the new
repo as its `claude.md`.

## Goal

`sloptic.org`: a user submits a deployed web app URL and gets its **slop score** (lower is better), the
per-axis breakdown (security / qa / performance), the report card, and its **percentile against the frozen
2026.1 population**. Same product as the CLI grade, on the web.

## Architecture: two repos

- **`sloptic/sloptic-main`** (exists) is the grader, the ruler. Consumed as the engine (pip-installable /
  importable), never forked into the web app. Grading logic changes land here and stay CI-locked.
- **`sloptic/sloptic-web`** (NEW) is the product: the sloptic.org frontend + a thin API that enqueues grade
  jobs + a worker that runs the grader. The frontend can be static-ish (Next/SvelteKit) on Vercel/Netlify/
  Cloudflare Pages; the API + worker need Python + Playwright + an LLM key.
- **Grading is async.** A grade takes minutes and needs a browser + an LLM call, so it is a queued job
  (submit → poll status → results), not request/response. The worker imports `sloptic` and calls the
  pipeline; results (slop, axis_slop, findings, coverage, platform, percentile) are stored and served.
- The web product needs `validation/benchmark-curve.json` (curve 2026.1) to compute the percentile, and
  `scripts/benchmark.py rank` (or its logic) as the ranking call.
- Start with worker-in-the-backend; split the grader into its own hardened microservice when the security
  sandbox needs its own isolated network context (below).

## THE security model (this drives everything)

The grader fires **active attack payloads** (SQLi, command injection, XSS, path traversal, XXE, upload
webshells). Pointing that at an arbitrary user-supplied URL is **unauthorized testing** (a real legal/abuse
problem) and turns the service into an SSRF/DoS relay. This is the project's standing rule, "only test
targets you own or are authorized to test," applied to a public product. Non-negotiable:

- **Passive by default.** Unverified targets get only the *observational* floor: headers, TLS, accessibility,
  performance, soft-404, CWV. That is ~all of the slop signal anyway (the injection family is ~0% of corpus
  fires), so a passive-only public grade is genuinely useful AND completely safe.
- **Active probing only after domain-ownership verification** (below), scoped to the verified origin.
- **Egress-sandboxed grader**: block loopback / RFC1918 / link-local / metadata IPs (169.254.169.254) in
  BOTH grading and verification fetches. Reuse the exact blocklist from the v2.0 Family-1 deploy-gate work
  ([[sloptic-v2-roadmap]] / `docs/V2_ROADMAP.md`).
- **Rate limits + per-user quotas** (LLM + compute cost per grade), respect robots and bot-challenges (never
  defeat them), a Terms of Service.

Miss this and sloptic.org is an abuse vector. Get it right and "passive floor for anyone, full grade for
owners" is a clean product story.

## Domain ownership verification

Prove control of the origin to be actively tested by serving a secret token we issue.

1. **File token (primary, fits any served app).** Issue `token = sloptic-verify-<random>`. User serves it at
   `https://<origin>/.well-known/sloptic-verification.txt` (body = token). We GET it and compare. Serving our
   token at the origin IS control of what is deployed there = authorization to actively probe it.
2. **DNS TXT (whole-domain).** User adds `TXT _sloptic.<domain> = sloptic-verify-<random>`; we resolve and
   compare. Proves DNS-zone control; good for authorizing many subdomains/deployments at once.
3. **Meta tag (convenience).** `<meta name="sloptic-site-verification" content="<token>">` in the homepage
   head; we fetch and parse.

Flow: issue token bound to (user, origin) with expiry → show instructions → user installs → "check" →
fetch/resolve (egress-sandboxed) → on match persist a `(user, verified_origin, method, verified_at)` grant →
unlock active probes scoped to that origin.

Four rules that keep it safe:
- **The grant is ACCOUNT-BOUND, and a verified origin is NEVER globally open.** This is the load-bearing
  control. Active grading checks whether the REQUESTING account holds a grant for the origin. Alice verifying
  `alice.com` writes a grant for Alice; Mallory submitting `alice.com` has no grant and gets PASSIVE only.
  Verification authorizes the verifying ACCOUNT, not the URL, so scraping the web for Sloptic-tokened sites
  and turning the grader loose on them does not work. Do NOT model verification as "this origin is now
  active-gradable"; model it as "this account may actively grade this origin." Consequently: active grades
  REQUIRE an authenticated account (also gives quota + ban); passive grades can be anonymous with IP limits.
  The token file is world-readable and that is fine, reading it confers nothing; an attacker would have to
  serve THEIR OWN issued token on the origin, which needs real control, and even then the grant is only theirs.
- **Scope to the verified origin** (scheme + host + port). A verified origin authorizes only URLs under
  itself; never a different origin; do not let a redirect carry authorization off the verified origin.
- **Egress-sandbox the verification fetch** too (block internal/metadata IPs).
- **Time-box + re-check.** A grant lasts e.g. 90 days and re-verifies before an active grade (or require the
  token stay in place), so a domain that changes hands cannot retain stale authorization.

### Verification tiers (defense in depth)

Active grading is the legally-loaded, low-marginal-value tier (injection is ~0% of the slop signal), so gate
it hard and keep the passive floor easy:

- **Active grade = a custom domain + TWO independent control proofs: file token AND DNS TXT.** They prove
  DIFFERENT surfaces (control of what is served vs control of the DNS zone), so an attacker who can plant a
  file (open upload / subdomain takeover) still fails the DNS factor. Two files at two paths do NOT count as
  two factors (same surface); DNS is the independent axis. Require both to be present and re-checked at grade
  time.
- **Platform subdomains (`*.vercel.app`, `*.netlify.app`, ...) get the passive floor.** They cannot edit the
  platform's DNS zone, so the DNS factor is structurally unavailable; rather than substitute a weak
  same-surface proof, give them single-factor-or-anonymous PASSIVE grading (which is ~all the value). The path
  to an active grade is "attach a custom domain." This also keeps the model simple for the 65%-Vercel corpus.
- **Depth is layered, not just two files.** Every active grade carries: (1) the two control proofs, (2) the
  account-bound grant, (3) a logged "I own this and authorize active testing" attestation (ToS-bound, so abuse
  is a traceable, bannable act, not an anonymous one), (4) egress sandbox + rate limits + re-check of both
  factors at grade time. No single failure opens the active tier.

## Grader-side change this depends on (SHIPPED in sloptic-main v1.1)

DONE 2026-08-01. `sloptic/safety.py` classifies all 91 probes **37 passive / 54 active**, and `--passive-only`
(CLI) + `safety.passive_catalog()` (programmatic) drop the active ones. The definition (two gates): PASSIVE =
changes no state AND fetches nothing hidden, it reads only what the app serves every visitor (page / assets /
bundle / headers / normal responses) and reports leaks found there ("public anyway, nobody looked"), including
a served source map and a secret sitting in the bundle. ACTIVE = mutates / sends a payload / needs multiple
identities / OR goes fetching hidden data (guessing /.env or /.git, querying the backend, pulling bulk data).
FAIL-CLOSED: an unclassified probe is treated active. CI-locked (`test_safety.py`): the two sets partition the
live catalog, the dangerous families can never be passive, and `passive_catalog` excludes every active probe. Score comparability note: a passive-only grade is a DIFFERENT measurement from a full grade
(fewer applicable probes); surface that to the user and rank passive grades against a passive curve or label
them clearly, do not mix them on the full-grade percentile.

## Open decisions for the new session / Ian

- Frontend stack + host (Next on Vercel is the obvious default; the corpus shows why it is popular).
- Queue/worker infra (a managed queue + container worker; the worker is the heavy, sandboxed piece).
- Auth model (anonymous passive grades with IP rate-limit, or require sign-in for any grade?).
- Passive-only percentile: rank against a passive-subset curve, or just show the raw passive slop + axis.
- Persistence (results store, verification grants, quotas).
- Whether to expose the platform_id / builder finding in the public report (nice differentiator).

## The new repo's claude.md

Written as a standalone file: `docs/claude-sloptic-web.md`. Copy it into `sloptic/sloptic-web` and rename it
to `claude.md`. It is kept as its own file (not inline here) so the two do not drift.
