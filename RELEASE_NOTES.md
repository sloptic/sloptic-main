# Sloptic v2.2.0

Sloptic grades any deployed web app, whatever its stack or purpose, and returns one
**slop score** you can compare across apps (lower is better, `0` means nothing found),
along with where that app ranks against a frozen population of others. It reads no source
and needs no spec, so the same grade applies to every submission no matter what each one
was built with.

Versions 1.1 and 1.2 kept the 2026.1 curve, so grades stayed comparable and the changes were
precision and diagnostics. Version 2.0 is different: it is a **new ruler**. New probe families and
continuous scoring changed what the number measures, and the reference curve moved to **2026.3**, so
a 2.0 score does not compare to a 1.x one. A 2.0 percentile is quoted against 2026.3. Version 2.1 keeps that 2026.3 ruler, so a 2.1 grade compares directly to a 2.0 one, and it adds the egress sandbox the hosted service needs to accept public URL submissions safely. Version 2.2 keeps it as well, and spends its changes on the crawl, on a second frozen curve for the passive battery, and on the client the hosted service needs to verify an event.

## What's new in 2.2.0

- **A rendering deadline the interpreter cannot ignore.** A crawl that pinned the GIL sailed straight past
  its own watchdog, because a `threading.Timer` cannot fire while the main thread holds the lock, and the
  grade stayed wedged until the batch runner killed the whole app at 900 seconds. The full corpus run lost
  114 apps that way. Route rendering now runs in a forked child that streams each route back the instant it
  finishes, and the parent holds a 150 second budget it enforces with an OS signal the child has no way to
  swallow. A wedged crawl now grades what the crawler already found. On the app that surfaced this, a 900
  second DNF became an 87.5 second grade.
- **A second frozen curve, for the passive battery.** `passive-2026.1` is frozen from the 44 probe passive
  subset alone, the slice a visitor's browser sees with no active testing, over its own 1,750 app run. The
  hosted tier that grades a stranger's URL runs that battery, so it now has a ruler built from the same
  battery instead of borrowing percentiles from the full one. The two never mix: a percentile always cites
  the curve it was measured against, and `benchmark.py` refuses a record whose battery does not match the
  curve it is asked to rank on.
- **The corpus figures as data.** `scripts/stats.py --corpus-json` writes the whole aggregate picture of a
  corpus run to one committed, versioned JSON, `validation/corpus-figures-active.json` and
  `-passive.json`, so a site or a report reads figures instead of transcribing them. Aggregate only by
  construction: no app names, no URLs, no row that identifies one team.
- **A Devpost client in the package.** `sloptic.devpost` promotes the scraper's Devpost logic out of
  `scripts/` and into the package, so event verification consumes it rather than reimplementing it. Every
  fetch is tri-state, `ok` / `not_found` / `blocked`, because Devpost's WAF answers a rate limited client
  with 202, 403, 405, 429 or 503 and sometimes an empty body, and a client that folds those into the same
  value a 404 returns will eventually read a block as proof that something is absent. Only 404 and 410 mean
  absence. The event host is pinned as exactly `<slug>.devpost.com` and rechecked after redirects, and link
  extraction returns hrefs rather than answering "does this page contain X", so a token quoted in a
  discussion thread can never pass for one the organizer published.
- **`rank()` no longer truncates the score it is ranking.** It cast a fractional slop score to an integer
  before searching the distribution, which put an app in the wrong place against a curve that has been
  continuous since 2.0.
- **No curve movement.** The full ruler is still 2026.3, so a 2.2 grade compares directly to a 2.0 or 2.1
  one.

## What's new in 2.1.0

- **An egress sandbox, so the hosted service can take public URLs.** Grading a URL a stranger submitted
  means fetching a destination you did not choose, which without a guard can walk a fetch toward
  loopback, a private network, or the cloud metadata endpoint and turn the grader into an SSRF relay.
  2.1 adds one resolver level chokepoint, a guard on `socket.getaddrinfo` that refuses any host
  resolving to a non-public address, covering every httpx client, raw socket, and redirect hop at once,
  plus a browser tier filter that aborts a private subresource in the Chromium lane. It validates every
  resolved address all or nothing and hands that same address back to the dialer, so the address checked
  is the address connected and there is no DNS rebinding window. Modes are set by `SLOPTIC_EGRESS` (`on`
  strict by default, `local` to allow loopback for the reference app lane, `off` to bypass), and
  `origin_scope()` pins a public grade to one origin so a redirect off site fails closed.
- **The guard is opt in.** It installs from the grade entrypoints, `pipeline.run()` and the CLI, so
  importing the package for a probe or a utility leaves the standard library untouched.
- **No curve movement.** For public targets the scores are byte identical, so 2.1 stays on curve 2026.3
  and nothing in the distribution moves.

## What's new in 2.0.0

- **Managed backend exposure, reached and confirmed.** A new browser and API lane checks whether an
  app's managed backend (Supabase or Firebase) is readable or writable by an anonymous client, and
  proves it by reading a real row or completing a real insert instead of guessing. On the 2026.3
  corpus this is the single largest exploitable class, 18 apps leaking a table to anyone, several with
  plaintext passwords. The prior ruler could not reach it; this one does.
- **Continuous scoring, so the number spreads.** Performance and color contrast now score on a
  continuous scale instead of pass, half, and fail tiers. An app at a Lighthouse score of 85 carries
  the small penalty it earns instead of rounding to zero, and contrast severity scales with how far
  below the threshold it sits. The distribution spreads toward near unique scores, which is what a
  ranking wants.
- **Weakest link tiebreak.** At an equal score, the app whose single worst finding is smaller now
  ranks ahead, inserted between the catastrophe gate and the defended surface breadth. One severe
  trapdoor, a broken deploy, a locked out signup, or silent data loss, is worse than the same slop
  spread over moderate findings, and the ranking now says so.
- **The reach frontier.** New probes drive the app off its happy path, establishing a session,
  creating data and reading it back, and driving a second account, so the stored XSS, integrity, cross
  site request, and access control checks can reach a surface a passive fetch never sees. On a corpus
  that is two thirds static frontends this surface is often absent, but where it exists the probes now
  fire.
- **Perf and accessibility on the seasoned engines.** Performance is measured by a pinned Lighthouse
  (13.4.1), accessibility by a pinned axe-core (4.10.2), each consumed at its source instead of
  rebuilt, so the two axes sit at the frontier of what those fields can measure and move only when the
  pinned engine does.

## What's new in 1.2.0

- **Bot-challenge / interstitial guard.** A CDN or WAF sometimes serves a challenge page ("Just a
  moment...", a Cloudflare `cf-mitigated` response), and a sleeping app can serve a wake-up page,
  in place of the real app. Grading that is doubly wrong: its HTML draws false findings, and it
  hides the real surface so every later probe reports a false clean. Sloptic now detects these
  interstitials (`net.is_bot_challenge`): if the target answers with one, the grade is **withheld**
  and flagged `bot_challenge` instead of scored, and a mitigation that trips *mid-grade* (from the
  grader's own active traffic) is caught by an end-of-run re-check. Flagged records are excluded
  from corpus statistics. Conservative by design: a genuine 403 or error page is not treated as a
  challenge, so a real grade is never withheld.

## What's new in 1.1.0

- **Injection oracles hardened against LLM echo.** The command-injection, SSTI, path-traversal, XXE,
  and file-upload detectors moved from an arithmetic marker to a salted-hash oracle: a real shell or
  template hashes a random salt exactly, but a language model in the response path cannot, so an AI
  endpoint that echoes or fabricates a value can no longer trigger a false positive. Validated on the
  full corpus, the two standing command-injection false positives are gone with no regressions.
- **Platform identifier (off-score diagnostic).** Each app is classified by hosting platform (Vercel,
  Netlify, Railway, Render, Lovable, ...) from response headers and origin suffix, and by AI builder
  (Lovable, Bolt) from served markup. It surfaces a new corpus finding: Lovable-built apps carry a
  statistically significant slop premium, and it is entirely performance.
- **Honesty fixes.** The parity dashboard now reports "cannot assess" when a run lacks the ground-truth
  labels to measure, instead of a silent clean result; the corpus report's backend-tier denominator is
  corrected with the tier overlap made explicit; and the guarantee is stated precisely as stability plus
  precision vouched on the classes with explicit rules, unaudited elsewhere.

- **`--passive-only` grading tier.** Every probe is classified passive or active in `sloptic/safety.py` (37
  passive, 54 active). A passive probe changes no state and fetches nothing hidden: it reads only what the app
  serves to every visitor and reports leaks found there. An active probe mutates, sends a payload, needs
  multiple identities, or goes fetching hidden data. `--passive-only` runs the passive subset, so a target can
  be graded on its universal floor without being actively tested. Fail-closed (an unclassified probe is treated
  active) and CI-locked. A passive grade is a subset and does not compare to a full grade.

## Highlights

- **Comparable by design.** A raw score becomes a percentile against a frozen reference
  distribution, so a grade reads as "cleaner than 70 percent of the
  population," on top of the bare "42 slop." That comparison is what separates Sloptic from a scanner.
- **Exact, tie-aware ranking.** The percentile is read off the full frozen distribution,
  not interpolated between a handful of landmarks. Two apps at the same score are not
  treated as equal: ties break on whether a catastrophe fired, then on the size of the single
  worst finding, then on how much worst case slop the app defended (the score it would carry
  had every applicable probe fired), then on the breadth of surface it exercised.
- **Catastrophe gate.** An exploitable-now class (SQL injection, a served secret file, a
  world readable managed backend) is reported as an absolute gate whatever the rank says. A
  favorable comparison to equally-broken peers never launders it.
- **102 probes across three axes.** Security (60), quality and correctness (29), and
  performance (13). Each axis reports its own damped subtotal, and the three sum exactly
  to the slop score.
- **Deduction-only and risk-priced.** No positive credit, no 0-to-100 ceiling. Each
  penalty is frequency times severity. A probe's detection variants collapse to one
  finding, and repeated instances of one category have diminishing marginal penalty, so a
  single root cause counts once.
- **Intent-independent.** Sloptic only fires on failures that are defects regardless of
  what the app is for: a world readable managed backend, a login with no rate limiting, text too
  faint to read, a button that does nothing, a crash on malformed input, a dev build shipped to
  production. It never judges whether a feature is good.
- **Coverage honesty.** Every grade ships a coverage report, so a `0` that means "clean"
  is distinguishable from a `0` that means "we could not reach the surface."
- **Stack-blind deployment.** The same catalog runs against a local subprocess, a
  sandboxed Docker submission, or a live URL. Everything downstream of "the app answers
  `$PORT`" is identical.

## Reproducibility and calibration

The score is stable because it is deterministic by construction, which is the property a ranking
depends on. No model sits in the number: the perception and coverage LLM only proposes targets, and a
deterministic probe alone decides every fire, at temperature 0 with a cached plan. The two seasoned
engines are pinned (axe-core 4.10.2, Lighthouse 13.4.1). Repeat runs of the 1.x engine over the full
corpus correlated at **0.97 or higher**, with deciles better than 92 percent identical and no
systematic drift; 2.0 adds probes while keeping determinism, so the movement that remains is confined to the
places where black box nondeterminism is unavoidable, stateful browser behavior, Core Web Vitals
timing, and the security tail behind authentication.

Correctness is anchored two ways: a fixed set of reference apps with a known answer key (the
vulnerable app must accrue slop, the hardened app must score `0`), and a recall benchmark of scenarios
tagged with a CWE. `uv run pytest -q` runs the calibration suite.

## Frozen reference curve: 2026.3

This release ships reference curve **2026.3** (provisional), frozen from a corpus run of 1,625
live web apps. It stores the full score distribution as anonymous per app rows (score, whether a
catastrophe fired, the single worst finding, worst case slop defended, surface breadth) with no per
app identity, so a percentile is exact with no interpolation, and ties resolve the same way every
time. A percentile is always quoted against a named curve version, so the claim is
checkable and does not drift as the population changes.

## Scope, honestly

Sloptic is strongest on the unauthenticated, observable surface and on apps rendered on the client
with backends on the same origin. It is weaker where a defect hides behind authentication it cannot
establish from the outside, or where judging the finding needs product intent. Those limits are
reported openly.

The recall audit (measuring the false negative rate against ground truth benchmarks
across the full catalog) is in progress and continues in a follow-up release. This
release guarantees stability (the ruler repeats) and precision on the classes that
carry explicit precision rules; findings elsewhere are unaudited.
That unaudited mass is dominated by deterministic presence checks where false positive
risk is structurally low, but since the audit cannot distinguish "no rule needed" from
"no rule written," we report it as unaudited instead of claiming a precision we have not
checked. The recall number is not yet claimed.

## Install

```sh
uv sync                      # core
uv sync --group browser      # adds Playwright, for accessibility, CWV, and DOM XSS probes
uv run playwright install chromium
```

## Usage

```sh
# grade a live URL (only test targets you own or are authorized to test)
uv run python -m sloptic.cli --target https://your-app.example.com

# grade a submission (a zip containing a Dockerfile), built and run in a sandbox
uv run python -m sloptic.cli --submission team.zip

# grade one app and place it on the frozen curve (percentile, per-axis rank, gates)
uv run python -m sloptic.cli --target https://your-app.example.com --out app.jsonl
uv run python scripts/benchmark.py rank --results app.jsonl
```

## License

Apache-2.0.
