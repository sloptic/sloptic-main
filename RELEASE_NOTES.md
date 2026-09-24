# Sloptic v3.0.0

Sloptic grades any deployed web app, whatever its stack or purpose, and returns one
**slop score** you can compare across apps (lower is better, `0` means nothing found),
along with where that app ranks against a frozen population of others. It reads no source
and needs no spec, so the same grade applies to every submission no matter what each one
was built with.

Versions 1.1 and 1.2 kept the 2026.1 curve, so grades stayed comparable and the changes were
precision and diagnostics. Version 2.0 is different: it is a **new ruler**. New probe families and
continuous scoring changed what the number measures, and the reference curve moved to **2026.3**, so
a 2.0 score does not compare to a 1.x one. A 2.0 percentile is quoted against 2026.3. Version 2.1 keeps that 2026.3 ruler, so a 2.1 grade compares directly to a 2.0 one, and it adds the egress sandbox the hosted service needs to accept public URL submissions safely. Version 2.2 keeps it as well, and spends its changes on the crawl, on a second frozen curve for the passive battery, and on the client the hosted service needs to verify an event.

Version 3.0 is the next **new ruler**. Accessibility becomes its own axis, performance is corrected for the speed of the box that measured it, and new detection reaches classes the 2.x battery could not, so the reference curves move to **2026.4** (full) and **passive-2026.2** (passive). A 3.0 score does not compare to a 2.x one, and a 3.0 percentile is quoted against 2026.4.

## What's new in 3.0.0

- **A new ruler, and accessibility as its own axis.** The score now splits four ways, security, quality,
  accessibility and performance, and the four subtotals still sum exactly to the slop score. Accessibility
  made up a large share of the quality number while it sat inside it, so a team could not tell an
  inaccessible app from a broken one; it now reports on its own, priced as before. The full curve **2026.4** is final, frozen from a
  run of 2,685 live hackathon apps, 1,579 of them curve eligible. The middle of the distribution barely moved
  (median 48.4 against 2026.3's 50.0) while the upper tail grew (95th percentile 140 against 130), which is
  what new detection reaching more apps should look like.
- **Performance corrected for the box that measured it.** Lighthouse's default throttling models the network
  but never slows the real CPU; it runs the trace at the host's actual speed and multiplies CPU time by a fixed
  factor, so a busy grading box scores an app worse through no fault of the app. A controlled comparison found
  a lone grade on an idle box about 6.6 Lighthouse points kinder than the same app graded four at a time.
  Every grade now records the host speed Lighthouse measured (`benchmark_index`), and the curve carries a
  normalization fitted from that comparison, so a solo submission ranks fairly against a population graded
  in parallel. Performance axis only; the other three are untouched.
- **The ruler travels with the grade.** Every record is stamped with the curves it was scored against, and
  the report card prints them, so a stored grade never silently reads as current after the ruler moves. A
  grade that predates the stamp reads as unspecified, never as the current ruler.
- **A per path WAF block no longer ends the grade.** An edge that blocks one sensitive path (a firewall
  refusing `/.env`) while serving the app normally used to read as a challenge on the whole app, and the grade
  stopped there. The grader now re-fetches the origin before halting: a reachable app keeps grading, and only
  an app wide challenge, or an origin that cannot be reached at all, halts. On one hosting platform, 70 apps
  that were cut short at exactly that path in the previous run are now graded in full, with none challenged.
- **New detection.**
  - A Gemini key found in a bundle is confirmed against Google with one free call instead of guessed from its
    format. It spends a request against the owner's credential, so it runs only where ownership is attested.
    The secret patterns also cover the 2026 model providers and name an Anthropic key correctly.
  - A Supabase Storage bucket an anonymous client can list, where per user paths expose other users' files.
    A now redundant CVE probe is dropped.
  - A reusable session token carried in a URL query string, where it leaks into history, logs and referrers.
  - A linked page still showing generator boilerplate. Two distinct placeholders on one page are required, so
    deliberate example copy does not fire.
- **Precision.** The boolean SQL injection oracle now requires a negative control and skips generator streams.
  A cross host redirect after a CSRF attempt reads as a bounce, not an acceptance. Host header injection never
  fires on an error response. A session token counts only on the graded origin's own URLs. Platform error
  pages, starter templates and title only shells are no longer graded as apps. Unresolved `{placeholder}`
  endpoint templates are dropped before any probe sees them. An app that redirects is graded at the origin it
  settles on. Five more third party hosts are excluded from the curve: a hosted presentation, a package
  registry, two app store listings, and a no code site builder.
- **One slow probe costs its own time, not the grade.** Each non browser probe runs against its own wall clock,
  and one that overruns lands in `blocked_probes` for the retry pass instead of consuming the whole grade. The
  path that handled that overrun also had a bug that crashed the entire grade; it is fixed. The injection
  fan out now runs inside the context of the thread that submitted it, the browser's top level navigation is
  scoped to the graded origin, and a grade that times out records the phase, probe and progress where it died.
- **The report card says what went wrong.** The line under each finding now states the finding and its
  failing detail rather than raw evidence. Accessibility rule ids read in plain language, with the element each
  violation occurred on. Console errors are quoted, not just counted. The performance audit is named and its
  value labeled.
- **Tooling.** `scripts/stats.py --app` audits one app end to end, including the Devpost event, submission and
  whether it won. `--hackathon` prints one event's roster with a five number slop summary. The committed corpus
  figures now read their version from the ruler, so they cannot lag the frozen curve.

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
- **The origin scope now holds inside the injection fan out.** `origin_scope()` pins a public grade to one
  origin so a redirect cannot carry authorization somewhere the grant never covered. It is a ContextVar, and
  a thread the pool starts gets a fresh empty context, so the check silently did not run in the worker
  threads that send the injection payloads: only the public address predicate was left, and a third party
  host passes that by definition. A target answering its discovered endpoints with a redirect elsewhere
  could have SQL injection, command injection and traversal payloads delivered to that third party, turning
  a grant for one host into a relay. The scope is now bound to the callable on the submitting thread, in
  both fan out pools, and the regression tests assert from inside a worker, since a main thread test passes
  either way. Present since 2.1.0, where `origin_scope` shipped. No score moves: the corpus and reference
  lanes never enter a scope, and an unscoped bind returns the callable itself.
- **Grade timing as data.** `scripts/stats.py --timing-json` writes how long a grade actually takes to
  `validation/grade-timing.json`, keyed by battery, so a hosted grader quotes an ETA from measured runs
  rather than guessing. A passive grade runs at a median of 94 seconds against 185 for the full battery,
  6% of full grades that start hit the 900 second cap against 2% of passive ones, and a dead URL costs two
  tenths of a second. These are contended wall clock times from a four way parallel corpus run, and the
  file carries that caveat next to the numbers so they read as an upper bound rather than a promise.
- **Every finding carries the contribution it made.** A report listing findings with their penalty lists
  prices, and prices do not add up to the score, because the dampers sit between the two: on the corpus the
  raw penalties sum to a median 1.9 times the score. Each entry of `findings` now also carries
  `contribution`, what that finding actually added after a variant group collapsed and its category decayed,
  rounded by largest remainder so the column sums to `slop_score` exactly as emitted. `penalty` is unchanged
  next to it, since what a fault is worth alone is a separate fact from what it added here.
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
- **106 probes across four axes.** Security (63), quality and correctness (27),
  accessibility (3), and performance (13). Each axis reports its own damped subtotal, and the
  four sum exactly to the slop score.
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

Across two consecutive 3.0 corpus runs, on the 906 apps graded unchallenged both times, individual
verdicts barely moved. Of the verdicts that fired in either run, the security header probes flipped in under
1 percent of cases, accessibility in 2 percent, crash resistance in 3 percent. The one material source of
per app noise is the Lighthouse score near its 90 point pass line, where about 15 percent of those verdicts
flip between runs; it is priced as a continuous
shortfall rather than a hard verdict for that reason.

Correctness is anchored two ways: a fixed set of reference apps with a known answer key (the
vulnerable app must accrue slop, the hardened app must score `0`), and a recall benchmark of scenarios
tagged with a CWE. `uv run pytest -q` runs the calibration suite.

## Frozen reference curves: 2026.4 and passive-2026.2

This release ships the full reference curve **2026.4** (final), frozen from a corpus run of 2,685 live
hackathon apps, 1,579 of them eligible for the curve, and the passive floor curve **passive-2026.2**, frozen
from its own run of the passive battery over the same corpus. Each stores its full score distribution as
anonymous per app rows (score, whether a catastrophe fired, the single worst finding, worst case slop
defended, surface breadth) with no per app identity, so a percentile is exact with no interpolation and ties
resolve the same way every time. A percentile is always quoted against a named curve version, so the claim is
checkable and does not drift as the population changes. The full curve also carries its performance
normalization, so a grade is ranked as if measured on the population's box.

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
