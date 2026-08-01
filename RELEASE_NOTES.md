# Sloptic v1.1.0

Sloptic grades any deployed web app, whatever its stack or purpose, and returns one
**slop score** you can compare across apps (lower is better, `0` means nothing found),
along with where that app ranks against a frozen population of others. It reads no source
and needs no spec, so the same grade applies to every submission no matter what each one
was built with.

This builds on the v1.0 engine. The scoring model and the frozen reference curve (2026.1) are
unchanged, so grades stay comparable to v1.0; the changes below are precision and diagnostics,
not a new ruler.

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
  active) and CI-locked. A passive grade is a subset, not comparable to a full grade.

The frozen reference curve stays **2026.1** (the score distribution did not move).

## Highlights

- **Comparable by design.** A raw score becomes a percentile against a frozen reference
  distribution, so a grade is not just "42 slop" but "cleaner than 70 percent of the
  population." That comparison is what separates Sloptic from a scanner.
- **Exact, tie-aware ranking.** The percentile is read off the full frozen distribution,
  not interpolated between a handful of landmarks. Two apps at the same score are not
  treated as equal: ties break on whether a catastrophe fired, then on how much worst-case
  slop the app actually defended (the score it would carry had every applicable probe
  fired), then on the breadth of surface it exercised.
- **Catastrophe gate.** An exploitable-now class (SQL injection, a served secret file, a
  world-readable managed backend) is reported as an absolute gate whatever the rank says. A
  favorable comparison to equally-broken peers never launders it.
- **91 probes across three axes.** Security (57), quality and correctness (22), and
  performance (12). Each axis reports its own damped subtotal, and the three sum exactly
  to the slop score.
- **Deduction-only and risk-priced.** No positive credit, no 0-to-100 ceiling. Each
  penalty is frequency times severity. A probe's detection variants collapse to one
  finding, and repeated instances of one category have diminishing marginal penalty, so a
  single root cause counts once.
- **Intent-independent.** Sloptic only fires on failures that are defects regardless of
  what the app is for: a leaked SQL error, a login with no rate limiting, near-invisible
  text, a crash on malformed input, a dev build shipped to production. It never judges
  whether a feature is good.
- **Coverage honesty.** Every grade ships a coverage report, so a `0` that means "clean"
  is distinguishable from a `0` that means "we could not reach the surface."
- **Stack-blind deployment.** The same catalog runs against a local subprocess, a
  sandboxed Docker submission, or a live URL. Everything downstream of "the app answers
  `$PORT`" is identical.

## Reproducibility and calibration

The score is stable, which is the property a ranking depends on. Two independent
full-corpus runs of live web apps agree closely:

- Spearman rank correlation **0.974**.
- Deciles **92.6 percent identical** (96 percent within one decile).
- **92 percent** of apps scored exactly the same; no systematic drift.

The movement that remains is confined to the probes where black-box nondeterminism is
unavoidable (stateful browser behaviors, Core Web Vitals timing, and the auth or
timing-gated security tail); the deterministic surface holds.

Correctness is anchored two ways: a fixed set of reference apps with a known answer key
(the vulnerable app must accrue slop, the hardened app must score `0`), and a recall
benchmark of CWE-tagged scenarios. `uv run pytest -q` runs the calibration suite (865
tests).

## Frozen reference curve: 2026.1

This release ships reference curve **2026.1** (final), frozen from a corpus run of 1,537
live web apps. It stores the full score distribution as anonymous per-app rows (score,
whether a catastrophe fired, worst-case slop defended, surface breadth) with no per-app
identity, so a percentile is exact rather than interpolated and ties resolve the same way
every time. A percentile is always quoted against a named curve version, so the claim is
checkable and does not drift as the population changes.

## Scope, honestly

Sloptic is strongest on the unauthenticated, observable surface and on client-rendered
apps with same-origin backends. It is weaker where a defect hides behind authentication
it cannot establish black-box, or where judging the finding needs product intent. Those
limits are reported, not hidden.

The recall audit (measuring the false-negative rate against ground-truth benchmarks
across the full catalog) is in progress and continues in a follow-up release. This
release guarantees stability (the ruler repeats) and precision on the classes that
carry explicit precision rules; findings elsewhere are unaudited rather than vouched.
That unaudited mass is dominated by deterministic presence checks where false-positive
risk is structurally low, but since the audit cannot distinguish "no rule needed" from
"no rule written," we report it as unaudited rather than claim a precision we have not
checked. The recall number is not yet claimed.

## Install

```sh
uv sync                      # core
uv sync --group browser      # adds Playwright, for accessibility, CWV, and DOM-XSS probes
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
