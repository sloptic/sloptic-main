# Sloptic

Sloptic grades any deployed web app, whatever its stack or purpose, and gives it one score you can
compare across apps. Point it at a URL and it returns a **slop score** (lower is better, `0` means
nothing found) along with where that app ranks against a population of others. It reads no source and
needs no spec, so the same grade applies to every submission in a hackathon no matter what each one
was built with.

```sh
pip install sloptic
sloptic --target https://your-app.example.com
```

## Why

Merriam-Webster made *slop* its 2025 word of the year, the low effort content generative AI now
churns out in bulk, the junk images and filler text clogging every feed. Software is the same
phenomenon one layer down. AI assisted building made shipping a web app nearly free, and hackathon
galleries fill with submissions that look finished but were never hardened. Studies of AI generated
code bear out the worry, finding a vulnerability in roughly half of it. Yet when we graded 1,600+
real submissions ourselves, the failure was rarely a dramatic exploit. Far more often it was the
boring, pervasive floor left undone, no security headers, no rate limiting, broken accessibility, a
dev build in production. App slop, it turns out, is chronic, a missing floor far more often than a smoking gun. The full study, with the exact
figures and the per axis breakdowns, is in [CORPUS_REPORT.md](CORPUS_REPORT.md).

Hence the name.

> **sloptic** */ˈslɒp.tɪk/* *n.* a coinage from *slop*, 2025's word of the year for the low effort
> output of generative AI, and *optic*, an instrument for bringing something into focus. The
> apparatus by which slop of the software kind, the app that ships functional but unhardened, is
> resolved into a single comparable number, serenely indifferent to whatever it was meant to be.

## The niche

Most tools that probe a web app are fuzzers or scanners. They hunt for bugs in one app and hand you
a list. Sloptic does something different, and turns an arbitrary app into a **comparable quality
number**, so many unrelated apps can be ranked on the same yardstick without knowing anything about
what any of them does.

That is the purpose it was built for, objective quality grading of hackathon submissions. Sloptic
began as the resilience grader for the HackLet League and is now its own project, for that league and
for any hackathon organizer who wants an objective, consistent quality measure across every entry. A
human judge cannot hold a hundred stacks in their head. Sloptic grades them all the same way and places
each one on a single curve.

Sloptic grades the observable consequences of slop, the failures that are wrong no matter what
the app is for, and it leaves aside the code that produced them.

## What it grades

Sloptic only fires on failures that are **independent of intent**, things that are defects regardless of what
the app is meant to do. A managed backend the public can read, a login with no rate limiting, text too faint to read, a
button that does nothing, a crash on malformed input, a dev build shipped to production. None of these depend on knowing
the app's purpose. That boundary is deliberate. Humans carry intent, Sloptic carries the part a
machine can judge objectively. It will never tell you whether a feature is good. It tells you whether
the app holds up.

The catalog is **100+ probes** across three axes.

| axis | examples |
|------|----------|
| **security** | managed backend exposure (Supabase or Firebase RLS), exposed `.env` / `.git` / secrets in the bundle, missing rate limiting, header, CORS, and redirect defenses, and the injection classes (SQLi, XSS, SSTI, path traversal, SSRF) |
| **qa** | accessibility (axe-core, tiered by severity), controls that do nothing, crashes on malformed input, broken links, soft 404s, a dev build shipped to production, content type honesty |
| **performance** | Lighthouse, run locally at a pinned version, giving the overall performance score and the Core Web Vitals it reports (LCP, CLS, TBT, load time), throttled and scored as the median of three runs |

Each axis reports its own damped subtotal, and the three sum exactly to the slop score.

Performance is the one axis Sloptic does not measure with probes of its own. It defers to Lighthouse,
run locally at a pinned version, because a hand written timing probe cannot match years of calibration
and its false positives would poison a score meant to be trusted. The heavier Lighthouse audits, page
weight, request count, and DOM size, are read from the same run and reported off the score as
diagnostics.

## The score, and comparing across apps

- **Deductions only, and unbounded.** There is no positive credit and no 0 to 100 ceiling. An app with
  no attack surface and an app that defends its surface both score `0`: "nothing found" and "found
  and handled" are the same outcome. In practice almost no live app reaches `0`, because the universal
  hygiene floor, the security headers and the like, is nearly always missing something.
- **Priced by risk.** Each penalty is frequency times severity (expected harm), a designed table rather
  than raw severity.
- **Damped, so one root cause counts once.** A probe's detection variants collapse to a single
  finding, and repeated instances of the same category across many endpoints have diminishing
  marginal penalty. Ten endpoints missing a header are not ten findings.
- **Comparable.** A frozen reference distribution turns a raw score into a percentile, so "42
  slop" reads as "cleaner than 70 percent of the population." That comparison is what makes ranking
  possible, and it is what separates Sloptic from a scanner.

## Coverage honesty

A low score means something only if you know what was tested. Every grade ships with a coverage
report (probes applicable, probes that ran, surface observed) so a `0` that means "clean" is
distinguishable from a `0` that means "we could not reach the surface." Sloptic grades the
unauthenticated, observable surface well. It does not claim to exercise deep authenticated behavior, or behavior that depends on intent, and it says so instead of implying comprehensiveness.

## Install

```sh
pip install sloptic                # core: everything reachable over HTTP
pip install "sloptic[browser]"     # + Playwright, for accessibility, DOM XSS, and SPA rendering
playwright install chromium        # the browser binary, once
```

The performance axis runs Lighthouse locally at a pinned version through `npx`, so grading
performance also needs Node installed. Lighthouse drives Chrome over a loopback DevTools port, so if
you run the grader behind a firewall, leave loopback reachable for its user. A blocked loopback does
not error: the whole performance axis silently reads N/A while the rest of the grade looks clean, and
the only trace is `na_reason: requires unmet: lighthouse` on the twelve perf probes.

## Usage

Grade a live URL from the command line (deploys nothing, tears nothing down, and only test targets
you own or are authorized to test).

```sh
sloptic --target https://your-app.example.com
```

Or drive it as a library.

```python
from sloptic.catalog import load_catalog, default_catalog_dir
from sloptic.deploy import RemoteDeployer
from sloptic.pipeline import run

report = run(RemoteDeployer("https://your-app.example.com"), load_catalog(default_catalog_dir()))
print(report.slop_score, report.axis_slop)
```

Grade a submission (a zip containing a `Dockerfile`), built and run in a sandbox, then graded (needs
Docker).

```sh
sloptic --submission team.zip
```

A submission that will not unzip, has no `Dockerfile`, will not build, or never answers `$PORT`
yields a `DNF` record and exits nonzero. It never crashes the grader.

## How it deploys

The pipeline depends only on a `Deployer`, so the same catalog runs against any of three backends.

- **`SubprocessDeployer`** (dev and CI) launches a trusted reference app locally. It is never used
  for untrusted code.
- **`DockerDeployer`** (production) builds an untrusted submission's `Dockerfile` and runs it in a
  sandbox that is ephemeral, with fixed CPU, RAM, and PID quotas, `--cap-drop=ALL`,
  `--security-opt=no-new-privileges`, and an optional read-only rootfs on an egress-blocked internal
  network for hostile code.
- **`RemoteDeployer`** (dogfooding) targets a URL that is already running and deploys nothing.

Everything downstream of "the app answers `$PORT`" is identical and blind to the stack.

## How correctness is checked

Two instruments check correctness, because each answers a different question.

1. **Reference apps** (`references/`: `vulnerable`, `hardened`, `minimal`, `jsonapi`, `qa-janky`,
   `spa`) are a fixed calibration set with a known answer key. The vulnerable app must accrue slop,
   the hardened app must score `0`. This is the correctness anchor.
2. **A recall benchmark** of scenarios tagged with a CWE confirms each probe fires when its bug is actually
   present. A corpus of real apps tells you how often a defect occurs, but only a benchmark with
   ground truth tells you the detector works.

From a source checkout, `uv sync` then `uv run pytest -q` runs the full calibration suite against the
bundled reference apps (the `references/` directory, absent from the pip package).

## Scope, honestly

Sloptic is for grading deployed web apps at scale, hackathon submissions, CI gates, and your own
projects. It is strongest on the unauthenticated observable surface and on SPAs rendered on the client with
backends on the same origin. It is weaker where a defect hides behind authentication it cannot establish from the outside, or where judging the finding needs product intent. Those limits are reported openly.

## License

Apache-2.0.
