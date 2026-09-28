# Sloptic

Sloptic grades any deployed web app, whatever its stack or purpose, and gives it one score you can compare
across apps. Point it at a URL and it returns a **slop score** (lower is better, `0` means nothing found) and
where that app ranks against a frozen population of others. It reads no source and needs no spec, so every
submission to a hackathon gets the same grade whatever it was built with.

```sh
pip install sloptic
sloptic --target https://your-app.example.com
```

## Who it is for

Sloptic is for the people who build and judge web apps: a team checking its own app before a deadline, a
hackathon organizer grading every submission on one scale, a CI gate on your own project.

There are two ways to use it:

- **[sloptic.org](https://sloptic.org)** grades a URL in the browser, with no install. Anyone can run the
  passive battery, which reads only what the app already serves. Probes that send test payloads run only after
  your account proves it controls the app's domain. Organizers can verify their Devpost event and grade its
  submissions together.
- **The package** (`pip install sloptic`) runs the same grader locally or in CI. Use it only on apps you own
  or are authorized to test.

Both rank a grade against the same frozen reference curves, built from a corpus of real hackathon apps. The
study behind those curves is [CORPUS_REPORT.md](CORPUS_REPORT.md).

## Why

Merriam-Webster made *slop* its 2025 word of the year, for the low effort content generative AI churns out in
bulk. Software has its own version. AI assisted building made shipping a web app nearly free, and hackathon
galleries fill with submissions that look finished but were never hardened. Source code studies find a
security flaw in close to half of AI generated code.

When we graded nearly 1,600 live hackathon apps from the outside, exploitable flaws were rare: 4.7% of apps.
The common failures were the basics: 98% sent no Content Security Policy, 65% failed an accessibility check,
and 63% scored below 90 on Lighthouse performance. The full study is in [CORPUS_REPORT.md](CORPUS_REPORT.md).

> **sloptic** */ˈslɒp.tɪk/* *n.* a coinage from *slop*, 2025's word of the year for the low effort output of
> generative AI, and *optic*, an instrument that brings something into focus. The instrument that turns slop
> of the software kind, the app that ships functional but unhardened, into one comparable number, without
> regard to what the app was meant to do.

## What makes it different

Fuzzers and scanners hunt for bugs in one app and hand you a list. Sloptic turns an arbitrary app into a
**comparable quality number**, so unrelated apps can be ranked on one scale without knowing what any of them
does.

It was built for that: grading hackathon submissions objectively. Sloptic began as the resilience grader for
the HackLet League and is now its own project. A human judge cannot hold a hundred stacks in their head.
Sloptic grades them all the same way and places each one on one shared curve.

## What it grades

Sloptic fires only on failures that are **independent of intent**: defects whatever the app is meant to do. A
managed backend the public can read, a login with no rate limiting, text too faint to read, a button that
does nothing, a crash on malformed input. None of these depend on the app's purpose. Sloptic never judges
whether a feature is good, only whether the app holds up.

The catalog is **100+ probes** across four axes.

| axis | examples |
|------|----------|
| **security** | managed backend exposure (Supabase or Firebase RLS), exposed `.env` / `.git` / secrets in the bundle, missing rate limiting, header, CORS, and redirect defenses, and the injection classes (SQLi, XSS, SSTI, path traversal, SSRF) |
| **qa** | controls that do nothing, crashes on malformed input, broken links, soft 404s, a dev build shipped to production, content type honesty, password recovery that never arrives |
| **accessibility** | axe-core on the rendered page, tiered by severity: text too faint to read, buttons and fields with no accessible name, missing labels, a page with no language or title |
| **performance** | Lighthouse, run locally at a pinned version: the overall performance score and the Core Web Vitals it reports (LCP, CLS, TBT, load time), throttled and scored as the median of three runs |

Each axis reports its own damped subtotal, and the four sum exactly to the slop score.

Performance is the one axis Sloptic does not measure with its own probes. It defers to Lighthouse, run
locally at a pinned version, because our own timing probes produced too many false positives. The heavier
Lighthouse audits (page weight, request count, DOM size) come from the same run and are reported off the
score as diagnostics.

## The score, and comparing across apps

- **Deductions only, and unbounded.** There is no positive credit and no 0 to 100 ceiling. An app with no
  attack surface and an app that defends its surface both score `0`. In the 2026.4 corpus no app scored `0`,
  because almost every app misses part of the hygiene floor, such as the security headers.
- **Priced by risk.** Each penalty is frequency times severity (expected harm), a designed table rather than
  raw severity.
- **Damped, so one root cause counts once.** A probe's detection variants collapse to a single finding, and
  repeated findings in one category count for less each time. Ten endpoints missing a header are not ten
  findings.
- **Comparable.** A frozen reference distribution turns a raw score into a percentile: a `30` is cleaner than
  73% of the 2026.4 population. There are two frozen curves, the full battery and the passive subset, and a
  percentile always names the one it used.

## Coverage

A low score means something only if you know what was tested. Every grade ships with a coverage report
(probes applicable, probes that ran, surface observed), so a `0` that means "clean" is distinguishable from a
`0` that means "we could not reach the surface." Sloptic grades the unauthenticated, observable surface well.
It does not exercise deep authenticated behavior or behavior that depends on intent.

## Install

```sh
pip install sloptic                # core: everything reachable over HTTP
pip install "sloptic[browser]"     # + Playwright, for accessibility, DOM XSS, and SPA rendering
playwright install chromium        # the browser binary, once
```

The performance axis runs Lighthouse locally at a pinned version through `npx`, so grading performance also
needs Node installed. Lighthouse drives Chrome over a loopback DevTools port, so if you run the grader behind a
firewall, leave loopback reachable for its user. A blocked loopback does not error: the whole performance axis
reads N/A while the rest of the grade looks clean, and the only trace is `na_reason: requires unmet:
lighthouse` on the perf probes.

## Usage

Grade a live URL from the command line. This deploys nothing and tears nothing down. Only test targets you own
or are authorized to test.

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

Grade a submission (a zip containing a `Dockerfile`), built and run in a sandbox, then graded (needs Docker).

```sh
sloptic --submission team.zip
```

A submission that will not unzip, has no `Dockerfile`, will not build, or never answers `$PORT` yields a `DNF`
record and exits nonzero. It never crashes the grader.

## How it deploys

The pipeline depends only on a `Deployer`, so the same catalog runs against any of three backends.

- **`SubprocessDeployer`** (dev and CI) launches a trusted reference app locally. It is never used for
  untrusted code.
- **`DockerDeployer`** (production) builds an untrusted submission's `Dockerfile` and runs it in an ephemeral
  sandbox with fixed CPU, RAM, and PID quotas, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, and an
  optional read only rootfs on an egress blocked internal network.
- **`RemoteDeployer`** targets a URL that is already running and deploys nothing.

Everything after "the app answers `$PORT`" is identical and blind to the stack.

## How correctness is checked

1. **Reference apps** (`references/`: `vulnerable`, `hardened`, `minimal`, `jsonapi`, `qa-janky`, `spa`) are
   a fixed calibration set with a known answer key. The vulnerable app must accrue slop, and the hardened app
   must score `0`.
2. **A recall benchmark** of scenarios tagged with a CWE checks that each probe fires when its bug is present.
   A corpus of real apps shows how often a defect occurs. Only a benchmark with ground truth shows the
   detector works.

From a source checkout, `uv sync` then `uv run pytest -q` runs the full calibration suite against the bundled
reference apps (the `references/` directory, absent from the pip package).

## Scope

Sloptic grades deployed web apps at scale: hackathon submissions, CI gates, and your own projects. It is
strongest on the unauthenticated, observable surface and on SPAs rendered on the client with backends on the
same origin. It is weaker where a defect hides behind authentication it cannot establish from the outside, or
where judging a finding needs product intent. Each grade reports those limits.

## License

Apache-2.0.
