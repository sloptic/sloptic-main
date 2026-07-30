# Sloptic

A **black-box HTTP resilience grader**. Point it at a running web app — a live URL, a repo it
deploys, or a submitted `Dockerfile` — and it probes the app over HTTP and emits a **slop score**:
deduction-only, unbounded, lower is better, `0` = nothing found. It never reads your source.

The name is for **AI slop**. Sloptic grades the *observable* consequences of slop — the failures
that are wrong no matter what the app is for — not the code that produced them.

```sh
uv run python -m sloptic.cli --target https://your-app.example.com
```

## What it grades

Sloptic only fires on **intent-independent** failures: things that are defects regardless of what
the app is supposed to do. A leaked SQL error, a login with no rate limiting, a page of
near-invisible text, a crash on malformed input, a dev build shipped to production — none of these
depend on knowing the app's purpose. That boundary is deliberate: **humans carry intent, Sloptic
carries the parts a machine can judge objectively.** It will never tell you whether a feature is
*good*; it tells you whether the app *holds up*.

The catalog is **91 probes** across three axes:

| axis | probes | examples |
|------|:------:|----------|
| **security** | 57 | SQLi, XSS/SSTI, path traversal, SSRF, exposed `.git`/backups/secrets, missing rate-limiting, header/CORS/redirect defenses, managed-backend (Supabase/Firebase) RLS |
| **qa** | 22 | accessibility (axe-core, severity-tiered), broken links, soft-404s, unhandled 5xx, dev-build-shipped, content-type honesty |
| **performance** | 12 | TTFB, page weight, request count, Core Web Vitals (throttled, best-of-N), computed load time |

Each axis reports its own damped subtotal; the three sum exactly to the slop score.

## The score

- **Deduction-only and unbounded.** There is no positive credit to protect and no 0–100 ceiling. An
  app with no attack surface and an app that defends its surface both score `0` — "no slop found"
  and "slop found and handled" are the same outcome.
- **Risk-priced.** Each penalty is `frequency × severity` (expected harm), not raw severity — a
  designed table, not ordinal multiplication.
- **Damped, so one root cause counts once.** A probe's detection *variants* collapse to a single
  finding; repeated instances of the same category across many endpoints have diminishing marginal
  penalty. Ten missing-header endpoints are not ten findings.

## Coverage honesty

A low score is only meaningful if you know what was tested. Every grade ships with a coverage
report — **probes applicable, probes that ran, surface observed** — so a `0` that means "clean" is
distinguishable from a `0` that means "we couldn't reach the surface." Sloptic grades the
unauthenticated, observable surface well; it does **not** claim to exercise deep authenticated or
intent-dependent behavior, and it says so rather than implying comprehensiveness.

## Install

```sh
uv sync                      # core
uv sync --group browser      # + Playwright, for the accessibility / CWV / DOM-XSS probes
uv run playwright install chromium
```

## Usage

**Grade a live URL** (deploys nothing, tears nothing down — only test targets you own or are
authorized to test):

```sh
uv run python -m sloptic.cli --target https://your-app.example.com
```

**Grade a submission** (a zip with a `Dockerfile`) — built and run in a sandbox, then graded:

```sh
uv run python -m sloptic.cli --submission team.zip
```

A submission that won't unzip, has no `Dockerfile`, won't build, or never answers `$PORT` yields a
`DNF` record and exits non-zero — never a crash.

**Run the calibration suite** against the bundled reference apps:

```sh
uv run pytest -q
```

## How it deploys

The pipeline depends only on a `Deployer`, so the same catalog runs against any of three backends:

- **`SubprocessDeployer`** (dev/CI) — launches a **trusted reference app** locally. Never used for
  untrusted code.
- **`DockerDeployer`** (production) — builds an untrusted submission's `Dockerfile` and runs it in a
  sandbox: ephemeral, fixed CPU/RAM/PID quotas, `--cap-drop=ALL`, `--security-opt=no-new-privileges`,
  and an optional read-only rootfs on an **egress-blocked** internal network for hostile code.
- **`RemoteDeployer`** (dogfooding) — targets an already-running URL. Deploys nothing.

Everything downstream of "the app answers `$PORT`" is identical and stack-blind.

## How correctness is checked

Two instruments, because they answer different questions:

- **Reference apps** (`references/`: `vulnerable`, `hardened`, `minimal`, `jsonapi`, `qa-janky`,
  `spa`) — a fixed calibration triad with a known answer key. The vulnerable app must accrue slop;
  the hardened app must score `0`. This is the correctness anchor.
- **A recall benchmark** of CWE-tagged scenarios confirms each probe fires when its bug is actually
  present — the corpus of real apps tells you *how often* a defect occurs, but only a benchmark with
  ground truth tells you the *detector works*.

`uv run pytest -q` runs the calibration suite (848 tests).

## Scope, honestly

Sloptic is for grading deployed web apps at scale — hackathon submissions, CI gates, your own
projects. It is strongest on the unauthenticated observable surface and on client-rendered SPAs with
same-origin backends. It is weaker where a defect hides behind authentication it can't establish
black-box, or where judging the finding needs product intent. Those limits are reported, not hidden.

## License

Apache-2.0.
