# claude.md: Sloptic

Guidance for working on Sloptic with Claude Code. Sloptic is a black-box HTTP resilience grader: it
deploys or points at a web app, probes it over HTTP, and emits a **slop score** (deduction-only,
unbounded, lower is better, `0` means nothing found). It never reads the target's source.

## Architecture in one breath

The engine is fixed; **probes are data** (`catalog/**/*.yaml`, loaded by `load_catalog()`). A probe is
either declarative (fetch a target, apply a matcher) or a predicate (a multi-step oracle in
`sloptic/probes.py`). The pipeline is `deploy -> discover -> applicability -> execute -> aggregate ->
report`, and it runs identically against three deployers (`SubprocessDeployer` for trusted reference
apps, `DockerDeployer` for untrusted submissions in a sandbox, `RemoteDeployer` for a live URL).

## The score

- **Deduction-only and unbounded.** No positive credit, no 0-to-100 ceiling. An app with no surface and
  an app that defends its surface both score `0`.
- **Per-axis.** security, qa, and performance each report a damped subtotal, and the three sum exactly to
  the slop score.
- **Risk-priced.** Each penalty is frequency times severity, a designed table, not raw severity.
- **Damped.** A probe's detection variants collapse to one finding, and repeated instances of one
  category across endpoints have diminishing marginal penalty.

## What Sloptic will and will not fire on

It fires only on **intent-independent** failures: defects no matter what the app is for (a leaked SQL
error, a login with no rate limiting, an unhandled 5xx, near-invisible text, a dev build shipped to
production). It never judges whether a feature is good. That boundary is deliberate: a machine carries
the objective part, humans carry intent.

## Working conventions

- **A predicate is three-state:** `True` (slop), `False` (tested, clean), `None` (not applicable, could
  not establish the conditions to test). A `False` when you could not actually test is a false clean, a
  missed finding. When in doubt, return `None`.
- **Evidence, always.** A predicate records what it measured or attempted in `ctx.evidence`, for every
  outcome, not just slop. It is the product's transparency.
- **N/A must say why.** A `not_applicable` result carries a distinct reason, so a `0` that means "clean"
  is never confused with a `0` that means "we could not reach the surface."
- **One finding per class, all its techniques.** Cover a class's techniques (SQLi error/boolean/union/
  time; XSS script/img/svg/attr) but collapse them to one finding. Breadth is recall, not score
  inflation, so keep each technique precise enough not to false-fire.
- **The calibration gate is non-negotiable.** Every change keeps `uv run pytest` green. A probe must
  read slop on `references/vulnerable`, clean on `references/hardened`, and N/A or clean on
  `references/minimal`: the same surface, three verdicts.

## Adding or changing probes

See `CONTRIBUTING.md` for the full recipe (schema, the two detection primitives, the reference-app
calibration, and penalty pricing).

## Running it

```sh
uv sync --group browser && uv run playwright install chromium   # browser probes
uv run pytest -q                                                 # the calibration suite
uv run python -m sloptic.cli --target https://your-app.example.com
```
