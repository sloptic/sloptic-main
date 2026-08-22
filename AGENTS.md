# AGENTS.md — Sloptic

Practical map for an agent working in this repo. Read `claude.md` for the full philosophy; this file is the
"start here" that routes you to the authoritative docs and states the workflow + the rules that actually bite.

## What this is

Sloptic grades how well any live web app holds up on the things every app should have. The output is a **slop
score**: unbounded, deduction-only, lower-is-better. It probes an app over HTTP (plus a headless-browser pass for
SPAs), collects findings, and prices each into a score. It is a black-box resilience grader, not a pentest suite:
it carries no human intent, so it only measures what is intent-independent and observable.

Mental model: the score is the product. Check-count is not. A finding must be **real, attributable, and
evidenced**, or it does not belong in the number.

## Orient yourself (read in this order)

- `README.md` — what it does, how to run one grade.
- `claude.md` — the philosophy and the non-negotiables (intent-independence, evidence-over-heuristic, precision
  vs recall, attribution, how not to fool yourself). Read this before changing scoring or adding a probe.
- `CONTRIBUTING.md` — authoring probes: the schema, the two detection primitives, add/change/remove a probe, the
  calibration gate, pricing a penalty.
- `docs/SCORING_V2_SPEC.md` — the scoring contract (severity blocks, ranges, escalators, dampers).
- `docs/V2_ROADMAP.md` — where it is going.

## Layout

- `sloptic/` — the package.
  - `pipeline.py` — orchestration: deploy/target, discover, run the probe battery, aggregate the score.
  - `discovery.py` — maps the app's surface (routes, forms, endpoints, client bundles) from a crawl + render.
  - `probes.py` — the predicates (the detection functions), the `PREDICATES` registry, and `_PREDICATE_REASONS`.
  - `aggregate.py` — turns findings into the score (the dampers live here).
  - `catalog.py` / `schema.py` — load and type the catalog.
  - `auth.py`, `browser.py`, `baas.py`, `email_verify.py` — session establishment (self-register, email/code
    verification, BaaS) so probes can reach the authenticated surface.
  - `safety.py` — the passive/active classification (fail-closed: a new probe is active unless listed passive).
  - `reportcard.py` — renders a finished grade into a team report card (post-hoc; never in the score path).
  - others: `net`, `deploy`, `lighthouse` (perf axis), `secretscan`, `depscan`, `jsmine`, `openapi`, `oob`, ...
- `catalog/` — the **source of truth** for probes: one YAML per probe under `security/`, `qa/`, `performance/`,
  plus `_severity_classes.yaml`. The CLI and scripts only reflect the catalog.
- `references/` — deterministic reference apps: `vulnerable/` and `hardened/` are the calibration anchors; the
  others (`jsonapi`, `spa`, `minimal`, `qa-janky`) are per-technique and per-mode CI locks.
- `tests/` — pytest suite (calibration anchor + per-probe unit/integration tests).
- `scripts/` — batch running, single-grade helpers, and reporting (e.g. `list_probes.py`).

## Dev workflow

```
uv sync
uv run pytest -q        # run FROM the repo root (this directory)
```

- The suite is the contract: **every change keeps `uv run pytest -q` green**, including the calibration anchor on
  `references/vulnerable` (must read slop) and `references/hardened` (must read clean).
- No Docker or Postgres is needed for the suite (backend references run on SQLite via uv). Tests that need a
  headless browser (Playwright) or Docker auto-skip where those are unavailable: a skip there is expected, not a
  failure.
- One logical change per commit.

## The score, in three lines (full contract in SCORING_V2_SPEC)

- **Unbounded, deduction-only, lower-is-better.** No 0-100, no ceiling.
- Each probe's real penalty is a **severity block**: a `range` with `default` (the floor) and evidence
  **escalators** that lift it toward the ceiling. The catalog `penalty:` field is only a nominal floor; the
  scored value is `_severity_penalty(range, escalators, evidence)`.
- Two dampers only: **variant-group fires once** (same flaw, many techniques -> one finding) and **within-category
  diminishing returns** (`x0.6` per additional finding in a category).

## Non-negotiables (the litmus every scored probe passes)

- **Intent-independence / the wedge test.** A probe belongs in the score only if you can build a deterministic
  vulnerable/hardened reference pair for it. If the failure is only defined relative to human intent, a spec, the
  environment, or a non-reproducible runtime, it cannot be scored (it can still be an off-score diagnostic).
- **Evidence over heuristic + causal specificity.** A scored oracle keys on evidence **causally specific** to the
  flaw: a ground-truth state change (auth bypass), a provider-specific error string, a salted-hash execution
  proof, or a differential controlled against the endpoint's own noise floor. A confoundable signal (a bare
  timing delta, a marker reflection an LLM/proxy emits with no vuln) is advisory/off-score, never scored.
- **Precision-first.** A false positive on an authoritative score is worse than a miss. Guard every technique and
  verify on a real app, not just the anchor.
- **One finding per flaw.** Technique breadth is for recall; it collapses to one finding (a predicate returns
  once, or probes share a `variant_group_id`).
- **N/A is a verdict and must say WHY** (`na_reason`), never a silent "clean" (a false clean is a missed finding).
- **Determinism.** No LLM in the score number. Any LLM is discovery-seeding (a pointer verified by probes) or an
  off-score coverage audit, at temperature 0 with structured output.

## Adding or changing a scored probe (checklist)

A new detection primitive touches all of these; a declarative or variant probe is lighter (see CONTRIBUTING).

1. `catalog/<bundle>/<id>.yaml` — the severity block, `applicability.requires`, and the `predicate`.
2. The predicate in `sloptic/probes.py`, registered in `PREDICATES`, with a one-line entry in `_PREDICATE_REASONS`.
3. Classify it in `sloptic/safety.py` — **active** if it mutates / injects / fault-induces / hammers / uses
   multiple accounts; **passive** otherwise.
4. Author the report-card copy in `sloptic/reportcard.py` `_CONTENT` (expected / indicates / remediation). A
   coverage test fails until every scored probe has it.
5. A `references/` vulnerable/hardened pair (the wedge) plus a per-technique CI lock in `tests/`.
6. Price it via the severity block: risk = frequency x severity (see CONTRIBUTING, "Pricing a penalty").
7. Update the calibration anchor if the reference now fires it, and keep the suite green.

## Gotchas

- Run `pytest` from the repo root; some tests are cwd-sensitive.
- Browser (Playwright) and Docker-deploy tests skip without those deps. That is expected.
- The catalog is the source of truth. `scripts/list_probes.py` and `reportcard.py` only *display* the catalog and
  finished grades; they never compute a score. Both are coverage/severity test-guarded, so a new scored probe
  fails a test until its card copy exists and the range display stays correct.
- Prefer the dedicated modules (`auth`/`browser`/`baas`/`email_verify`) for anything that needs a session; do not
  re-implement registration in a probe.
