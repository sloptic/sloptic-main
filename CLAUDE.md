# CLAUDE.md — operating manual for this repo

You are working on **hacklet-fuzz-runner**: a black-box HTTP resilience grader. It deploys a web app,
probes it over HTTP, and emits a **slop score** — *deduction-only, unbounded, lower is better*. It was
extracted from the `hacklet-league` monorepo to stand on its own; this file is your orientation. Read
`STATE.md` for where things stand right now, `PROJECT_LOG.md` for how we got here, and
`FUZZ_RUNNER_SPEC.md` for the canonical design.

## The one idea

Grade the **intent-independent, observable** resilience surface of an app — the failures that are wrong
*regardless of what the app is for* (SQLi, stack-trace leaks, missing security headers, crashes on
malformed input, slow TTFB). Humans carry *intent* (does this feature do what it claims); the runner
carries everything universal. **The moat is the score's trustworthiness, not the number of checks.** A
check that fires on a false positive is worse than a missing check — it poisons comparability.

## Golden rules (do not violate without explicit sign-off)

1. **Test gate before every commit.** Run the offline suite and keep it green:
   ```bash
   uv run pytest -q --ignore=tests/test_docker_deploy.py --ignore=tests/test_docker_hardened.py
   ```
   The two ignored files spin real Docker containers (reused names) — only run them when Docker is free.
   Browser tests need the browser group (see Run recipes); without it, exclude `tests/test_browser.py`
   and the other render-dependent ones. A green core run is ~250 tests.
2. **One commit per change.** End every code-writing turn with a ready-to-paste commit command.
   Conventional-commit style, scope in parens, `+`-join multiple related parts:
   `feat(discovery): infer field names for anonymous SPA inputs`. Explain the *why* in the body.
3. **Results are append-only JSONL.** Never rewrite a results/parity file in place — a crash mid-write
   must not corrupt prior rows. Dedup happens at *read* time (keep the latest row per repo by timestamp,
   see `scripts/stats.py`). "We do not want corrupted files."
4. **This pipeline runs UNTRUSTED code.** `deploy_and_grade.py` builds and runs arbitrary hackathon repos
   in Docker. Only ever run a batch on a **sandboxed, firewalled** box. See the threat model in
   `FUZZ_RUNNER_SPEC.md#threat-model`.
5. **The grader must never change its own session's credentials.** Password-change / password-reset forms
   are withheld from submission (`auth.is_password_change_form`) — a grader that resets the admin password
   locks itself (and every later probe) out. Don't "fix" that withholding.
6. **Never commit the hidden probe pool.** The real precision boundary is a *separate private*
   fuzz-catalog repo; `**/hidden/` and `catalog-hidden/` are gitignored as a backstop. Keep it that way,
   especially if this repo goes public.

## Run recipes

```bash
# one-time
uv sync                                  # core deps (httpx, pydantic, pyyaml, pytest)
uv sync --group browser && uv run playwright install chromium   # for browser-based discovery/grading

# grade a single live target (no LLM, no Docker) — the pure grader
uv run python -m hacklet_runner.cli --target http://host:port [--no-browser]

# LLM-assisted: clone a repo, plan a Docker deploy, run it, grade it, tear it down
uv run python scripts/deploy_and_grade.py [--no-browser] --record out.jsonl https://github.com/u/r

# full batch: Devpost gallery -> repos -> deploy+grade each -> stats -> parity dashboard
uv run python scripts/run_batch.py <devpost-url-or-repo-list> --results out.jsonl [--limit N]

# read a finished batch
uv run python scripts/stats.py out.jsonl            # auditable slop breakdown
uv run python scripts/parity.py out.jsonl           # coverage: observed vs expected surface, by stack
uv run python scripts/list_probes.py                # the catalog
```

**Environment:** `OPENROUTER_API_KEY` (required for deploy planning), `OPENROUTER_MODEL`
(default `qwen/qwen3.7-plus` — a cheap, strong anti-hallucinator; abstention is the property we want),
`HL_BUILD_CACHE_CAP` (default `20GB`, the per-batch build-cache reserve). Seed the key for a terminal
session with `export OPENROUTER_API_KEY=...` (or your shell's secret manager) before a batch.

## Architecture map

**`hacklet_runner/`** — the grader core (pure, no LLM):
| module | role |
|---|---|
| `pipeline.py` | `run(deployer, catalog, render=…, seed_features=…)` — orchestrates discover → applicability → execute → aggregate → `Report` |
| `discovery.py` | the **Discovery Profile** (routes / forms / endpoints / capabilities); browser multi-route render; `surface_metrics` (healthy-observed surface); endpoint **baselining** (env-dead endpoints); feature **seeding** |
| `probes.py` | probe execution — injection (SQLi/XSS/SSTI/LFI/cmdi/XXE/SSRF), crash-resistance, headers/CORS/compression, etc. Each vuln class runs **comprehensive techniques** that collapse to **one** finding |
| `aggregate.py` | scoring: deduction-only slop, **dampers** (variant-group-fires-once; within-category geometric decay `CATEGORY_DECAY=0.6`); `coverage_metrics` (test-coverage fingerprint) |
| `schema.py` | `Report` / `Endpoint` / `Finding` dataclasses (surface, coverage, timings) |
| `auth.py` | login detection (form + JSON API); the password-change withholding |
| `browser.py` | Playwright render (`render_routes` batch; system-Chrome fallback) |
| `deploy.py` | `RemoteDeployer` and target/URL handling |
| `catalog.py` | loads the probe YAMLs |
| `secretscan.py`, `openapi.py`, `jsmine.py`, `oob.py`, `perf.py`, `net.py`, `ingest.py` | source secret scan; OpenAPI ingest; JS route mining; out-of-band; perf sampling; net helpers; untrusted-zip ingest (zip-slip guarded) |

**`catalog/`** — 65 probe YAMLs: `security/` (41), `qa/` (12), `performance/` (12).
**`scripts/`** — the deploy+batch pipeline: `deploy_and_grade.py`, `run_batch.py`, `devpost_repos.py`, `stats.py`, `parity.py`, `list_probes.py`.
**`references/`** — reference apps for precision/recall validation: `vulnerable` (accrues slop, anchor score **642**), `hardened` (clean), `minimal`, `spa`, `qa-janky`, `jsonapi`. Tests grade these to lock discrimination.
**`tests/`** — the offline gate (one file per probe/subsystem).

## Domain models (the hard-won concepts)

- **Scoring** — unbounded, deduction-only slop (lower = better); **no 0–100 normalization** (reverted, on
  purpose). Per-axis decomposition (security / qa / perf). Penalties are **risk-priced** = frequency ×
  severity. Security penalty **ceiling 40**; a variant group fires once; geometric decay within a category
  stops one weakness from dominating. Vulnerable-reference anchor = **642 / hardened = 0**.
- **Discovery parity** — *an undiscovered surface reads as a clean surface.* If the runner is blind to a
  stack's login/upload, that app scores artificially low and comparability breaks. So parity is a
  **precondition** for the score. Measure coverage **%** *and* coverage **TYPE**: five apps that each
  expose a login must yield five observed logins. `scripts/parity.py` is the instrument.
- **Three-layer timeout defense** — `build` (per-build timeout) → `grade` (per-grade, run in a forked,
  `setsid` subprocess with its own hard timeout, killed via `os.killpg`) → `app` (external batch backstop
  in `run_batch.py`). **Hard lesson:** an in-process signal (SIGALRM) *cannot* interrupt a GIL-holding
  C-spin (e.g. Playwright after the browser dies) — only an external SIGKILL of the process group works.
  Diagnosis: `ps -o etime,stat,%cpu` + `/proc/PID/wchan`; `Rl+`/98%/`wchan:0` = CPU spin (needs external
  kill); `S+`/0% = I/O wait (the grade timeout catches it). **Self-kill trap:** `pkill -f <name>` matches
  your own shell — kill by explicit PID from `/proc`.
- **Gradeability gate** — the deploy planner LLM emits `app_kind` + `web_gradeable`. Non-web apps
  (mobile / CLI / notebook / game) are **skipped, not faked** — a hollow placeholder server produces a
  meaningless score that poisons the dataset. It also emits a `features` inventory = parity ground truth.
- **Surface health** — env-var-dead endpoints (a 500 on a *well-formed* request because a Supabase/Gemini
  key is a dummy) are **baselined out** so they don't confound findings. Parity measures the
  *healthy-observed* surface, not the reached-but-broken one.
- **Build cache** — `deploy_and_grade._inject_build_cache` rewrites pip/npm installs to BuildKit cache
  mounts so downloads persist across the 3 deploy attempts *and* a timeout-kill; teardown keeps a capped
  shared slice (`--reserved-space`) so common wheels download once per batch.

## Known blind spots / open threads

- **Genuine SPA login/upload discovery misses** — on some `spa-path` apps a client-rendered
  form/input is never reached (hash-routing, formless control, or an un-rendered route). This is the
  next recall investigation. (API-login/upload false blind-spots are already fixed.)
- **API BOLA / broad data-exposure** and **SPA JS route-mining** — thinner coverage; see
  `PROJECT_LOG.md` and the validation notes.
- **Signal strength** — "winners score lower slop than non-winners" held at small n (85 vs 96); needs a
  bigger field to firm up. Batches are the way we gather that.

## When you add a probe

Every vuln class needs **comprehensive technique breadth** (e.g. SQLi = error + boolean + union + time)
that all collapse to **one** finding, plus a **precision guard** (it must not fire on the hardened
reference) and a **CI lock** (a test that pins its behavior on the reference apps). See the authoring
workflow and intent-independence litmus in `FUZZ_RUNNER_SPEC.md`.
