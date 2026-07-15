# CLAUDE.md: operating manual for this repo

You are working on **hacklet-fuzz-runner**, a black box HTTP resilience grader. It deploys a web app,
probes it over HTTP, and emits a **slop score** that is deduction only, unbounded, and lower is better. It
was extracted from the `hacklet-league` monorepo to stand on its own, and this file is your orientation.
Read `STATE.md` for where things stand right now, `PROJECT_LOG.md` for how we got here, and
`FUZZ_RUNNER_SPEC.md` for the canonical design.

## The one idea

Grade the intent independent, observable resilience surface of an app, the failures that are wrong no
matter what the app is for (SQLi, stack trace leaks, missing security headers, crashes on malformed input,
slow TTFB). Humans carry intent, the question of whether a feature does what it claims. The runner carries
everything universal. The moat is the score's trustworthiness, not the number of checks. A check that
fires on a false positive is worse than a missing check, because it poisons comparability.

## Golden rules (do not violate without explicit sign-off)

1. **Test gate before every commit.** Run the offline suite and keep it green:
   ```bash
   uv run pytest -q --ignore=tests/test_docker_deploy.py --ignore=tests/test_docker_hardened.py
   ```
   The two ignored files spin real Docker containers with reused names, so run them only when Docker is
   free. Browser tests need the browser group (see Run recipes). Without it, exclude `tests/test_browser.py`
   and the other render dependent files. A green run is about 347 passing (365 with Docker and a browser).
2. **One commit per change.** End every code writing turn with a ready to paste commit command.
   Conventional commit style, scope in parens, `+`-join related parts:
   `feat(discovery): infer field names for anonymous SPA inputs`. Put the why in the body.
3. **Results are append only JSONL.** Never rewrite a results or parity file in place. A crash mid write
   must not corrupt prior rows. Dedup happens at read time, keeping the latest row per repo by timestamp
   (see `scripts/stats.py`). We do not want corrupted files.
4. **This pipeline runs untrusted code.** `deploy_and_grade.py` builds and runs arbitrary hackathon repos
   in Docker. Only ever run a batch on a sandboxed, firewalled box. See the threat model in
   `FUZZ_RUNNER_SPEC.md`.
5. **The grader must never change its own session's credentials.** Password change and password reset forms
   are withheld from submission (`auth.is_password_change_form`). A grader that resets the admin password
   locks itself, and every later probe, out. Do not "fix" that withholding.
6. **Never commit the hidden probe pool.** The real precision boundary is a separate private fuzz-catalog
   repo. `**/hidden/` and `catalog-hidden/` are gitignored as a backstop. Keep it that way, especially if
   this repo goes public.

## Run recipes

```bash
# one time
uv sync                                  # core deps (httpx, pydantic, pyyaml, pytest)
uv sync --group browser && uv run playwright install chromium   # for browser-based discovery/grading

# grade a single live target (no LLM, no Docker), the pure grader
uv run python -m hacklet_runner.cli --target http://host:port [--no-browser]

# LLM-assisted: clone a repo or take a URL, plan a Docker deploy, run it, grade it, tear it down
uv run python scripts/deploy_and_grade.py --record out.jsonl https://github.com/u/r
uv run python scripts/deploy_and_grade.py --record out.jsonl --url https://theirapp.vercel.app

# full batch across one or more hackathons: gallery -> deploy+grade each -> stats -> parity
uv run python scripts/run_batch.py --hackathon <slug ...> --results out.jsonl [--limit N] --url-only

# read a finished batch
uv run python scripts/stats.py out.jsonl            # slop distribution, per probe fire counts, coverage
uv run python scripts/precision.py out.jsonl        # residual false positive audit on scored apps
uv run python scripts/parity.py out.jsonl           # observed vs expected surface, coverage per app
uv run python scripts/report_card.py out.jsonl --app <substr>   # a team's per finding report card
uv run python scripts/list_probes.py                # the catalog
```

**Environment:** `OPENROUTER_API_KEY` (required for deploy planning and the LLM perception and audit
passes). `OPENROUTER_MODEL` (default `qwen/qwen3.7-plus`, cheap and strong at abstaining rather than
hallucinating). `HL_BUILD_CACHE_CAP` (default `20GB`, the per batch build cache reserve). Reasoning is off
by default on the perception and audit calls (`reasoning: {enabled: false}`). `--llm-reasoning` turns it
back on. Export the key for a terminal session before a batch.

## Architecture map

**`hacklet_runner/`**, the grader core (deterministic, the LLM never sets the score):

| module | role |
|---|---|
| `pipeline.py` | `run(deployer, catalog, ...)` orchestrates discover, applicability, execute, aggregate, into a `Report`. Caches the discovered surface per commit so a re-grade replays the exact crawl. |
| `discovery.py` | the Discovery Profile (routes, forms, endpoints, capabilities), browser multi route render, `surface_metrics` (healthy observed surface), endpoint baselining (dead endpoints), feature seeding. |
| `probes.py` | probe execution. Injection (SQLi, XSS, SSTI, LFI, cmdi, XXE, SSRF), crash resistance, headers, CORS, compression, and more. Each vuln class runs comprehensive techniques that collapse to one finding. `MATCHERS` and `PREDICATES` are the primitive registries. |
| `aggregate.py` | scoring. Deduction only slop, dampers (variant group fires once, within category geometric decay `CATEGORY_DECAY=0.6`), `coverage_metrics`. |
| `reportcard.py` | turns a graded record into per finding feedback (expected, actual, indicates, fix), with public and hidden pool disclosure tiers. |
| `schema.py` | `Report`, `Profile`, `Endpoint`, `Outcome`, `Probe` dataclasses (surface, coverage, timings, and `pool` on `Probe`). |
| `auth.py` | login detection (form and JSON API), self registration, the password change withholding. |
| `browser.py` | Playwright render (`render_routes` batch, system Chrome fallback), browser driven SPA registration. |
| `deploy.py` | `RemoteDeployer` and target/URL handling. |
| `catalog.py` | loads the probe YAMLs. |
| `secretscan.py`, `openapi.py`, `jsmine.py`, `oob.py`, `perf.py`, `net.py`, `ingest.py` | source secret scan, OpenAPI ingest, JS route mining, out of band, perf sampling, net helpers, untrusted zip ingest (zip slip guarded). |

**`catalog/`**, 72 probe YAMLs: `security/` (47), `qa/` (13), `performance/` (12).
**`scripts/`**, the deploy and batch pipeline plus the readers: `deploy_and_grade.py`, `run_batch.py`,
`devpost_repos.py`, `stats.py`, `precision.py`, `parity.py`, `report_card.py`, `list_probes.py`. The LLM
perception and audit passes live in `deploy_and_grade.py`.
**`references/`**, reference apps for precision and recall: `vulnerable` (accrues slop, anchor score
**642**, axis `{security 416, qa 158, performance 68}`), `hardened` (clean), `minimal`, `spa`, `qa-janky`,
`jsonapi`. Tests grade these to lock discrimination.
**`tests/`**, the offline gate, one file per probe or subsystem.

## Domain models (the hard-won concepts)

- **Scoring.** Unbounded, deduction only slop, lower is better. No 0 to 100 normalization (reverted, on
  purpose). Per axis decomposition (security, qa, perf). Penalties priced by risk, frequency times
  severity. Security penalty ceiling 40, a variant group fires once, geometric decay within a category
  stops one weakness from dominating. Vulnerable anchor 642, hardened 0.
- **The LLM's bounded role.** The LLM decides where to look and flags what discovery missed. It never sets
  the score. Two passes, both in `deploy_and_grade.py`: a perception pass (`perceive_surface`) that seeds
  proactive discovery, verified by the deterministic probes, and an off score coverage auditor
  (`audit_coverage`) that reports missed surface to a human. A hallucinated pointer makes a probe fire on
  nothing, which no-ops, so a bad pointer only ever discovers less, never changes the score. Determinism
  comes from temp-0 plus the per commit surface cache, not from the model being steady.
- **Precision is the product.** A false positive is worse than a miss. `scripts/precision.py` measures
  residual false positives on scored apps. The last full run sat near 1% across 1043 real hackathon apps,
  down from about 32% early on. Broken and placeholder apps rank DNF class, below every running app, so
  they never score a misleading clean zero.
- **Discovery parity.** An undiscovered surface reads as a clean surface. If the runner is blind to a
  stack's login or upload, that app scores artificially low and comparability breaks, so parity is a
  precondition for the score. Measure coverage percent and coverage type. Five apps that each expose a
  login must yield five observed logins. `scripts/parity.py` is the instrument.
- **The layered timeout defense.** `build` (per build timeout), then `grade` (per grade, run in a forked
  `setsid` subprocess with its own hard timeout, killed via `os.killpg`), then `app` (an external batch
  backstop in `run_batch.py`). Hard lesson: an in process signal (SIGALRM) cannot interrupt a GIL holding
  C spin, for instance Playwright after the browser dies. Only an external SIGKILL of the process group
  works. Diagnose with `ps -o etime,stat,%cpu` and `/proc/PID/wchan`. `Rl+` at 98% with `wchan:0` is a CPU
  spin that needs the external kill. `S+` at 0% is I/O wait that the grade timeout catches. Self kill trap:
  `pkill -f <name>` matches your own shell, so kill by explicit PID from `/proc`.
- **Gradeability gate.** The deploy planner LLM emits `app_kind` and `web_gradeable`. Non-web apps (mobile,
  CLI, notebook, game) are skipped, not faked. A hollow placeholder server produces a meaningless score
  that poisons the dataset. It also emits a `features` inventory, which is parity ground truth.
- **Surface health.** Endpoints that 500 on a well formed request because a Supabase or Gemini key is a
  dummy are baselined out so they do not confound findings. Parity measures the healthy observed surface,
  not the reached but broken one.
- **Build cache.** `deploy_and_grade._inject_build_cache` rewrites pip and npm installs to BuildKit cache
  mounts so downloads persist across the 3 deploy attempts and a timeout kill. Teardown keeps a capped
  shared slice so common wheels download once per batch.

## Known blind spots and open threads

- **SPA action discovery.** The coverage auditor still flags client side action buttons that discovery
  misses on some SPAs. Proactive perception recovers a lot of this, but its endpoint precision is low
  (it perceives many candidate paths and most 404), so it is off score by design. Forms are the reliable
  part. This is the standing recall frontier.
- **Deep authenticated CRUD probes read N/A on the URL cohort.** Data integrity round-trip, the race
  probe, and three of the four IDOR probes need two registered accounts and a real server side create and
  read, which scraped SPAs and platform pages do not offer. That is correct, not a bug. They fire on the
  league's self contained builds. See `STATE.md`.
- **Two residual false positive classes.** Rate limiting on third party platform logins (the "is this the
  team's own app" question), and Web Vitals variance from free tier cold starts. Both are better
  characterized by a live pilot than by more scraping.

## When you add a probe

Every vuln class needs comprehensive technique breadth (SQLi is error, boolean, union, and time) that all
collapse to one finding, plus a precision guard so it never fires on the hardened reference, plus a CI
lock, a test that pins its behavior on the reference apps. See the authoring workflow and the intent
independence litmus in [CONTRIBUTING.md](CONTRIBUTING.md) and `FUZZ_RUNNER_SPEC.md`.
