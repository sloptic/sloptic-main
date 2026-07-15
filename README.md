# HackLet fuzz runner

Point it at a web app. It probes the app over HTTP and emits a **slop score**: deduction only, lower is
better, 0 is clean. Canonical design lives in [FUZZ_RUNNER_SPEC.md](FUZZ_RUNNER_SPEC.md).

> **New here (human or agent)?** Read **[CLAUDE.md](CLAUDE.md)** (operating manual),
> **[STATE.md](STATE.md)** (where the project stands and what is next), and
> **[PROJECT_LOG.md](PROJECT_LOG.md)** (how it got here). Current shape in one line: **72 probes** across
> three bundles, discovery driven by a real browser, an LLM assisted deploy and grade pipeline plus a
> batch orchestrator in `scripts/`, and a team facing report card. Validated on 1043 real hackathon apps
> at about 1% residual false positives.

## What it does

The pipeline is `deploy → discover → applicability → execute → aggregate → report`. Two reference apps
with the same surface anchor it: a **vulnerable** one that accrues slop and a **hardened** one that stays
clean. The vulnerable app scores 642, the hardened app scores 0, and the test suite locks that gap so a
change that breaks discrimination fails CI.

The catalog covers intent independent durability: injection (SQL, XSS, SSTI, LFI, command, SSRF, XXE),
crash resistance on malformed input, security headers and CORS and CSP, exposed secrets and dotfiles and
source maps, broken access control (IDOR and missing row level security on a managed backend), Core Web
Vitals and load time and page weight, accessibility through axe-core, and HTTP correctness. Each vuln
class runs many techniques that collapse to one finding, and every probe is guarded so it never fires on
the hardened app.

## Run it

```sh
uv run pytest -q                                                          # the calibration suite
uv run python -m hacklet_runner.cli --app references/vulnerable/app.py    # prints a slop report
uv run python -m hacklet_runner.cli --app references/hardened/app.py      # slop_score 0
```

## Grade a submission

A submission arrives as a zip containing a `Dockerfile`. The runner unzips it safely (guarded against
zip slip and size bombs), finds the Dockerfile (archive root or a single top level folder), builds it,
runs the image in the sandbox, fuzzes it, and prints the report.

```sh
# built and run in Docker:
uv run python -m hacklet_runner.cli --submission team.zip

# production sandbox (read only rootfs, egress blocked network):
docker network create --internal hacklet-fuzz-net          # one time
uv run python -m hacklet_runner.cli --submission team.zip --harden
```

A submission that will not unzip, has no Dockerfile, will not build, or never answers `$PORT` prints
`{"status": "DNF", ...}` and exits 1. It never crashes the runner. Extraction and build context live in
`hacklet_runner/ingest.py`, and everything after "the container answers `$PORT`" is identical to the
reference path.

## Grade a live URL

The same catalog can fuzz an already running endpoint with no Docker, on any box including a dev machine.
This is how the runner grades a scraped hackathon whose teams already deployed.

```sh
uv run python -m hacklet_runner.cli --target https://hackletleague.com
```

Only test targets you own or are authorized to test. The runner deploys nothing and never tears the
target down. Discovery renders the site in a browser, so it reaches client rendered forms and controls a
static crawl would miss.

## Grade a whole hackathon

`scripts/deploy_and_grade.py` hands an LLM a hackathon repo or a live URL, gets back a deploy plan or a
grade target, runs it, grades it, and records the result. `scripts/run_batch.py` drives that over a whole
event, or several at once.

```sh
# every live URL across a set of hackathons, one balanced pass:
uv run python scripts/run_batch.py --hackathon hackharvard-2025 treehacks-2026 \
  --results run.jsonl --limit 250 --concurrency 6 \
  --audit-coverage --proactive --browser-auth --url-only --tldr

uv run python scripts/stats.py run.jsonl        # distribution, per probe fire counts, coverage
uv run python scripts/precision.py run.jsonl    # residual false positive audit on scored apps
uv run python scripts/parity.py run.jsonl       # observed vs expected surface, coverage per app
```

Results are append only JSONL. Re-running the same `--results` file resumes the batch and retries only
the untested or failed apps. Batches run breadth first across the slugs, so a partial or interrupted run
is still a balanced sample.

## Report card

`scripts/report_card.py` turns a graded record into per finding feedback a team can act on: what a
durable app should have done, what the runner saw, what the failure indicates, and how to fix it.

```sh
uv run python scripts/report_card.py run.jsonl --app theirapp.vercel.app            # markdown
uv run python scripts/report_card.py run.jsonl --app theirapp --html card.html      # shareable page
uv run python scripts/report_card.py run.jsonl --app theirapp --organizer           # reveal hidden checks
```

Public findings render in full, because building a real 429 or real headers is the point. Hidden pool
findings show up as an opaque count in the team card and are itemized only under `--organizer`, so a team
cannot teach to a test it cannot see. Both count toward the score the same way.

## Hosting model

The pipeline depends only on a `Deployer` (`hacklet_runner/deploy.py`).

- **`SubprocessDeployer`** (dev and CI) launches a trusted reference app as a local subprocess on an
  injected `$PORT`. No Docker. Never used for untrusted submissions.
- **`DockerDeployer`** (production) builds the submission's Dockerfile and runs it in the sandbox where
  Docker exists: ephemeral, fixed CPU and RAM and PID quotas, `--cap-drop=ALL`,
  `--security-opt=no-new-privileges`, `$PORT` injected. Everything downstream of "the container answers
  `$PORT`" is identical and stack blind. The calibration runs through it and scores the same, and that
  equivalence is the test (`tests/test_docker_deploy.py`).
- **`RemoteDeployer`** (live URL) targets an already running URL you own or are authorized to test.
  Deploys nothing, needs no Docker, never tears the target down.

### Hardened sandbox (production)

For untrusted submissions, turn on the hardening toggles.

```py
DockerDeployer(ctx, read_only=True, network="hacklet-fuzz-net", runtime="runsc")
```

Create the egress blocked network once (`docker network create --internal hacklet-fuzz-net`) and install
gVisor for `runtime="runsc"`. `tests/test_docker_hardened.py` verifies that hardening preserves the
reference calibration and that the `--internal` network actually blocks egress. It manages its own
throwaway network, so it needs no setup.
