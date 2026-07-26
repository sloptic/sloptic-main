# HackLet fuzz runner (Stage 5 vertical slice)

Deploys a submission, probes it over HTTP, and emits a **slop score** (deduction-only, lower is
better). This is the smallest end-to-end proof of the pipeline; the catalog and sandbox grow from
here. Canonical design: [../FUZZ_RUNNER_SPEC.md](../FUZZ_RUNNER_SPEC.md).

## What the slice proves

`deploy → discover → applicability → execute → aggregate → report`, against two reference apps
with the same surface: a **vulnerable** one (accrues slop) and a **hardened** one (clean). Three
probes, one per bundle:

- `sec-sqli-001` — SQL injection via a boolean/auth-bypass **oracle** (security)
- `qa-errhyg-001` — leaked stack trace, a **declarative** matcher (qa)
- `perf-ttfb-001` — TTFB speed gate ≥ 3s (performance)

## Run it

```sh
uv run pytest -q                                          # the three-way calibration suite
uv run python -m hacklet_runner.cli --app references/vulnerable/app.py   # prints a slop report
uv run python -m hacklet_runner.cli --app references/hardened/app.py     # slop_score 0
```

## Engaging the runner (a submission)

Submissions arrive as a zip containing a `Dockerfile`. The runner unzips it safely (zip-slip and
size-capped), locates the Dockerfile (archive root or a single top-level folder), builds it, runs
the image in the sandbox, fuzzes it, and prints the slop report:

```sh
# a real submission, built + run in Docker:
uv run python -m hacklet_runner.cli --submission team.zip

# production sandbox (read-only rootfs + egress-blocked network):
docker network create --internal hacklet-fuzz-net          # one-time
uv run python -m hacklet_runner.cli --submission team.zip --harden
```

A submission that won't unzip, has no Dockerfile, won't build, or never answers `$PORT` prints
`{"status": "DNF", ...}` and exits 1 — never a runner crash. (Extraction → build context lives in
`hacklet_runner/ingest.py`; the deploy/fuzz path is identical to the reference apps below.)

### Dogfooding — aim at any live URL

The same catalog can fuzz an **already-running** endpoint with no Docker (runs on any box, including
this dev machine) — point it at the league's own site:

```sh
uv run python -m hacklet_runner.cli --target https://hackletleague.com
```

Only test targets you own or are authorized to test. The runner deploys nothing and never tears the
target down. (Discovery crawls the site and security-header checks now fan across every discovered
route. Injection probes still read N/A against a JS-rendered SPA whose forms a static crawl can't
see — the browser harness is the next step there.)

## Hosting model

The pipeline depends only on a `Deployer` (`hacklet_runner/deploy.py`):

- **`SubprocessDeployer`** (dev/CI) launches a **trusted reference app** as a local subprocess on
  an injected `$PORT`. No Docker required. **Never** used for untrusted submissions.
- **`DockerDeployer`** (production) builds the submission's `Dockerfile` and runs it in the sandbox
  on the runner host where Docker exists: ephemeral, fixed CPU/RAM/PID quotas, `--cap-drop=ALL`,
  `--security-opt=no-new-privileges`, `$PORT` injected. Everything downstream of "container answers
  `$PORT`" is identical and stack-blind. The three-way calibration runs through it and scores
  identically — that equivalence is the test (`tests/test_docker_deploy.py`).
- **`RemoteDeployer`** (dogfooding) targets an already-running URL you own or are authorized to
  test. Deploys nothing, needs no Docker, and never tears the target down.

### Hardened sandbox (production)

For untrusted submissions, enable the hardening toggles:

```py
DockerDeployer(ctx, read_only=True, network="hacklet-fuzz-net", runtime="runsc")
```

Create the egress-blocked network once (`docker network create --internal hacklet-fuzz-net`) and
install gVisor for `runtime="runsc"`. `tests/test_docker_hardened.py` verifies that hardening
preserves the 98/0/0 calibration and that the `--internal` network actually blocks egress; it
manages its own throwaway network, so it needs no setup.

## Not yet in the slice (tracked in the spec)

Browser-driven discovery (Playwright) for SPAs + FCP/INP; the hidden pool; stochastic sampling
(median-of-N); container orchestration + throughput across many submissions; gVisor/Firecracker
runtime install on the runner host.

Already wired: the composition dampers (`aggregate.py` — variant-group-once +
diminishing-returns-within-category; per-bundle ordering lives in the penalty magnitudes) and the
vuln/hardened/minimal reference triad.
