#!/usr/bin/env python3
"""LLM-assisted deploy + grade for a hackathon repo (Devpost / GitHub).

Clone a repo, ask an LLM (via OpenRouter) HOW to deploy it — a Dockerfile, an optional DB sidecar, env,
and a migrate step — then execute that plan on a throwaway docker network, iterating on build/run/health
failures by feeding the error back to the LLM, and finally grade the running app with the fuzz-runner.
The LLM ONLY figures out the deploy; the fuzzer does the grading.

    export OPENROUTER_API_KEY=sk-or-...
    # optional: export OPENROUTER_MODEL=...   (default qwen/qwen3.7-plus — cheap + a strong anti-hallucinator,
    #   which this identify-the-app task needs; retries can web-search for stack versions it doesn't know)
    uv run python scripts/deploy_and_grade.py https://github.com/user/repo   # browser grade (default)
    uv run python scripts/deploy_and_grade.py --no-browser --attempts 4 https://github.com/user/repo
    uv run python scripts/deploy_and_grade.py /path/to/local/repo            # skip the clone

Safety: builds + runs UNTRUSTED code in Docker. Run it on a sandbox/firewalled box (your RMM workstation
is ideal). It does NOT inject real secrets — an app needing an external API key may only partly boot; the
grader still probes whatever comes up.
"""
import argparse
import contextlib
import hashlib
import json
import multiprocessing as mp
import os
import pathlib
import queue
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from collections import Counter, defaultdict
from urllib.parse import urlsplit

import httpx

_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from hacklet_runner import browser  # noqa: E402
from hacklet_runner.jsonl import append_jsonl  # noqa: E402
from hacklet_runner.scope import off_target  # noqa: E402
from hacklet_runner.aggregate import CATEGORY_DECAY, _damped_total  # noqa: E402
from hacklet_runner.catalog import load_catalog  # noqa: E402
from hacklet_runner.deploy import RemoteDeployer  # noqa: E402
from hacklet_runner.pipeline import run  # noqa: E402
from hacklet_runner.schema import profile_from_dict, profile_to_dict  # noqa: E402


def _axis_str(axis: dict) -> str:
    return " · ".join(f"{b} {round(axis[b])}" for b in ("security", "qa", "performance") if b in axis)


# input/payload evidence keys — what MADE a probe fire (the malformed body, injection string, field). Config
# checks (headers/seo) have none, so they get no trigger line; only payload-bearing findings show one.
_TRIGGER_KEYS = ("payload", "value", "technique", "where", "param", "field", "filename")


def _trigger_str(ev: dict) -> str:
    parts = [f"{k}={ev[k]}" for k in _TRIGGER_KEYS if ev.get(k) not in (None, "", [], {})]
    if parts and ev.get("target"):
        parts.insert(0, f"@{ev['target']}")
    return "  ".join(str(p) for p in parts)[:96]

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
# Cheap + WELL-CALIBRATED: this task hinges on the LLM admitting "not a web app" / not inventing features.
# Qwen3.7 Plus ($0.32/$1.28, 1M context) is a strong anti-hallucinator — the 3.7 generation halved
# AA-Omniscience hallucination (44%->23% on Max, best in group) by ABSTAINING rather than guessing, which
# is exactly the instinct the gradeability gate needs. Recency of stack knowledge is handled separately by
# web-search on retries (see plan_deploy `online`), so the base model needn't be bleeding-edge. Override
# with OPENROUTER_MODEL (e.g. qwen/qwen3.7-max for even lower hallucination, openai/gpt-5-mini for OpenAI).
DEFAULT_MODEL = os.environ.get("OPENROUTER_MODEL", "qwen/qwen3.7-plus")
AUDIT_TIMEOUT_S = 180   # HARD wall-clock cap on ONE coverage-audit LLM call (p75 was 43s; a hang once hit 1486s)
NET = "hl-deploy-net"
APP = "hl-deploy-app"
DB = "hl-db"
# after each app, keep at most this much build cache (LRU): enough to hold the shared pip/npm wheels that
# later apps in the batch reuse, capped so it can't grow unbounded. Docker 29's flag for the old
# --keep-storage. Override for a bigger/smaller disk budget.
_BUILD_CACHE_CAP = os.environ.get("HL_BUILD_CACHE_CAP", "20GB")
DB_CREDS = {"user": "hacklet", "password": "hacklet", "db": "hacklet"}


class DeployError(Exception):
    """A build/run/health failure whose message is fed back to the LLM for a revised plan."""


# ---- docker helpers -------------------------------------------------------------------------------

def _docker(*args, timeout=None, check=False):
    p = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise DeployError((p.stderr or p.stdout)[-3000:])
    return p


_STEP = re.compile(r"^#\d+ \[[^\]]*\d+/\d+\]\s+(.+)")   # BuildKit step header, e.g. "#5 [2/6] RUN npm ci"
_STEP_LEGACY = re.compile(r"^Step \d+/\d+ : (.+)")       # legacy builder
_META = re.compile(r"load metadata for (\S+)")


def _build_streamed(dockerfile, ctx, verbose=False, timeout=1200):
    """docker build. verbose -> stream every line (prefixed '│'). Otherwise print only the high-level
    steps: base-image pull, each RUN/COPY/WORKDIR instruction (so 'RUN npm install' / 'RUN pip install
    -r requirements.txt' are visible), and errors — with a heartbeat during long steps. Always captures
    the tail for the LLM error-feedback loop."""
    proc = subprocess.Popen(["docker", "build", "-f", str(dockerfile), "-t", APP, str(ctx)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    lines, start, dots = [], time.time(), 0
    for line in proc.stdout:
        lines.append(line)
        if verbose:
            sys.stderr.write("    │ " + line)
            sys.stderr.flush()
        else:
            step = _STEP.match(line) or _STEP_LEGACY.match(line)
            meta = _META.search(line)
            if step or meta or (line.startswith("#") and "ERROR" in line):
                if dots:
                    sys.stderr.write("\n"); dots = 0
                if step:
                    sys.stderr.write("    ▸ " + step.group(1).split("@sha256:")[0].strip()[:90] + "\n")
                elif meta:
                    sys.stderr.write("    ▸ pulling base image " + meta.group(1) + "\n")
                else:
                    sys.stderr.write("    ✗ " + line.strip()[:120] + "\n")
                sys.stderr.flush()
            elif line.strip():          # suppressed detail -> a heartbeat so long installs show life
                dots += 1
                if dots % 80 == 0:
                    sys.stderr.write("."); sys.stderr.flush()
        if time.time() - start > timeout:
            proc.kill()
            lines.append("\n(build exceeded %ds — killed)" % timeout)
            break
    if dots:
        sys.stderr.write("\n")
    proc.wait()
    return proc.returncode, "".join(lines)[-3000:]


# pip/npm/apt downloads are the slow step of a build, and on a low-bandwidth box a heavy-deps app can blow the
# build timeout on downloads ALONE — then each retry re-downloads from scratch, so a marginally-too-heavy
# app stays too heavy forever. A BuildKit cache mount banks those downloads OUTSIDE the image layer, in the
# daemon's build cache, so they persist across the 3 attempts — and even across a timeout-KILLed build: the
# cache ref survives cancellation, and pip re-fetches any half-written wheel via its own hash check. Per-app
# _teardown keeps a size-capped slice, so packages one app downloads are REUSED by the next — the whole point
# on a package-overlapping cohort. BuildKit is the default builder here (Docker 23+), so the mount flag needs
# no `# syntax=` directive. Each package manager gets ITS OWN cache dir (npm's dir does nothing for yarn/pnpm);
# apt additionally needs its docker-clean hook stripped (the base image auto-deletes the .debs, which would
# defeat the mount) and sharing=locked (dpkg isn't concurrency-safe across the parallel builds). --no-cache-dir
# is stripped because it defeats the very cache we add (the mount keeps the wheels out of the image layer anyway).
_PIP_INSTALL = re.compile(r"\bpip[0-9.]*\s+install\b")
_NPM_INSTALL = re.compile(r"\bnpm\s+(?:install|ci|i)\b")
_YARN_INSTALL = re.compile(r"\byarn\b(?!\s+(?:run|build|start|test|dev|lint)\b)")
_PNPM_INSTALL = re.compile(r"\bpnpm\s+(?:install|i|add)\b")
_APT_INSTALL = re.compile(r"\bapt(?:-get)?\s+install\b")
_NO_CACHE_DIR = re.compile(r"\s--no-cache-dir\b")
_APT_DECLEAN = "rm -f /etc/apt/apt.conf.d/docker-clean;"   # else the base image auto-deletes the cached .debs


def _inject_build_cache(dockerfile: str) -> str:
    """Add a persistent pip/npm download cache mount to each RUN that installs deps, so retries (and, once
    teardown keeps a capped cache, the next app) reuse what a prior — possibly timed-out — build already
    pulled. Formatting-preserving: only the `RUN` token of a matching instruction is rewritten; its
    backslash-continued lines are left as-is (the mount applies to the whole instruction regardless)."""
    lines = dockerfile.splitlines()
    out = list(lines)
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)RUN(\s+)(.*)$", lines[i])
        if not m:
            i += 1
            continue
        j = i                                      # extend over backslash-continued lines -> one logical RUN
        while lines[j].rstrip().endswith("\\") and j + 1 < len(lines):
            j += 1
        body = "\n".join(lines[i:j + 1])
        mounts, prefix = [], ""
        if _PIP_INSTALL.search(body):
            mounts.append("--mount=type=cache,target=/root/.cache/pip")
        if _NPM_INSTALL.search(body):
            mounts.append("--mount=type=cache,target=/root/.npm")
        if _YARN_INSTALL.search(body):
            mounts.append("--mount=type=cache,target=/usr/local/share/.cache/yarn")
        if _PNPM_INSTALL.search(body):
            mounts.append("--mount=type=cache,target=/root/.local/share/pnpm/store")
        if _APT_INSTALL.search(body):    # cache the .debs; strip docker-clean (else they're auto-deleted)
            mounts.append("--mount=type=cache,target=/var/cache/apt,sharing=locked")
            prefix = _APT_DECLEAN + " "
        if mounts and "--mount=" not in lines[i]:   # don't double-inject if the LLM already added one
            out[i] = f"{m.group(1)}RUN {' '.join(mounts)} {prefix}{m.group(3)}"
        for k in range(i, j + 1):                   # --no-cache-dir defeats the cache we just added -> drop
            out[k] = _NO_CACHE_DIR.sub("", out[k])
        i = j + 1
    return "\n".join(out)


def _teardown():
    _docker("rm", "-f", "-v", APP, DB)   # -v reaps the sidecar's anonymous data volume (else it orphans)
    _docker("network", "rm", NET)
    _docker("rmi", "-f", APP)   # drop this repo's app image; base images stay cached (speeds later builds)
    # Reclaim build cache but KEEP a size-capped slice: the pip/npm cache mounts (heavy ML wheels,
    # node_modules) download once and are reused by later apps in the batch — on a low-bandwidth box that
    # cross-app reuse is the whole point. --reserved-space keeps up to _BUILD_CACHE_CAP of the most-recent
    # cache and LRU-evicts the rest, so it can't grow unbounded; base *images* live in `docker images`,
    # untouched, so later builds still skip the base-image pull.
    _docker("builder", "prune", "-f", "--reserved-space", _BUILD_CACHE_CAP)


# ---- 1. clone + gather deploy context -------------------------------------------------------------

_CONTEXT_FILES = ("README.md", "README", "readme.md", "package.json", "requirements.txt", "Pipfile",
                  "pyproject.toml", "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
                  "Procfile", ".env.example", ".env.sample", "go.mod", "Gemfile", "composer.json",
                  "next.config.js", "vite.config.js", "app.py", "main.py", "server.js", "index.js",
                  "manage.py", "wsgi.py", "asgi.py")


class CloneError(Exception):
    """git clone failed or timed out. A timeout ('took forever to clone' — usually a huge / Git-LFS repo)
    is itself a signal, so it's recorded distinctly instead of crashing the run with a traceback."""


def clone(url_or_path: str, timeout: int = 300) -> pathlib.Path:
    if pathlib.Path(url_or_path).exists():
        return pathlib.Path(url_or_path).resolve()
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="hl-deploy-"))
    dest = tmp / "repo"
    print(f"  cloning {url_or_path} ...")
    try:
        p = subprocess.run(["git", "clone", "--depth", "1", url_or_path, str(dest)],
                           capture_output=True, text=True, timeout=timeout)
        if p.returncode != 0:
            raise CloneError(f"clone failed: {p.stderr.strip()[:200]}")
    except (subprocess.TimeoutExpired, CloneError) as e:
        shutil.rmtree(tmp, ignore_errors=True)   # don't leak a partial/huge clone on failure
        raise CloneError(f"CLONE TIMEOUT (>{timeout}s)"
                         if isinstance(e, subprocess.TimeoutExpired) else str(e))
    return dest


def _record_plan_meta(result: dict, plan: dict) -> None:
    """Copy the LLM's identification (kind + stack + source-implied surface + features) onto the record —
    recorded even when the app is skipped or fails to deploy, so the stack/kind DISTRIBUTION and the
    parity ground-truth don't drop those apps."""
    for k in ("app_kind", "web_gradeable", "stack", "stack_profile", "expected_surface", "features"):
        result[k] = plan.get(k)


def gather_context(repo: pathlib.Path) -> str:
    tree = subprocess.run(["bash", "-c",
                           f"cd {repo} && (git ls-files 2>/dev/null || find . -type f) "
                           "| grep -vE 'node_modules/|\\.git/|dist/|build/|venv/' | head -200"],
                          capture_output=True, text=True).stdout
    parts = [f"REPO FILE TREE (truncated):\n{tree}"]
    seen = set()
    for pat in _CONTEXT_FILES:
        for f in list(repo.rglob(pat))[:2]:
            if f.is_file() and f not in seen and "node_modules" not in f.parts and ".git" not in f.parts:
                seen.add(f)
                try:
                    body = f.read_text(encoding="utf-8", errors="replace")[:4000]
                except OSError:
                    continue
                parts.append(f"\n===== {f.relative_to(repo)} =====\n{body}")
    return "\n".join(parts)[:24000]


# ---- 2. ask the LLM for a deploy plan -------------------------------------------------------------

_SYSTEM = """You are a deployment engineer. Given a hackathon repo, output a JSON plan to build and run it
in Docker for black-box testing. Respond with ONLY a JSON object, no prose, no markdown fences.

Constraints and environment you are targeting:
- A shared docker network. If the app needs a database, request a sidecar; it will be reachable at
  hostname "hl-db" on the standard port. Credentials are user=hacklet password=hacklet db=hacklet.
- The app MUST bind 0.0.0.0 (not 127.0.0.1) and listen on the "port" you specify.
- Do NOT rely on real third-party secrets/API keys. If the app reads env vars, provide harmless
  defaults in app_env so it boots as far as possible; note in "notes" anything that won't work.
- Prefer generating a fresh, correct Dockerfile over a broken existing one. Pin dependency versions that
  are known to be mutually compatible (e.g. Flask 2.0.x needs Werkzeug 2.0.x). Install deps, copy the
  app code (many repos' Dockerfiles forget to COPY the code), set the workdir, expose the port.
- Installs are cached across retries by a BuildKit mount that is injected for you, so DO NOT pass pip's
  --no-cache-dir (it defeats the cache). Just write normal `RUN pip install -r requirements.txt` /
  `RUN npm ci` lines. If a build times out on heavy deps, on retry TRIM the dependency set (drop
  ML/GPU/build-only packages the web surface doesn't need) rather than re-pinning the same heavy wheels.

FIRST, decide whether this repo is even a RUNNABLE WEB SERVICE a black-box HTTP tester can grade. Many
hackathon repos are NOT: native mobile apps (iOS/Swift/SwiftUI, Android/Kotlin, React Native, Flutter),
CLIs / libraries, desktop-native apps, Discord/Slack bots, Jupyter/ML notebooks or training scripts,
games (Unity/Unreal/Pygame), hardware/embedded. If it is NOT something you can serve over HTTP, set
"web_gradeable": false with the right "app_kind", and DO NOT fabricate a placeholder server just to pass
the health check (a hollow server produces a meaningless slop score that poisons the dataset) — leave the
deploy fields empty. Only when web_gradeable is true do you need a real Dockerfile / port / health_path.

Then IDENTIFY THE TECH STACK (stack_profile), the user-facing surface (expected_surface), and inventory
the app's actual FEATURES from the code (features). Base everything on the code you SEE — routes,
components, models, forms, framework config — not guesses; if unsure, prefer fewer claims over invented
ones. Routing especially matters: a hash-routed SPA (React HashRouter, `/#/route`, common on GitHub
Pages) is discovered very differently from a path-routed SPA or a server-rendered app.

JSON schema (all keys required unless marked optional):
{
  "app_kind": "one of: web-app | web-api | static-site | cli | library | mobile | desktop | bot | notebook-ml | game | other",
  "web_gradeable": true,     // false => a black-box HTTP grader can't assess it; SKIP deploy, do NOT fake a server
  "stack": "short description, e.g. 'React hash-routed SPA' or 'Flask + Jinja + Postgres' or 'iOS SwiftUI app'",
  "stack_profile": {
    "framework": "primary framework/library: React|Next.js|Vue|Svelte|Angular|Flask|Django|FastAPI|Express|Rails|SwiftUI|... or 'static'",
    "routing": "one of: spa-hash | spa-path | ssr | server-rendered | static | api-only | none",
    "frontend": "e.g. 'React SPA' | 'server-rendered templates' | 'none'",
    "backend": "e.g. 'Flask' | 'Express' | 'none (static site)'",
    "api_style": "one of: rest | graphql | none"
  },
  "expected_surface": {
    "login": true, "signup": false, "upload": false, "search": false, "api": true,
    "views": 5
  },
  "features": [   // the app's actual features/operations inferred FROM THE CODE — ground truth for fine-grained
                  // parity AND injection targeting. Each: {name, kind, path?, method?, params?, body_fields?}.
                  // kind in: form|crud-create|crud-read|crud-update|crud-delete|search|upload|auth|realtime|payment|other.
                  // params = the query-string input NAMES the endpoint reads; body_fields = the JSON/form
                  // request-body property NAMES it reads. Take these VERBATIM from the source — ONLY names that
                  // actually appear in the code (never invent one to "help"); [] when the endpoint takes none.
                  // This is the input surface a crawler can't see; the deterministic security probes inject into
                  // exactly these names, so precise names = real coverage, a wrong name just harmlessly no-ops.
                  // [] features if none/unsure. e.g.:
    {"name": "create project", "kind": "crud-create", "path": "/projects", "method": "post", "body_fields": ["title", "description"]},
    {"name": "delete project", "kind": "crud-delete", "path": "/projects/{id}", "method": "delete"},
    {"name": "semantic search", "kind": "search", "path": "/api/search", "method": "get", "params": ["q", "limit"]},
    {"name": "download report", "kind": "crud-read", "path": "/download", "method": "get", "params": ["file"]}
  ],
  "dockerfile": "the FULL Dockerfile text to write at the build_context root (may be \"\" if web_gradeable is false)",
  "files": { "relative/path": "full file contents to overwrite/create (repairs, e.g. a fixed requirements.txt)" },  // optional, may be {}
  "build_context": ".",                       // subdir (relative to repo root) holding the app
  "port": 8000,                                // the port the app listens on inside the container
  "app_env": { "KEY": "value" },               // env for the app container (DB url, harmless defaults)
  "db": { "type": "postgres|mysql|mongo|none", "image": "postgres:16-alpine", "env": {"POSTGRES_USER":"hacklet","POSTGRES_PASSWORD":"hacklet","POSTGRES_DB":"hacklet"} },
  "migrate": "optional shell command to run in the app image before serving (e.g. 'flask db upgrade'), or empty string",
  "health_path": "/",                          // a path that returns <500 when the app is up
  "notes": "anything the grader should know"
}
If a previous attempt failed, you will be given the error — fix the specific cause (missing COPY, wrong
port, dep conflict, missing build tool, wrong start command, DB not ready, etc.)."""


def plan_deploy(context: str, model: str, error: str = "", prev: dict = None, online: bool = False) -> dict:
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        sys.exit("OPENROUTER_API_KEY is not set. export it and re-run.")
    user = f"REPO CONTEXT:\n{context}"
    if error:
        user += (f"\n\nThe PREVIOUS plan FAILED. Previous plan:\n{json.dumps(prev)[:3000]}"
                 f"\n\nError output:\n{error[:4000]}\n\nReturn a corrected JSON plan.")
    # temperature 0: greedy decoding makes the source-read (deploy plan + feature SEED) as reproducible as an
    # LLM gets — same repo -> near-same plan. Combined with the per-commit plan CACHE (see main), the LLM's
    # contribution is frozen, so re-grading identical code can't yield a different score (the fairness bug).
    body = {"model": model, "temperature": 0,
            "messages": [{"role": "system", "content": _SYSTEM}, {"role": "user", "content": user}]}
    if online:   # retries: let the model WEB-SEARCH for current dep versions / deploy config it may not know
        body["plugins"] = [{"id": "web", "max_results": 3, "search_prompt":
                            "Use these web results for CURRENT dependency versions, framework config, and "
                            "Docker/build setup for this stack (the app may use versions newer than your "
                            "training data):"}]
    try:
        r = httpx.post(OPENROUTER_URL, json=body, timeout=120,
                       headers={"Authorization": "Bearer " + key,
                                "HTTP-Referer": "https://hacklet.league", "X-Title": "hacklet-deploy"})
    except httpx.HTTPError as e:
        sys.exit(f"OpenRouter request failed: {e}")
    if r.status_code != 200:
        sys.exit(f"OpenRouter {r.status_code}: {r.text[:400]}")
    content = r.json()["choices"][0]["message"]["content"]
    m = re.search(r"\{.*\}", content, re.S)   # tolerate stray prose / code fences
    if not m:
        sys.exit(f"LLM did not return JSON:\n{content[:400]}")
    return json.loads(m.group(0))


# ---- 2a. per-commit plan cache: freeze the LLM's contribution for COMPUTATIONAL reproducibility ---
# The LLM is a discovery/deploy POINTER, never a scorer — but at temp>0 it still drifts run-to-run, so
# re-grading identical code could deploy differently or seed a different surface -> a different score. That
# is a fairness violation (an appeal must re-grade to the same number). Fix: cache the SUCCESSFUL plan
# (Dockerfile + features + stack) keyed by the immutable commit SHA. Same commit -> same frozen plan ->
# same deploy + same discovery seed -> reproducible. Freezing the LLM is only HALF, though: the browser
# crawl + interaction clicking add their OWN timing non-determinism (2b caches the discovered SURFACE too).
_CACHE_DIR = pathlib.Path(os.environ.get("HL_CACHE_DIR", pathlib.Path.home() / ".cache" / "hacklet-plan"))


def _git_sha(repo: pathlib.Path):
    """The cloned repo's commit SHA — the immutable identity a cached plan is keyed to. None for a local
    non-git path (no stable identity, so no caching — a local checkout can change under us)."""
    with contextlib.suppress(Exception):
        r = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    return None


def _plan_cache_path(repo_url: str, sha: str) -> pathlib.Path:
    return _CACHE_DIR / (hashlib.sha256(f"{repo_url}@{sha}".encode()).hexdigest()[:24] + ".json")


def load_cached_plan(repo_url: str, sha):
    """The frozen plan for this exact (repo, commit), or None. Reused verbatim so the deploy + discovery
    seed are identical to the first grade — the source of computational reproducibility."""
    if not sha:
        return None
    p = _plan_cache_path(repo_url, sha)
    if p.exists():
        with contextlib.suppress(Exception):
            return json.loads(p.read_text())
    return None


def store_cached_plan(repo_url: str, sha, plan: dict) -> None:
    """Freeze the plan that WORKED (deployed + graded) for this commit, so every later run reuses it."""
    if not sha:
        return
    with contextlib.suppress(Exception):
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _plan_cache_path(repo_url, sha).write_text(json.dumps(plan))


# ---- 2b. per-commit SURFACE cache: freeze the DISCOVERED surface (crawl + interaction) too ---------
# The plan cache froze the LLM; this freezes the browser. discover() renders + clicks reveal-triggers, and
# that carries timing non-determinism a modal that loads slowly on one run, not the next => a different
# surface => a different score on IDENTICAL code. So on the FIRST grade we mint the canonical surface and
# freeze it (keyed by the same commit SHA); every re-grade reuses it verbatim and skips the crawl entirely
# (relative paths transplant onto the fresh deployment; only base_url re-binds). Repo/zip only — a --url is
# inherently point-in-time (the live site drifts), so it always re-discovers and the record IS the capture.
def _profile_cache_path(repo_url: str, sha: str) -> pathlib.Path:
    return _CACHE_DIR / (hashlib.sha256(f"{repo_url}@{sha}".encode()).hexdigest()[:24] + ".surface.json")


def load_cached_profile(repo_url: str, sha):
    """The frozen discovered surface for this exact (repo, commit) as a Profile, or None on miss/no-sha/
    parse error (best-effort — a miss just re-crawls). Companion to load_cached_plan; a commit can have a
    frozen plan but no surface yet (deployed, but its first grade hasn't finished discovery)."""
    if not sha:
        return None
    p = _profile_cache_path(repo_url, sha)
    if p.exists():
        with contextlib.suppress(Exception):
            return profile_from_dict(json.loads(p.read_text()))
    return None


def store_cached_profile(repo_url: str, sha, profile) -> None:
    """Freeze the canonical surface discovered on this commit's first grade (called from the grade worker
    the instant discovery completes, before probing — the surface is a complete artifact regardless of
    whether probing later times out)."""
    if not sha:
        return
    with contextlib.suppress(Exception):
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _profile_cache_path(repo_url, sha).write_text(json.dumps(profile_to_dict(profile)))


# ---- 2b. LLM coverage auditor: catch surface the DETERMINISTIC discovery missed -------------------
# The same LLM that plans deploys reads the live page and flags interactive surface our fuzzer's
# discovery didn't capture (an AfroSecured-style upload behind an oddly-labelled button, a login the
# regexes didn't classify) + placeholder/broken pages. Its findings are NOTED on the record so the
# misses accumulate into a fixable backlog instead of silently under-grading. Best-effort: any failure
# returns None and the grade proceeds — the audit never breaks a run.

_AUDIT_SYSTEM = """You audit a black-box web fuzzer's DISCOVERY coverage. You get (1) a compact map of a
web page's ACTUAL interactive surface, and (2) what the fuzzer's automated discovery OBSERVED. Find
SURFACE THE FUZZER MISSED — controls a user can clearly use that the observed surface does NOT represent:
a login/signup, a file UPLOAD (incl. drag-drop or an 'Add evidence'/'Attach'-style button), a search box,
a key create/submit action, a form. Flag a miss ONLY when the page CLEARLY has it AND observed lacks it —
never invent surface. Also classify the page state.
Respond with ONLY a JSON object, no prose/markdown:
{"missed": [{"kind": "login|signup|upload|search|form|action|other", "label": "the on-page label",
  "why": "why discovery likely missed it"}],
 "page_state": "working | placeholder | broken | login-wall | not-an-app",
 "notes": "one short line"}
Empty "missed": [] when the observed surface already covers the page."""


def _surface_skeleton(dom: str) -> str:
    """A compact map (~1-2KB) of a rendered page's interactive surface for the auditor: headings, button/
    link labels, input types+names, form actions, and a visible-text snippet. Small enough to be cheap,
    rich enough for the LLM to reason 'there's clearly an upload here that observed doesn't have'."""
    def _t(h):
        return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", h)).strip()
    labels = []
    for m in re.findall(r"<(?:button|a)\b[^>]*>(.*?)</(?:button|a)>", dom, re.S | re.I):
        t = _t(m)[:40]
        if t and t not in labels:
            labels.append(t)
    inputs = []
    for tag in re.findall(r"<input\b[^>]*>|<textarea\b[^>]*>|<select\b[^>]*>", dom, re.I):
        typ = (re.search(r'type=["\']?([a-zA-Z]+)', tag) or [None, "text"])[1]
        nm = (re.search(r'(?:name|placeholder|aria-label)=["\']([^"\']+)', tag) or [None, ""])[1]
        inputs.append(f"{typ}:{nm}".strip(":")[:40])
    actions = re.findall(r'<form\b[^>]*action=["\']([^"\']+)', dom, re.I)
    heads = [_t(h)[:60] for h in re.findall(r"<h[12]\b[^>]*>(.*?)</h[12]>", dom, re.S | re.I)]
    return (f"headings: {heads[:6]}\nbuttons/links: {labels[:40]}\n"
            f"inputs: {inputs[:20]}\nform_actions: {actions[:10]}\nvisible_text: {_visible_text(dom)[:280]}")


def _llm_json(system: str, user: str, model: str = DEFAULT_MODEL, timeout: float = AUDIT_TIMEOUT_S,
              reasoning: bool = False):
    """One temp-0 OpenRouter chat call -> the first JSON object in the reply, or None (no key / API error /
    non-JSON / timeout). Never raises. HARD-capped at `timeout`s via a DAEMON thread we join(): a hung/slow
    response can never eat the grade budget (a scalar httpx timeout is only PER-PHASE — one call trickled
    keepalive for 1486s, never tripping the 90s read timeout); on the cap we abandon it and the daemon dies
    with the process. Shared by the off-score coverage audit and the in-discovery perception pass — both
    temp-0, with determinism coming from caching the frozen result per-commit upstream (the cache, not temp-0,
    is the real guarantee: OpenRouter can route temp-0 to different backends)."""
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        return None
    body = {"model": model, "temperature": 0,   # greedy: as stable as an LLM gets; the per-commit cache is the guarantee
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    if not reasoning:
        # perception + audit are EXTRACTION/classification, not deep reasoning -> disabling thinking cuts the
        # DOMINANT token cost AND wall-clock (qwen3.7-plus/Alibaba: ~10s/390-reason-tok -> ~0.8s/0 on a classify
        # call) and is more deterministic. reasoning:{enabled:false} is the OpenRouter-canonical lever and the ONE
        # that actually works here — chat_template_kwargs.enable_thinking is a provider passthrough Alibaba SILENTLY
        # IGNORES (verified live), and reasoning.exclude only HIDES thinking (still generated + billed). Default
        # keeps reasoning on (the validated baseline).
        body["reasoning"] = {"enabled": False}
    out = {}

    def _call():
        try:
            r = httpx.post(OPENROUTER_URL, json=body, timeout=httpx.Timeout(timeout, connect=10.0),
                           headers={"Authorization": "Bearer " + key,
                                    "HTTP-Referer": "https://hacklet.league", "X-Title": "hacklet-fuzz"})
            if r.status_code == 200:
                out["content"] = r.json()["choices"][0]["message"]["content"]
        except Exception:
            pass                       # best-effort: a failed call must never break the grade

    t = threading.Thread(target=_call, daemon=True)
    t.start()
    t.join(timeout)                    # HARD wall-clock cap — take control back after `timeout`s no matter what
    content = out.get("content")
    if not content:
        return None                    # timed out, errored, or non-200
    try:
        m = re.search(r"\{.*\}", content, re.S)
        return json.loads(m.group(0)) if m else None
    except Exception:
        return None


def audit_coverage(skeleton: str, observed: dict, features=None, model: str = DEFAULT_MODEL,
                   timeout: float = AUDIT_TIMEOUT_S, reasoning: bool = False):
    """OFF-SCORE coverage critic: ask the LLM what surface `observed` (the fuzzer's discovery) missed + the
    page state. Returns {missed, page_state, notes} or None (best-effort, never raises). A FLAG only — never
    in the slop number (that's the perception pass's job to feed as probeable surface; this reports the gap)."""
    if not skeleton.strip():
        return None
    user = (f"PAGE SURFACE (what a user sees):\n{skeleton}\n\n"
            f"FUZZER OBSERVED (structured):\n{json.dumps(observed, default=str)[:1600]}")
    if features:
        user += f"\n\nSOURCE FEATURES (from the repo, if known):\n{json.dumps(features)[:800]}"
    return _llm_json(_AUDIT_SYSTEM, user, model, timeout, reasoning)


_PERCEIVE_SYSTEM = """You perceive a web page's INTERACTIVE SURFACE for a black-box fuzzer, so it can TEST
controls its automated crawl missed (client-rendered logins, upload widgets, action buttons a static crawl
can't see). You get (1) a compact map of the page's ACTUAL rendered surface and (2) what the fuzzer's crawl
OBSERVED. Emit the PROBEABLE surface the crawl MISSED — concrete targets, not prose:
- forms: a login / signup / upload / search / contact / create form the crawl lacks. Give action (the submit
  path, RELATIVE — your best evidence-based guess), method, fields (input names), file_fields (upload inputs).
- endpoints: an API operation behind a button/action (e.g. a 'New Board' button POSTing to /api/boards). Give
  path (relative), method, params (query names), body_fields (JSON/form body names).
RULES: emit ONLY surface the page CLEARLY has AND observed lacks — NEVER invent. Prefer relative paths. If a
path or field isn't evidenced, OMIT that item rather than guess (a hallucinated target wastes a probe). Also
classify the page state. Respond with ONLY a JSON object, no prose/markdown:
{"forms": [{"kind": "login|signup|upload|search|contact|create|other", "action": "/path", "method": "post",
  "fields": ["email","password"], "file_fields": [], "label": "Sign in"}],
 "endpoints": [{"kind": "create|search|read|update|delete|other", "path": "/path", "method": "post",
  "params": [], "body_fields": ["title"], "label": "New Board"}],
 "page_state": "working|placeholder|broken|login-wall|not-an-app"}
Empty "forms"/"endpoints" when the crawl already covers the page."""


def perceive_surface(skeleton: str, observed: dict, model: str = DEFAULT_MODEL, timeout: float = AUDIT_TIMEOUT_S,
                     reasoning: bool = False):
    """PROACTIVE discovery: read the RENDERED page + what the crawl observed, and return the PROBEABLE surface
    the crawl MISSED as STRUCTURED targets — {forms:[{kind,action,method,fields,file_fields,label}],
    endpoints:[{kind,path,method,params,body_fields,label}], page_state} — for the fuzzer to MERGE into its
    Profile and probe DETERMINISTICALLY. The INVARIANT (same as the source-read #2 pointer, now applied to the
    rendered surface): the LLM only WIDENS which targets get probed; each probe self-gates (fires on real slop,
    N/A on a hallucinated target), so a wrong guess just no-ops and the LLM never touches the score. Returns
    None on no-key / error / timeout, so the deterministic crawl stays the FLOOR (graceful degradation). Hard-
    capped via _llm_json; feed it a cached skeleton per-commit upstream for reproducibility."""
    if not skeleton.strip():
        return None
    user = (f"PAGE SURFACE (rendered — what a user sees):\n{skeleton}\n\n"
            f"FUZZER CRAWL OBSERVED:\n{json.dumps(observed, default=str)[:1600]}")
    return _llm_json(_PERCEIVE_SYSTEM, user, model, timeout, reasoning)


def _print_perceived(perceived) -> None:
    """Announce what the perception LLM did (proactive discovery), DURING discovery before the probes run, so a
    --proactive run is always legible: you see the LLM point, then the deterministic probes fire on those
    targets. ALWAYS prints a status (found targets / nothing to add / call failed) — silence used to look
    identical to 'didn't run', which was confusing on a well-crawled app that has no missed surface."""
    if perceived is None:
        print("\n  🔮 PROACTIVE PERCEPTION — the perception call failed / timed out; no surface added "
              "(the deterministic crawl is the floor)")
        return
    forms = perceived.get("forms") or []
    eps = perceived.get("endpoints") or []
    if not forms and not eps:
        print("\n  🔮 PROACTIVE PERCEPTION — ran; the crawl already covered the page, nothing to add")
        return
    print(f"\n  🔮 PROACTIVE PERCEPTION — the LLM found {len(forms)} form(s) + {len(eps)} endpoint(s) the crawl "
          f"missed, feeding them to the probes:")
    for f in forms:
        names = ", ".join([*(f.get("fields") or []), *(f.get("file_fields") or [])])
        print(f"    ↳ FORM {(f.get('method') or '?').upper():4} {f.get('action') or '?'}  [{f.get('kind') or '?'}]"
              + (f"  fields: {names}" if names else ""))
    for e in eps:
        names = ", ".join([*(e.get("params") or []), *(e.get("body_fields") or [])])
        print(f"    ↳ API  {(e.get('method') or '?').upper():4} {e.get('path') or '?'}  [{e.get('kind') or '?'}]"
              + (f"  inputs: {names}" if names else ""))


# ---- 3. execute the plan --------------------------------------------------------------------------

_DB_READY = {
    "postgres": ["pg_isready", "-U", DB_CREDS["user"]],
    "mysql": ["mysqladmin", "ping", "-h", "127.0.0.1", "-u", "root", "-phacklet"],
    "mongo": ["mongosh", "--quiet", "--eval", "db.runCommand({ping:1})"],
}
_DB_DEFAULT_IMAGE = {"postgres": "postgres:16-alpine", "mysql": "mysql:8", "mongo": "mongo:7"}


def _start_db(db: dict):
    dbtype = db.get("type", "none")
    if dbtype in ("none", "", None):
        return
    image = db.get("image") or _DB_DEFAULT_IMAGE.get(dbtype, "postgres:16-alpine")
    env = db.get("env") or {}
    if dbtype == "mysql":
        env.setdefault("MYSQL_ROOT_PASSWORD", "hacklet")
        env.setdefault("MYSQL_DATABASE", DB_CREDS["db"])
    print(f"  starting {dbtype} sidecar ({image}) at host '{DB}' ...")
    args = ["run", "-d", "--name", DB, "--network", NET]
    for k, v in env.items():
        args += ["-e", f"{k}={v}"]
    _docker(*args, image, check=True)
    ready = _DB_READY.get(dbtype)
    for _ in range(40):
        if ready and _docker("exec", DB, *ready).returncode == 0:
            print("  db ready"); return
        time.sleep(2)
    print("  (db readiness probe timed out — continuing anyway)")


def execute(plan: dict, repo: pathlib.Path, verbose: bool = False, build_timeout: int = 480) -> str:
    # clean slate: drop BOTH the app AND the db sidecar from any prior attempt (or a killed prior run),
    # else the next `docker run --name hl-db` Conflicts and every retry fails identically.
    _docker("rm", "-f", "-v", APP, DB)   # -v also reaps any leftover sidecar volume from a killed run
    _docker("network", "create", NET)  # idempotent-ish; ignore "already exists"
    _start_db(plan.get("db") or {"type": "none"})

    ctx = (repo / plan.get("build_context", ".")).resolve()
    for rel, content in (plan.get("files") or {}).items():
        target = (ctx / rel).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    dockerfile = ctx / "Dockerfile.hacklet"
    dockerfile.write_text(_inject_build_cache(plan["dockerfile"]))

    print("  docker build (streaming — base-image pull + npm/pip install is the slow part):")
    rc, tail = _build_streamed(dockerfile, ctx, verbose=verbose, timeout=build_timeout)
    if rc != 0:
        # a timeout-kill is its own signal (undeployably heavy/bloated deps), not a broken build — tag it
        # distinctly so it's the first error line and stats can count "too slow to build" separately.
        kind = f"BUILD TIMEOUT (>{build_timeout}s)" if "build exceeded" in tail else "BUILD FAILED"
        raise DeployError(f"{kind}:\n" + tail)

    app_env = plan.get("app_env") or {}
    env_args = []
    for k, v in app_env.items():
        env_args += ["-e", f"{k}={v}"]
    env_args += ["-e", f"PORT={plan['port']}"]

    migrate = (plan.get("migrate") or "").strip()
    if migrate:
        print(f"  migrate: {migrate}")
        m = _docker("run", "--rm", "--network", NET, *env_args, APP, "sh", "-c", migrate, timeout=300)
        if m.returncode != 0:
            print("  (migrate returned nonzero — continuing)\n" + (m.stderr or m.stdout)[-600:])

    print("  running app ...")
    _docker("run", "-d", "--name", APP, "--network", NET, *env_args, APP, check=True, timeout=120)
    time.sleep(3)
    ip = _docker("inspect", "-f",
                 '{{(index .NetworkSettings.Networks "%s").IPAddress}}' % NET, APP).stdout.strip()
    if not ip:
        raise DeployError("app container has no IP (it exited?):\n" + _docker("logs", "--tail", "40", APP).stderr)
    url = f"http://{ip}:{plan['port']}"
    health = plan.get("health_path", "/")
    for _ in range(20):
        p = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "4",
                            url + health], capture_output=True, text=True)
        code = p.stdout.strip()
        if code and code != "000" and int(code) < 500:
            print(f"  up at {url} (health {health} -> {code})")
            return url
        time.sleep(2)
    logs = _docker("logs", "--tail", "50", APP)
    raise DeployError(f"app did not become healthy at {url}{health}.\nLOGS:\n"
                      + (logs.stdout + logs.stderr)[-3000:])


# ---- 4. grade + main ------------------------------------------------------------------------------

class GradeTimeout(Exception):
    """The grading phase blew its wall-clock budget. A pathological target — e.g. every HTML response
    hangs the socket — makes each fan-out probe pay a full read timeout per route, so grading can grind
    for tens of minutes. This bounds it so one broken app can't stall a batch."""


def _grade_heartbeat(done, total, probe, outcomes):
    # on_progress fires twice per probe; the pre-run call (outcomes is None) is the 'still alive' tick so
    # a slow grade is visibly PROGRESSING, not frozen. \r-updates one stderr line (cleared in grade()).
    if outcomes is None:
        sys.stderr.write(f"\r  grading {done + 1:>2}/{total}  {probe.id:24}")
        sys.stderr.flush()


def _parse_headers(items) -> dict | None:
    """--header 'Name: Value' (repeatable) -> {Name: Value}; None when none supplied (the common path). The
    Option-B provided session — sent on the whole run so the authed-surface probes reach the logged-in surface."""
    if not items:
        return None
    out = {}
    for it in items:
        name, sep, val = it.partition(":")
        if sep and name.strip():
            out[name.strip()] = val.strip()
    return out or None


def _grade_worker(url, use_browser, features, q, cached_profile=None, cache_key=None, repo_url=None,
                  proactive=False, model=DEFAULT_MODEL, browser_auth=False, session_headers=None,
                  llm_reasoning=False, recon=False):
    os.setsid()   # own process group so the parent can SIGKILL this child AND its headless chrome together
    try:
        render = browser.render_routes if use_browser else None
        # cache_key set (a repo commit SHA, not --no-cache) -> freeze the surface discovery mints. Writes to
        # disk from the child; the file survives the fork. cached_profile set -> reuse it, skip the crawl.
        on_profile = (lambda p: store_cached_profile(repo_url, cache_key, p)) if cache_key else None
        # PROACTIVE discovery: an LLM perceives the rendered pages for surface the crawl missed. Built HERE, in
        # the forked child, so the closure never crosses a process boundary; module-level perceive_surface /
        # _surface_skeleton are in scope. None -> the deterministic crawl stays the floor.
        perceive = None
        if proactive:
            def perceive(doms, observed):
                skeleton = "\n\n".join(_surface_skeleton(d) for d in doms.values() if d)
                if not skeleton.strip():
                    print("\n  🔮 PROACTIVE PERCEPTION — skipped: the render returned no page surface to read")
                    return None
                p = perceive_surface(skeleton, observed, model=model, reasoning=llm_reasoning)
                _print_perceived(p)   # None -> call failed; empty -> nothing to add; else -> the targets
                return p
        # SPA AUTH: browser-driven self-registration for the session/idor probes (an SPA's form action is a
        # placeholder; the real POST is a JS fetch). register_in_browser is module-level -> safe in the fork.
        # None -> the auth self-oracle uses only its httpx paths (which already work on server-rendered apps).
        browser_register = browser.register_in_browser if (browser_auth and use_browser) else None
        if cached_profile is None:   # a cache HIT reuses the frozen surface -> no discovery, no delay to explain
            _kinds = "crawl" + (" + browser-render" if use_browser else "") + (" + LLM perception" if proactive else "")
            print(f"  discovering surface ({_kinds}) — this runs before the first probe ...", flush=True)
        report = run(RemoteDeployer(url, health_timeout=20), load_catalog(str(_ROOT / "catalog")),
                     render=render, on_progress=_grade_heartbeat, seed_features=features, headers=session_headers,
                     cached_profile=cached_profile, on_profile=on_profile, perceive=perceive,
                     browser_register=browser_register, recon=recon)
        q.put(("ok", report))
    except BaseException as e:   # report ANY failure back to the parent instead of dying silently
        q.put(("err", f"{type(e).__name__}: {e}"))


def _hard_kill_group(p) -> None:
    """SIGKILL the grade child AND its process group (its chrome/etc.), then reap it — on a timeout or Ctrl-C,
    so nothing is orphaned. p.pid IS the child's pgid after its own setsid()."""
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.killpg(p.pid, signal.SIGKILL)
    with contextlib.suppress(Exception):
        p.kill()
    p.join(5)


def grade(url: str, use_browser: bool, timeout=None, features=None,
          cached_profile=None, cache_key=None, repo_url=None, proactive=False, model=DEFAULT_MODEL,
          browser_auth=False, session_headers=None, llm_reasoning=False, recon=False):
    """Grade the running app in a CHILD PROCESS. A subprocess (not an in-process SIGALRM) because a signal
    can't interrupt a Playwright CPU-spin (the browser probes), but an EXTERNAL SIGKILL of the child + its
    chrome always works. `timeout` is the grading phase's OWN wall-clock budget (independent of deploy time,
    which used to starve grading): a number BOUNDS it (raises GradeTimeout on expiry — batches pass one so a
    pathological app can't stall the run); None = NO cap (a direct run you're watching — Ctrl-C kills the
    child cleanly). `features` seeds discovery for api-only apps."""
    ctx = mp.get_context("fork")
    q = ctx.Queue()
    p = ctx.Process(target=_grade_worker,
                    args=(url, use_browser, features, q, cached_profile, cache_key, repo_url, proactive, model,
                          browser_auth, session_headers, llm_reasoning, recon))
    p.start()
    try:
        result = q.get(timeout=timeout)              # timeout=None (direct run) blocks until the child reports
    except queue.Empty:                              # a SET timeout (batch) elapsed -> None -> hard-kill below
        result = None
    except KeyboardInterrupt:                         # Ctrl-C on an uncapped run -> take the child + its chrome down
        _hard_kill_group(p)
        raise
    finally:
        sys.stderr.write("\r" + " " * 44 + "\r")     # wipe the heartbeat line
        sys.stderr.flush()
    if result is None:                               # timed out (or the child vanished) -> hard-kill the group
        _hard_kill_group(p)
        raise GradeTimeout(f"grading exceeded {timeout}s")
    p.join(5)
    kind, payload = result
    if kind == "err":
        raise RuntimeError(f"grade worker failed: {payload}")
    return payload


# --url ingest hits real, often link-rotted deployments. Reject a DEAD one BEFORE grading its shell:
# unreachable, a 4xx/5xx entry, or a known host placeholder (a Pages/Vercel/Netlify "no site here" page
# that answers 200/404 but hosts no app — otherwise we'd grade the placeholder to meaningless garbage).
_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
_DEAD_PAGE = re.compile(
    r"There isn't a GitHub Pages site here|"                          # GitHub Pages: no site published
    r"DEPLOYMENT_NOT_FOUND|The deployment could not be found|"        # Vercel
    r"Site not found|Not Found - Request ID|"                         # Netlify
    r"no such app|couldn't find that app|no application configured",  # generic PaaS not-found
    re.I)
# a CLIENT-SIDE 404: the host answers 200 but the SPA ROUTER renders a 'page not found' at the entry (a
# broken/missing root route). Only visible in the RENDERED dom — the static shell doesn't carry it. Match
# the not-found message as the page's main content, tolerant of the exact wording (React/Vue/Angular defaults).
_GHOST_PATH = "/__hacklet_nonexistent_probe_9z8x7q__"   # a path no real app serves -> reveals catch-all/404 behavior
_CLIENT_404 = re.compile(
    r"page not ?found|could(n'?t| not) be found|this page (does ?n'?t|does not) exist|"
    r"404\D{0,40}(not ?found|error|does ?n'?t exist)|nothing (to see )?here|"
    r"application error|something went wrong", re.I)   # a crashed SPA / error-boundary shell is broken, not an app
# a working-LOOKING but empty deployment: a coming-soon / maintenance / service-down splash, or a web
# server's DEFAULT page (nginx/Apache) — the deploy 'succeeded' but hosts no real app. Placeholder, not app.
_PLACEHOLDER = re.compile(
    r"coming soon|under construction|under maintenance|scheduled maintenance|be right back|"
    r"we'?ll be back (soon|shortly)|temporarily (unavailable|down)|service (temporarily )?unavailable|"
    r"site is (down|offline)|parked (domain|free)|future home of|default (web )?page|"
    r"welcome to nginx|apache2? (ubuntu )?default page|\bit works!", re.I)
# A broken build/route serving the JS/CSS BUNDLE as the page body — the browser paints raw source as visible
# text (the dominant Bolt/Netlify break: ~28 of bolt3's 42 DNFs). HTTP 200, so a status check misses it, and
# it often carries no 'not found' words. These markers are dense in source and ~absent in real UI copy.
_SOURCE_MARK = re.compile(
    r"var\(--|--[a-z][\w-]*\s*:|@media\b|@keyframes\b|@font-face\b|!important|"          # CSS
    r"[.#][a-zA-Z][\w-]*\s*\{|:\s*#[0-9a-fA-F]{3,8}\b|\b\d+(?:px|rem|vh|vw)\b|"           # CSS rules / units
    r"function\s*\(|=>|\bconst\s|\blet\s|module\.exports|\bimport\s.+?\bfrom\b", re.I)   # JS


def _visible_text(html: str) -> str:
    """Served/rendered markup -> visible text, with <script> AND <style> stripped: neither renders as page
    text, and their contents would false-match the dead-shell / source-dump patterns — inline JS carries
    route/handler-name strings, and inline CSS carries design tokens / @media / hex colors. <style> especially:
    a real site that inlines its critical CSS (Tailwind / Next / design tokens) would otherwise read as a 'raw
    CSS dump' and be false-flagged URL DEAD — insightaco.org, a live site, was."""
    t = re.sub(r"<(script|style)\b[^>]*>.*?</\1>", " ", html, flags=re.S | re.I)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", t)).strip()


def _looks_like_client_404(dom: str) -> bool:
    """True if a RENDERED dom's main content is a 'page not found' shell (client-side 404)."""
    return bool(_CLIENT_404.search(_visible_text(dom)[:1500]))


def _looks_like_source_dump(html: str) -> bool:
    """True if the visible text is raw CSS/JS SOURCE rather than UI copy — the dominant Bolt/Netlify break
    (the bundle painted as the page body). Deterministic backing for a 'broken' verdict that a status check
    misses (it's HTTP 200) — the signal the LLM audit was carrying alone. PRECISION-biased: fires only when
    source markers DOMINATE a substantial body, so a page with real prose/UI — including a legit code-display
    app, whose markers are diluted by copy — is spared (density falls below threshold)."""
    vis = _visible_text(html)
    if len(vis) < 300:                                   # too little text to judge confidently
        return False
    sample = vis[:4000]
    hits = len(_SOURCE_MARK.findall(sample))
    return hits >= 12 and hits / (len(sample) / 1000) >= 4   # >=12 markers AND >=4/KB -> body is source, not copy


def _dead_shell_reason(html: str):
    """A dead/placeholder SHELL (served OR rendered markup): a client-side 404, a coming-soon / maintenance /
    server-default splash, or a raw source dump. The text patterns check only the PROMINENT top of the visible
    text (low FP — a real app that merely mentions 'coming soon' for a future feature isn't flagged)."""
    vis = _visible_text(html)[:1500]
    if _CLIENT_404.search(vis):
        return "client-side 404 (renders 'not found' at HTTP 200)"
    if _PLACEHOLDER.search(vis):
        return "placeholder page (coming-soon / maintenance / server default)"
    if _looks_like_source_dump(html):
        return "raw source dump (CSS/JS painted as page text — broken build/route)"
    return None


# A submission URL that is SOURCE / a notebook / a doc / a video — NOT the team's deployed app. Grading it tests
# the PLATFORM (GitHub's login + headers, Colab's page) to meaningless slop. *.github.io is a real deployed Pages
# site and is NOT matched. (Verified: ~25 v2 "apps" were github-enterprise repo pages / Colab drive notebooks.)
_NON_APP_HOST = re.compile(
    r"^https?://(?:www\.)?(?:"
    r"github\.com/|gitlab\.com/|bitbucket\.org/|github\.[a-z0-9-]+\.(?:edu|com|org)/|"   # code-repo pages
    r"colab\.research\.google\.com|colab\.google|kaggle\.com/code|deepnote\.com|"        # notebooks
    r"devpost\.com|notion\.so|docs\.google\.com|drive\.google\.com|figma\.com|"          # docs / design
    r"youtube\.com|youtu\.be|loom\.com|vimeo\.com"                                       # demo videos
    r")", re.I)

# Third-party PLATFORM content pages: the submitted URL is the platform's OWN page (an agent listing, a game
# page whose game runs in an iframe, a blockchain explorer, a map viewer) — grading it grades the platform's
# UI + endpoints (agentverse's /api/cookie-consent, itch's chrome), penalizing many teams for one platform's
# bugs. DNF at ingestion, like source/doc links. NOTE: base44.app / *.web.app / *.vercel.app etc. are the
# TEAM's deployed app (kept gradeable) — only platform CONTENT-page hosts belong here.
_PLATFORM_PAGE_HOST = re.compile(
    r"^https?://(?:www\.)?(?:"
    r"agentverse\.ai|asi1\.ai|"                            # fetch.ai agent marketplace / shared-chat pages
    r"(?:[a-z0-9-]+\.)?itch\.io|"                          # itch.io game pages (the game runs in an iframe)
    r"explorer\.solana\.com|solscan\.io|"                  # blockchain explorers (third-party)
    r"(?:[a-z0-9-]+\.)*arcgis\.com|"                       # ArcGIS map viewer (third-party)
    r"(?:[a-z0-9-]+\.)*worldlabs\.ai"                      # World Labs 3D world viewer (marble.worldlabs.ai/world/<uuid>)
    r")", re.I)


def _host_of(url: str) -> str:
    """The FULL host of a URL — netloc, lowercased, port-stripped. urlsplit keeps the WHOLE host incl. the
    subdomain, so team1.vercel.app and team2.vercel.app are DIFFERENT hosts. The single source of truth for
    'which host is this', shared by the scope-out check (_non_app_url) and the frequency count below."""
    return urlsplit(url).netloc.lower().split(":")[0]


# A DATA-DRIVEN backstop to the ENUMERATED _PLATFORM_PAGE_HOST list (an enumerated host list always lags new
# platforms). A platform reveals itself STATISTICALLY: the SAME full host recurs across many submissions,
# because teams CANNOT share a deployment host — each team gets its OWN subdomain (team1.vercel.app), so a
# full host (netloc, incl. subdomain) seen many times is the platform's own content domain, not a team's app.
# K=3: low enough to catch a small platform cluster (asi1.ai across 5 shared-chat links), high enough that two
# teams who happen to collide on one host aren't scoped out. Keyed on the FULL host ONLY — NEVER the
# registrable domain: web.app / vercel.app / netlify.app / base44.app / github.io are popular, but each team's
# SUBDOMAIN under them is distinct (count 1 each), so a common registrable domain never triggers this.
_CORPUS_PLATFORM_MIN_COUNT = 3


def _corpus_platform_hosts(urls, min_count=_CORPUS_PLATFORM_MIN_COUNT):
    """Infer platform hosts from the BATCH's own URL distribution — the backstop to _PLATFORM_PAGE_HOST. Any
    FULL host (netloc) appearing across >= min_count submissions is a shared third-party platform (teams can't
    share a deployment host), so its URLs are scoped out with the SAME DNF path as an enumerated match (feed
    the returned set to _non_app_url / _dead_url_reason). Returns the set of inferred platform hosts; prints
    one line per host — scoping submissions out of scoring is never silent (a silent scope-cut is a bug)."""
    counts = Counter(h for h in (_host_of(u) for u in urls) if h)
    inferred = set()
    for host, n in sorted(counts.items()):   # sorted -> deterministic log order across runs
        if n >= min_count:
            inferred.add(host)
            print(f"host {host} appeared {n} times across submissions -> inferred platform, "
                  f"excluding {n} url(s) from scoring")
    return inferred


def _non_app_url(url: str, platform_hosts=None):
    """A source / notebook / doc / video link OR a third-party platform's own content page rather than the
    team's deployed app -> reason (else None). *.github.io is a deployed GitHub Pages site -> gradeable.
    `platform_hosts`: an optional set of corpus-inferred platform hosts (from _corpus_platform_hosts) — a URL
    whose full host is in it is scoped out with the SAME reason-string DNF path as an enumerated
    _PLATFORM_PAGE_HOST match, so the two platform sources (enumerated + inferred) compose, not diverge."""
    host = _host_of(url)
    if host == "github.io" or host.endswith(".github.io"):
        return None
    if platform_hosts and host in platform_hosts:
        return (f"corpus-inferred platform host ({host} recurs across submissions), "
                "not the team's deployed app")
    if _PLATFORM_PAGE_HOST.match(url):
        return "third-party platform's own page (agentverse/itch/explorer/...), not the team's deployed app"
    return "source / notebook / doc link, not a deployed app" if _NON_APP_HOST.match(url) else None


def _dead_url_reason(url: str, render=None, timeout: float = 10.0, platform_hosts=None):
    """Returns a reason string if `url` is NOT a working deployment, else None. A NOTE, not a grade — so a
    dead demo link is counted honestly instead of grading a 404 page or crashing the batch child. Catches:
    a source/notebook/doc link (not a deployed app), a third-party / corpus-inferred platform page
    (`platform_hosts`, see _corpus_platform_hosts), unreachable / 4xx-5xx entry / host placeholder shell /
    coming-soon-maintenance splash (static), and — with `render` — a client-side 404 or rendered placeholder."""
    non_app = _non_app_url(url, platform_hosts)
    if non_app:
        return non_app
    try:
        r = httpx.get(url, timeout=timeout, follow_redirects=True, verify=False,
                      headers={"User-Agent": _UA})
    except httpx.HTTPError as e:
        return f"unreachable ({type(e).__name__})"
    if r.status_code >= 400:
        return f"HTTP {r.status_code}"
    if _DEAD_PAGE.search(r.text[:6000]):
        return "host placeholder / 404 shell (no app deployed)"
    static_shell = _dead_shell_reason(r.text)   # static coming-soon / server-default (or a rare inlined 404)
    if static_shell:
        return static_shell
    if render is not None:   # SPA client-side 404 / rendered placeholder: only the rendered entry shows it
        with contextlib.suppress(Exception):
            base = url.rstrip("/")
            doms = render(base + "/", ["/"])
            dom = doms.get("/") or (next(iter(doms.values()), "") if doms else "")
            if dom:
                rendered_shell = _dead_shell_reason(dom)
                if rendered_shell:
                    return rendered_shell
                # BROKEN CATCH-ALL: a guaranteed-nonexistent path renders a 404/error shell AND the entry
                # renders the SAME thing -> the app serves that dead shell for EVERY route (nothing real is
                # deployed; this is the world-of-vibecraft class that scored SQLi-40 on a 404 page). A working
                # SPA whose entry differs from its 404 component is fine — that's good 404 UX, not a dead app.
                ghost = next(iter((render(base + _GHOST_PATH, ["/"]) or {}).values()), "")
                if ghost and _dead_shell_reason(ghost) and _visible_text(dom)[:800] == _visible_text(ghost)[:800]:
                    return f"broken app — every route renders a {_dead_shell_reason(ghost)}"
    return None


def _broken_verdict(surf: dict, entry_dom: str):
    """For a page the LLM audit flagged broken/placeholder/not-an-app, decide DNF vs DISPUTED. DNF is the MAX
    penalty (ranked below every working submission), so it needs CORROBORATION: a DETERMINISTIC broken signal
    (dead-shell / source-dump on the rendered entry, or a suppressed catch-all) OR the genuine ABSENCE of real
    captured surface. Else it's DISPUTED — real forms/endpoints captured AND nothing deterministic agrees, so
    scoring it (high slop ranks it near the bottom) beats flooring a demonstrably-working app on the model's
    say-so. Returns (dnf: bool, reason: str)."""
    surf = surf or {}
    shell = _dead_shell_reason(entry_dom) if entry_dom else None
    det_broken = bool(surf.get("catch_all")) or bool(shell)
    real_surface = not surf.get("catch_all") and bool(surf.get("forms") or surf.get("endpoints"))
    if det_broken or not real_surface:
        return True, shell or ("catch-all (phantom surface)" if surf.get("catch_all") else "no real surface captured")
    return False, "disputed — real surface captured, no deterministic broken signal"


def main():
    ap = argparse.ArgumentParser(description="LLM-assisted deploy + fuzz-grade of a hackathon repo.")
    ap.add_argument("repo", help="a git URL, a local path, or (with --url) a live app URL")
    ap.add_argument("--url", action="store_true", dest="url_ingest",
                    help="treat the positional as a LIVE, already-deployed app URL: grade it directly over "
                         "HTTP(S) with NO clone / LLM plan / Docker deploy (for Vercel/Railway/*.app "
                         "submissions with no gradeable repo). Enables the HTTPS-only probes.")
    ap.add_argument("--model", default=DEFAULT_MODEL, help="OpenRouter model id (default: %(default)s)")
    ap.add_argument("--audit-coverage", action="store_true", dest="audit_coverage",
                    help="after grading, have the LLM audit DISCOVERY coverage against the live page — note "
                         "interactive surface the fuzzer missed (AfroSecured-style) + placeholder/broken "
                         "pages onto the record (coverage_audit), so misses accrue into a fixable backlog. "
                         "One cheap LLM call + a light render per app; works for repo AND url grades.")
    ap.add_argument("--proactive", action="store_true",
                    help="PROACTIVE discovery: during discovery an LLM perceives the RENDERED pages and feeds "
                         "the probeable surface the crawl MISSED (client-rendered logins / uploads / action "
                         "buttons) INTO the fuzzer's forms/endpoints, so the probes actually test it. The LLM "
                         "only WIDENS targets; each probe self-gates (N/A on a hallucination) so it never "
                         "touches the score, and a model outage degrades to today's deterministic crawl (the "
                         "floor). Opt-in; repo grades freeze the augmented surface in the per-commit cache.")
    ap.add_argument("--browser-auth", action="store_true", dest="browser_auth",
                    help="SPA auth: when httpx self-registration gets no session (a client-rendered app whose "
                         "signup form action is a placeholder — the real POST is a JS fetch), drive the browser "
                         "to fill + submit the signup so the app's OWN JS registers, and use the session cookie "
                         "it sets — waking the session/idor probes on self-hosted SPAs. Opt-in (an extra browser "
                         "launch per auth app); best-effort, N/A on captcha / email-verify / SSO / third-party auth.")
    ap.add_argument("--header", action="append", dest="headers", metavar="'Name: Value'",
                    help="a request header sent on the WHOLE run (repeatable) — the Option-B auth fallback for apps "
                         "we can't self-register (captcha / email-verify / SSO). Provide a live session and the "
                         "authed-surface probes reach the logged-in surface as that identity: a COOKIE app -> "
                         "--header 'Cookie: sessionid=…'; a bolt/Supabase/Firebase (token) app -> --header "
                         "'Authorization: Bearer eyJ…' (from DevTools -> Network -> an authed request). A single "
                         "provided session is ONE identity, so the cross-user IDOR/BOLA probes stay N/A (no false pos).")
    ap.add_argument("--no-web-search", dest="web_search", action="store_false",
                    help="don't let the LLM web-search on retries (default: retries CAN search OpenRouter's "
                         "web plugin for current dep versions / deploy config, ~$0.02/retry)")
    ap.add_argument("--llm-reasoning", dest="llm_reasoning", action="store_true", default=False,
                    help="opt the PERCEPTION + AUDIT passes back INTO the LLM's thinking/CoT. Default is OFF: an "
                         "A/B (2026-07-15) showed no-think holds page-state + score + precision (paired median "
                         "delta 0) while cutting the audit LLM ~3.7x (36s->10s) and the dominant token cost, and "
                         "it's more deterministic. reasoning:{enabled:false} is the OpenRouter lever that actually "
                         "works on qwen3.7-plus (chat_template_kwargs.enable_thinking is silently ignored).")
    ap.add_argument("--no-llm-reasoning", dest="llm_reasoning", action="store_false", default=False,
                    help="(now the default — accepted for back-compat) keep perceive+audit no-think.")
    ap.add_argument("--no-cache", action="store_true", help="don't reuse/store the per-commit deploy-plan "
                    "cache — re-plan from scratch every run (default: a commit's SUCCESSFUL plan is frozen so "
                    "re-grades are reproducible; the cache lives at HL_CACHE_DIR, default ~/.cache/hacklet-plan)")
    ap.add_argument("--attempts", type=int, default=3, help="max deploy attempts (LLM fixes errors between)")
    ap.add_argument("--build-timeout", type=int, default=480, dest="build_timeout",
                    help="kill a docker build after N seconds (default 480). Lower = better batch "
                         "throughput but risks false-killing a genuinely heavy build; 300 is aggressive")
    ap.add_argument("--grade-timeout", type=int, default=None, dest="grade_timeout",
                    help="wall-clock cap (seconds) on the grading phase, externally enforced by killing the "
                         "grade subprocess (even a Playwright CPU-spin, which a signal can't touch). Default "
                         "NONE for a DIRECT run — you're watching it, so it runs to completion; Ctrl-C kills "
                         "the child + its chrome cleanly. run_batch ALWAYS passes an explicit value, so a "
                         "BATCH stays bounded — one pathological app can't stall an overnight run.")
    ap.add_argument("--clone-timeout", type=int, default=300, dest="clone_timeout",
                    help="git clone timeout in seconds (default 300; a timeout is recorded, not a crash)")
    ap.add_argument("--checkpoint", metavar="FILE", help="write the stack-ID here right after planning, so "
                    "an external kill (wedge) can still recover the app's classification for deploy-parity")
    ap.add_argument("--no-browser", dest="browser", action="store_false",
                    help="skip the browser-rendered surface (faster). DEFAULT is browser ON for grading: "
                         "the render finds SPA forms/routes a static crawl misses (biggest recall win) + "
                         "adds a11y / Core Web Vitals / DOM-XSS / console-error probes")
    ap.add_argument("--recon", action="store_true",
                    help="RECON mode: deploy -> render -> classify backend hosts, then STOP (skip the ~66-probe "
                         "gauntlet). Records host_tiers only (no slop score) to SIZE the SPA off-origin gap "
                         "cheaply — a fast sample. Implies browser (recon needs the render). Point --record at a "
                         "SEPARATE file; stats.py (i3) BACKEND-TIER DISTRIBUTION aggregates it.")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="stream the full docker build output (default: high-level steps only)")
    ap.add_argument("--keep", action="store_true", help="don't tear the containers down after grading")
    ap.add_argument("--record", metavar="FILE", help="append the full result (metadata + findings + "
                    "evidence) as a JSON line to FILE, for scripts/stats.py")
    ap.add_argument("--meta", metavar="JSON", default="",
                    help="metadata to merge into the record, e.g. from devpost_repos --json "
                         "('{\"hackathon\":\"x\",\"project\":\"...\",\"winner\":true}')")
    ap.add_argument("--platform-host", action="append", dest="inferred_platform_hosts", metavar="HOST",
                    help="a corpus-inferred platform host (from run_batch's host-frequency detector) to DNF, "
                         "exactly like an enumerated _PLATFORM_PAGE_HOST match. Repeatable; url-ingest only.")
    args = ap.parse_args()
    if args.browser and not os.environ.get("HL_BROWSER_PREFLIGHTED"):   # single-app: fail loud too, unless
        ok, detail = browser.browser_preflight()                        # run_batch already preflighted (env set)
        if not ok:
            sys.exit(f"ERROR: --browser is on (the default) but chromium won't launch here:\n    {detail}\n"
                     f"  fix:  uv run playwright install chromium chromium-headless-shell\n"
                     f"  or grade static-only (skips a11y/console/CWV/dead-controls/dom-xss):  add --no-browser")

    meta = json.loads(args.meta) if args.meta.strip() else {}
    # source: the LENS this grade is — "repo" (our controlled Docker deploy, dummy keys, powers the
    # reproducibility metric) vs "url" (their live deployment, real keys + full surface but their infra
    # headers). A submission can be graded BOTH ways; stats keep the two separate — never blended.
    result = {"repo": args.repo, "deployed": False, "attempts_used": 0, "browser": args.browser,
              "source": "url" if args.url_ingest else "repo", "model": args.model, "ts": time.time(), **meta}

    plan, url, error, repo = None, None, "", None
    _sha, cached_profile = None, None   # repo-commit identity + its frozen surface; stay None for --url
    # wall-clock per phase, as MEASUREMENT not just gates — which stacks are expensive to deploy vs grade,
    # and how that correlates with slop/coverage. Accumulated across retries; partial on an early return.
    timings = {"clone_s": 0.0, "plan_s": 0.0, "deploy_s": 0.0, "grade_s": 0.0, "total_s": 0.0}
    t_app = time.monotonic()
    try:
        if args.url_ingest:   # a LIVE, already-deployed app -> skip clone/plan/deploy, grade the URL raw
            url = args.repo
            off = off_target(url)   # AIRTIGHT SCOPE GUARD: a third-party link (reddit/discord/github/...) that
            if off:                 # slipped into the target list must NEVER be fetched or probed. Before any GET.
                result.update(url_ingest=True, skipped=True, off_target=off, web_gradeable=False,
                              app_kind="off-target", skip_reason=f"off-target host ({off}) — not the submission's app")
                print(f"\n  OFF-TARGET ({off}) — a third-party link, not an app; recorded, NOT fetched or probed.")
                return
            result.update(url_ingest=True, app_kind="web-app", web_gradeable=True,
                          stack="live app (url-ingest)", stack_profile={"routing": "url-ingest"})
            # link-rot is common -> don't grade a dead deployment's 404 shell. With the browser on, this
            # also catches a client-side 404 (SPA renders 'not found' at HTTP 200) via a one-route render.
            dead = _dead_url_reason(url, render=(browser.render_routes if args.browser else None),
                                    platform_hosts=set(args.inferred_platform_hosts or []))
            if dead:
                result["dead_url"] = True                         # counted as "url does not work" (deployed=False)
                result["deploy_error"] = f"URL DEAD — {dead}"
                print(f"\n  URL DEAD ({dead}) — not a working deployment; recorded, not graded.")
                return
            print(f"\n=== url-ingest: grading live app (no clone/plan/deploy) → {url} ===")
        else:
            _t = time.monotonic()
            repo = clone(args.repo, timeout=args.clone_timeout)
            timings["clone_s"] = round(time.monotonic() - _t, 1)
            context = gather_context(repo)
            _sha = _git_sha(repo)   # immutable commit identity for the caches (None on a local path -> no cache)
            cached_plan = None if args.no_cache else load_cached_plan(args.repo, _sha)
            cached_profile = None if args.no_cache else load_cached_profile(args.repo, _sha)
            if cached_plan:
                print(f"  ↺ reusing the cached deploy plan for commit {_sha[:8]} "
                      f"— frozen for reproducibility (--no-cache to re-plan)")
            for attempt in range(1, args.attempts + 1):
                result["attempts_used"] = attempt
                if attempt == 1 and cached_plan:   # FROZEN: reuse the cached plan, skip the (stochastic) LLM
                    plan = cached_plan
                    _routing = (plan.get("stack_profile") or {}).get("routing", "?")
                    print(f"  stack (frozen): {plan.get('stack')} [{_routing}]  port: {plan.get('port')}  "
                          f"db: {(plan.get('db') or {}).get('type')}")
                else:
                    online = attempt >= 2 and args.web_search   # attempt 1 cheap/no-search; retries look up stacks
                    print(f"\n=== attempt {attempt}/{args.attempts}: planning deploy ({args.model}"
                          f"{' + web search' if online else ''}) ===")
                    _t = time.monotonic()
                    plan = plan_deploy(context, args.model, error=error, prev=plan, online=online)
                    timings["plan_s"] += round(time.monotonic() - _t, 1)   # LLM planning, summed across attempts
                    _routing = (plan.get("stack_profile") or {}).get("routing", "?")
                    print(f"  stack: {plan.get('stack')} [{_routing}]  port: {plan.get('port')}  "
                          f"db: {(plan.get('db') or {}).get('type')}")
                    notes = (plan.get("notes") or "").strip()
                    if notes:   # a few wrapped, hanging-indented lines (was one 200-char line cut mid-sentence)
                        for i, line in enumerate(textwrap.wrap(notes, width=100)[:6]):
                            print(("  notes: " if i == 0 else "         ") + line)
                if args.checkpoint and attempt == 1:   # persist the stack-ID BEFORE the risky deploy/grade, so
                    _ck = {}                            # a wedge-kill still yields a labelled record (deploy-parity)
                    _record_plan_meta(_ck, plan)
                    with contextlib.suppress(OSError):
                        with open(args.checkpoint, "w") as _f:
                            json.dump(_ck, _f)
                if plan.get("web_gradeable") is False:   # not a runnable web service (mobile/CLI/notebook/...)
                    _record_plan_meta(result, plan)      # -> SKIP: no fabricated server, no meaningless score
                    result["skipped"] = True
                    result["skip_reason"] = f"not web-gradeable (app_kind={plan.get('app_kind') or '?'})"
                    print(f"\n  SKIP — {result['skip_reason']}; recorded, not graded (no fabricated deploy)")
                    return
                _t = time.monotonic()
                try:
                    url = execute(plan, repo, verbose=args.verbose, build_timeout=args.build_timeout)
                    timings["deploy_s"] += round(time.monotonic() - _t, 1)   # build + db + run + health
                    if _sha and not cached_plan and not args.no_cache:
                        store_cached_plan(args.repo, _sha, plan)   # freeze the plan that WORKED for this commit
                    result.pop("deploy_error", None)   # a later attempt SUCCEEDED -> drop the earlier failure's
                    result.pop("timeout", None)        # error/timeout so a deployed app isn't tagged as failed
                    break
                except DeployError as e:
                    timings["deploy_s"] += round(time.monotonic() - _t, 1)   # a failed attempt cost time too
                    error = str(e)
                    result["deploy_error"] = (error.strip().splitlines() or ["unknown"])[0][:200]
                    if "BUILD TIMEOUT" in result["deploy_error"]:
                        result["timeout"] = "build"   # 'took forever to build' — a bloat/deployability signal
                    print(f"  deploy failed:\n{error[-800:]}")
                    _docker("rm", "-f", "-v", APP, DB)   # tear down this attempt's containers + volume
            if plan:   # kind + stack + features + source-implied surface — recorded even on deploy FAILURE, so
                _record_plan_meta(result, plan)          # the stack-distribution + parity ground-truth stay whole
            if not url:
                print("\nGAVE UP — could not deploy after all attempts.")
                return   # result (deployed=False, deploy_error) is written in the finally
        result.update(deployed=True)
        print(f"\n=== grading {url} ===")
        if cached_profile is not None:   # frozen crawl -> no browser/interaction this run (deterministic + fast)
            print(f"  ↺ reusing the cached discovery surface for commit {_sha[:8]} "
                  f"({len(cached_profile.routes)} routes, {len(cached_profile.forms)} forms, "
                  f"{len(cached_profile.endpoints)} endpoints) — frozen, skipping the crawl")
        _t = time.monotonic()
        try:
            report = grade(url, args.browser or args.recon, timeout=args.grade_timeout,   # recon NEEDS the render
                           features=(plan.get("features") if plan else None),   # url-ingest has no plan
                           cached_profile=cached_profile,
                           cache_key=(None if args.no_cache else _sha), repo_url=args.repo,
                           proactive=args.proactive, model=args.model, browser_auth=args.browser_auth,
                           session_headers=_parse_headers(args.headers), llm_reasoning=args.llm_reasoning,
                           recon=args.recon)
        except GradeTimeout as e:
            timings["grade_s"] = round(time.monotonic() - _t, 1)
            result["grade_timeout"] = True         # deployed but ungradeable in budget (broken/pathological
            result["timeout"] = "grade"            # target); the 'took forever' signal + shows in stats
            result["deploy_error"] = f"GRADE TIMEOUT (>{args.grade_timeout}s)"
            print(f"\n  GRADE TIMEOUT — {e}. Target too pathological to grade in budget; "
                  f"recorded, moving on.")
            return   # the finally writes the record (deployed=True, grade_timeout=True) + tears down
        except Exception as e:   # grade worker died — an unreachable/5xx-only URL, or a real crash. Record
            timings["grade_s"] = round(time.monotonic() - _t, 1)   # it cleanly; never traceback out of a child.
            msg = str(e)
            unreachable = any(s in msg for s in ("did not respond", "only 5xx", "unreachable", "has no IP"))
            if args.url_ingest and unreachable:    # the live URL went down between the liveness check and grade
                result["deployed"] = False         # -> it did NOT work (counted as a dead URL, not a grade bug)
                result["dead_url"] = True
                result["deploy_error"] = "URL DEAD — did not respond / 5xx only"
                print(f"\n  URL DEAD — {msg[:160]}; recorded, moving on.")
            else:
                result["deploy_error"] = f"GRADE FAILED: {msg[:180]}"
                print(f"\n  GRADE FAILED — {msg[:200]}; recorded, moving on.")
            return
        timings["grade_s"] = round(time.monotonic() - _t, 1)
        slop = [o for o in report.outcomes if o.outcome == "slop_detected"]
        # Collapse fan-out to ONE finding per (probe, reason): a header probe fires once per asset (civ2:
        # 61 identical x-content-type-options rows). The score damper already handles the penalty; the
        # findings list shouldn't carry 60 duplicates. Keep `count` + up to 5 sample targets. stats.py
        # expands by `count` when it rebuilds the damped subtotals, so the score math is unaffected.
        findings, _seen = [], {}
        for o in slop:
            key = (o.probe_id, o.reason)
            f = _seen.get(key)
            if f is not None:
                f["count"] += 1
                if o.target and o.target not in f["targets"] and len(f["targets"]) < 5:
                    f["targets"].append(o.target)
                continue
            f = {"probe_id": o.probe_id, "bundle": o.bundle, "category": o.category, "penalty": o.penalty,
                 "group": o.variant_group_id, "reason": o.reason, "target": o.target, "count": 1,
                 "targets": [o.target] if o.target else [], "evidence": o.evidence}
            _seen[key] = f
            findings.append(f)
        result.update(slop_score=report.slop_score, axis_slop=report.axis_slop,
                      observed_surface=report.surface, coverage=report.coverage, findings=findings)
        if args.recon:
            result["recon"] = True   # host_tiers-only record (no probes ran) -> excluded from the score distribution
        print(f"\n  SLOP SCORE: {report.slop_score}   ({_axis_str(report.axis_slop)})")
        cov = report.coverage
        if cov.get("probes_total"):   # test coverage: how much of the battery applied vs went n/a (calibration)
            print(f"  COVERAGE: {cov['probes_applicable']}/{cov['probes_total']} tests applicable "
                  f"({cov['pct_applicable']}%)   n/a kinds: {', '.join(cov['na_kinds']) or 'none'}")
        # ALL findings, grouped bundle -> category. The category shows its DAMPED subtotal (what it adds
        # to the score); the rows under it are each flaw's RAW penalty, which taper within the category
        # (within-category diminishing returns + variant-group), so the rows can exceed the subtotal.
        cat_fired, cat_probes = defaultdict(list), defaultdict(list)
        for o in slop:
            cat_fired[(o.bundle, o.category)].append(o)          # all fired (with fan-out) -> exact subtotal
        for o in {o.probe_id: o for o in slop}.values():
            cat_probes[(o.bundle, o.category)].append(o)          # one row per probe
        subs = {k: _damped_total(v, CATEGORY_DECAY) for k, v in cat_fired.items()}
        order = {"security": 0, "qa": 1, "performance": 2}
        n = sum(len(v) for v in cat_probes.values())
        print(f"  {n} findings   (category = damped subtotal it adds; rows = each flaw's raw penalty)")
        last = None
        for key in sorted(cat_probes, key=lambda k: (order.get(k[0], 9), -subs[k])):
            bundle, cat = key
            if bundle != last:
                last = bundle
                print(f"    [{bundle}  {round(report.axis_slop.get(bundle, 0))}]")
            print(f"      {cat:22} {round(subs[key]):>3}")
            for o in sorted(cat_probes[key], key=lambda o: -o.penalty):
                print(f"        {o.probe_id:20} {o.penalty:>3}  {o.reason[:56]}")
                trig = _trigger_str(o.evidence)          # show WHAT triggered it (payload/injection/field)
                if trig:
                    print(f"        {'':22}↳ {trig}")
        if args.audit_coverage:   # LLM coverage CRITIC — read the live page, ALWAYS print + record what
            audit, why, doms = None, "", {}  # discovery missed (like deploy notes). Best-effort: never breaks a grade.
            _t = time.monotonic()  # the audit renders + calls the LLM -> its own timed phase (audit_s)
            try:
                # audit the entry page + the head app sub-routes discovery found (routes_list), interact ON
                # so a click-gated login/upload — on the landing OR a sub-route like /report — lands in the
                # skeleton the LLM reasons over. Bounded to a handful of routes to keep the audit cheap.
                _rl = report.surface.get("routes_list") or []
                routes = ["/"] + [r for r in _rl if isinstance(r, str) and r != "/"][:4]
                doms = browser.render_routes(url, routes, interact=True) if args.browser else {}
                skeleton = "\n\n".join(_surface_skeleton(d) for d in doms.values() if d)
                if not skeleton:
                    why = "no rendered page surface (browser off or render empty)"
                else:
                    audit = audit_coverage(skeleton, report.surface, result.get("features"), model=args.model,
                                           reasoning=args.llm_reasoning)
                    if audit is None:
                        why = "LLM returned nothing (missing OPENROUTER_API_KEY or an API error)"
            except Exception as e:
                why = f"{type(e).__name__}: {e}"
            timings["audit_s"] = round(time.monotonic() - _t, 1)   # only set on audit runs -> stats counts only these
            if audit:
                result["coverage_audit"] = audit
                if audit.get("page_state") in ("broken", "not-an-app", "placeholder"):
                    # DNF is the MAX penalty, so the LLM's holistic 'broken' can't impose it ALONE — see
                    # _broken_verdict: it needs a deterministic broken signal OR no real captured surface, else
                    # the app is DISPUTED (scored high-slop + flagged for review, not floored on a model's say-so).
                    entry_dom = doms.get("/") or next((d for d in doms.values() if d), "")
                    dnf, why_dnf = _broken_verdict(report.surface, entry_dom)
                    if dnf:
                        result["functional"] = False
                        print(f"  ⚠ NON-FUNCTIONAL (page_state={audit['page_state']}; {why_dnf}) — ranks "
                              f"DNF-class, not scored as a working app")
                    else:
                        result["disputed_broken"] = audit["page_state"]
                        print(f"  ⚠ DISPUTED BROKEN (page_state={audit['page_state']}, but discovery captured "
                              f"real surface + no deterministic signal) — SCORED, not DNF'd on the LLM alone; "
                              f"flagged for review")
                miss = audit.get("missed") or []
                print(f"\n  LLM COVERAGE AUDIT — verdict: {audit.get('page_state') or '?'}   "
                      + (f"{len(miss)} missed surface" if miss else "no gaps (discovery covered the page)"))
                for m in miss:
                    print(f"    ↳ MISSED {m.get('kind') or '?'}: {(m.get('label') or '').strip()}"
                          + (f"  — {m.get('why').strip()}" if m.get('why') else ""))
                for i, line in enumerate(textwrap.wrap((audit.get('notes') or '').strip(), width=100)[:4]):
                    print(("    note: " if i == 0 else "          ") + line)
            else:
                print(f"\n  LLM COVERAGE AUDIT — skipped: {why}")
    except CloneError as e:   # clone failed/timed out BEFORE the deploy loop — record it, don't crash
        result["deploy_error"] = str(e)
        if "TIMEOUT" in str(e):
            result["timeout"] = "clone"
        print(f"  {e}")
    finally:
        timings["total_s"] = round(time.monotonic() - t_app, 1)
        result["timings"] = timings
        _audit_s = timings.get("audit_s")   # present only when --audit-coverage ran
        print(f"  timing: clone {timings['clone_s']:.0f}s · plan {timings['plan_s']:.0f}s · "
              f"deploy {timings['deploy_s']:.0f}s · grade {timings['grade_s']:.0f}s · "
              + (f"audit {_audit_s:.0f}s · " if _audit_s else "")
              + f"total {timings['total_s']:.0f}s   ·   model {args.model}")
        if args.record:
            append_jsonl(args.record, result)   # lock-guarded: safe under parallel url grading (run_batch --concurrency)
            print(f"  recorded -> {args.record}")
        if args.url_ingest:
            pass                       # nothing was deployed — no containers/temp-clone to tear down
        elif args.keep:
            print(f"\n(left running: docker rm -f {APP} {DB}; docker network rm {NET})")
        else:
            _teardown()
        if repo and str(repo).startswith(tempfile.gettempdir()):
            shutil.rmtree(repo.parent, ignore_errors=True)


if __name__ == "__main__":
    main()
