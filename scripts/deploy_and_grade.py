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
import time
from collections import defaultdict

import httpx

_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from hacklet_runner import browser  # noqa: E402
from hacklet_runner.aggregate import CATEGORY_DECAY, _damped_total  # noqa: E402
from hacklet_runner.catalog import load_catalog  # noqa: E402
from hacklet_runner.deploy import RemoteDeployer  # noqa: E402
from hacklet_runner.pipeline import run  # noqa: E402


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


# pip/npm downloads are the slow step of a build, and on a low-bandwidth box a heavy-deps app can blow the
# build timeout on downloads ALONE — then each retry re-downloads from scratch, so a marginally-too-heavy
# app stays too heavy forever. A BuildKit cache mount banks those downloads OUTSIDE the image layer, in the
# daemon's build cache, so they persist across the 3 attempts — and even across a timeout-KILLed build: the
# cache ref survives cancellation, and pip re-fetches any half-written wheel via its own hash check. Per-app
# _teardown disposes it. BuildKit is the default builder here (Docker 23+), so the mount flag needs no
# `# syntax=` directive. --no-cache-dir is stripped because it defeats the very cache we add (and, unlike a
# plain cacheless install, the mount keeps the wheels out of the image layer, so image size is unaffected).
_PIP_INSTALL = re.compile(r"\bpip[0-9.]*\s+install\b")
_NPM_INSTALL = re.compile(r"\bnpm\s+(?:install|ci|i)\b|\byarn\b|\bpnpm\b")
_NO_CACHE_DIR = re.compile(r"\s--no-cache-dir\b")


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
        mounts = []
        if _PIP_INSTALL.search(body):
            mounts.append("--mount=type=cache,target=/root/.cache/pip")
        if _NPM_INSTALL.search(body):
            mounts.append("--mount=type=cache,target=/root/.npm")
        if mounts and "--mount=" not in lines[i]:   # don't double-inject if the LLM already added one
            out[i] = f"{m.group(1)}RUN {' '.join(mounts)} {m.group(3)}"
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
                  // parity. Each: {name, kind, path?, method?}. kind in: form|crud-create|crud-read|crud-update|
                  // crud-delete|search|upload|auth|realtime|payment|other. [] if none/unsure. e.g.:
    {"name": "create project", "kind": "crud-create", "path": "/projects", "method": "post"},
    {"name": "delete project", "kind": "crud-delete", "path": "/projects/{id}", "method": "delete"},
    {"name": "semantic search", "kind": "search", "path": "/api/search", "method": "get"}
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
    body = {"model": model, "temperature": 0.2,
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


def audit_coverage(skeleton: str, observed: dict, features=None, model: str = DEFAULT_MODEL):
    """Ask the LLM what surface the page has that `observed` (the fuzzer's discovery) missed, + the page
    state. Returns {missed, page_state, notes} or None (no key / any error — best-effort, never raises)."""
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key or not skeleton.strip():
        return None
    user = (f"PAGE SURFACE (what a user sees):\n{skeleton}\n\n"
            f"FUZZER OBSERVED (structured):\n{json.dumps(observed, default=str)[:1600]}")
    if features:
        user += f"\n\nSOURCE FEATURES (from the repo, if known):\n{json.dumps(features)[:800]}"
    body = {"model": model, "temperature": 0.1,
            "messages": [{"role": "system", "content": _AUDIT_SYSTEM}, {"role": "user", "content": user}]}
    try:
        r = httpx.post(OPENROUTER_URL, json=body, timeout=90,
                       headers={"Authorization": "Bearer " + key,
                                "HTTP-Referer": "https://hacklet.league", "X-Title": "hacklet-audit"})
        if r.status_code != 200:
            return None
        content = r.json()["choices"][0]["message"]["content"]
        m = re.search(r"\{.*\}", content, re.S)
        return json.loads(m.group(0)) if m else None
    except Exception:
        return None   # best-effort: a failed audit must never break the grade


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


def _grade_worker(url, use_browser, features, q):
    os.setsid()   # own process group so the parent can SIGKILL this child AND its headless chrome together
    try:
        render = browser.render_routes if use_browser else None
        report = run(RemoteDeployer(url, health_timeout=20), load_catalog(str(_ROOT / "catalog")),
                     render=render, on_progress=_grade_heartbeat, seed_features=features)
        q.put(("ok", report))
    except BaseException as e:   # report ANY failure back to the parent instead of dying silently
        q.put(("err", f"{type(e).__name__}: {e}"))


def grade(url: str, use_browser: bool, timeout: int = 480, features=None):
    """Grade the running app in a CHILD PROCESS with its OWN hard wall-clock budget. Why a subprocess and
    not an in-process SIGALRM: a signal can't interrupt a Playwright CPU-spin (the browser probes), so an
    in-process cap silently overruns — but an EXTERNAL SIGKILL of the child + its chrome always works. And
    because it's the grade's own budget, it's independent of how long deploy took (the shared per-app total
    used to starve grading). Raises GradeTimeout on expiry. `features` seeds discovery for api-only apps."""
    ctx = mp.get_context("fork")
    q = ctx.Queue()
    p = ctx.Process(target=_grade_worker, args=(url, use_browser, features, q))
    p.start()
    try:
        result = q.get(timeout=timeout)              # up to `timeout` for the report to arrive
    except queue.Empty:
        result = None
    finally:
        sys.stderr.write("\r" + " " * 44 + "\r")     # wipe the heartbeat line
        sys.stderr.flush()
    if result is None:                               # timed out (or the child vanished) -> hard-kill the group
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.killpg(p.pid, signal.SIGKILL)         # p.pid IS the child's pgid after its setsid() (+ chrome)
        with contextlib.suppress(Exception):
            p.kill()
        p.join(5)
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
_CLIENT_404 = re.compile(
    r"page not ?found|could(n'?t| not) be found|this page (does ?n'?t|does not) exist|"
    r"404\D{0,40}(not ?found|error|does ?n'?t exist)|nothing (to see )?here", re.I)
# a working-LOOKING but empty deployment: a coming-soon / maintenance / service-down splash, or a web
# server's DEFAULT page (nginx/Apache) — the deploy 'succeeded' but hosts no real app. Placeholder, not app.
_PLACEHOLDER = re.compile(
    r"coming soon|under construction|under maintenance|scheduled maintenance|be right back|"
    r"we'?ll be back (soon|shortly)|temporarily (unavailable|down)|service (temporarily )?unavailable|"
    r"site is (down|offline)|parked (domain|free)|future home of|default (web )?page|"
    r"welcome to nginx|apache2? (ubuntu )?default page|\bit works!", re.I)


def _visible_text(html: str) -> str:
    """Served/rendered markup -> visible text, scripts stripped (inline JS carries route/handler-name
    strings that would false-match the dead-shell patterns)."""
    t = re.sub(r"<script\b[^>]*>.*?</script>", " ", html, flags=re.S | re.I)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", t)).strip()


def _looks_like_client_404(dom: str) -> bool:
    """True if a RENDERED dom's main content is a 'page not found' shell (client-side 404)."""
    return bool(_CLIENT_404.search(_visible_text(dom)[:1500]))


def _dead_shell_reason(html: str):
    """A dead/placeholder SHELL (served OR rendered markup): a client-side 404, or a coming-soon /
    maintenance / server-default splash. Only the PROMINENT top of the visible text is checked (low FP —
    a real app that merely mentions 'coming soon' for a future feature isn't flagged)."""
    vis = _visible_text(html)[:1500]
    if _CLIENT_404.search(vis):
        return "client-side 404 (renders 'not found' at HTTP 200)"
    if _PLACEHOLDER.search(vis):
        return "placeholder page (coming-soon / maintenance / server default)"
    return None


def _dead_url_reason(url: str, render=None, timeout: float = 10.0):
    """Returns a reason string if `url` is NOT a working deployment, else None. A NOTE, not a grade — so a
    dead demo link is counted honestly instead of grading a 404 page or crashing the batch child. Catches:
    unreachable / 4xx-5xx entry / host placeholder shell / coming-soon-maintenance splash (static), and —
    when `render` is supplied — a client-side 404 or rendered placeholder the static shell hides."""
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
            doms = render(url, ["/"])
            dom = doms.get("/") or (next(iter(doms.values()), "") if doms else "")
            if dom:
                rendered_shell = _dead_shell_reason(dom)
                if rendered_shell:
                    return rendered_shell
    return None


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
    ap.add_argument("--no-web-search", dest="web_search", action="store_false",
                    help="don't let the LLM web-search on retries (default: retries CAN search OpenRouter's "
                         "web plugin for current dep versions / deploy config, ~$0.02/retry)")
    ap.add_argument("--attempts", type=int, default=3, help="max deploy attempts (LLM fixes errors between)")
    ap.add_argument("--build-timeout", type=int, default=480, dest="build_timeout",
                    help="kill a docker build after N seconds (default 480). Lower = better batch "
                         "throughput but risks false-killing a genuinely heavy build; 300 is aggressive")
    ap.add_argument("--grade-timeout", type=int, default=480, dest="grade_timeout",
                    help="hard wall-clock cap (seconds) on the grading phase (default 480), enforced by an "
                         "external kill of a grade subprocess — so grading gets its OWN budget independent "
                         "of deploy time, and even a Playwright CPU-spin (which a signal can't touch) is bounded")
    ap.add_argument("--clone-timeout", type=int, default=300, dest="clone_timeout",
                    help="git clone timeout in seconds (default 300; a timeout is recorded, not a crash)")
    ap.add_argument("--checkpoint", metavar="FILE", help="write the stack-ID here right after planning, so "
                    "an external kill (wedge) can still recover the app's classification for deploy-parity")
    ap.add_argument("--no-browser", dest="browser", action="store_false",
                    help="skip the browser-rendered surface (faster). DEFAULT is browser ON for grading: "
                         "the render finds SPA forms/routes a static crawl misses (biggest recall win) + "
                         "adds a11y / Core Web Vitals / DOM-XSS / console-error probes")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="stream the full docker build output (default: high-level steps only)")
    ap.add_argument("--keep", action="store_true", help="don't tear the containers down after grading")
    ap.add_argument("--record", metavar="FILE", help="append the full result (metadata + findings + "
                    "evidence) as a JSON line to FILE, for scripts/stats.py")
    ap.add_argument("--meta", metavar="JSON", default="",
                    help="metadata to merge into the record, e.g. from devpost_repos --json "
                         "('{\"hackathon\":\"x\",\"project\":\"...\",\"winner\":true}')")
    args = ap.parse_args()

    meta = json.loads(args.meta) if args.meta.strip() else {}
    # source: the LENS this grade is — "repo" (our controlled Docker deploy, dummy keys, powers the
    # reproducibility metric) vs "url" (their live deployment, real keys + full surface but their infra
    # headers). A submission can be graded BOTH ways; stats keep the two separate — never blended.
    result = {"repo": args.repo, "deployed": False, "attempts_used": 0, "browser": args.browser,
              "source": "url" if args.url_ingest else "repo", "ts": time.time(), **meta}

    plan, url, error, repo = None, None, "", None
    # wall-clock per phase, as MEASUREMENT not just gates — which stacks are expensive to deploy vs grade,
    # and how that correlates with slop/coverage. Accumulated across retries; partial on an early return.
    timings = {"clone_s": 0.0, "plan_s": 0.0, "deploy_s": 0.0, "grade_s": 0.0, "total_s": 0.0}
    t_app = time.monotonic()
    try:
        if args.url_ingest:   # a LIVE, already-deployed app -> skip clone/plan/deploy, grade the URL raw
            url = args.repo
            result.update(url_ingest=True, app_kind="web-app", web_gradeable=True,
                          stack="live app (url-ingest)", stack_profile={"routing": "url-ingest"})
            # link-rot is common -> don't grade a dead deployment's 404 shell. With the browser on, this
            # also catches a client-side 404 (SPA renders 'not found' at HTTP 200) via a one-route render.
            dead = _dead_url_reason(url, render=(browser.render_routes if args.browser else None))
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
            for attempt in range(1, args.attempts + 1):
                result["attempts_used"] = attempt
                online = attempt >= 2 and args.web_search   # attempt 1 cheap/no-search; retries look up recent stacks
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
        _t = time.monotonic()
        try:
            report = grade(url, args.browser, timeout=args.grade_timeout,
                           features=(plan.get("features") if plan else None))   # url-ingest has no plan
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
            audit, why = None, ""  # discovery missed (like the deploy notes). Best-effort: never breaks a grade.
            try:
                # observed_surface carries route COUNTS, not the list, so audit the ENTRY page (interact ON
                # so a click-gated login/upload on the landing lands in the skeleton the LLM reasons over).
                doms = browser.render_routes(url, ["/"], interact=True) if args.browser else {}
                skeleton = "\n\n".join(_surface_skeleton(d) for d in doms.values() if d)
                if not skeleton:
                    why = "no rendered page surface (browser off or render empty)"
                else:
                    audit = audit_coverage(skeleton, report.surface, result.get("features"), model=args.model)
                    if audit is None:
                        why = "LLM returned nothing (missing OPENROUTER_API_KEY or an API error)"
            except Exception as e:
                why = f"{type(e).__name__}: {e}"
            if audit:
                result["coverage_audit"] = audit
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
        print(f"  timing: clone {timings['clone_s']:.0f}s · plan {timings['plan_s']:.0f}s · "
              f"deploy {timings['deploy_s']:.0f}s · grade {timings['grade_s']:.0f}s · "
              f"total {timings['total_s']:.0f}s")
        if args.record:
            with open(args.record, "a") as f:
                f.write(json.dumps(result) + "\n")
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
