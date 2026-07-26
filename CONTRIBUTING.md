# Authoring probes

How to add, change, and remove fuzz probes. The runner is a **fixed engine**; **probes are data**
(`catalog/**/*.yaml`, loaded by `load_catalog()` at run time). Reusing existing detection needs no
code change — only a *new* detection primitive touches Python. Canonical design lives in
[../FUZZ_RUNNER_SPEC.md](../FUZZ_RUNNER_SPEC.md); this is the practical recipe.

The live lists of detection primitives are **`MATCHERS` and `PREDICATES` in `hacklet_runner/probes.py`**
— that's the source of truth (this doc deliberately does not enumerate them, so it can't drift). Skim
those dicts to see everything that exists today.

## The probe schema

```yaml
id: sec-sqli-001            # unique — the LOADER KEYS ON THIS, NOT THE FILENAME (a dup id collides even
                            #          across differently-named files)
bundle: security            # security | qa | performance
category: sql-injection     # diminishing-returns damper applies WITHIN a category (sorted-desc decay)
variant_group_id: <id>      # optional; probes sharing one fire ONCE at the max penalty (same logical flaw)
pool: public                # public | hidden
evidence_model: provable    # provable (slop visible in a response) | oracle (differential / self-as-oracle)
penalty: 40                 # slop added when it fires (deduction-only; always positive)
applicability:
  requires: [any_endpoint_accepts_text_input]   # capabilities from discovery; empty = always applicable
probe:
  # EITHER declarative (fetch a target, apply matchers):
  method: POST
  target: /search           # a literal path, or the selector "routes"/"forms" to fan across the surface
  query: { q: "<payload>" }  #   optional query params
  data:  { age: abc }        #   optional form body
  # OR a predicate (multi-step oracle):
  predicate: sqli_auth_bypass
  payload: "' OR '1'='1' -- "   # arbitrary keys under probe: are read by the predicate via probe.probe
slop_if:                      # declarative ONLY; ALL must match -> slop. Omit for predicate probes.
  - response_contains: "<payload>"
```

## The two detection primitives (contracts)

**Matcher** — `MATCHERS[name](resp, arg=None) -> bool`. Pure function over ONE response; `True` when
slop is present. For declarative probes.

**Predicate** — `PREDICATES[name](ctx, probe) -> bool | None`. A multi-step oracle. **Three-state, and
the third state is load-bearing:**

| return | meaning |
| --- | --- |
| `True`  | slop detected → the probe's `penalty` applies |
| `False` | clean → tested and the flaw is absent |
| `None`  | **not applicable** — could not establish the conditions to test (no such surface, self-registration failed, …). This is NOT a clean pass. A `False` when you couldn't actually test is a **false-clean = a missed finding.** When in doubt between `False` and `None`, return `None`. |

The `ctx` object gives a predicate: `ctx.base_url`, `ctx.headers` (auth), `ctx.profile` (the discovered
surface — `.routes`, `.forms`, `.endpoints`, `.capabilities`), `ctx.client` (a shared httpx client), and
`ctx.evidence` (see below). For a fresh, correctly-authenticated client use
`make_client(ctx.base_url, ctx.headers)` (seeds the cookie into the jar so a rotating session is
followed; defaults `verify=False` so an https target with a self-signed cert is reachable).

### Evidence (required for a new predicate)

Every predicate should record what it measured / attempted via `ctx.evidence.update(key=value, ...)`,
for **all** outcomes — clean and n/a too, not just slop. It rides in `--json` and the `-v` view, and is
the product's transparency ("load_time_s=0.4 ✓", "tried error+boolean+union+time, none hit"). Keep it
small and typed (numbers, short strings, small lists). Example:

```python
def perf_ttfb(ctx, probe) -> bool:
    thresh = perf.TTFB_PROFILE
    with make_client(ctx.base_url, ctx.headers) as c:
        sample = perf.sample_ttfb(c, "/")
    ctx.evidence.update(ttfb_s=round(sample, 3), threshold_s=thresh)   # <- what it measured
    return sample >= thresh
```

### Safety (a probe fetches an UNTRUSTED, possibly-authenticated target)

- **Never GET a discovered `<a href>` navigation or a state-changing endpoint with the auth cookie.**
  A blind fetch of `<a href="logout.php">` logs the grader's own session out mid-run and blinds every
  later probe (this actually happened — `fix 8071b67`). Fetch only true subresources
  (`<img/script/media src>`, `<link href>`), and skip logout/delete-looking links (see `broken_links`).
- Never send `PUT`/`PATCH`/`DELETE` payloads that mutate the target's state; grading must be safe to
  re-run. Read-only injection (`GET`/benign `POST`) only.
- A predicate that raises is caught and degraded to N/A for that one probe (the run never DNFs) — but
  don't rely on it; handle `httpx.HTTPError`/`InvalidURL` yourself.

## Add a probe

### 1. Declarative, reusing a matcher — one file, no code
Drop a YAML in `catalog/<bundle>/` with a `target` + `slop_if` using an existing matcher.

### 2. A variant of an existing class — one file, same `variant_group_id`
A new SQLi syntax / XSS payload: copy a sibling YAML, change the `payload`, keep the
`variant_group_id`. It reuses the oracle and folds into the fires-once group (the group counts one
penalty no matter how many syntaxes fire). **Give it a unique `id`.**

### 3. A new detection primitive — +1 function, then the YAML
Add a `MATCHERS` or `PREDICATES` entry (and a matching `_MATCHER_REASONS`/`_PREDICATE_REASONS` line for
the human "why it fired"). Predicates emit `ctx.evidence`. **Comprehensive-technique-per-class:** cover
the class's techniques (SQLi = error/boolean/UNION/time; XSS = script/img/svg/attr/…) but collapse them
to ONE finding — a single predicate that returns once, or siblings sharing a `variant_group_id`. Breadth
is recall, not score inflation; keep each technique precise (marker / differential / confirmation
guards) so breadth doesn't cost false positives.

### CI-lock it (per-technique reference servers)
Add `tests/test_<name>.py` that stands up a throwaway `http.server` exhibiting exactly the flaw (one
per technique) and asserts the predicate fires, plus a clean server it must not fire on, plus the N/A
case. A fake `ctx` is `type("C", (), {"base_url": url, "headers": None, "client": None, "evidence": {}})()`
— note the **`evidence: {}`** (a predicate writes to it; the full suite catches a missing one via
`AttributeError`).

## Change a probe
- **Tuning** (penalty, payload, threshold, applicability, pool) → edit the YAML field, re-run the suite.
- **Detection logic** → edit the matcher/predicate (affects every probe that uses it — review
  accordingly).
- **Pool flip** (public ↔ hidden) → change `pool:` and move the file between this public catalog and
  the private `fuzz-catalog` repo.

## Remove a probe
Delete the YAML — the runner stops loading it. Remove its assertion in `tests/`. For an event-grade
catalog, *deprecate in the changelog* rather than silently delete, so past results stay interpretable.

## Pricing a penalty (risk = frequency × severity)
A penalty is **expected harm**, not raw severity. Price it by how often a real user is hurt × how badly:

- **Security = low-frequency × terminal-severity.** A DB-dumping SQLi / auth-bypass / RCE is rare per app
  (injection incidence ~3% of endpoints, Verizon DBIR / OWASP) but a single one is company-ending (avg
  breach $4.4M, IBM 2025). These sit at the **per-instance ceiling (≈40)** and no other class outranks a
  single one. Defense-in-depth (missing headers) is low × low → stays small.
- **QA / performance = high-frequency × moderate-severity.** Every visitor on slow 4G hits the slow page
  (~53% bounce past 3s, Google 2016; ~79% never return); every wrong-order user hits the crash (~32%
  churn after one bad experience, PwC 2018); ~16% of people are barred by a11y failures (WHO 2023). Priced
  **up toward the deadly range but strictly below the catastrophic-security ceiling** — no single qa/perf
  penalty ≥ the worst single security penalty.
- **Net effect (deliberate):** the aggregate leans qa/perf (high-frequency harm stacks across many probes
  and instances), while the per-incident ceiling stays with catastrophic security.

Don't multiply ordinal severities (Cox 2008, *What's Wrong with Risk Matrices?* — ordinal labels aren't
cardinal). These magnitudes are a **designed table** with a consequence-triggered override band (terminal
severity keeps the ceiling regardless of low frequency), the practice NIST 800-30 / MIL-STD-882E use.

## The calibration gate (non-negotiable)
Every add/change must keep `uv run pytest` green. A probe must read **slop on `references/vulnerable`,
clean on `references/hardened`, and N/A or clean on `references/minimal`** — the same surface, three
verdicts. If your probe needs a surface the references lack, add it (broken in `vulnerable`, defended in
`hardened`). So "add a probe" is usually three coupled edits:

1. the probe YAML,
2. the reference surface (if new),
3. the test assertion.

That coupling is the point: a probe that can't separate defended-from-broken-from-absent does not merge.

**The score:** `tests/test_pipeline.py` holds the **single authoritative** vulnerable-app score
(`assert report.slop_score == N`, plus an `axis_slop` decomposition assertion that must sum to it). A
probe that fires on `vulnerable` changes `N` by its (damped) penalty — update it there, in **one** place. `test_remote.py` and the docker tests
assert *deployer-equivalence* (they equal the SubprocessDeployer baseline), so they self-track and never
need editing for a scoring change.

## Over time
Versioning (semver + quarterly cadence), PR review, and public-vs-hidden governance are in
[../FUZZ_RUNNER_SPEC.md](../FUZZ_RUNNER_SPEC.md). Hidden probes are authored the same way but live in the
private `fuzz-catalog` repo, never this public one.
