# Authoring probes

How to add, change, and remove fuzz probes. The runner is a fixed engine and probes are data
(`catalog/**/*.yaml`, loaded by `load_catalog()` at run time). Reusing an existing detection primitive
needs no code change. Only a new primitive touches Python. The canonical design lives in
[FUZZ_RUNNER_SPEC.md](FUZZ_RUNNER_SPEC.md). This is the practical recipe.

The live lists of primitives are `MATCHERS` and `PREDICATES` in `hacklet_runner/probes.py`. That is the
source of truth. This doc does not enumerate them on purpose, so it cannot drift. Skim those two dicts to
see everything that exists today.

## The probe schema

```yaml
id: sec-headers-001         # unique. The LOADER KEYS ON THIS, not the filename. A duplicate id collides
                            # even across differently named files.
bundle: security            # security | qa | performance
category: security-headers  # the within-category damper applies here (sorted-desc geometric decay)
variant_group_id: <id>      # optional. Probes sharing one fire ONCE, at the max penalty (same logical flaw).
pool: public                # public | hidden
evidence_model: provable    # provable (slop visible in a response) | oracle (differential / uses itself)
penalty: 3                  # slop added when it fires. Deduction only, always positive.
applicability:
  requires: [at_least_one_http_endpoint_exists]   # capabilities from discovery. Omit for always-applicable.
probe:
  # EITHER declarative (fetch a target, apply matchers):
  target: /                 # a literal path, or the selector "routes" / "forms" to fan across the surface
  method: GET               # optional, defaults GET
  query: { q: "<payload>" } # optional query params
  data:  { age: abc }       # optional form body
  # OR a predicate (a multi-step oracle):
  predicate: api_sqli       # arbitrary extra keys under probe: reach the predicate via probe.probe[...]
  max_attempts: 120
slop_if:                    # declarative ONLY. ALL must match to score. Omit for predicate probes.
  - response_missing_header: content-security-policy
```

## The two primitives

**Matcher.** `MATCHERS[name](resp, arg=None) -> bool`. A pure function over one response. `True` when slop
is present. Used by declarative probes.

**Predicate.** `PREDICATES[name](ctx, probe) -> bool | None`. A multi-step oracle. It returns one of three
values, and the third one carries real weight.

| return | meaning |
| --- | --- |
| `True`  | slop detected. The probe's `penalty` applies. |
| `False` | clean. Tested, and the flaw is absent. |
| `None`  | not applicable. Could not establish the conditions to test, so nothing was measured (no such surface, registration failed, no injectable slot). This is not a clean pass. A `False` returned when you could not actually test is a false clean, which is a missed finding. When you are unsure between `False` and `None`, return `None`. |

`ctx` gives a predicate: `ctx.base_url`, `ctx.headers` (auth), `ctx.profile` (the discovered surface, with
`.routes`, `.forms`, `.endpoints`, `.capabilities`), `ctx.client` (a shared httpx client), `ctx.evidence`
(below), and `ctx.register(suffix="")` (self registration, which drives a browser when the app needs one).
For a fresh, correctly authenticated client, use `make_client(ctx.base_url, ctx.headers)`. It seeds the
cookie into the jar so a rotating session is followed, and defaults `verify=False` so an https target with
a self signed cert is still reachable.

### Evidence (required for a new predicate)

Every predicate records what it measured or attempted through `ctx.evidence.update(key=value, ...)`, for
all three outcomes, not only slop. It rides in `--json` and the `-v` view and is the product's
transparency, the difference between "no rate limiting" and "sent 10 wrong-password logins, none
throttled". Keep it small and typed: numbers, short strings, small lists.

```python
def perf_ttfb(ctx, probe) -> bool:
    thresh = perf.TTFB_PROFILE
    with make_client(ctx.base_url, ctx.headers) as c:
        sample = perf.sample_ttfb(c, "/")
    ctx.evidence.update(ttfb_s=round(sample, 3), threshold_s=thresh)   # what it measured, always
    return sample >= thresh
```

### Safety (a probe fetches an untrusted, possibly authenticated target)

- Never GET a discovered `<a href>` navigation link or a state changing endpoint with the auth cookie. A
  blind fetch of `<a href="logout.php">` logs the grader's own session out mid run and blinds every later
  probe. This actually happened (fix `8071b67`). Fetch only true subresources (`<img/script/media src>`,
  `<link href>`), and skip logout and delete looking links (see `broken_links`).
- Never send a `PUT`, `PATCH`, or `DELETE` that mutates the target's state. Grading has to be safe to
  re-run. Read only injection (`GET` or benign `POST`) only.
- A predicate that raises is caught and degraded to N/A for that one probe, so a run never DNFs on it. Do
  not lean on that. Handle `httpx.HTTPError` and `httpx.InvalidURL` yourself.

## Add a probe

**1. Declarative, reusing a matcher. One file, no code.** Drop a YAML in `catalog/<bundle>/` with a
`target` and a `slop_if` that uses an existing matcher.

**2. A variant of an existing class. One file, same `variant_group_id`.** A new SQLi syntax or XSS payload:
copy a sibling YAML, change the `payload`, keep the `variant_group_id`. It reuses the oracle and folds
into the fires-once group, which counts one penalty no matter how many syntaxes fire. Give it a unique
`id`.

**3. A new primitive. One function, then the YAML.** Add a `MATCHERS` or `PREDICATES` entry, plus a
matching line in `_MATCHER_REASONS` or `_PREDICATE_REASONS` for the human "why it fired". Predicates write
`ctx.evidence`. Cover the whole class of techniques but collapse them to one finding: SQLi runs error,
boolean, union, and time, XSS runs script, img, svg, and attribute, and a single predicate returns once,
or siblings share a `variant_group_id`. Breadth is recall, not extra score. Keep each technique precise
(a marker, a differential, a confirmation guard) so breadth does not buy false positives.

### Lock it in CI (a reference server per technique)

Add `tests/test_<name>.py` that stands up a throwaway `http.server` exhibiting exactly the flaw, one per
technique, and asserts the predicate fires. Add a clean server it must not fire on, and the N/A case where
the surface is absent. For a simple predicate that only reads `base_url`, `headers`, `client`, and
`evidence`, the minimal stub is enough:

```python
ctx = type("C", (), {"base_url": url, "headers": None, "client": None, "evidence": {}})()
```

Note the `evidence: {}`. A predicate writes to it, and the full suite catches a missing one through an
`AttributeError`. A predicate that reads `ctx.profile` or calls `ctx.register()` (any auth, session, or
IDOR probe) needs more than the stub. Give it a real `Profile` and a `register()` method, or build the
real context with `pipeline._Ctx`. See `tests/test_api_injection.py` (a stub with a `register()`) and
`tests/test_innocence_check.py` (the real `_Ctx` against a live `http.server`) for the two patterns.

## Change a probe

- **Tuning** (penalty, payload, threshold, applicability, pool): edit the YAML field and re-run the suite.
- **Detection logic**: edit the matcher or predicate. It affects every probe that uses it, so review those.
- **Pool flip** (public to hidden or back): change `pool:` and move the file between this public catalog
  and the private `fuzz-catalog` repo. The report card already withholds hidden findings from the team
  card, so a flip changes disclosure with no other code change.

## Remove a probe

Delete the YAML and the runner stops loading it. Remove its assertion in `tests/`. For an event grade
catalog, deprecate it in the changelog rather than delete it silently, so past results stay interpretable.

## Pricing a penalty (risk = frequency times severity)

A penalty is expected harm, not raw severity. Price it by how often a real user is hurt times how badly.

- **Security is low frequency times terminal severity.** A database dumping SQLi, an auth bypass, or RCE
  is rare per app (injection incidence around 3% of endpoints, per OWASP and the Verizon DBIR) but a single
  one is company ending (average breach 4.4M dollars, IBM 2025). These sit at the per instance ceiling of
  about 40, and no other class outranks a single one. Defense in depth like a missing header is low times
  low, so it stays small.
- **QA and performance are high frequency times moderate severity.** Every visitor on slow 4G hits the
  slow page (about 53% bounce past 3s, Google 2016). Every wrong-order user hits the crash (about 32%
  churn after one bad experience, PwC 2018). About 16% of people are barred by an accessibility failure
  (WHO 2023). Priced up toward the deadly range but kept strictly below the catastrophic security ceiling.
  No single qa or perf penalty reaches the worst single security penalty.
- **Net effect, on purpose.** The aggregate leans qa and perf, because high frequency harm stacks across
  many probes and instances, while the per incident ceiling stays with catastrophic security.

Do not multiply ordinal severities (Cox 2008, *What's Wrong with Risk Matrices?*, ordinal labels are not
cardinal). These magnitudes are a designed table with a consequence triggered override band, where
terminal severity keeps the ceiling regardless of low frequency. That is the practice NIST 800-30 and
MIL-STD-882E use.

## The calibration gate (non-negotiable)

Every add or change keeps `uv run pytest` green. A probe reads slop on `references/vulnerable`, clean on
`references/hardened`, and N/A or clean on `references/minimal`. Same surface, three verdicts. If your
probe needs a surface the references lack, add it: broken in `vulnerable`, defended in `hardened`. So "add
a probe" is usually three coupled edits.

1. the probe YAML,
2. the reference surface, if it is new,
3. the test assertion.

That coupling is the point. A probe that cannot separate defended from broken from absent does not merge.

The authoritative score lives in one place. `tests/test_pipeline.py` asserts the vulnerable app's total,
`report.slop_score == 642`, alongside `report.axis_slop == {"security": 416, "qa": 158, "performance":
68}` and a check that the axes sum to the total. A probe that fires on `vulnerable` moves 642 by its
damped penalty, and you update it there, in that one place. `test_remote.py` and the docker tests assert
deployer equivalence (they equal the SubprocessDeployer baseline), so they self track and never need
editing for a scoring change.

## Over time

Versioning (semver on a quarterly cadence), PR review, and public versus hidden governance live in
[FUZZ_RUNNER_SPEC.md](FUZZ_RUNNER_SPEC.md). Hidden probes are authored the same way but live in the
private `fuzz-catalog` repo, never this public one.
