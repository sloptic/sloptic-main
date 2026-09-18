# Perf normalization (benchmark_index)

Spec for correcting the Lighthouse perf axis for host-CPU contention, so a grade's perf is comparable
regardless of how busy the box was when it ran. Decided 2026-09-18 off the v25 A/B. Sibling of the ruler and
404-shell notes: design-complete, implemented **at the freeze** (it needs `bi_ref` from the final run and it
has to land coherently with the re-built curve).

## The problem

Perf is the one axis that measures **time** (LCP/TBT/Speed-Index), and time scales with the box's CPU load.
The worker grades events at concurrency 4, but a **solo** submission on an otherwise-idle worker grades alone
and gets the whole box, so its perf comes out optimistic — and sloptic.org percentile-ranks and shares solo
grades ("cleaner than X%"), so that optimism inflates a real credential. Worse, because the worker runs up to
4 grades, a solo grade's contention depends on concurrent traffic, so the *same app* scores differently at a
busy vs a quiet moment — the perf percentile is not reproducible. `LIGHTHOUSE_SLOTS` does not fix this: it is a
concurrency **cap** (stops traces corrupting each other), not a floor, so a lone grade still runs uncontended.

## The evidence (v25 A/B: same ~120 apps at grade concurrency 1 vs 4)

- Perf: conc1 (idle) scores **+6.6 Lighthouse pts** (mean) / +4 median higher than conc4; scored perf slop
  7.4 vs 12.2. It is **96% of the whole conc1-vs-conc4 total-slop delta**.
- **Security delta exactly 0, QA ~0** (3/62 apps, the dead-controls click window) — those axes are
  presence/behavioral, not timing, so contention does not touch them. Normalization is **perf-axis only**.
- Metric level: **Total Blocking Time −54%**, **Speed Index −19%** (the CPU-bound metrics Lighthouse weights
  ~30% + ~10%), while server-response-time and CLS are dead flat and FCP/LCP barely move. Textbook CPU
  contention, and `benchmark_index` is a CPU-speed measure, so it is the right lever.

## The formula (score-level, linear)

```
perf_norm = clamp( perf_obs − k · clamp(bi_obs − bi_ref, 0, bi_cap),  0, 100 )
```

- `perf_obs`  — median-of-3 Lighthouse composite (0–100), `observed_surface.lighthouse.performance`.
- `bi_obs`    — that grade's `observed_surface.lighthouse.benchmark_index`.
- `bi_ref`    — the box-speed the curve is frozen at (see constants).
- `k`         — perf points per benchmark_index unit.
- `bi_cap`    — bound on the correction so a wildly-fast box cannot over-penalize.

The perf-axis slop is then derived from `perf_norm` through the **existing** green/orange/red tiering
(slop = shortfall under 90). Normalization sits in front of the tier logic; nothing downstream changes.

The correction is one-sided by the inner `clamp(..., 0, ...)`: only grades on a **faster-than-reference** box
(`bi_obs > bi_ref`, the idle/solo case) are pulled down. A busier-than-reference grade is left alone rather
than boosted — we correct the optimism a solo grade gets, we do not reward grading on a slow box.

## Constants

- `bi_ref` — **median `benchmark_index` over the frozen curve population**, computed at the final run and
  frozen as a constant (like the ruler). Provisional from the A/B conc-4 arm: ~1437. Set it at the freeze.
- `k` — **fit from the v25 paired A/B, not re-run.** A bigger dedicated A/B was considered and dropped: it is
  two more full corpus runs (weeks of box time) for a second-order refinement. Robust (Theil-Sen /
  zero-the-median) `k ≈ 0.011`; least-squares `k ≈ 0.017`. Use the **robust 0.011** so the typical app is not
  overcorrected (the gap is right-skewed; LS chases a few heavy-JS outliers and overcorrects the median).
- `bi_cap` — set from the A/B's bi spread so the tail is bounded; provisional ~600 (roughly the conc1-vs-conc4
  bi gap), i.e. never subtract more than ~7 pts. Tune when `bi_ref` is set.

**k must come from a PAIRED A/B, never a single run's cross-section.** In one conc-4 run, regressing perf on
benchmark_index across apps conflates app quality with box speed (a good app on a slow box looks like a bad
app on a fast one). Only same-app-two-speeds isolates the box effect. That is why `k` is frozen from the A/B
and only `bi_ref` comes from the final run.

## Where it applies

Rank/curve layer (`scripts/benchmark.py`), not the pipeline score. The record keeps **raw** perf +
benchmark_index (auditable, re-fittable without re-grading); `build` and `rank` normalize with frozen
`k`/`bi_ref`. The curve population is all ~conc-4 (`bi ≈ bi_ref`), so their corrections are ≈0 and the frozen
curve is essentially unchanged — the work is pulling *divergent live grades* onto a curve that stays put. Land
it **with** the freeze (normalize the curve build and rank together); do not wire it against the current
non-normalized 2026.3 curve, that would rank a normalized app against an un-normalized population.

## What it fixes / does not

Removes ~**97% of the systematic** directional bias (the fairness + reproducibility problem). Leaves ~**±6.6
per-app noise**: benchmark_index explains only 26% of the per-app variance; the rest is contention it cannot
see (heavy-JS TBT swings, network/memory jitter). That residual is **non-directional** and already present in
the curve, so it is not a fairness issue — we correct the bias, not the noise.

## Implementation sketch

```python
# benchmark.py — frozen constants, bumped at the freeze in lockstep with the curve
_PERF_NORM = {"k": 0.011, "bi_ref": None, "bi_cap": 600}   # bi_ref set from the final run's median benchmark_index

def _normalized_perf(perf_obs: float, bi_obs: float | None) -> float:
    p = _PERF_NORM
    if bi_obs is None or p["bi_ref"] is None:
        return perf_obs                                    # no bi (legacy / no lighthouse) -> raw, unchanged
    over = min(max(bi_obs - p["bi_ref"], 0.0), p["bi_cap"])
    return min(100.0, max(0.0, perf_obs - p["k"] * over))
```

Apply in `build` (per corpus record, before the perf-axis distribution is frozen) and in `rank` (on the app
being placed), reading `perf_obs`/`bi_obs` from `observed_surface.lighthouse`. Add a test that a solo-shaped
grade (`bi_obs` ≫ `bi_ref`) is pulled toward the reference while a reference-load grade is unchanged, and that
a missing `bi_obs` is a no-op.

## Freeze checklist additions

- Compute `bi_ref` = median `benchmark_index` over the final-run graded corpus; set it in `_PERF_NORM`.
- Confirm the final run graded at conc 4 + `SLOPTIC_LIGHTHOUSE_SLOTS=3` (matches the worker; run_batch defaults
  the semaphore to 1 if unset).
- Rebuild both curves with normalization active; bump `k`/`bi_ref` beside the curve version and the ruler.
