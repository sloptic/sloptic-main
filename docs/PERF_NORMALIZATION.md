# Perf normalization (benchmark_index)

Correcting the Lighthouse perf axis for host-CPU contention, so a grade's perf is comparable regardless of how
busy the box was when it ran. Decided 2026-09-18 off the v25 A/B.

**STATUS: WIRED 2026-09-18 (`benchmark.py`), inert until a curve carries params.** The code is live but a no-op
against the current 2026.3 curve (which has no `perf_norm`), so it changed nothing today. It self-activates
when `build` freezes a curve that carries `benchmark_index` (the final run), which computes and stores
`bi_ref`. That is why it was safe to land before the freeze rather than during it. Remaining at the freeze:
`build` auto-computes `bi_ref` from the final-run population; optionally refit `k` if a larger A/B is ever run
(dropped for v3.0 as weeks of box time).

**Implemented at the SLOP layer, not the score layer.** `axis_slop` sums to `slop_score`, and the perf slop is
what enters the curve, so the shipped form corrects the perf axis slop directly (below) rather than
re-normalizing the raw Lighthouse score and re-tiering it. It is a linear approximation of the score-level
ideal, chosen because it needs only to remove the SYSTEMATIC bias (the residual per-app noise dominates the
tiering nonlinearity anyway) and it avoids re-implementing Lighthouse's scoring in the benchmark layer.

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

## The formula (slop-level, as implemented)

```
over        = clamp(bi_obs − bi_ref, 0, bi_cap)
perf_slop'  = perf_slop + k · over                  # a faster box under-reported perf slop -> add it back
slop_score' = slop_score + k · over                 # axes sum to the total, so the total moves by the same delta
```

- `perf_slop` — the record's `axis_slop["performance"]` (what the curve is built on).
- `bi_obs`    — that grade's `observed_surface.lighthouse.benchmark_index`.
- `bi_ref`    — the box-speed the curve is frozen at (see constants).
- `k`         — perf **slop** added back per benchmark_index unit (slop-space, from the A/B).
- `bi_cap`    — bound on the correction so a wildly-fast box cannot over-penalize.

One-sided by the inner `clamp(..., 0, ...)`: only a **faster-than-reference** grade (`bi_obs > bi_ref`, the
idle/solo case) gets slop added; a busier-than-reference or reference-load grade is left alone, and a missing
benchmark_index is a no-op. Nothing downstream changes — the corrected `axis_slop`/`slop_score` flow through
the existing dist, overall, and per-axis ranking.

(The conceptual ideal is score-level — normalize the raw Lighthouse score, then re-tier — but that would mean
re-implementing Lighthouse's log-normal scoring + weights in the benchmark layer for a correction whose job is
only to remove the systematic offset. The slop-level linear form captures that offset directly.)

## Constants

- `bi_ref` — **median `benchmark_index` over the curve population**, computed by `build` and stored in the
  curve (not a hand-set constant). ~1437 on the Dell at conc-4 from the A/B; the final-run build sets the real
  one automatically.
- `k = 0.013` (slop-space) — **fit from the v25 paired A/B, not re-run.** A bigger dedicated A/B was dropped:
  two more full corpus runs (weeks of box time) for a second-order refinement. This is the slop-space
  least-squares fit (adds perf slop back per benchmark_index unit); it zeros the mean gap and leaves the
  right-skewed tail (a few heavy-JS apps swing more than benchmark_index predicts). Refit on a larger A/B if
  the tail ever matters.
- `bi_cap = 600` — bounds the correction at ~8 slop pts (roughly the conc1-vs-conc4 bi gap) so a wildly-fast
  box can't over-penalize.

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

## Implementation (shipped)

`scripts/benchmark.py`:
- constants `_PERF_NORM_K = 0.013` (slop-space, v25 A/B) and `_PERF_NORM_CAP = 600.0`;
- `_perf_norm_params(rows)` — returns `{k, bi_ref, bi_cap}` with `bi_ref = median(benchmark_index)` over the
  population, or `None` when no row carries a benchmark_index (a pre-instrumentation corpus);
- `_normalized(record, params)` — the one-sided slop correction above, a no-op without params / benchmark_index
  / a perf axis;
- `build` computes the params, normalizes every row before freezing the distributions, and stores the params
  under `curve["perf_norm"]`;
- `rank` normalizes the incoming record (and its total `score`) iff `curve["perf_norm"]` is present.

Locked by `tests/test_benchmark.py`: the one-sided/no-op behavior, `build` freezing params only with
benchmark_index, **rank against a params-less curve unchanged** (the 2026.3 coherence guarantee), and a
fast-box grade corrected worse against a normalized curve.

## Freeze checklist additions

- Confirm the final run graded at conc 4 + `SLOPTIC_LIGHTHOUSE_SLOTS=3` (matches the worker; run_batch defaults
  the semaphore to 1 if unset) so the curve's contention condition matches live grading.
- Build both curves from the final run: `build` auto-computes and stores `bi_ref` and stamps `perf_norm`, so
  normalization is active on the new curves and inert on nothing — no constant to hand-set. Just verify
  `perf_norm.bi_ref` in the built curve looks sane (~the Dell's conc-4 median, ≈1437).
- Sanity-check that the normalized curves shifted perf as expected vs an un-normalized rebuild (the population
  is ~all at `bi_ref`, so the curves should barely move; the effect is on divergent live grades).
- Optional: refit `k` if a larger A/B is ever run (not for v3.0).
