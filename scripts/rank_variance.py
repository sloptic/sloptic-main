"""Per-probe contribution to RANK variance on a grading jsonl.

The admission test for a middle-band probe. NOT a re-run: reads recorded slop_score +
findings + coverage.applied, and does a leave-one-out re-ranking off the recorded penalties.
For every probe it reports:

  * applicability  = applied / scored          (how often the probe even runs)
  * cond_fire      = fired / applied           (how often it fires WHEN it runs)
  * prevalence     = fired / scored            (the two multiplied -- the figure that
                                                conflates the two above; decompose it)
  * mean/std pen   = per-app penalty spread across the scored pop (0 where not fired);
                     a near-constant tax has high mean but low std
  * footrule       = avg |rank shift| per app when the probe is removed (the ordering it
                     carries). FIRST-ORDER: sum(finding.penalty) != slop_score because
                     damping is applied after, so trust footrule as a RANKING of carriers,
                     not as an exact displacement.
  * spearman       = full-vs-LOO ranking correlation (1.0 = removing it changes nothing)

--corr also prints the pairwise correlation of the top carriers' per-app penalty vectors.
The admission bar for a NEW probe (once it has run on the corpus): mid applicability *and*
high std *and* low |corr| with the existing carriers. Prevalence alone is necessary, not
sufficient -- a 35%-prevalence probe that co-fires with an existing carrier just adds a
constant to that axis rather than new ordering.

Usage:  uv run --with numpy python scripts/rank_variance.py [jsonl] [--corr] [--top N]
"""
import json
import sys
from collections import defaultdict

import numpy as np

args = [a for a in sys.argv[1:] if not a.startswith("--")]
PATH = args[0] if args else "multihacksfinalv15.jsonl"
DO_CORR = "--corr" in sys.argv
TOP = int(sys.argv[sys.argv.index("--top") + 1]) if "--top" in sys.argv else 35

apps = []          # (slop, {probe: penalty}, set(applied))
bundle_of = {}
for line in open(PATH):
    d = json.loads(line)
    if d.get("slop_score") is None:
        continue
    pens = defaultdict(float)
    for f in d.get("findings") or []:
        pens[f["probe_id"]] += f.get("penalty") or 0
        bundle_of.setdefault(f["probe_id"], f.get("bundle", "-"))
    applied = (d.get("coverage") or {}).get("applied") or []
    apps.append((float(d["slop_score"]), dict(pens), set(applied) if isinstance(applied, list) else set()))

n = len(apps)
slop = np.array([a[0] for a in apps])
sum_pen = np.array([sum(a[1].values()) for a in apps])
add_err = np.abs(sum_pen - slop)
print(f"scored apps: {n}")
print(f"additivity (sum finding.penalty vs slop_score): mean|diff|={add_err.mean():.2f} "
      f"max={add_err.max():.0f} exact={int((add_err < 0.5).sum())}/{n}  -> footrule is first-order\n")

def ranks(v):
    return np.argsort(np.argsort(v, kind="mergesort"), kind="mergesort").astype(float)

def spearman(a, b):
    ra, rb = ranks(a) - ranks(a).mean(), ranks(b) - ranks(b).mean()
    den = np.sqrt((ra * ra).sum() * (rb * rb).sum())
    return float((ra * rb).sum() / den) if den else 1.0

base_rank = ranks(slop)
probes = set()
for _, pens, applied in apps:
    probes |= set(pens) | applied

rows = []
for p in probes:
    fired = np.array([a[1].get(p, 0.0) for a in apps])
    n_appl = int(sum(1 for a in apps if p in a[2]))
    n_fire = int((fired > 0).sum())
    loo_rank = ranks(slop - fired)
    rows.append(dict(
        probe=p, bundle=bundle_of.get(p, "-"), appl=n_appl, fire=n_fire,
        applic=n_appl / n if n else 0, cond=(n_fire / n_appl if n_appl else 0),
        prev=n_fire / n if n else 0, mean=float(fired.mean()), std=float(fired.std()),
        footrule=float(np.abs(base_rank - loo_rank).mean()), spear=spearman(slop, slop - fired)))

rows.sort(key=lambda r: r["footrule"], reverse=True)
hdr = f"{'probe':28} {'bnd':4} {'applic%':>7} {'cond%':>6} {'prev%':>6} {'meanP':>6} {'stdP':>6} {'footrl':>7} {'spear':>7}"
print("CARRIERS OF THE ORDERING (leave-one-out rank displacement)")
print(hdr)
for r in rows[:TOP]:
    print(f"{r['probe']:28} {r['bundle'][:4]:4} {100*r['applic']:7.1f} {100*r['cond']:6.1f} "
          f"{100*r['prev']:6.1f} {r['mean']:6.2f} {r['std']:6.2f} {r['footrule']:7.2f} {r['spear']:7.4f}")

if DO_CORR:
    carriers = [r["probe"] for r in rows[:14]]
    M = np.array([[a[1].get(p, 0.0) for p in carriers] for a in apps])
    C = np.corrcoef(M.T)
    print("\nTOP-CARRIER correlations |r|>=0.25 (redundant axes):")
    for i in range(len(carriers)):
        for j in range(i + 1, len(carriers)):
            if abs(C[i, j]) >= 0.25:
                print(f"  r={C[i, j]:+.2f}  {carriers[i]:22} {carriers[j]}")
    print("\nmean |r| with the other carriers (low = independent axis):")
    for i, p in enumerate(carriers):
        print(f"  {p:22} {np.mean([abs(C[i, j]) for j in range(len(carriers)) if j != i]):.3f}")
