"""PNG charts for the corpus writeup (LinkedIn article + PDF carousel, read on phones). Imported by
stats.py --charts; a normal stats run never imports matplotlib.

Every chart writes `<name>.png` PLUS a sibling `<name>.csv` holding the exact numbers it plots, so the article
prose and the images can never drift. Each image carries a provenance footer (run file + sloptic version + n),
because a chart that leaves the repo needs to carry its own source.

Phone-optimized: ~1600px wide at 2x, large sans-serif labels, one accent against grey, no gradients / 3D /
chartjunk, direct data labels on bars instead of legends.
"""
import csv
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # so `import benchmark` resolves (same dir)

ACCENT = "#2563eb"   # one accent (blue) -- the element the eye should land on
MUTED = "#9aa7b8"    # everything else
INK = "#0f172a"
FAINT = "#64748b"

# Chart-1 acute sets, at PROBE level. exposure-006 (source map) is the "moderate" 11% tier -> excluded.
# csrf/dos excluded from "exploitable" (victim-action / availability, not a compromise-now smoking gun).
_RCE = {"sec-cmdi-001", "sec-sqli-001", "sec-sqli-002", "sec-sqli-003", "sec-sqli-004", "sec-sqli-005",
        "sec-ssti-001", "sec-upload-001"}
_ACUTE = _RCE | {
    "sec-xss-001", "sec-xss-002", "sec-domxss-001", "sec-lfi-001", "sec-xxe-001", "sec-ssrf-001",
    "sec-filterinj-001", "sec-hosthdr-001", "sec-split-001", "sec-redirect-001", "sec-upload-002",
    "sec-authbypass-001", "sec-idor-001", "sec-idor-002", "sec-idor-003", "sec-idor-004", "sec-idor-005",
    "sec-backend-001", "sec-backend-002", "sec-backend-003", "sec-exposure-001", "sec-exposure-002",
    "sec-exposure-003", "sec-exposure-004", "sec-exposure-005", "sec-exposure-007", "sec-exposure-008",
    "sec-secrets-001", "sec-secrets-002"}


def _fired(scored, pid):
    return sum(any(f.get("probe_id") == pid for f in r.get("findings") or []) for r in scored)


def _fired_any(scored, ids):
    return sum(any(f.get("probe_id") in ids for f in r.get("findings") or []) for r in scored)


def _pct_label(v):
    return f"{v:.0f}%" if v >= 10 else f"{v:.1f}%"


def _write_csv(path, header, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def _sloptic_version():
    try:
        from importlib.metadata import version
        return version("sloptic")
    except Exception:
        pass
    try:
        import re
        pp = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()
        m = re.search(r'^version\s*=\s*"([^"]+)"', pp, re.M)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "dev"


def _finish(fig, out, name, run, ver, n):
    """Shared layout close-out: auto-margins for labels, reserve a footer band, stamp provenance, save PNG."""
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    _footer(fig, run, ver, n)
    fig.savefig(out / name, facecolor="white")


def _footer(fig, run_name, version, n):
    fig.text(0.5, 0.02, f"{run_name}   ·   sloptic {version}   ·   n = {n:,} graded apps   ·   "
             f"scripts/charts.py", ha="center", va="bottom", fontsize=9.5, color=MUTED)


# ---- Chart 1: prevalence, chronic vs acute (the hero) --------------------------------------------------
def _chart1(plt, scored, n, out, run, ver):
    chronic = [("No Content-Security-Policy", "sec-headers-002"), ("No clickjacking defense", "sec-headers-004"),
               ("No X-Content-Type-Options", "sec-headers-001"), ("No Referrer-Policy", "sec-headers-005"),
               ("Critical accessibility violation", "qa-a11y-001"), ("Login with no rate limiting", "sec-ratelimit-001")]
    rows = [(lab, 100 * _fired(scored, pid) / n, "chronic") for lab, pid in chronic]
    rows.append(("Any exploitable vulnerability", 100 * _fired_any(scored, _ACUTE) / n, "acute"))
    rows.append(("Remote code execution", 100 * _fired_any(scored, _RCE) / n, "acute"))

    # custom y so a gap (a "visual break") sits between the chronic block and the acute stubs
    ypos = [8, 7, 6, 5, 4, 3, 1, 0]
    labels = [r[0] for r in rows]
    vals = [r[1] for r in rows]
    colors = [ACCENT if r[2] == "acute" else MUTED for r in rows]

    fig, ax = plt.subplots(figsize=(8.8, 6.6))
    ax.barh(ypos, vals, color=colors, height=0.72, zorder=3)
    ax.set_yticks(ypos)
    ax.set_yticklabels(labels)
    ax.set_xlim(0, 108)
    for yp, v, k in zip(ypos, vals, [r[2] for r in rows]):
        ax.text(v + 1.5, yp, _pct_label(v), va="center", ha="left", fontsize=15,
                fontweight="bold", color=ACCENT if k == "acute" else INK)
    ax.axhline(2, color="#d7dee7", lw=1.2, ls=(0, (2, 3)), zorder=1)
    ax.text(107, 2.35, "CHRONIC  —  missing hygiene", ha="right", va="bottom", fontsize=11,
            color=FAINT, fontweight="bold")
    ax.text(107, 1.65, "ACUTE  —  exploitable holes", ha="right", va="top", fontsize=11,
            color=ACCENT, fontweight="bold")
    ax.set_xlabel(f"% of graded apps (n = {n:,})")
    ax.set_title("Chronic, not acute", loc="left", pad=14)
    ax.tick_params(length=0)
    ax.set_axisbelow(True)
    ax.xaxis.grid(True, color="#eef1f5", lw=1)
    _finish(fig, out, "chart1_prevalence.png", run, ver, n)
    plt.close(fig)
    _write_csv(out / "chart1_prevalence.csv", ["finding", "pct_of_graded_apps", "tier", "n_graded"],
               [[r[0], round(r[1], 2), r[2], n] for r in rows])


# ---- Chart 2: defended vs realized ---------------------------------------------------------------------
def _chart2(plt, scored, n, out, run, ver):
    from benchmark import _catalog_index, _slop_potential
    idx = _catalog_index()
    slop = [r["slop_score"] for r in scored]
    pot = [_slop_potential(r, idx) for r in scored]
    med_s, med_p = statistics.median(slop), statistics.median(pot)
    defended = 100 * (1 - med_s / med_p)

    fig, ax = plt.subplots(figsize=(7.6, 5.6))
    bars = ax.bar([0, 1], [med_p, med_s], width=0.55, color=[MUTED, ACCENT], zorder=3)
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["Worst-case slop\n(if every applicable\nprobe fired)", "Actual slop\n(median app)"])
    ax.set_ylim(0, med_p * 1.18)
    for b, v in zip(bars, [med_p, med_s]):
        ax.text(b.get_x() + b.get_width() / 2, v + med_p * 0.02, f"{v:.0f}", ha="center", va="bottom",
                fontsize=20, fontweight="bold", color=INK)
    ax.annotate(f"the median app defends\n{defended:.0f}% of its worst-case\nfailure surface",
                xy=(1, med_s), xytext=(0.62, med_p * 0.62), fontsize=15, color=ACCENT, fontweight="bold",
                ha="center", va="center")
    ax.set_ylabel("slop score (lower is better)")
    ax.set_title("Slop is the rare exception", loc="left", pad=14)
    ax.tick_params(length=0)
    ax.set_axisbelow(True)
    ax.yaxis.grid(True, color="#eef1f5", lw=1)
    _finish(fig, out, "chart2_defended.png", run, ver, n)
    plt.close(fig)
    _write_csv(out / "chart2_defended.csv", ["metric", "median_slop", "n_graded"],
               [["worst_case_potential", round(med_p), n], ["actual", round(med_s), n],
                ["defended_pct", round(defended, 1), n]])


# ---- Chart 3: score distribution -----------------------------------------------------------------------
def _chart3(plt, scored, n, out, run, ver):
    scores = [r["slop_score"] for r in scored]
    med = statistics.median(scores)
    fig, ax = plt.subplots(figsize=(8.4, 5.4))
    counts, edges, _ = ax.hist(scores, bins=10, color=MUTED, edgecolor="white", linewidth=1.2, zorder=3)
    ax.axvline(med, color=ACCENT, lw=2.5, zorder=4)
    ax.text(med, max(counts) * 1.02, f"median {med:.0f}", color=ACCENT, fontsize=15, fontweight="bold",
            ha="center", va="bottom")
    ax.set_xlabel("slop score (lower is better)")
    ax.set_ylabel("number of apps")
    ax.set_title("One smooth, unimodal distribution", loc="left", pad=14)
    ax.tick_params(length=0)
    ax.set_axisbelow(True)
    ax.yaxis.grid(True, color="#eef1f5", lw=1)
    _finish(fig, out, "chart3_distribution.png", run, ver, n)
    plt.close(fig)
    _write_csv(out / "chart3_distribution.csv", ["bucket_low", "bucket_high", "count"],
               [[round(edges[i], 1), round(edges[i + 1], 1), int(counts[i])] for i in range(len(counts))])


# ---- Chart 4: backend tier -----------------------------------------------------------------------------
def _chart4(plt, recs, n, out, run, ver):
    def tiers(r):
        s = r.get("observed_surface") or {}
        t = s.get("host_tiers") if isinstance(s, dict) else None
        return t if isinstance(t, dict) and isinstance(t.get("counts"), dict) else None
    tiered = [t for r in recs for t in [tiers(r)] if t and sum(t["counts"].values())]
    nt = len(tiered)
    spec = [("Same-origin frontend", "same_origin"), ("Third-party vendor", "vendor"),
            ("Opaque (unattributable)", "opaque"), ("Own backend (injectable)", "own_backend"),
            ("Managed backend (BaaS)", "managed_baas")]
    rows = [(lab, sum(1 for t in tiered if (t["counts"] or {}).get(k))) for lab, k in spec]
    rows.sort(key=lambda x: -x[1])
    labels = [r[0] for r in rows]
    counts = [r[1] for r in rows]
    colors = [ACCENT if lab.startswith("Own backend") else MUTED for lab in labels]

    fig, ax = plt.subplots(figsize=(8.6, 5.4))
    y = list(range(len(rows)))
    ax.barh(y, counts, color=colors, height=0.66, zorder=3)
    ax.set_yticks(y)
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlim(0, max(counts) * 1.45)
    for yp, c in zip(y, counts):
        ax.text(c + max(counts) * 0.02, yp, f"{c}  ({100 * c / nt:.0f}%)", va="center", ha="left",
                fontsize=14, fontweight="bold", color=INK)
    ax.set_xlabel(f"apps with observed runtime traffic (n = {nt:,})\ntiers overlap, do not sum to 100%")
    ax.set_title("The backend is mostly out of reach", loc="left", pad=14)
    ax.tick_params(length=0)
    ax.set_axisbelow(True)
    ax.xaxis.grid(True, color="#eef1f5", lw=1)
    _finish(fig, out, "chart4_backend_tier.png", run, ver, n)
    plt.close(fig)
    _write_csv(out / "chart4_backend_tier.csv", ["tier", "apps", "pct_of_traffic_bearing", "n_traffic_bearing"],
               [[r[0], r[1], round(100 * r[1] / nt, 1), nt] for r in rows])


# ---- Chart 5: winners vs non-winners -------------------------------------------------------------------
def _chart5(plt, scored, n, out, run, ver):
    win = [r["slop_score"] for r in scored if r.get("winner") is True]
    non = [r["slop_score"] for r in scored if r.get("winner") is False]
    mw, mn = statistics.median(win), statistics.median(non)
    fig, ax = plt.subplots(figsize=(7.6, 5.6))
    bp = ax.boxplot([win, non], vert=True, widths=0.5, patch_artist=True, showfliers=False,
                    medianprops=dict(color=ACCENT, linewidth=2.5))
    for patch in bp["boxes"]:
        patch.set(facecolor="#eef1f5", edgecolor=MUTED, linewidth=1.4)
    for w in bp["whiskers"] + bp["caps"]:
        w.set(color=MUTED, linewidth=1.4)
    ax.set_xticks([1, 2])
    ax.set_xticklabels([f"Winners\n(n = {len(win)})", f"Non-winners\n(n = {len(non)})"])
    ax.text(1, mw, f"  median {mw:.0f}", va="center", ha="left", color=ACCENT, fontsize=14, fontweight="bold")
    ax.text(2, mn, f"  median {mn:.0f}", va="center", ha="left", color=ACCENT, fontsize=14, fontweight="bold")
    ax.set_ylabel("slop score (lower is better)")
    ax.set_title("Winners look like everyone else", loc="left", pad=14)
    ax.tick_params(length=0)
    ax.set_axisbelow(True)
    ax.yaxis.grid(True, color="#eef1f5", lw=1)
    _finish(fig, out, "chart5_winners.png", run, ver, n)
    plt.close(fig)
    _write_csv(out / "chart5_winners.csv", ["group", "n", "median_slop", "mean_slop"],
               [["winners", len(win), round(mw, 1), round(statistics.mean(win), 1)],
                ["non_winners", len(non), round(mn, 1), round(statistics.mean(non), 1)]])


def render_all(recs, out_dir="docs/charts", run_name="run.jsonl"):
    """Generate all five charts + sibling CSVs into out_dir. Lazy matplotlib import."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        raise SystemExit("charts need matplotlib: `uv run --with matplotlib python scripts/stats.py <run> --charts`")
    ver = _sloptic_version()
    plt.rcParams.update({
        "font.family": "sans-serif", "font.sans-serif": ["DejaVu Sans", "Arial", "Helvetica"],
        "font.size": 15, "axes.titlesize": 20, "axes.titleweight": "bold", "axes.labelsize": 15,
        "xtick.labelsize": 14, "ytick.labelsize": 14, "axes.edgecolor": MUTED, "axes.linewidth": 0.8,
        "text.color": INK, "axes.labelcolor": FAINT, "xtick.color": FAINT, "ytick.color": INK,
        "figure.facecolor": "white", "savefig.dpi": 200, "axes.spines.top": False, "axes.spines.right": False,
    })
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    scored = [r for r in recs if r.get("slop_score") is not None and not r.get("recon")]
    n = len(scored)
    _chart1(plt, scored, n, out, run_name, ver)
    _chart2(plt, scored, n, out, run_name, ver)
    _chart3(plt, scored, n, out, run_name, ver)
    _chart4(plt, recs, n, out, run_name, ver)
    _chart5(plt, scored, n, out, run_name, ver)
    return sorted(str(p) for p in out.glob("chart*"))
