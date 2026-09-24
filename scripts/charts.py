"""PNG figures and significance tests for CORPUS_REPORT.md. Imported by stats.py --charts; a normal stats run
never imports matplotlib or scipy.

Every figure plots the curve-eligible population (stats._is_graded, the same predicate as the curve and the
figures JSON) and most read their numbers straight from corpus_json(), so the report prose, the figures JSON and
the images cannot drift. Each figure writes `<name>.png` plus a sibling `<name>.csv` holding the exact numbers
it plots, and carries a provenance footer (run file, sloptic version, n). tests.csv holds every hypothesis test
the report quotes.

Style: one accent against grey, direct data labels, no legends where a label will do, no 3D or gradients.
"""
import csv
import itertools
import statistics
from collections import Counter, defaultdict
from pathlib import Path

ACCENT = "#2563eb"
ACCENT2 = "#f59e0b"
MUTED = "#9aa7b8"
INK = "#0f172a"
FAINT = "#64748b"
GRID = "#eef1f5"

AXES = ["security", "qa", "accessibility", "performance"]
AXIS_LABEL = {"security": "Security", "qa": "Quality", "accessibility": "Accessibility",
              "performance": "Performance"}

# plain names for the probes a reader meets in the fire frequency chart
PROBE_LABEL = {
    "sec-headers-002": "No Content-Security-Policy", "sec-headers-004": "No clickjacking defense",
    "sec-headers-005": "No Referrer-Policy", "sec-headers-001": "No X-Content-Type-Options",
    "qa-a11y-001": "Accessibility violation (axe)", "perf-lighthouse-001": "Lighthouse performance below 90",
    "qa-deadctrl-001": "A control that does nothing", "sec-sri-001": "Third party script without SRI",
    "qa-crash-010": "Crash on malformed input", "sec-headers-003": "No HSTS",
    "sec-exposure-006": "Source maps shipped", "qa-console-001": "Uncaught JavaScript error",
    "qa-links-001": "Broken internal link", "qa-seo-001": "Missing basic meta tags",
    "sec-secrets-003": "Google key that reaches Gemini",
}

AXE_LABEL = {"color-contrast": "Text contrast too low", "button-name": "Button with no name",
             "meta-viewport": "Zoom disabled", "label": "Form field with no label",
             "select-name": "Dropdown with no name", "link-name": "Link with no text",
             "html-has-lang": "No page language", "document-title": "No page title",
             "scrollable-region-focusable": "Scroll area unreachable by keyboard", "image-alt": "Image with no alt text"}

# the exploitable classes, by the category of the gating finding
EXPLOIT_CLASS = {"secrets-exposure": "Live credential in the bundle", "backend-exposure": "Open managed backend",
                 "exposure": "Served .git or hidden file", "xss": "Stored XSS",
                 "access-control": "Access control bypass", "data-exposure": "Anonymous data exposure",
                 "sql-injection": "SQL injection"}


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


class _Ctx:
    def __init__(self, plt, out, run, ver, n):
        self.plt, self.out, self.run, self.ver, self.n = plt, out, run, ver, n

    def finish(self, fig, name):
        fig.tight_layout(rect=(0, 0.05, 1, 1))
        fig.text(0.5, 0.015, f"Source: {self.run}, Sloptic {self.ver}, n = {self.n:,} curve eligible apps",
                 ha="center", va="bottom", fontsize=9, color=MUTED)
        fig.savefig(self.out / f"{name}.png", facecolor="white")
        self.plt.close(fig)


def _style(ax, grid="y"):
    ax.tick_params(length=0)
    ax.set_axisbelow(True)
    if grid:
        getattr(ax, f"{grid}axis").grid(True, color=GRID, lw=1)


def _scored(f):
    """Same rule as stats._scored: report_only diagnostics and zero cost fires never count as a finding."""
    if (f.get("evidence") or {}).get("report_only"):
        return False
    return (f.get("penalty") or 0) > 0


def _axis(r, a):
    return (r.get("axis_slop") or {}).get(a, 0) or 0


def _lh(r):
    lh = (r.get("observed_surface") or {}).get("lighthouse")
    return lh.get("performance") if isinstance(lh, dict) else None


def _hbar(ctx, name, title, labels, values, xlabel, fmt, highlight=None, csv_rows=None, csv_header=None,
          xmax=None, size=(9, 5.6)):
    fig, ax = ctx.plt.subplots(figsize=size)
    y = list(range(len(labels)))
    colors = [ACCENT if (highlight and highlight(i)) else MUTED for i in y]
    ax.barh(y, values, color=colors, height=0.68, zorder=3)
    ax.set_yticks(y)
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    top = xmax or max(values) * 1.28
    ax.set_xlim(0, top)
    for yp, v in zip(y, values):
        ax.text(v + top * 0.012, yp, fmt(v), va="center", ha="left", fontsize=12, fontweight="bold", color=INK)
    ax.set_xlabel(xlabel)
    ax.set_title(title, loc="left", pad=12)
    _style(ax, "x")
    ctx.finish(fig, name)
    if csv_rows is not None:
        _write_csv(ctx.out / f"{name}.csv", csv_header, csv_rows)


# ---- fig 1: the funnel ---------------------------------------------------------------------------------
def fig_funnel(ctx, fj):
    a = fj["attrition"]
    dnf = a["dnf_by_reason"]
    names = {"dead URL (link rot / 4xx / 5xx)": "Dead URL (link rot, 4xx, 5xx)",
             "other": "Not an app, or other", "ungraded (grade aborted / timed out)": "Timed out or aborted",
             "entry challenge (WAF withheld the grade)": "Bot challenge at entry"}
    rows = [("Attempted (live URL on Devpost)", a["attempted"]), ("Graded, curve eligible", a["graded"])]
    rows += [(names.get(k, k), v) for k, v in sorted(dnf.items(), key=lambda x: -x[1])]
    _hbar(ctx, "fig01_funnel", "Submission outcomes", [r[0] for r in rows], [r[1] for r in rows],
          "apps", lambda v: f"{v:,}  ({100 * v / a['attempted']:.0f}%)", highlight=lambda i: i == 1,
          xmax=a["attempted"] * 1.45,
          csv_rows=[[r[0], r[1], round(100 * r[1] / a["attempted"], 1)] for r in rows],
          csv_header=["stage", "apps", "pct_of_attempted"])


# ---- fig 2: the distribution ---------------------------------------------------------------------------
def fig_distribution(ctx, fj):
    d = fj["distribution"]
    bins = [b for b in d["bins"] if b[0] < 250]
    tail = sum(b[2] for b in d["bins"] if b[0] >= 250)
    fig, ax = ctx.plt.subplots(figsize=(10, 5.6))
    ax.bar([b[0] + 5 for b in bins], [b[2] for b in bins], width=9.2, color=MUTED, zorder=3)
    top = max(b[2] for b in bins)
    for key, lab, col in [("q1", "Q1", FAINT), ("median", "median", ACCENT), ("q3", "Q3", FAINT),
                          ("p90", "p90", FAINT)]:
        v = d[key]
        med = key == "median"
        # dashed lines stop below the median label row so no label crosses a line
        ax.vlines(v, 0, top * (1.1 if med else 1.0), color=col, lw=2.2 if med else 1.3,
                  linestyles="-" if med else (0, (3, 3)), zorder=4)
        ax.text(v + (-1.5 if key == "q1" else 1.5), top * (1.12 if med else 1.02), f"{lab} {v:.0f}", color=col,
                fontsize=12, fontweight="bold", ha="right" if key == "q1" else "left", va="bottom")
    ax.set_ylim(0, top * 1.24)
    ax.text(248, top * 0.25, f"{tail} {'app' if tail == 1 else 'apps'} above 250\n(max {d['max']:.0f})", ha="right", fontsize=11,
            color=FAINT)
    ax.set_xlabel("slop score, 10 point bins (lower is better)")
    ax.set_ylabel("apps")
    ax.set_title("Slop score distribution", loc="left", pad=12)
    _style(ax)
    ctx.finish(fig, "fig02_distribution")
    _write_csv(ctx.out / "fig02_distribution.csv", ["bin_low", "bin_high", "apps"], d["bins"])


# ---- fig 3: the four axes ------------------------------------------------------------------------------
def fig_axes(ctx, fj, graded):
    sp = fj["axis_split"]
    order = sorted(AXES, key=lambda a: -sp[a]["share_pct"])
    fig, (a1, a2) = ctx.plt.subplots(1, 2, figsize=(12, 5.4), gridspec_kw={"width_ratios": [1, 1.25]})
    shares = [sp[a]["share_pct"] for a in order]
    y = list(range(len(order)))
    a1.barh(y, shares, color=[ACCENT if i == 0 else MUTED for i in y], height=0.66, zorder=3)
    a1.set_yticks(y)
    a1.set_yticklabels([AXIS_LABEL[a] for a in order])
    a1.invert_yaxis()
    a1.set_xlim(0, max(shares) * 1.3)
    for yp, v in zip(y, shares):
        a1.text(v + 0.6, yp, f"{v:.0f}%", va="center", fontsize=13, fontweight="bold", color=INK)
    a1.set_xlabel("share of all slop in the corpus")
    a1.set_title("Share of total slop", loc="left", pad=10, fontsize=16)
    _style(a1, "x")
    data = [[_axis(r, a) for r in graded] for a in order]
    bp = a2.boxplot(data, vert=True, widths=0.55, patch_artist=True, showfliers=False,
                    medianprops=dict(color=ACCENT, linewidth=2.4))
    for p in bp["boxes"]:
        p.set(facecolor=GRID, edgecolor=MUTED, linewidth=1.3)
    for w in bp["whiskers"] + bp["caps"]:
        w.set(color=MUTED, linewidth=1.3)
    a2.set_xticks(range(1, len(order) + 1))
    a2.set_xticklabels([AXIS_LABEL[a] for a in order], fontsize=12)
    a2.set_ylabel("axis subtotal per app")
    a2.set_title("Subtotal per app, outliers hidden", loc="left", pad=10, fontsize=16)
    _style(a2)
    ctx.finish(fig, "fig03_axes")
    _write_csv(ctx.out / "fig03_axes.csv", ["axis", "share_pct", "median", "q1", "q3", "mean", "max"],
               [[a, sp[a]["share_pct"], sp[a]["median"], sp[a]["q1"], sp[a]["q3"], sp[a]["mean"], sp[a]["max"]]
                for a in order])


# ---- fig 4: axis independence --------------------------------------------------------------------------
def fig_axis_corr(ctx, graded, ss):
    m = [[1.0] * 4 for _ in range(4)]
    rows = []
    for i, j in itertools.combinations(range(4), 2):
        rho, p = ss.spearmanr([_axis(r, AXES[i]) for r in graded], [_axis(r, AXES[j]) for r in graded])
        m[i][j] = m[j][i] = float(rho)
        rows.append([AXES[i], AXES[j], round(float(rho), 3), float(p)])
    fig, ax = ctx.plt.subplots(figsize=(7.4, 6.2))
    im = ax.imshow(m, cmap="Blues", vmin=-0.2, vmax=1.0)
    ax.set_xticks(range(4))
    ax.set_yticks(range(4))
    ax.set_xticklabels([AXIS_LABEL[a] for a in AXES], fontsize=12, rotation=20)
    ax.set_yticklabels([AXIS_LABEL[a] for a in AXES], fontsize=12)
    for i in range(4):
        for j in range(4):
            ax.text(j, i, f"{m[i][j]:.2f}", ha="center", va="center", fontsize=14, fontweight="bold",
                    color="white" if m[i][j] > 0.6 else INK)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    ax.set_title("Axis correlation, Spearman ρ", loc="left", pad=12, fontsize=17)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ctx.finish(fig, "fig04_axis_correlation")
    _write_csv(ctx.out / "fig04_axis_correlation.csv", ["axis_a", "axis_b", "spearman_rho", "p_value"], rows)
    return rows


# ---- fig 5: fire frequency -----------------------------------------------------------------------------
def fig_fire_frequency(ctx, fj, top=14):
    ff = fj["fire_frequency"][:top]
    _hbar(ctx, "fig05_fire_frequency", "Most frequent findings",
          [PROBE_LABEL.get(f["probe_id"], f["probe_id"]) for f in ff], [f["pct"] for f in ff],
          "% of graded apps", lambda v: f"{v:.0f}%" if v >= 10 else f"{v:.1f}%",
          highlight=lambda i: ff[i]["probe_id"].startswith("sec-headers"), xmax=112, size=(10, 7),
          csv_rows=[[f["probe_id"], PROBE_LABEL.get(f["probe_id"], ""), f["apps"], f["pct"]] for f in ff],
          csv_header=["probe_id", "label", "apps", "pct"])


# ---- fig 6: worst finding per app ----------------------------------------------------------------------
def fig_worst_finding(ctx, graded):
    bands = [("Minor (1 to 10)", 0, 10), ("Moderate (11 to 20)", 10, 20), ("Serious (21 to 30)", 20, 30),
             ("Severe (31 to 40)", 30, 40), ("Critical (41+)", 40, 10 ** 9)]
    worst = [max((f.get("penalty") or 0 for f in r.get("findings") or [] if _scored(f)), default=0) for r in graded]
    counts = [sum(1 for w in worst if lo < w <= hi) for _, lo, hi in bands]
    n = len(graded)
    _hbar(ctx, "fig06_worst_finding", "Worst finding per app", [b[0] for b in bands], counts,
          "apps (each app counted once, in its worst band)", lambda v: f"{v:,}  ({100 * v / n:.0f}%)",
          highlight=lambda i: i == 4,
          csv_rows=[[b[0], c, round(100 * c / n, 1)] for b, c in zip(bands, counts)],
          csv_header=["worst_finding_band", "apps", "pct"])
    return counts


# ---- fig 7: the exploitable slice ----------------------------------------------------------------------
def fig_exploitable(ctx, graded):
    from benchmark import _is_gate
    per = Counter()
    apps = 0
    for r in graded:
        cats = {f.get("category") for f in r.get("findings") or [] if _is_gate(f)}
        if cats:
            apps += 1
            for c in cats:
                per[EXPLOIT_CLASS.get(c, c)] += 1
    rows = per.most_common()
    _hbar(ctx, "fig07_exploitable", f"Exploitable apps by class (n = {apps})", [r[0] for r in rows],
          [r[1] for r in rows], "apps (an app with two classes counts in both)", lambda v: f"{v}",
          highlight=lambda i: i < 2, csv_rows=[[r[0], r[1]] for r in rows] + [["distinct_apps", apps]],
          csv_header=["class", "apps"])


# ---- fig 8: winners ------------------------------------------------------------------------------------
def fig_winners(ctx, graded, ss):
    W = [r for r in graded if r.get("winner") is True]
    N = [r for r in graded if r.get("winner") is False]
    parts = [("Total slop", lambda r: r["slop_score"]),
             ("Everything but performance", lambda r: r["slop_score"] - _axis(r, "performance")),
             ("Performance axis", lambda r: _axis(r, "performance"))]
    rows = []
    for lab, fn in parts:
        a, b = [fn(r) for r in W], [fn(r) for r in N]
        p = float(ss.mannwhitneyu(a, b, alternative="two-sided").pvalue)
        rows.append([lab, statistics.median(a), statistics.median(b), p])
    fig, ax = ctx.plt.subplots(figsize=(10, 5.6))
    x = list(range(len(rows)))
    ax.bar([i - 0.19 for i in x], [r[1] for r in rows], width=0.36, color=ACCENT, zorder=3,
           label=f"Winners (n = {len(W)})")
    ax.bar([i + 0.19 for i in x], [r[2] for r in rows], width=0.36, color=MUTED, zorder=3,
           label=f"Non winners (n = {len(N)})")
    top = max(max(r[1], r[2]) for r in rows)
    for i, r in enumerate(rows):
        ax.text(i - 0.19, r[1] + top * 0.015, f"{r[1]:.1f}", ha="center", va="bottom", fontsize=12,
                fontweight="bold", color=ACCENT)
        ax.text(i + 0.19, r[2] + top * 0.015, f"{r[2]:.1f}", ha="center", va="bottom", fontsize=12,
                fontweight="bold", color=INK)
        ptxt = f"p = {r[3]:.3f}" if r[3] >= 0.001 else f"p = {r[3]:.1e}"
        ax.text(i, max(r[1], r[2]) + top * 0.1, ptxt, ha="center", fontsize=12, color=FAINT)
    ax.set_ylim(0, top * 1.28)
    ax.set_xticks(x)
    ax.set_xticklabels([r[0] for r in rows])
    ax.set_ylabel("median slop")
    ax.legend(frameon=False, loc="upper right", fontsize=12)
    ax.set_title("Median slop, winners and non winners", loc="left", pad=12)
    _style(ax)
    ctx.finish(fig, "fig08_winners")
    _write_csv(ctx.out / "fig08_winners.csv", ["component", "winner_median", "non_winner_median",
                                               "mann_whitney_p_two_sided"], rows)
    return rows


# ---- fig 9: by host platform ---------------------------------------------------------------------------
def fig_stack(ctx, graded, min_n=10):
    by = defaultdict(list)
    for r in graded:
        by[(r.get("platform") or {}).get("host_platform") or "unknown"].append(r["slop_score"])
    keep = sorted([(k, v) for k, v in by.items() if len(v) >= min_n], key=lambda kv: statistics.median(kv[1]))
    fig, ax = ctx.plt.subplots(figsize=(10, 6))
    bp = ax.boxplot([v for _, v in keep], vert=False, widths=0.6, patch_artist=True, showfliers=False,
                    medianprops=dict(color=ACCENT, linewidth=2.4))
    for p in bp["boxes"]:
        p.set(facecolor=GRID, edgecolor=MUTED, linewidth=1.3)
    for w in bp["whiskers"] + bp["caps"]:
        w.set(color=MUTED, linewidth=1.3)
    ax.set_yticks(range(1, len(keep) + 1))
    ax.set_yticklabels([f"{k}  (n = {len(v)}, median {statistics.median(v):.0f})" for k, v in keep], fontsize=12)
    ax.set_xlabel("slop score (outliers hidden)")
    ax.set_title("Slop by host platform", loc="left", pad=12)
    _style(ax, "x")
    ctx.finish(fig, "fig09_by_platform")
    _write_csv(ctx.out / "fig09_by_platform.csv", ["platform", "n", "median", "q1", "q3"],
               [[k, len(v), round(statistics.median(v), 1), round(statistics.quantiles(v, n=4)[0], 1),
                 round(statistics.quantiles(v, n=4)[2], 1)] for k, v in keep])
    return keep


# ---- fig 10: Lighthouse ---------------------------------------------------------------------------------
def fig_lighthouse(ctx, fj, graded):
    lh = [s for s in (_lh(r) for r in graded) if s is not None]
    o = fj["lighthouse"]["overall"]
    fig, ax = ctx.plt.subplots(figsize=(10, 5.4))
    edges = list(range(20, 105, 5))
    counts = [sum(1 for s in lh if lo <= s < lo + 5 or (lo == 100 and s == 100)) for lo in edges[:-1]]
    counts[-1] += sum(1 for s in lh if s == 100)
    colors = ["#ef4444" if lo < 50 else ACCENT2 if lo < 90 else "#16a34a" for lo in edges[:-1]]
    ax.bar([lo + 2.5 for lo in edges[:-1]], counts, width=4.6, color=colors, zorder=3)
    top = max(counts)
    ax.axvline(o["median"], color=INK, lw=2, zorder=4)
    ax.text(o["median"] - 1, top * 1.06, f"median {o['median']}", ha="right", va="bottom", fontsize=12,
            fontweight="bold")
    ax.text(95, top * 1.06, f"{o['pct_green']:.0f}% green (90+)", ha="center", va="bottom", fontsize=12,
            color="#16a34a", fontweight="bold")
    ax.set_ylim(0, top * 1.2)
    ax.set_xlabel("Lighthouse performance score (mobile, simulated throttling)")
    ax.set_ylabel("apps")
    ax.set_title("Lighthouse performance scores", loc="left", pad=12)
    _style(ax)
    ctx.finish(fig, "fig10_lighthouse")
    _write_csv(ctx.out / "fig10_lighthouse.csv", ["bin_low", "bin_high", "apps"],
               [[lo, lo + 5, c] for lo, c in zip(edges[:-1], counts)])


# ---- fig 11: accessibility rules -----------------------------------------------------------------------
def fig_a11y(ctx, graded, top=8):
    rules = Counter()
    fired = 0
    for r in graded:
        seen = set()
        for f in r.get("findings") or []:
            if f.get("probe_id") == "qa-a11y-001":
                ev = f.get("evidence") or {}
                for rule in (ev.get("rules") if isinstance(ev, dict) else None) or []:
                    seen.add(rule.get("id") if isinstance(rule, dict) else rule)
        if seen:
            fired += 1
            rules.update(seen)
    rows = rules.most_common(top)
    _hbar(ctx, "fig11_a11y_rules", "Accessibility violations by axe rule", [AXE_LABEL.get(r[0], r[0]) for r in rows],
          [100 * r[1] / fired for r in rows], f"% of the {fired:,} apps with an axe finding",
          lambda v: f"{v:.0f}%", highlight=lambda i: i == 0, xmax=100,
          csv_rows=[[r[0], r[1], round(100 * r[1] / fired, 1)] for r in rows],
          csv_header=["axe_rule", "apps", "pct_of_a11y_apps"])


# ---- fig 12: reach ----------------------------------------------------------------------------------------
def fig_reach(ctx, fj):
    au = fj["auth_surface"]
    part = au["partition"]
    names = {"no_auth": "No auth at all", "signup_undrivable": "Signup we cannot drive",
             "password_only": "Password signup, drivable", "login_only": "Login wall, no signup",
             "sso_only": "SSO only", "password_and_sso": "Password + SSO, drivable"}
    arows = sorted(part.items(), key=lambda kv: -kv[1])
    bt = fj["backend_tier"]
    tnames = {"same_origin": "Same origin frontend", "vendor": "Third party vendor",
              "own_backend": "Own backend", "managed_baas": "Managed backend (BaaS)", "opaque": "Opaque host"}
    brows = sorted([(k, bt[k]) for k in tnames], key=lambda kv: -kv[1])
    fig, (a1, a2) = ctx.plt.subplots(1, 2, figsize=(13, 5.4))
    for ax, rows, lab, total, hi, title in [
            (a1, [(names[k], v) for k, v in arows], "apps", au["n"],
             lambda k: "drivable" in k, "Auth shape"),
            (a2, [(tnames[k], v) for k, v in brows], "apps with traffic, tiers overlap", bt["n"],
             lambda k: k == "Own backend", "Backend tier")]:
        y = list(range(len(rows)))
        ax.barh(y, [r[1] for r in rows], color=[ACCENT if hi(r[0]) else MUTED for r in rows], height=0.66,
                zorder=3)
        ax.set_yticks(y)
        ax.set_yticklabels([r[0] for r in rows], fontsize=12)
        ax.invert_yaxis()
        mx = max(r[1] for r in rows)
        ax.set_xlim(0, mx * 1.45)
        for yp, r in zip(y, rows):
            ax.text(r[1] + mx * 0.02, yp, f"{r[1]}  ({100 * r[1] / total:.0f}%)", va="center", fontsize=11,
                    fontweight="bold")
        ax.set_xlabel(f"{lab} (n = {total:,})", fontsize=12)
        ax.set_title(title, loc="left", pad=10, fontsize=16)
        _style(ax, "x")
    ctx.finish(fig, "fig12_reach")
    _write_csv(ctx.out / "fig12_reach.csv", ["panel", "group", "apps", "n"],
               [["auth", k, v, au["n"]] for k, v in arows] + [["backend_tier", k, v, bt["n"]] for k, v in brows])


# ---- hypothesis tests the report quotes -----------------------------------------------------------------
def tests(ctx, graded, ss):
    rows = []
    bld = lambda r: (r.get("platform") or {}).get("builder") or "hand"   # noqa: E731
    hand = [r["slop_score"] for r in graded if bld(r) == "hand"]
    lov = [r["slop_score"] for r in graded if bld(r) == "lovable"]
    rows.append(["lovable slop > hand built slop", "Mann-Whitney U, one sided", len(lov), len(hand),
                 float(ss.mannwhitneyu(lov, hand, alternative="greater").pvalue), ""])
    be = lambda r: any(f["probe_id"].startswith("sec-backend") for f in r.get("findings") or [])  # noqa: E731
    ai = [r for r in graded if bld(r) in ("lovable", "bolt")]
    hd = [r for r in graded if bld(r) == "hand"]
    a1, h1 = sum(map(be, ai)), sum(map(be, hd))
    odds, p = ss.fisher_exact([[a1, len(ai) - a1], [h1, len(hd) - h1]])
    rows.append(["backend exposure rate, AI built vs hand built", "Fisher exact, two sided", len(ai), len(hd),
                 float(p), f"{a1}/{len(ai)} vs {h1}/{len(hd)}, odds ratio {float(odds):.1f}"])
    W = [r for r in graded if r.get("winner") is True]
    N = [r for r in graded if r.get("winner") is False]
    lw = [s for s in map(_lh, W) if s is not None]
    ln = [s for s in map(_lh, N) if s is not None]
    rows.append(["Lighthouse score, winners vs non winners", "Mann-Whitney U, two sided", len(lw), len(ln),
                 float(ss.mannwhitneyu(lw, ln, alternative="two-sided").pvalue),
                 f"medians {statistics.median(lw)} vs {statistics.median(ln)}"])
    sz = lambda r: (r.get("observed_surface") or {}).get("surface_size") or 0  # noqa: E731
    rows.append(["observed surface size, winners vs non winners", "Mann-Whitney U, two sided", len(W), len(N),
                 float(ss.mannwhitneyu(list(map(sz, W)), list(map(sz, N)), alternative="two-sided").pvalue),
                 f"medians {statistics.median(map(sz, W))} vs {statistics.median(map(sz, N))}"])
    by = defaultdict(list)
    for r in graded:
        by[(r.get("platform") or {}).get("host_platform") or "unknown"].append(r["slop_score"])
    grp = [v for v in by.values() if len(v) >= 10]
    rows.append(["slop differs across host platforms (n >= 10)", "Kruskal-Wallis", len(grp), sum(map(len, grp)),
                 float(ss.kruskal(*grp).pvalue), ""])
    ev = defaultdict(list)
    for r in graded:
        ev[r.get("hackathon")].append(r["slop_score"])
    eg = [v for v in ev.values() if len(v) >= 10]
    rows.append(["slop differs across events (n >= 10)", "Kruskal-Wallis", len(eg), sum(map(len, eg)),
                 float(ss.kruskal(*eg).pvalue), ""])
    rho, p = ss.spearmanr([r["slop_score"] for r in graded], list(map(sz, graded)))
    rows.append(["slop vs observed surface size", "Spearman", len(graded), "", float(p), f"rho {float(rho):.3f}"])
    scores = [r["slop_score"] for r in graded]
    rows.append(["distribution shape", "sample skewness / excess kurtosis", len(graded), "", "",
                 f"skew {float(ss.skew(scores)):.2f}, excess kurtosis {float(ss.kurtosis(scores)):.2f}"])
    import random
    rng = random.Random(0)
    boot = sorted(statistics.median(rng.choices(scores, k=len(scores))) for _ in range(2000))
    rows.append(["median slop, 95% bootstrap CI", "percentile bootstrap, 2000 resamples, seed 0", len(graded),
                 "", "", f"{boot[50]:.1f} to {boot[1949]:.1f}"])
    _write_csv(ctx.out / "tests.csv", ["hypothesis", "test", "n_a", "n_b", "p_value", "detail"], rows)
    return rows


def render_all(graded, figures, out_dir="docs/charts", run_name="run.jsonl"):
    """Render every report figure (+ sibling CSVs) and tests.csv into out_dir. `graded` is the curve eligible
    population (stats._is_graded) and `figures` is corpus_json() over the same run."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from scipy import stats as ss
    except ImportError:
        raise SystemExit("charts need matplotlib + scipy: "
                         "`uv run --with matplotlib --with scipy python scripts/stats.py <run> --charts`")
    plt.rcParams.update({
        "font.family": "sans-serif", "font.sans-serif": ["DejaVu Sans", "Arial", "Helvetica"],
        "font.size": 13, "axes.titlesize": 18, "axes.titleweight": "bold", "axes.labelsize": 13,
        "xtick.labelsize": 12, "ytick.labelsize": 12, "axes.edgecolor": MUTED, "axes.linewidth": 0.8,
        "text.color": INK, "axes.labelcolor": FAINT, "xtick.color": FAINT, "ytick.color": INK,
        "figure.facecolor": "white", "savefig.dpi": 160, "axes.spines.top": False, "axes.spines.right": False,
    })
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ctx = _Ctx(plt, out, run_name, _sloptic_version(), len(graded))
    fig_funnel(ctx, figures)
    fig_distribution(ctx, figures)
    fig_axes(ctx, figures, graded)
    fig_axis_corr(ctx, graded, ss)
    fig_fire_frequency(ctx, figures)
    fig_worst_finding(ctx, graded)
    fig_exploitable(ctx, graded)
    fig_winners(ctx, graded, ss)
    fig_stack(ctx, graded)
    fig_lighthouse(ctx, figures, graded)
    fig_a11y(ctx, graded)
    fig_reach(ctx, figures)
    tests(ctx, graded, ss)
    return sorted(str(p) for p in out.glob("*") if p.suffix in (".png", ".csv"))
