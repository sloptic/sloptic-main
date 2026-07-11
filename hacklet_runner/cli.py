"""Deploy/target an app, probe it over HTTP, and report a slop score (lower is better).

Default output is a human-readable summary; --failed lists the probes that detected slop; --json
prints the full machine-readable report. See --help for all options.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import textwrap
from collections import defaultdict
from dataclasses import asdict

from . import browser
from .aggregate import CATEGORY_DECAY
from .catalog import load_catalog
from .deploy import DockerDeployer, RemoteDeployer, SubprocessDeployer
from .ingest import SubmissionError, extract_submission
from .pipeline import run

_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Any deploy/build/health failure -> DNF (the worst outcome), not a crash.
_DEPLOY_FAILURES = (RuntimeError, TimeoutError, subprocess.SubprocessError, OSError)


# ---- output renderers (pure: build text, caller prints) -------------------------------------

def _report_payload(report) -> dict:
    return {"slop_score": report.slop_score, "axis_slop": report.axis_slop,
            "surface": report.surface, "coverage": report.coverage,
            "outcomes": [asdict(o) for o in report.outcomes]}


def _coverage_text(report) -> str:
    """Terminal view of test COVERAGE — what % of the battery applied, and which KINDS ran vs n/a — so a
    low slop score is legible as 'clean' or 'we had little to test'. Empty when no coverage was computed."""
    c = report.coverage
    if not c or not c.get("probes_total"):
        return ""
    lines = [f"  Test coverage: {c['probes_applicable']}/{c['probes_total']} tests applicable "
             f"({c['pct_applicable']}%) · {c['probes_na']} n/a"]
    if c.get("ran_kinds"):
        lines.append(f"    ran ({len(c['ran_kinds'])} kinds): " + ", ".join(c["ran_kinds"]))
    if c.get("na_kinds"):
        lines.append(f"    n/a ({len(c['na_kinds'])} kinds): " + ", ".join(c["na_kinds"]))
    return "\n".join(lines)


def _axis_line(report) -> str:
    # per-axis decomposition of the total (unbounded, same units); subtotals sum to slop_score
    order = ["security", "qa", "performance"]
    parts = [f"{b} {report.axis_slop.get(b, 0)}" for b in order if b in report.axis_slop]
    return "    " + " · ".join(parts) if parts else ""


def _summary_text(report, source: str) -> str:
    outs = report.outcomes
    slop = [o for o in outs if o.outcome == "slop_detected"]
    clean = sum(1 for o in outs if o.outcome == "clean")
    na = sum(1 for o in outs if o.outcome == "not_applicable")
    lines = [
        "",
        f"  {source}",
        "",
        f"  Slop score: {report.slop_score}        lower is better — 0 is clean",
    ]
    if report.axis_slop:
        lines.append(_axis_line(report))
    cov = _coverage_text(report)
    if cov:
        lines += ["", cov]
    lines += [
        "",
        f"  {len(slop)} slop · {clean} clean · {na} n/a        ({len(outs)} checks incl. fan-out)",
        "",
    ]
    if slop:
        lines.append(_score_breakdown_text(report))   # point-based, damper-aware, sums to the score
        lines += ["", "  → --failed lists each probe · --json for the full report"]
    else:
        lines.append("  clean — no slop detected.")
    lines.append("")
    return "\n".join(lines)


def _failed_text(report, source: str) -> str:
    slop = sorted(
        (o for o in report.outcomes if o.outcome == "slop_detected"),
        key=lambda o: (o.bundle, o.category, o.probe_id, o.target),
    )
    lines = ["", f"  {source} — {len(slop)} slop (score {report.slop_score})", ""]
    if not slop:
        return "\n".join(lines + ["  clean — no slop detected.", ""])
    lines.append(f"  {'PROBE':<16} {'CATEGORY':<18} {'PEN':>3}  {'TARGET':<14}  WHY")
    for o in slop:
        lines.append(f"  {o.probe_id:<16} {o.category:<18} {o.penalty:>3}  {(o.target or '—'):<14}  {o.reason}")
    lines.append("")
    return "\n".join(lines)


def _num(n: float) -> str:
    return f"{n:.0f}" if abs(n - round(n)) < 0.05 else f"{n:.1f}"


def _score_breakdown_text(report, decay: float = CATEGORY_DECAY) -> str:
    """Show the dampers at work: how fired penalties fold into the score. Mirrors aggregate.compute_slop_score
    — a variant group contributes once (its max member), then within each category the penalties decay
    (sorted desc, each further hit ×decay); categories sum per bundle, bundles sum to the total."""
    fired = [o for o in report.outcomes if o.outcome == "slop_detected"]
    if not fired:
        return ""
    # variant-group collapse: keep the highest-penalty member per group, remember how many fired
    groups: dict[str, list] = {}       # gid -> [rep_outcome, member_count]
    singles = []
    for o in fired:
        if o.variant_group_id:
            g = groups.get(o.variant_group_id)
            if g is None:
                groups[o.variant_group_id] = [o, 1]
            else:
                g[1] += 1
                if o.penalty > g[0].penalty:
                    g[0] = o
        else:
            singles.append(o)
    cat_pens: dict[tuple, list] = defaultdict(list)   # (bundle, category) -> [penalties feeding the decay]
    cat_notes: dict[tuple, list] = defaultdict(list)  # (bundle, category) -> ["group ×N→max"]
    for o in singles:
        cat_pens[(o.bundle, o.category)].append(o.penalty)
    for gid, (rep, count) in groups.items():
        cat_pens[(rep.bundle, rep.category)].append(rep.penalty)
        if count > 1:
            cat_notes[(rep.bundle, rep.category)].append(f"{gid} ×{count}→{rep.penalty} once")

    lines = ["  how the score is built"
             "   (variant group fires once at its max · then within a category each further hit ×%.1f)" % decay, ""]
    order = {"security": 0, "qa": 1, "performance": 2}
    bundles = sorted({b for b, _ in cat_pens}, key=lambda b: order.get(b, 9))
    bundle_sub = {}
    for bundle in bundles:
        cats = [(bundle, c) for (b, c) in cat_pens if b == bundle]
        sub = {key: [p * decay ** i for i, p in enumerate(sorted(cat_pens[key], reverse=True))] for key in cats}
        bundle_sub[bundle] = round(sum(sum(sub[k]) for k in cats))   # = axis_slop[bundle], self-contained
        lines.append(f"  {bundle}  {bundle_sub[bundle]}")
        for key in sorted(cats, key=lambda k: -sum(sub[k])):
            terms = sub[key]
            formula = " + ".join(_num(t) for t in terms[:5]) + (" + …" if len(terms) > 5 else "")
            note = "   [" + "; ".join(cat_notes[key]) + "]" if cat_notes.get(key) else ""
            lines.append(f"    {key[1]:<20} {_num(sum(terms)):>6}   {formula}{note}")
    roll = " + ".join(f"{b} {bundle_sub[b]}" for b in bundles)
    lines += ["", f"  total  {report.slop_score}   ({roll})"]
    return "\n".join(lines)


def _print_report(report, source: str, args) -> None:
    if args.json:
        print(json.dumps(_report_payload(report), indent=2))
        return
    if args.failed:
        print(_failed_text(report, source))
    else:
        print(_summary_text(report, source))   # summary now always includes the score breakdown


def _fail(args, status: str, reason: str):
    if args.json:
        print(json.dumps({"status": status, "reason": reason}, indent=2))
    else:
        print(f"\n  {status}: {reason}\n")
    raise SystemExit(1)


# ---- live progress (stderr, so --json/--failed on stdout stays clean) ------------------------

_MARK = {"slop_detected": "SLOP", "clean": " ok ", "not_applicable": " -- "}


def _fmt_evidence(ev: dict) -> str:
    """"ttfb_s=0.03  threshold_s=0.8" — the measured values / what was attempted, for any outcome."""
    return "  ".join(f"{k}={v}" for k, v in ev.items())


def _bar(done: int, total: int, probe) -> None:
    w = 24
    filled = int(w * done / total) if total else w
    sys.stderr.write(f"\r\033[K  [{'█' * filled}{'░' * (w - filled)}] "
                     f"{done}/{total}  {probe.bundle}/{probe.category}")
    sys.stderr.flush()


def _make_progress(args):
    """An on_progress callback for run() at the chosen verbosity (or None). All output is on stderr."""
    if args.verbose:
        def cb(done, total, probe, outcomes):
            if outcomes is None:
                sys.stderr.write(f"\n▸ [{done + 1}/{total}] {probe.id}\n")
            else:
                for o in outcomes:
                    tag = f"SLOP -{o.penalty}" if o.outcome == "slop_detected" else _MARK[o.outcome]
                    detail = "  ".join(x for x in (o.reason, _fmt_evidence(o.evidence)) if x)
                    why = f"  {detail}" if detail else ""
                    sys.stderr.write(f"    {tag:<9} {o.category:<18} {(o.target or '—'):<16}{why}\n")
            sys.stderr.flush()
        return cb
    if args.quiet or not sys.stderr.isatty():
        return None  # no animated bar when silenced or piped/non-interactive
    return lambda done, total, probe, outcomes: _bar(done, total, probe) if outcomes is None else None


def _clear_bar(args) -> None:
    if not args.verbose and not args.quiet and sys.stderr.isatty():
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()


# ---- entry point ----------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        prog="hacklet-runner",
        description="Deploy/target an app, probe it over HTTP, and report a slop score (lower is better).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            examples:
              %(prog)s --app references/vulnerable/app.py     # trusted ref, no Docker
              %(prog)s --submission team.zip --harden         # untrusted zip, sandboxed (Docker host)
              %(prog)s --target https://example.com --failed  # an already-running URL

            Only fuzz targets you own or are authorized to test.
            """
        ),
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--submission", metavar="ZIP", help="a submission .zip (built + sandboxed via Docker)")
    src.add_argument("--target", metavar="URL", help="an already-running URL (dogfooding; no Docker)")
    src.add_argument("--app", metavar="PATH", help="a trusted reference app.py (subprocess; dev/CI)")
    ap.add_argument("--catalog", metavar="DIR", default=str(_ROOT / "catalog"), help="probe catalog dir")
    ap.add_argument("--browser", action="store_true",
                    help="render pages with a headless browser (finds SPA/client-rendered forms)")
    ap.add_argument("--header", action="append", metavar="H", default=[],
                    help="auth header sent on EVERY request, e.g. --header 'Cookie: session=...' or "
                         "'Authorization: Bearer ...' — probes the authenticated surface as that user "
                         "(repeatable; note: state-changing probes then act AS that user)")
    ap.add_argument("--harden", action="store_true",
                    help="production sandbox for --submission: read-only rootfs + egress-blocked network")
    ap.add_argument("--network", metavar="NET", default="hacklet-fuzz-net",
                    help="docker network for --harden (create once: docker network create --internal NET)")
    ap.add_argument("--source", metavar="DIR",
                    help="also statically scan this source tree for hardcoded secrets (auto for "
                         "--submission; use with --target when you also have the repo). Folds into the score.")
    out = ap.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="print the full machine-readable JSON report")
    out.add_argument("--failed", action="store_true", help="list only the probes that detected slop")
    out.add_argument("-v", "--verbose", action="store_true",
                     help="stream every probe/target outcome as it runs (stderr), and append the "
                          "score breakdown showing the variant-group + within-category dampers")
    out.add_argument("-q", "--quiet", action="store_true", help="suppress the live progress bar")
    args = ap.parse_args()

    catalog = load_catalog(args.catalog)
    render = browser.render_routes if args.browser else None
    source = args.app or args.target or args.submission
    auth_headers = {}
    for h in args.header:
        name, sep, value = h.partition(":")
        if not sep:
            _fail(args, "bad-arg", f"--header must be 'Name: Value', got: {h!r}")
        auth_headers[name.strip()] = value.strip()
    progress = _make_progress(args)

    if args.source and not pathlib.Path(args.source).exists():
        _fail(args, "bad-arg", f"--source path does not exist: {args.source}")

    # Trusted reference app: subprocess, no Docker.
    if args.app:
        report = run(SubprocessDeployer(args.app), catalog, render=render, headers=auth_headers,
                     on_progress=progress, source_dir=args.source)
        _clear_bar(args)
        _print_report(report, source, args)
        return

    # Already-running URL: dogfooding, no Docker, no teardown of the target.
    if args.target:
        try:
            report = run(RemoteDeployer(args.target), catalog, render=render, headers=auth_headers,
                         on_progress=progress, source_dir=args.source)
        except _DEPLOY_FAILURES as e:
            _fail(args, "unreachable", str(e)[:500])
        _clear_bar(args)
        _print_report(report, source, args)
        return

    # Untrusted submission: unzip -> build -> sandboxed run -> fuzz.
    try:
        sub = extract_submission(args.submission)
    except SubmissionError as e:
        _fail(args, "DNF", str(e))
    try:
        deployer = DockerDeployer(
            str(sub.context_dir),
            read_only=args.harden,
            network=args.network if args.harden else None,
        )
        report = run(deployer, catalog, render=render, headers=auth_headers, on_progress=progress,
                     source_dir=args.source or str(sub.context_dir))  # scan the submission's own source
    except _DEPLOY_FAILURES as e:
        _fail(args, "DNF", str(e)[:500])
    finally:
        sub.cleanup()
    _clear_bar(args)
    _print_report(report, source, args)


if __name__ == "__main__":
    main()
