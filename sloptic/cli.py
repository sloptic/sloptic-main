"""Deploy/target an app, probe it over HTTP, and report a slop score (lower is better).

Default output is a human-readable summary; --failed lists the probes that detected slop; --json
prints the full machine-readable report; --report-card renders the team-facing durability card
(what was expected, what we saw, what it indicates, how to fix, per finding). See --help.
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

from . import browser, runcache, safety
from .aggregate import CATEGORY_DECAY
from .catalog import ProbeSelectionError, default_catalog_dir, load_catalog, select_probes
from .deploy import DockerDeployer, RemoteDeployer, SubprocessDeployer
from .ingest import SubmissionError, extract_submission
from .pipeline import run

_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Any deploy/build/health failure -> DNF (the worst outcome), not a crash.
_DEPLOY_FAILURES = (RuntimeError, TimeoutError, subprocess.SubprocessError, OSError)


# ---- output renderers (pure: build text, caller prints) -------------------------------------

def _report_payload(report) -> dict:
    return {"slop_score": report.slop_score, "axis_slop": report.axis_slop,
            "surface": report.surface, "coverage": report.coverage, "platform": report.platform,
            "bot_challenge": report.bot_challenge, "challenge_stage": report.challenge_stage,
            "challenge_onset": report.challenge_onset, "request_counts": report.request_counts,
            "blocked_probes": report.blocked_probes, "incomplete_axes": report.incomplete_axes,
            "outcomes": [asdict(o) for o in report.outcomes]}


def _grade_record(report, source: str) -> dict:
    """One grade as a benchmark-RANKABLE record: the same shape the corpus writer emits, so a single app can be
    placed on the frozen curve with `python scripts/benchmark.py rank --results <file>`. `findings` are the fired
    outcomes — the ranker reads their category for the absolute gate and their probe_id for coverage; the rest
    (axis_slop, coverage.applied/ran_kinds, observed_surface) drive the per-axis rank, slop_potential and the
    completeness bundle."""
    findings = [asdict(o) for o in report.outcomes if o.outcome == "slop_detected"]
    rec = {"repo": source, "deployed": True, "slop_score": report.slop_score,
           "axis_slop": report.axis_slop, "coverage": report.coverage, "observed_surface": report.surface,
           "platform": report.platform, "bot_challenge": report.bot_challenge,
           "challenge_stage": report.challenge_stage, "challenge_onset": report.challenge_onset,
           "request_counts": report.request_counts, "blocked_probes": report.blocked_probes,
           "incomplete_axes": report.incomplete_axes, "findings": findings}
    # v2.0 Family 2: carry the OFF-SCORE a11y advisory candidates even when a11y is CLEAN (so not in `findings`).
    # The decorrelated apps are exactly the ones clean on the scored a11y carrier but failing an advisory rule,
    # so the re-grade needs their advisory data to measure decorrelation before promoting any of it to the score.
    for o in report.outcomes:
        adv = (o.evidence or {}).get("advisory_a11y")
        if adv:
            rec["advisory_a11y"] = adv
            break
    return rec


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
    # per-axis decomposition of the total (unbounded, same units); subtotals sum to slop_score. An axis a
    # challenge cut short is flagged ⚠ — its subtotal is a floor (untested probes could only ADD slop).
    order = ["security", "qa", "performance"]
    inc = set(report.incomplete_axes or [])
    parts = [f"{b} {report.axis_slop.get(b, 0)}{' ⚠' if b in inc else ''}"
             for b in order if b in report.axis_slop or b in inc]
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
    if report.incomplete_axes:   # a challenge cut the grade short -> say so LOUDLY; never let it read as clean
        axes = ", ".join(report.incomplete_axes)
        n = len(report.blocked_probes or [])
        lines += ["",
                  f"  ⚠ {axes} INCOMPLETE — {n} probes edge-blocked by a challenge"
                  f"{f' at {report.challenge_onset}' if report.challenge_onset else ''}.",
                  f"    Partial grade: a low {axes} score here is NOT a clean bill of health."]
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


def _render_card(report, source: str, args) -> None:
    """Team-facing durability report card. Markdown to stdout (--report-card), or written to a file whose
    extension picks the format (.html -> a shareable page, else markdown). Reuses the corpus-shaped grade
    record, so the CLI card is byte-identical to the batch `scripts/report_card.py` output for the same app."""
    from .reportcard import build_card, to_html, to_markdown
    card = build_card(_grade_record(report, source), catalog_root=args.catalog, organizer=args.organizer)
    dest = args.report_card
    if dest and dest != "-":
        text = to_html(card) if dest.lower().endswith((".html", ".htm")) else to_markdown(card)
        pathlib.Path(dest).write_text(text)
        print(f"  report card written to {dest}")
    else:
        print(to_markdown(card))


def _print_report(report, source: str, args) -> None:
    if getattr(args, "out", None):
        from .jsonl import append_jsonl
        append_jsonl(args.out, _grade_record(report, source))
    if getattr(args, "report_card", None) is not None:
        _render_card(report, source, args)
        return
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
        prog="sloptic",
        description="Deploy/target an app, probe it over HTTP, and report a slop score (lower is better).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            examples:
              %(prog)s --app references/vulnerable/app.py     # trusted ref, no Docker
              %(prog)s --submission team.zip --harden         # untrusted zip, sandboxed (Docker host)
              %(prog)s --target https://example.com --failed  # an already-running URL
              %(prog)s --app references/vulnerable/app.py --report-card card.html  # shareable team card

            Only fuzz targets you own or are authorized to test.
            """
        ),
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--submission", metavar="ZIP", help="a submission .zip (built + sandboxed via Docker)")
    src.add_argument("--target", metavar="URL", help="an already-running URL (dogfooding; no Docker)")
    src.add_argument("--app", metavar="PATH", help="a trusted reference app.py (subprocess; dev/CI)")
    ap.add_argument("--catalog", metavar="DIR", default=str(default_catalog_dir()), help="probe catalog dir")
    ap.add_argument("--probe", metavar="PATTERN", action="append", default=[],
                    help="run ONLY these probes (repeatable): an id glob (sec-sqli-004, sec-sqli-*, sec-*), "
                         "or bundle:security / category:xss for groupings an id glob can't express. Answers "
                         "'why didn't THIS probe fire here' in one fast run, and grades a target whose "
                         "expected vulnerability class is known without spending the whole battery's traffic "
                         "on it. RECALL ONLY: the score is a subset, not comparable to a full grade. A "
                         "pattern that matches nothing is a fatal error, never an empty catalog.")
    ap.add_argument("--passive-only", action="store_true",
                    help="run ONLY passive probes (observation a normal visitor does: headers/TLS/a11y/perf/"
                         "exposure GETs). Excludes every ACTIVE probe (injection, mutation, fault-induction, "
                         "hammering, multi-account). For grading a target whose ownership is NOT verified, "
                         "e.g. the public web product. A passive grade is a SUBSET, not comparable to a full grade.")
    ap.add_argument("--browser", action="store_true",
                    help="render pages with a headless browser (finds SPA/client-rendered forms)")
    ap.add_argument("--browser-auth", action="store_true", dest="browser_auth",
                    help="authenticate the crawl AND the probes via the browser register lane (implies the "
                         "effect of --browser for auth): self-register a throwaway account, carry its session "
                         "into the crawl so an SPA's behind-login surface (upload/CRUD/IDOR) is mapped, and let "
                         "the injection/upload probes reach it. No effect without --browser, or with --header "
                         "(a supplied session is used directly).")
    ap.add_argument("--header", action="append", metavar="H", default=[],
                    help="auth header sent on EVERY request, e.g. --header 'Cookie: session=...' or "
                         "'Authorization: Bearer ...' — probes the authenticated surface as that user "
                         "(repeatable; note: state-changing probes then act AS that user)")
    ap.add_argument("--email-domain", metavar="DOMAIN",
                    help="domain of a throwaway inbox WE own for the email-verification probes (e.g. "
                         "anachron.dev); registration addresses are hl-<tag>@DOMAIN")
    ap.add_argument("--email-endpoint", metavar="URL",
                    help="HTTP endpoint returning received mail as JSON (the Cloudflare Email Worker's /mail); "
                         "without --email-domain + --email-endpoint the email-verification probes read N/A")
    ap.add_argument("--email-token", metavar="TOKEN", default="",
                    help="Bearer token for --email-endpoint (the Worker's MAIL_TOKEN secret)")
    ap.add_argument("--harden", action="store_true",
                    help="production sandbox for --submission: read-only rootfs + egress-blocked network")
    ap.add_argument("--network", metavar="NET", default="sloptic-net",
                    help="docker network for --harden (create once: docker network create --internal NET)")
    ap.add_argument("--source", metavar="DIR",
                    help="also statically scan this source tree for hardcoded secrets (auto for "
                         "--submission; use with --target when you also have the repo). Folds into the score.")
    out = ap.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="print the full machine-readable JSON report")
    out.add_argument("--out", metavar="FILE",
                     help="append this grade as a JSONL record, then place it on the frozen curve with "
                          "`python scripts/benchmark.py rank --results FILE`")
    out.add_argument("--failed", action="store_true", help="list only the probes that detected slop")
    out.add_argument("--report-card", metavar="FILE", nargs="?", const="-",
                     help="render the team durability report card instead of the summary: markdown to stdout "
                          "(bare --report-card), or to a file (--report-card card.md, or card.html for a "
                          "shareable page). Per finding: what was expected, what we observed, what it "
                          "indicates, and how to fix it.")
    out.add_argument("--organizer", action="store_true",
                     help="with --report-card, reveal hidden-pool (anti-gaming) findings in full; "
                          "without it they are an opaque withheld count")
    out.add_argument("-v", "--verbose", action="store_true",
                     help="stream every probe/target outcome as it runs (stderr), and append the "
                          "score breakdown showing the variant-group + within-category dampers")
    out.add_argument("-q", "--quiet", action="store_true", help="suppress the live progress bar")
    cache = ap.add_argument_group("run cache")
    cache.add_argument("--refresh", action="store_true",
                       help="ignore any cached grade for this target and re-probe (then overwrite the cache)")
    cache.add_argument("--no-cache", action="store_true",
                       help="do not read or write the run cache at all (always grade fresh)")
    args = ap.parse_args()

    try:
        catalog = select_probes(load_catalog(args.catalog), args.probe)
    except ProbeSelectionError as e:
        sys.exit(f"ERROR: {e}")
    if args.passive_only:   # safe-on-unverified subset: drop every active probe before anything runs
        n_full = len(catalog)
        catalog = safety.passive_catalog(catalog)
        sys.stderr.write(f"  passive-only: {len(catalog)} of {n_full} probes (active probes excluded). "
                         f"This score is a SUBSET and is not comparable to a full grade.\n")
    if args.probe:   # a subset run: say so, because the score is NOT a full grade
        sys.stderr.write(f"  probe filter: {', '.join(args.probe)} -> {len(catalog)} of "
                         f"{len(load_catalog(args.catalog))} probes. Recall check only; this score is a "
                         f"SUBSET and is not comparable to a full grade.\n")
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

    # Run cache: a second grade of the same target (grade-affecting flags + code/catalog unchanged) reuses the
    # stored Report, so switching the OUTPUT view (--failed / --report-card / --json) doesn't re-probe the app.
    key = None if args.no_cache else runcache.cache_key(
        source, args.catalog, probes=args.probe, passive_only=args.passive_only, browser=args.browser,
        headers=args.header, source_dir=args.source, harden=args.harden, browser_auth=args.browser_auth)
    report = None
    if key and not args.refresh:
        hit = runcache.load(key)
        if hit:
            report, age = hit
            sys.stderr.write(f"  ✓ cached grade ({runcache.human_age(age)} old) — --refresh to re-grade\n")
    if report is None:
        report = _grade(args, source, catalog, render, auth_headers, progress)
        if key:
            runcache.save(key, report, source)
    _clear_bar(args)
    _print_report(report, source, args)


def _build_email_receiver(args):
    """The email-verification probes' inbox: an HttpReceiver over the configured Worker endpoint, or None (the
    probes then read N/A). Needs BOTH --email-domain (the address suffix) and --email-endpoint (the poll URL)."""
    if not (getattr(args, "email_endpoint", None) and getattr(args, "email_domain", None)):
        return None
    from .email_verify import HttpReceiver
    return HttpReceiver(domain=args.email_domain, endpoint=args.email_endpoint, token=args.email_token or "")


def _grade(args, source, catalog, render, auth_headers, progress):
    """Deploy the source (subprocess / remote URL / sandboxed submission) and run the battery, returning the
    Report. Deploy/build/health failure -> _fail (SystemExit). Factored out so main() can short-circuit to the
    run cache before this ever executes."""
    email_receiver = _build_email_receiver(args)   # email-verification probes' inbox (None -> they read N/A)
    # --browser-auth: self-register a throwaway account via the browser lane and (a) carry its session into the
    # crawl so an SPA's behind-login surface is mapped (auth_crawl), and (b) let the probes reuse it. Needs a real
    # browser render; off when a --header session is already supplied (that is used directly).
    browser_register = browser.register_in_browser if (args.browser_auth and args.browser) else None
    auth_crawl = bool(args.browser_auth and args.browser and not auth_headers)
    # Trusted reference app: subprocess, no Docker.
    if args.app:
        return run(SubprocessDeployer(args.app), catalog, render=render, headers=auth_headers,
                   on_progress=progress, source_dir=args.source, email_receiver=email_receiver,
                   browser_register=browser_register, auth_crawl=auth_crawl)

    # Already-running URL: dogfooding, no Docker, no teardown of the target.
    if args.target:
        try:
            return run(RemoteDeployer(args.target), catalog, render=render, headers=auth_headers,
                       on_progress=progress, source_dir=args.source, email_receiver=email_receiver,
                       browser_register=browser_register, auth_crawl=auth_crawl)
        except _DEPLOY_FAILURES as e:
            _fail(args, "unreachable", str(e)[:500])

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
        return run(deployer, catalog, render=render, headers=auth_headers, on_progress=progress,
                   browser_register=browser_register, auth_crawl=auth_crawl,
                   source_dir=args.source or str(sub.context_dir),  # scan the submission's own source
                   email_receiver=email_receiver)
    except _DEPLOY_FAILURES as e:
        _fail(args, "DNF", str(e)[:500])
    finally:
        sub.cleanup()


if __name__ == "__main__":
    main()
