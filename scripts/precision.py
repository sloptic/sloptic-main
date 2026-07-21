#!/usr/bin/env python3
"""precision.py — audit a results JSONL for likely FALSE POSITIVES, so the slop score can be trusted.

stats.py answers "where does slop concentrate?" (recall). This answers "are the fires REAL?" (precision) —
the half stats.py is blind to, and the half a SCORED competition cannot ship without.

The dominant FP mode on real corpora (found dogfooding the Bolt hackathon): a static-SPA catch-all, or a
broken / soft-404 shell, serves the SAME 200 page for every path. Discovery hallucinates phantom
forms/endpoints from that shell, and the server-side probes (SQLi/CSRF/injection/rate-limit) fire on
endpoints that don't exist server-side — e.g. a submission scored SQLi-40 + CSRF-25 on a literal 404 page.
The tell is already on every record: the LLM coverage-audit's `page_state` (broken/placeholder/not-an-app)
and whether the soft-404 probe fired (catch-all). This tool flags those fires deterministically, estimates
per-probe precision, and quantifies how much of the score is phantom.

OFF-SCORE + advisory: it never mutates a slop score. It tells you which fires to distrust and which probes
to harden (the fix is a catch-all/liveness GATE in discovery so the phantom surface is never scored). Run:
    uv run python scripts/precision.py results.jsonl [--json] [--show N]
"""
import argparse
import json
import random
from collections import Counter, defaultdict

# Probes that require a REAL server-side endpoint or state change — hallucinated on a catch-all/broken shell.
_PHANTOM_SENSITIVE = ("sec-sqli", "sec-csrf", "sec-cmdi", "sec-ssti", "sec-lfi", "sec-hosthdr",
                      "sec-split", "sec-ratelimit", "sec-idor", "sec-redirect", "sec-dos", "sec-xss",
                      "sec-ssrf", "qa-crash", "qa-race")
# These probes now route through the endpoint-level LIVENESS GATE (_endpoint_is_live in probes.py): they
# only fire on an endpoint proven distinct from a nonexistent sibling under its own prefix. So a SURVIVING
# fire is on a REAL server endpoint, and the host-level catch-all flag no longer implies a phantom — a modern
# app routinely pairs a catch-all SPA FRONTEND with a real API BACKEND (roadio's /api/locations/search, a real
# SQLi, was firing correctly but getting false-flagged here just because the frontend is a catch-all). We
# TRUST the gate for these and never call their fires catch-all phantoms.
_GATE_VETTED = ("sec-sqli-004", "sec-ratelimit-001", "sec-csrf-001", "qa-crash-010", "sec-dos-001",
                "sec-hosthdr-001")
# Everything else (headers/a11y/seo/perf/compression/dead-controls/...) measures the ACTUAL served
# response and stays real even on a catch-all — a missing CSP header is missing regardless.
_NON_WORKING = {"broken", "not-an-app", "placeholder"}   # page states where the WHOLE surface is untrustworthy
# Third-party fields that reflect by design (anti-bot tokens) — an XSS "reflection" here is the vendor's, not the app's.
_VENDOR_FIELDS = ("cf-turnstile-response", "g-recaptcha-response", "h-captcha-response", "__requestverificationtoken")
# Fires whose SIGNAL is timing (perf) or a load-induced error (crash / sqli-error) — trustworthy only when the
# app was graded in ISOLATION at stable latency. Under a concurrent batch a saturated grader inflates timing and
# a shared backend leaks 500s, so precision.py CANNOT vouch for these from the record alone: it reports them
# UNCONFIRMED (neither clean nor FP) -> re-fire in isolation to resolve. This is the anti-"0 FP is a lie" fix —
# the audit never again counts a concurrency-sensitive fire as verified-clean. (sqli-004's TIME technique is now
# dose-response-hardened and load-robust, but its error technique and crash can still ride a load-induced 500.)
_SIGNAL_SENSITIVE = {"perf-cwv-001", "perf-cwv-002", "perf-loadtime-001", "perf-ttfb-001",
                     "qa-crash-010", "sec-sqli-004"}


def _phantom_sensitive(pid):
    return pid.startswith(_PHANTOM_SENSITIVE)


def _audited(pid):
    """True iff precision.py has an ACTUAL rule that inspects this probe (phantom/catch-all, signal-
    instability, or the exposure/secret guard). When False, a `_suspect()==None` verdict means NO OPINION
    — the finding is UNAUDITED, not verified. The unaudited surface (a11y / headers / seo / perf-requests /
    web-vitals-count / …) is the MAJORITY of the score and exactly where scope & attribution FPs hide (the
    asi1 perf-requests fire is here: real signal, correct probe, live endpoint, wrong owner — every rule
    the audit owns says 'real'). Only a hand-sample (--sample) can vouch for it. See [[fuzz-runner]]."""
    return _phantom_sensitive(pid) or pid in _SIGNAL_SENSITIVE or pid.startswith("sec-secret")


def _page_state(r):
    return (r.get("coverage_audit") or {}).get("page_state")


def _soft404(r):
    return any(f.get("probe_id") == "qa-http-001" for f in r.get("findings", []))


def _suspect(f, catch_all):
    """Classify finding f on a scored app as one of:
      - ("fp", reason)        a likely FALSE POSITIVE (counts toward the precision gap)
      - ("advisory", reason)  a REAL finding flagged for review (NOT an FP), e.g. a third-party platform login
      - None                  looks real
    Gate-aware: sec-sqli-004 / sec-ratelimit-001 / sec-csrf-001 / qa-crash-010 route through the liveness gate,
    so a surviving fire is on a real endpoint — never a catch-all phantom. Rate-limit on a catch-all-frontend
    host is the one nuance: the login is live but is often a THIRD-PARTY platform login (real endpoint, wrong
    OWNER), so it is an advisory, not an FP — it dissolves when teams submit their own URLs."""
    pid = f.get("probe_id", "")
    ev = f.get("evidence") or {}
    if pid.startswith("sec-xss") and (ev.get("field") or "").lower() in _VENDOR_FIELDS:
        return ("fp", f"reflection is a vendor anti-bot field ({ev.get('field')}), not app-controlled XSS")
    if pid == "sec-ratelimit-001" and catch_all:
        return ("advisory", "rate-limit on a live login on a catch-all-frontend host — likely a third-party "
                            "platform login (real endpoint, verify it is the team's own app)")
    if pid in _SIGNAL_SENSITIVE:   # timing / load-induced-error signal: reliable only if graded in isolation.
        return ("unconfirmed", "timing / load-induced-error signal — not verifiable from batch data; clean if "
                               "graded in isolation, else re-fire isolated to confirm (not counted clean or FP)")
    if pid in _GATE_VETTED:
        return None   # liveness-gated: a surviving fire is on a REAL endpoint, not a catch-all phantom
    if _phantom_sensitive(pid) and catch_all:
        return ("fp", "catch-all / soft-404 host — the targeted endpoint likely doesn't exist server-side "
                      "(un-gated phantom-sensitive probe)")
    # Exposure fires on a catch-all host are deliberately NOT flagged. The shell guard now lives at the PROBE
    # level (response_is_dotenv rejects an HTML-shell body/content-type; .git/.aws use signatures HTML can't
    # satisfy; 006 validates the .map parses), so a SURVIVING exposure fire has already cleared it and is REAL.
    # Verified live: 8yhjs2.csb.app is a soft-404 SPA that ALSO serves a genuine /.env (application/octet-stream,
    # real Amplitude/Sentry keys). A host-level catch-all heuristic here DISMISSES real leaks — a false negative
    # on the most severe finding class, strictly worse than the false positive it was meant to catch.
    if pid.startswith("sec-secret") and catch_all:
        return ("advisory", "secret-pattern match in the bundle of a catch-all-frontend host — verify it's a "
                            "real embedded key (sk-ant / sk-live / AKIA…), not a library constant or the shell")
    # NOTE: a login-wall is NOT flagged — its login form + rate-limiting ARE real, testable surface.
    return None


def load(path):
    out = []
    for line in open(path):
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _gated(r):
    """DNF-class: excluded from scoring. functional=False is the grader's authoritative verdict (set with
    corroboration — a deterministic broken signal, or no real surface); the page_state fallback covers records
    graded before the veto. A `disputed_broken` record is the veto's product — the LLM called it broken but
    real surface was captured, so it's SCORED, never gated (and its fires ARE audited like any scored app)."""
    if r.get("disputed_broken"):
        return False
    return r.get("functional") is False or _page_state(r) in _NON_WORKING


def analyze(recs):
    have_score = [r for r in recs if isinstance(r.get("slop_score"), (int, float))]
    gated = [r for r in have_score if _gated(r)]          # correctly DNF'd by the gate -> not a precision problem
    scored = [r for r in have_score if not _gated(r)]     # the apps that ACTUALLY count toward the score
    per_probe = defaultdict(lambda: [0, 0])              # pid -> [fires, FALSE-positives]
    unaudited = defaultdict(lambda: [0, 0])              # pid -> [fires, penalty] the audit has NO rule for
    vouched = 0                                          # fires where a real precision rule ran and passed
    scored_penalty = 0                                   # total penalty across scored fires (for the share)
    fp_reasons, adv_reasons, unconf_reasons = Counter(), Counter(), Counter()
    flagged, advisories, unconfirmed = [], [], []        # (repo, pid, penalty, count, reason)
    catchall_apps = 0
    for r in scored:                                     # measure precision ONLY on what's actually scored
        catch_all = _soft404(r) or bool((r.get("observed_surface") or {}).get("catch_all"))
        catchall_apps += bool(catch_all)
        for f in r.get("findings", []):
            pid = f["probe_id"]
            pen = f.get("penalty", 0) * f.get("count", 1)
            per_probe[pid][0] += 1
            scored_penalty += pen
            res = _suspect(f, catch_all)
            if not res:                                  # `looks real` forks: a rule vouched for it, OR no rule
                if _audited(pid):                        # exists and the audit simply has no opinion (unaudited)
                    vouched += 1
                else:
                    unaudited[pid][0] += 1
                    unaudited[pid][1] += pen
                continue
            klass, why = res
            row = (r.get("repo", ""), pid, f.get("penalty", 0), f.get("count", 1), why)
            if klass == "fp":
                per_probe[pid][1] += 1
                fp_reasons[why.split(" —")[0].split(" (")[0]] += 1
                flagged.append(row)
            elif klass == "unconfirmed":                 # concurrency/latency-sensitive — NOT counted clean or FP
                unconf_reasons[why.split(" —")[0].split(" (")[0]] += 1
                unconfirmed.append(row)
            else:                                        # advisory: a REAL finding flagged for review, not an FP
                adv_reasons[why.split(" —")[0].split(" (")[0]] += 1
                advisories.append(row)
    return {"scored": scored, "gated": gated, "gated_slop": sum(r.get("slop_score") or 0 for r in gated),
            "per_probe": per_probe, "fp_reasons": fp_reasons, "adv_reasons": adv_reasons,
            "unconf_reasons": unconf_reasons, "unconfirmed": unconfirmed,
            "vouched": vouched, "unaudited": dict(unaudited), "scored_penalty": scored_penalty,
            "flagged": flagged, "advisories": advisories, "catchall_apps": catchall_apps}


def _wilson(k, n, z=1.96):
    """95% Wilson score interval for a binomial proportion. Unlike the normal approximation it stays inside
    [0,1] and does not collapse to a fake-tight band at k=0 (0/30 hand-audited is NOT '0% FP, done' — Wilson
    reports it as ~0–11%, which is the honest read on a small sample). This is the whole point of the CI."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return (max(0.0, c - h), min(1.0, c + h))


def _fire_target(f):
    ev = f.get("evidence") or {}
    return ev.get("endpoint") or ev.get("target") or ev.get("path") or ""


def _sample_worksheet(recs, n, seed):
    """Emit N random SCORED fires as a hand-audit worksheet (TSV). The human fills the `verdict` column
    (fp | ok), then `precision.py --tally FILE` turns it into a real FP rate + 95% CI — the ground-truth
    number the heuristic audit structurally cannot produce (it has no oracle; this IS the oracle)."""
    a = analyze(recs)
    fires = [(r.get("repo", ""), f) for r in a["scored"] for f in r.get("findings", [])]
    random.Random(seed).shuffle(fires)                   # seeded -> the draw is reproducible / auditable
    pick = fires[: min(n, len(fires))]
    print(f"# hand-audit worksheet — {len(pick)} of {len(fires)} scored fires (seed={seed}). Reproduce each")
    print(f"# and set VERDICT = fp (false positive) | ok (real) | blank to skip. Then:")
    print(f"#   uv run python scripts/precision.py --tally THIS_FILE")
    print("verdict\trepo\tprobe_id\tpenalty\ttarget\trepro")
    for repo, f in pick:
        repro = " ".join(str((f.get("evidence") or {}).get("repro") or "").split())[:200]
        print(f"\t{repo}\t{f.get('probe_id', '')}\t{f.get('penalty', 0)}\t{_fire_target(f)}\t{repro}")


def _tally(path):
    """Read a filled worksheet and print the hand-audited FP rate + 95% Wilson CI over the resolved verdicts."""
    k = n = 0
    per_probe = defaultdict(lambda: [0, 0])              # pid -> [audited, fp]
    for line in open(path):
        if line.startswith("#") or line.startswith("verdict\t"):
            continue
        cols = line.rstrip("\n").split("\t")
        v = (cols[0].strip().lower() if cols else "")
        if v not in ("fp", "ok"):
            continue                                     # blank / unresolved -> not counted either way
        n += 1
        k += (v == "fp")
        pid = cols[2] if len(cols) > 2 else "?"
        per_probe[pid][0] += 1
        per_probe[pid][1] += (v == "fp")
    if not n:
        print("no resolved verdicts (fill the `verdict` column with fp/ok, then re-run --tally)")
        return
    lo, hi = _wilson(k, n)
    print(f"\n═══ hand-audited precision — {n} fires resolved, {k} false positive(s) ═══")
    print(f"    FP rate    {k / n * 100:5.1f}%     95% CI  {lo * 100:4.1f}% – {hi * 100:4.1f}%")
    print(f"    precision  {(1 - k / n) * 100:5.1f}%     95% CI  {(1 - hi) * 100:4.1f}% – {(1 - lo) * 100:4.1f}%")
    print(f"    -> at n={n}, the TRUE FP rate is plausibly as high as {hi * 100:.1f}%. Widen the draw to tighten it.")
    worst = sorted(((pid, c, fp) for pid, (c, fp) in per_probe.items() if fp), key=lambda x: -x[2])
    if worst:
        print("    by probe (only those with an FP):")
        for pid, c, fp in worst:
            print(f"      {fp}/{c}  {pid}")
    print()


def main():
    ap = argparse.ArgumentParser(description="Audit a results JSONL for likely false positives (precision).")
    ap.add_argument("results", nargs="?", help="results JSONL (or a filled worksheet, with --tally)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--show", type=int, default=20, help="how many flagged findings to list")
    ap.add_argument("--sample", type=int, metavar="N", help="emit N random fires as a hand-audit worksheet (TSV)")
    ap.add_argument("--tally", action="store_true", help="treat `results` as a filled worksheet -> FP rate + 95%% CI")
    ap.add_argument("--seed", type=int, default=0, help="RNG seed for --sample (reproducible draw)")
    args = ap.parse_args()
    if not args.results:
        ap.error("a results JSONL (or worksheet, with --tally) is required")
    if args.tally:                                        # the OTHER half: ground-truth from resolved verdicts
        _tally(args.results)
        return
    recs = load(args.results)
    if args.sample:                                       # emit the worksheet the human resolves
        _sample_worksheet(recs, args.sample, args.seed)
        return
    a = analyze(recs)
    scored = a["scored"]
    total_fires = sum(v[0] for v in a["per_probe"].values())
    total_fp = sum(v[1] for v in a["per_probe"].values())
    fp_apps = len({x[0] for x in a["flagged"]})
    adv_apps = len({x[0] for x in a["advisories"]})
    total_unconf = len(a["unconfirmed"])
    unconf_apps = len({x[0] for x in a["unconfirmed"]})
    vouched = a["vouched"]
    unaudited = a["unaudited"]                            # pid -> [fires, penalty]
    unaudited_fires = sum(v[0] for v in unaudited.values())
    unaudited_pen = sum(v[1] for v in unaudited.values())
    pen_share = (unaudited_pen / a["scored_penalty"] * 100) if a["scored_penalty"] else 0.0

    if args.json:
        print(json.dumps({
            "n_scored": len(scored), "n_gated_dnf": len(a["gated"]), "gated_slop": a["gated_slop"],
            "scored_fires": total_fires, "false_positive_fires": total_fp, "fp_apps": fp_apps,
            "advisory_fires": len(a["advisories"]), "advisory_apps": adv_apps, "catchall_apps": a["catchall_apps"],
            "vouched_fires": vouched, "unaudited_fires": unaudited_fires,
            "unaudited_penalty_pct": round(pen_share, 1),
            "unaudited_by_probe": {pid: v[0] for pid, v in sorted(unaudited.items(), key=lambda x: -x[1][1])},
            "unconfirmed_fires": total_unconf, "unconfirmed_apps": unconf_apps,
            "unconfirmed_reasons": dict(a["unconf_reasons"].most_common()),
            "per_probe_precision": {pid: {"fires": v[0], "false_positives": v[1],
                                          "precision_pct": round((v[0] - v[1]) / v[0] * 100, 1) if v[0] else None}
                                    for pid, v in sorted(a["per_probe"].items())},
            "fp_reasons": dict(a["fp_reasons"].most_common()),
            "advisory_reasons": dict(a["adv_reasons"].most_common()),
        }, indent=2))
        return

    print(f"\n═══ precision audit — {len(scored)} SCORED apps  ({len(a['gated'])} DNF'd by the gate, excluded) ═══")
    print(f"\n⚠  NOT a true-precision number. This audit recognizes a FIXED list of FP classes (catch-all")
    print(f"   phantom · vendor-reflection · signal-instability) and has NO ground-truth oracle. It is blind")
    print(f"   to scope/attribution FPs — a REAL finding on the wrong owner's page (the asi1 perf case). For")
    print(f"   the real number, hand-sample:  python scripts/precision.py {args.results} --sample 30 > w.tsv")

    print(f"\n(0) DNF GATE — {len(a['gated'])} apps broken/not-an-app -> DNF-class, EXCLUDED "
          f"({a['gated_slop']} slop correctly kept out of the distribution; not a precision gap).")

    print(f"\n(1) WHAT THE AUDIT CAN / CANNOT VOUCH FOR")
    print(f"    {vouched:>5} / {total_fires} VOUCHED     — a precision rule ran and passed (liveness-gate / "
          f"catch-all / vendor-field).")
    print(f"    {unaudited_fires:>5} / {total_fires} UNAUDITED   — NO rule exists; neither confirmed nor suspect. "
          f"{pen_share:.0f}% of scored penalty. Hand-sample these:")
    for pid, (fires, pen) in sorted(unaudited.items(), key=lambda x: -x[1][1])[:12]:
        print(f"            {fires:>5} fires · {pen:>6} pen   {pid}")
    if total_unconf:
        print(f"    {total_unconf:>5} / {total_fires} UNCONFIRMED — timing / load-induced-error ({unconf_apps} apps); "
              f"re-fire in isolation to resolve:")
        for why, n in a["unconf_reasons"].most_common():
            print(f"            {n:>5}  {why}")
    print(f"    {total_fp:>5} / {total_fires} KNOWN-CLASS FP ({fp_apps} apps) — only the classes this audit can see:")
    for why, n in a["fp_reasons"].most_common():
        print(f"            {n:>5}  {why}")
    if not a["fp_reasons"]:
        print(f"            (none of the KNOWN classes survived — this says NOTHING about the unaudited surface above)")

    if a["advisories"]:
        print(f"\n(1b) OWNERSHIP-FLAGGED — REAL findings on live endpoints, NOT false positives")
        print(f"    {len(a['advisories'])} fires across {adv_apps} apps. These dissolve when teams submit their OWN URLs:")
        for why, n in a["adv_reasons"].most_common():
            print(f"      {n:>4}  {why}")

    print(f"\n(2) PER-PROBE CATCH-ALL/PHANTOM PRECISION  (audited probes only — NOT the whole surface; "
          f"[gated] = liveness-vetted)")
    rows = [(pid, v[0], v[1]) for pid, v in a["per_probe"].items() if _phantom_sensitive(pid) and v[0]]
    for pid, fires, fp in sorted(rows, key=lambda x: -x[2]) or [(None, 0, 0)]:
        if pid is None:
            print("    (no phantom-sensitive probes fired on scored apps)")
            break
        prec = (fires - fp) / fires * 100
        tag = " [gated]" if pid in _GATE_VETTED else ""
        print(f"    {pid:20} {fires:>4} fires · {fp:>4} FP · {prec:5.0f}% not-phantom {'█' * int(round(prec / 5))}{tag}")

    combined = [("   ", *x) for x in a["flagged"]] + [("[A]", *x) for x in a["advisories"]]
    if combined:
        print(f"\n(3) FLAGGED FINDINGS  (top {args.show} by penalty; [A] = advisory/ownership, not an FP)")
        for mark, repo, pid, pen, cnt, why in sorted(combined, key=lambda x: -x[3])[:args.show]:
            print(f"    {mark} {(repo or '').rsplit('/', 1)[-1][:28]:28} {pid:18} pen={pen:>3}×{cnt:<2} — {why[:52]}")
    print()


if __name__ == "__main__":
    main()
