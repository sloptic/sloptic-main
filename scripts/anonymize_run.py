"""Turn a corpus run file into a dataset that is safe to publish, and that stats.py still reads.

The raw run is never published: each record carries the app's URL, its hosts, session cookies and the evidence
behind every finding, including where a leaked credential or an open table sits. This keeps what the analysis
needs and drops or reduces the rest:

- `repo` becomes a stable random id (`anon:<hex>`); `project`, `session_replay`, `url` fields are dropped.
- `platform` keeps host_platform, edge and builder. `host` survives only on a third party host that the curve
  excludes (a slide deck, a registry), reduced to the matched platform suffix so eligibility stays identical.
- `observed_surface` keeps counts and flags; route, form and endpoint lists, the origin and host lists go.
- each finding keeps probe id, bundle, category, group, penalty, count and contribution. Evidence keeps only
  booleans, numbers, and the fields the report reads (report_only, Lighthouse metrics, audit display, axe rule
  ids, backend kind). Column names reduce to the categories counted (email, password). Paths, targets,
  reasons, repro requests, locations and secret details go.
- `hackathon` is withheld on every exploitable record, so the file never says which event holds an
  exploitable app. Winner flags stay.
- any remaining string is scrubbed of links and of the app's own host and project name.

Usage:
    uv run python scripts/anonymize_run.py multihacksv26retried.jsonl multihacksv26-anon.jsonl.gz
"""
import gzip
import json
import re
import secrets
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import stats  # noqa: E402
from benchmark import _has_catastrophe  # noqa: E402
from sloptic import platform_id  # noqa: E402

WITHHELD_EVENT = "withheld"

_TOP_KEEP = {"contract_version", "ruler", "deployed", "attempts_used", "browser", "source", "model", "ts",
             "provenance", "hackathon", "winner", "url_ingest", "app_kind", "web_gradeable", "stack",
             "stack_profile", "dead_url", "deploy_error", "timings", "slop_score", "axis_slop", "coverage",
             "platform", "bot_challenge", "challenge_stage", "challenge_onset", "request_counts",
             "blocked_probes", "incomplete_axes", "findings", "verdicts", "session_established", "retry",
             "grade_timeout", "timeout", "timeout_phase", "timeout_probe", "timeout_progress", "functional",
             "recon"}
_SURFACE_DROP = {"routes_list", "forms_list", "endpoints_list", "graded_origin", "landing_path"}
_FINDING_KEEP = {"probe_id", "bundle", "category", "group", "penalty", "count", "contribution"}
_EVIDENCE_STR_KEEP = {"backend", "display"}
_EVIDENCE_OTHER_KEEP = {"metrics", "rules"}
_LINK = re.compile(r"https?://\S+|\b[\w-]+(?:\.[\w-]+)*\.(?:com|app|dev|io|ai|net|org|tech|xyz|co|site|host|live|"
                   r"me|us|uk|ca|gg|sh|so|to|fun|page|cloud|run|build|space|online|store|info)\b", re.I)


def _needles(r):
    url = r.get("repo") or ""
    host = urllib.parse.urlparse(url if "://" in url else "http://" + url).hostname or ""
    label = host.split(".")[0]
    proj = r.get("project") if isinstance(r.get("project"), str) else ""
    return [n.lower() for n in (host, label if len(label) > 4 else "", proj if len(proj) > 4 else "") if n]


def _scrub(s, needles):
    s = _LINK.sub("<link>", s)
    low = s.lower()
    for n in needles:
        i = low.find(n)
        while i != -1:
            s = s[:i] + "<app>" + s[i + len(n):]
            low = s.lower()
            i = low.find(n, i + 5)
    return s


# enumerated values (event slugs, probe ids, platform names) are public group keys, never app text; a project
# named after its event or its host would otherwise get its group key scrubbed
_NO_SCRUB = {"hackathon", "host_platform", "edge", "builder", "probe_id", "bundle", "category", "group",
             "challenge_onset", "challenge_stage", "timeout_probe", "timeout_phase", "blocked_probes", "model",
             "app_kind", "source", "stack", "routing", "backend", "rules", "metrics", "ruler"}


def _deep_scrub(o, needles):
    if isinstance(o, dict):
        return {k: (v if k in _NO_SCRUB else _deep_scrub(v, needles)) for k, v in o.items()}
    if isinstance(o, list):
        return [_deep_scrub(v, needles) for v in o]
    return _scrub(o, needles) if isinstance(o, str) else o


def _anon_host(host):
    """Keep a host only when the curve excludes it as a third party surface, reduced to the matched suffix."""
    cat = platform_id.wrong_owner_host(host or "")
    if not cat:
        return None
    h = host.split("/")[0].split(":")[0].lower().rstrip(".")
    if cat == "editor-preview":
        return "id-preview--anon.lovable.app"
    if cat == "s3-bucket":
        return "s3.amazonaws.com"
    for suf in platform_id._WRONG_OWNER_SUFFIX:
        if h == suf or h.endswith("." + suf):
            return suf
    return None


def _evidence(ev):
    if not isinstance(ev, dict):
        return {}
    out = {}
    for k, v in ev.items():
        if isinstance(v, bool) or (isinstance(v, (int, float)) and not isinstance(v, bool)):
            out[k] = v
        elif k in _EVIDENCE_STR_KEEP and isinstance(v, str):
            out[k] = v
        elif k == "metrics" and isinstance(v, dict):
            out[k] = {mk: mv for mk, mv in v.items() if isinstance(mv, (str, int, float))}
        elif k == "rules" and isinstance(v, list):
            out[k] = [x for x in v if isinstance(x, str)]
        elif k in ("columns", "sensitive_columns") and isinstance(v, list):
            joined = " ".join(str(c) for c in v).lower()
            cats = [c for c, pat in (("email", r"email|e_mail"), ("password", r"pass|pwd")) if re.search(pat, joined)]
            out[k] = cats or (["other"] if v else [])   # keep truthiness: a non empty list stays non empty
    return out


def _finding(f):
    out = {k: f[k] for k in _FINDING_KEEP if k in f}
    out["evidence"] = _evidence(f.get("evidence"))
    return out


def anonymize(r, anon_id):
    needles = _needles(r)
    exploitable = _has_catastrophe(r)
    out = {k: v for k, v in r.items() if k in _TOP_KEEP}
    out["repo"] = anon_id
    if exploitable:
        out["hackathon"] = WITHHELD_EVENT
    if isinstance(r.get("platform"), dict):
        p = r["platform"]
        out["platform"] = {k: p[k] for k in ("host_platform", "edge", "builder") if k in p}
    if isinstance(r.get("observed_surface"), dict):
        s = {k: v for k, v in r["observed_surface"].items() if k not in _SURFACE_DROP}
        ht = s.get("host_tiers")
        if isinstance(ht, dict):
            s["host_tiers"] = {"counts": ht.get("counts")} if isinstance(ht.get("counts"), dict) else {}
        out["observed_surface"] = s
    if isinstance(r.get("findings"), list):
        out["findings"] = [_finding(f) for f in r["findings"]]
    if isinstance(r.get("verdicts"), list):
        out["verdicts"] = [{**{k: v[k] for k in v if k not in ("evidence", "reason", "target", "targets")},
                            "evidence": _evidence(v.get("evidence"))} for v in r["verdicts"] if isinstance(v, dict)]
    out = _deep_scrub(out, needles)
    h = _anon_host((r.get("platform") or {}).get("host")) if isinstance(r.get("platform"), dict) else None
    if h:   # set after the scrub, which would otherwise read the kept platform suffix as a link
        out["platform"]["host"] = h
    return out


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    src, dst = sys.argv[1], sys.argv[2]
    recs = stats.load(src)
    ids = set()
    opener = gzip.open if dst.endswith(".gz") else open
    with opener(dst, "wt") as fh:
        for r in recs:
            while True:
                aid = "anon:" + secrets.token_hex(6)
                if aid not in ids:
                    ids.add(aid)
                    break
            fh.write(json.dumps(anonymize(r, aid), separators=(",", ":")) + "\n")
    print(f"wrote {dst}: {len(recs)} records, {sum(_has_catastrophe(r) for r in recs)} with the event withheld")


if __name__ == "__main__":
    main()
