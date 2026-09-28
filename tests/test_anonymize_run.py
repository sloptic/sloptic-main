"""The published corpus dataset must carry no app identity and no exploit detail, and must still read the same
through stats.py. A synthetic record carrying every identifying field the real runs carry is anonymized and
checked for leaks."""
import gzip
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import anonymize_run  # noqa: E402
import stats  # noqa: E402

SECRETS = ["cool-app-xyz", "Cool App XYZ", "sb-abcdefgh.supabase.co", "sessionid=deadbeef",
           "/admin/users", "eyJhbGciOiJIUzI1NiJ9.payload.sig", "api.cool-app-xyz.dev"]


def _record(**over):
    r = {
        "repo": "https://cool-app-xyz.vercel.app", "project": "Cool App XYZ", "hackathon": "treehacks-2026",
        "winner": True, "deployed": True, "ts": 1.0, "source": "url", "url_ingest": True,
        "slop_score": 120.0, "axis_slop": {"security": 100.0, "qa": 10.0, "accessibility": 5.0, "performance": 5.0},
        "session_replay": {"Cookie": "sessionid=deadbeef"},
        "deploy_error": "",
        "platform": {"host": "cool-app-xyz.vercel.app", "host_platform": "vercel", "edge": "cloudflare",
                     "builder": None, "signals": ["suffix:cool-app-xyz"]},
        "observed_surface": {"graded_origin": "https://cool-app-xyz.vercel.app", "routes_list": ["/admin/users"],
                             "forms_list": [], "endpoints_list": ["https://api.cool-app-xyz.dev/v1"],
                             "landing_path": "/admin/users", "surface_size": 12, "has_login": True,
                             "host_tiers": {"counts": {"same_origin": 1, "managed_baas": 1},
                                            "baas_hosts": ["sb-abcdefgh.supabase.co"]},
                             "lighthouse": {"performance": 71, "benchmark_index": 1400}},
        "coverage": {"na_reasons_by_probe": {"sec-idor-001": "no login at https://cool-app-xyz.vercel.app/login"}},
        "findings": [
            {"probe_id": "sec-backend-001", "bundle": "security", "category": "backend-exposure", "penalty": 98,
             "contribution": 98, "count": 1, "target": "/admin/users", "reason": "table users open on Cool App XYZ",
             "evidence": {"backend": "supabase", "bulk_read": True, "table": "users",
                          "columns": ["id", "email", "password_hash"], "sensitive_columns": ["phone"],
                          "repro": {"url": "https://sb-abcdefgh.supabase.co/rest/v1/users",
                                    "headers": {"host": "sb-abcdefgh.supabase.co",
                                                "authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"}}}},
            {"probe_id": "perf-lighthouse-001", "bundle": "performance", "category": "overall", "penalty": 5,
             "contribution": 5, "evidence": {"metrics": {"total-blocking-time": "440 ms"}, "score": 71}},
            {"probe_id": "qa-a11y-001", "bundle": "accessibility", "category": "accessibility", "penalty": 5,
             "contribution": 5, "evidence": {"rules": ["color-contrast"],
                                             "locations": {"color-contrast": ["div.hero > p Cool App XYZ"]}}},
        ],
    }
    r.update(over)
    return r


def test_no_identifier_or_exploit_detail_survives():
    out = json.dumps(anonymize_run.anonymize(_record(), "anon:000000000001")).lower()
    for s in SECRETS:
        assert s.lower() not in out, s


def test_exploitable_record_withholds_its_event_but_keeps_what_the_report_reads():
    a = anonymize_run.anonymize(_record(), "anon:000000000001")
    assert a["hackathon"] == anonymize_run.WITHHELD_EVENT
    assert a["winner"] is True and a["repo"] == "anon:000000000001"
    assert a["platform"] == {"host_platform": "vercel", "edge": "cloudflare", "builder": None}
    backend = a["findings"][0]
    assert backend["probe_id"] == "sec-backend-001" and backend["penalty"] == 98
    assert backend["evidence"]["backend"] == "supabase" and backend["evidence"]["bulk_read"] is True
    assert backend["evidence"]["columns"] == ["email", "password"]     # categories only, never the names
    assert backend["evidence"]["sensitive_columns"] == ["other"]       # truthiness kept for the PII count
    assert a["findings"][1]["evidence"]["metrics"] == {"total-blocking-time": "440 ms"}
    assert a["findings"][2]["evidence"] == {"rules": ["color-contrast"]}
    assert a["observed_surface"]["host_tiers"] == {"counts": {"same_origin": 1, "managed_baas": 1}}


def test_clean_record_keeps_its_event():
    r = _record(findings=[])
    assert anonymize_run.anonymize(r, "anon:1")["hackathon"] == "treehacks-2026"


def test_wrong_owner_host_is_kept_as_its_suffix_so_eligibility_is_unchanged():
    r = _record(findings=[], repo="https://prezi.com/view/abc123", platform={"host": "prezi.com",
                                                                             "host_platform": "unknown"})
    a = anonymize_run.anonymize(r, "anon:1")
    assert a["platform"]["host"] == "prezi.com"
    assert stats.is_wrong_owner(a) == stats.is_wrong_owner(r) is True


def test_stats_reads_the_gzipped_output(tmp_path):
    p = tmp_path / "anon.jsonl.gz"
    with gzip.open(p, "wt") as fh:
        fh.write(json.dumps(anonymize_run.anonymize(_record(), "anon:1")) + "\n")
    recs = stats.load(str(p))
    assert len(recs) == 1 and recs[0]["slop_score"] == 120.0
