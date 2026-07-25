"""The RLS probes (sec-backend-001/002) test the tables the app ACTUALLY uses.

Table names were mined from the client bundle only — but a minifier, a dynamically-built query
(`.from(cfg.table)`), or a lazily-loaded chunk hides the name from a static scan, and the anon key can no
longer enumerate the PostgREST root (and guessing was refuted). The app's OWN runtime traffic always carries
it: `GET https://<proj>.supabase.co/rest/v1/<table>`. Discovery records those, the probes test them first.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner.discovery import _observed_backend_tables  # noqa: E402
from hacklet_runner.probes import _firestore_collections, _observed_tables, _supabase_tables  # noqa: E402
from hacklet_runner.schema import Profile, profile_from_dict, profile_to_dict  # noqa: E402


def test_observed_traffic_yields_supabase_and_firestore_table_names():
    observed = [
        ("GET", "https://abcproj.supabase.co/rest/v1/user_profiles?select=*", None),
        ("POST", "https://abcproj.supabase.co/rest/v1/orders", "{}"),
        ("GET", "https://firestore.googleapis.com/v1/projects/p/databases/(default)/documents/messages", None),
        ("GET", "https://app.example.com/api/local", None),          # same-origin -> not a backend table
        ("GET", "https://cdn.vendor.com/analytics.js", None),        # vendor -> ignored
    ]
    assert _observed_backend_tables(observed) == ["user_profiles", "orders", "messages"]


def test_observed_tables_are_deduped_and_empty_without_a_render():
    dupes = [("GET", "https://p.supabase.co/rest/v1/profiles?id=eq.1", None),
             ("GET", "https://p.supabase.co/rest/v1/profiles?id=eq.2", None)]
    assert _observed_backend_tables(dupes) == ["profiles"]
    assert _observed_backend_tables([]) == [] and _observed_backend_tables(None) == []


def test_observed_tables_rank_ahead_of_bundle_and_fallback_names():
    # a MINIFIED bundle: the real table never appears as a literal, so mining alone would miss it entirely
    minified = 'const q=await s.from(cfg.t).select("*");'
    assert "patient_records" not in _supabase_tables(minified)             # bundle scan alone: missed
    ranked = _supabase_tables(minified, ["patient_records"])
    assert ranked[0] == "patient_records"                                  # observed -> tested FIRST
    # observed + mined + fallback compose without duplicates, observed first
    mined = "supabase.from('invoices').select()"
    ranked2 = _supabase_tables(mined, ["invoices", "audit_log"])
    assert ranked2[:2] == ["invoices", "audit_log"] and ranked2.count("invoices") == 1
    fs = _firestore_collections("collection(db, 'notes')", ["chats"])
    assert fs[0] == "chats" and "notes" in fs


def test_probe_reads_observed_tables_off_the_profile_and_survives_the_cache():
    prof = Profile(base_url="https://x", backend_tables=["secrets_table"])
    ctx = type("C", (), {"profile": prof})()
    assert _observed_tables(ctx) == ["secrets_table"]
    # a cached re-grade must test the same tables (the surface cache freezes discovery)
    assert profile_from_dict(profile_to_dict(prof)).backend_tables == ["secrets_table"]
    # tolerant when discovery ran without a browser (no observed traffic) or on an old cache file
    assert _observed_tables(type("C", (), {"profile": Profile(base_url="https://x")})()) == []
    assert profile_from_dict({"base_url": "https://x"}).backend_tables == []
