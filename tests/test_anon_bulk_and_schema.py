"""Two detectors for evidence we were already looking at and never reporting.

sec-exposure-008 — ANONYMOUS BULK DATA. Measured on supavulnbase: an unauthenticated GET of
{basePath}/api/admin/export returns 6 sponsor_leads (contact_email, amount_cents), 4 payout_accounts
(account_last4, routing_hint) and 108 profiles. The instructive part is that payout_accounts is that fixture's
OWN control for correct owner-scoped RLS — the database policy is right and this route hands the data out
anyway. No amount of RLS testing finds it, because the flaw sits ABOVE the policy.

    The gate is COLUMN SENSITIVITY, never the path. A product catalog, a blog index and a public profile list
    all return bulk records and none is a leak; on the fixture, `profiles` (username/display_name/bio) is a
    declared CONTROL that must stay silent while sponsor_leads fires.

sec-backend-003 — SCHEMA DISCLOSURE. We were reading both shapes and reporting neither: the RLS probes
enumerate tables from the PostgREST mount root to build their candidate list, and the anon-write oracle reads
the SQLSTATE out of a rejected write to decide whether it passed RLS. The disclosure was a TOOL.
"""
import http.server
import json
import pathlib
import sys
import threading
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from sloptic.net import make_client  # noqa: E402
from sloptic.pipeline import _Ctx  # noqa: E402
from sloptic.probes import anon_bulk_data_exposed, backend_schema_disclosed  # noqa: E402
from sloptic.schema import Endpoint, Profile  # noqa: E402

_LEADS = [{"id": i, "company": "Acme", "contact_email": "a%d@x.test" % i, "amount_cents": 5000}
          for i in range(6)]
_PROFILES = [{"id": i, "username": "u%d" % i, "display_name": "U %d" % i, "bio": "hi"} for i in range(20)]
_CATALOG = [{"id": i, "name": "Widget %d" % i, "price": 9.99, "description": "a widget"} for i in range(12)]


def _serve(routes, seen_headers=None):
    """`routes` maps a path to (status, body). Records the request headers it saw."""
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path
            if seen_headers is not None:
                seen_headers.append(dict(self.headers))
            status, body = routes.get(path, (404, {"e": "no"}))
            b = (body if isinstance(body, str) else json.dumps(body)).encode()
            ctype = "text/html" if isinstance(body, str) else "application/json"
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _run(routes, paths=("/api/x",), headers=None, seen=None):
    srv = _serve(routes, seen)
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    prof = Profile(base_url=base, routes=["/"],
                   endpoints=[Endpoint(path=p, raw_path=p, method="get") for p in paths])
    ctx = _Ctx(base, make_client(base, headers, timeout=8.0, follow_redirects=True), prof, headers)
    try:
        return anon_bulk_data_exposed(ctx, type("P", (), {"probe": {}})()), dict(ctx.evidence)
    finally:
        ctx.client.close()
        srv.shutdown()


# ---------------------------------------------------------------- must fire

def test_bulk_records_with_a_sensitive_column_fire():
    hit, ev = _run({"/api/x": (200, _LEADS)})
    assert hit is True
    assert ev["records"] == 6 and "contact_email" in ev["sensitive_columns"]
    assert "readable to an anonymous request" in ev["repro"]["matched"]


def test_collections_nested_one_key_deep_are_found():
    # the export shape: several collections inside one object, so reading only the top level finds nothing
    hit, ev = _run({"/api/x": (200, {"generated": "weekly", "profiles": _PROFILES, "sponsor_leads": _LEADS})})
    assert hit is True and ev["collection"] == "sponsor_leads"   # the sensitive one, not the control one


def test_an_api_route_is_read_even_when_it_is_not_a_known_endpoint():
    srv = _serve({"/api/admin/export": (200, _LEADS)})
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    prof = Profile(base_url=base, routes=["/", "/api/admin/export"], endpoints=[])
    ctx = _Ctx(base, make_client(base, None, timeout=8.0, follow_redirects=True), prof, None)
    try:
        assert anon_bulk_data_exposed(ctx, type("P", (), {"probe": {}})()) is True
    finally:
        ctx.client.close()
        srv.shutdown()


# ---------------------------------------------------------------- must stay silent

def test_a_public_catalog_is_not_a_leak():
    # THE precision rule: bulk alone is not sensitive. A product list is the whole point of the app.
    hit, ev = _run({"/api/x": (200, _CATALOG)})
    assert hit is False and ev["anon_readable"] is False


def test_a_public_profile_list_is_not_a_leak():
    # supavulnbase's ctl-002 shape: username/display_name/bio readable by design
    assert _run({"/api/x": (200, _PROFILES)})[0] is False


def test_a_single_record_is_not_a_dump():
    assert _run({"/api/x": (200, [_LEADS[0]])})[0] is False
    assert _run({"/api/x": (200, {"leads": _LEADS[:2]})})[0] is False


def test_an_endpoint_that_refuses_anonymous_access_is_the_app_working():
    for code in (401, 403):
        assert _run({"/api/x": (code, _LEADS)})[0] is False


def test_a_non_json_response_is_never_judged():
    verdict, ev = _run({"/api/x": (200, "<html><body>lots of text</body></html>")})
    assert verdict is None and "na_reason" in ev


def test_a_body_sec_exposure_005_already_claims_is_left_to_it():
    """One leak must not be billed twice. A response carrying password material is sec-exposure-005's
    finding, and this probe is 40 points on top of its 35."""
    creds = [{"id": i, "email": "a%d@x.test" % i, "password": "hunter2-plaintext-%d" % i} for i in range(5)]
    verdict, _ev = _run({"/api/x": (200, creds)})
    assert verdict is not True


def test_no_route_to_judge_is_na_not_clean():
    verdict, ev = _run({}, paths=())
    assert verdict is None and "na_reason" in ev


def test_the_request_is_ANONYMOUS_even_when_a_session_is_supplied():
    """The claim is that a STRANGER can read this, so a caller-supplied --header identity must not be sent —
    otherwise the probe proves only that an authenticated user can read their own app."""
    seen = []
    _run({"/api/x": (200, _LEADS)}, headers={"Cookie": "session=theirs"}, seen=seen)
    assert seen, "the probe made no request"
    assert not any("theirs" in (h.get("Cookie") or "") for h in seen)


# ------------------------------------------------ v18 precision: name-only matches that are NOT leaks
# Thirteen apps fired in the v18 corpus; nine were false. The gate keyed on the column NAME alone, so an LLM
# token counter, a phonetics table, a shared config contact and five public directories all read as PII dumps.
# The three gates below (value-type match, per-row variance, public-directory suppression) are grounded in those
# exact shapes -- and the four REAL leaks in the same run must still fire.

def test_a_column_named_like_pii_whose_values_are_counts_is_not_a_leak():
    # 2-actual-hack /api/dashboard: `tokens_total` matched `token`, but the values are LLM token COUNTS (ints).
    rows = [{"id": i, "family": "gpt", "display_name": "M%d" % i, "tokens_total": 1067 + i} for i in range(13)]
    assert _run({"/api/x": (200, rows)})[0] is not True


def test_a_column_named_like_pii_whose_values_are_not_scalars_is_not_a_leak():
    # aaroncao06/AutoRhythm canonical_syllables.json: `phones` matched `phone`, but the values are ARPAbet
    # phoneme arrays (['Y','AE1']), not phone numbers.
    rows = [{"syllable_index": i, "syllable_text": "la", "word_index": i, "phones": ["Y", "AE1"]}
            for i in range(110)]
    assert _run({"/api/x": (200, rows)})[0] is not True


def test_a_survey_field_named_like_pii_is_not_a_leak():
    # cheerful-mind-match Patient entity: `phone_bedtime_habit` matched `phone`, but the value is a survey enum.
    rows = [{"id": i, "age": 30 + i, "concern_duration": "weeks", "phone_bedtime_habit": "1-2 hours"}
            for i in range(19)]
    assert _run({"/api/x": (200, rows)})[0] is not True


def test_one_shared_contact_repeated_across_config_rows_is_not_a_personal_dump():
    # restaurantyai /api/policies: 25 policy rows, every one carrying the SAME managerApprovalPhone -- a config
    # contact, not 25 people's numbers. Per-row variance is what separates a dump from a shared setting.
    rows = [{"_id": i, "maxTransferFee": 5, "noShowGraceMinutes": 15, "managerApprovalPhone": "+13235550124"}
            for i in range(25)]
    assert _run({"/api/x": (200, rows)})[0] is not True


def test_a_public_places_directory_is_not_a_leak():
    # mappy-ai /api/venues: 618 rows of address + a Google Places id + category -- a published listing, not PII.
    rows = [{"id": i, "address": "%d Main St" % i, "city": "NYC", "category": "cafe",
             "google_place_id": "ChIJ%d" % i, "google_maps_url": "http://maps/%d" % i} for i in range(20)]
    assert _run({"/api/x": (200, rows)})[0] is not True


def test_a_scraped_org_directory_is_not_a_leak():
    # eulogy-nu /api/homes: address/email/phone of funeral HOMES, flagged as scraped by `dataSource`.
    rows = [{"id": i, "name": "Home %d" % i, "address": "%d Elm" % i, "email": "h%d@dir.test" % i,
             "phone": "555-010%d" % i, "dataSource": "scrape"} for i in range(20)]
    assert _run({"/api/x": (200, rows)})[0] is not True


def test_an_institution_directory_is_not_a_leak():
    # voh-frontend /api/hospitals: name/address/phone of hospitals, an institutional listing (`departments`).
    rows = [{"id": i, "name": "Hosp %d" % i, "address": "%d Care Way" % i, "phone": "555-020%d" % i,
             "departments": ["ER"], "state": "NJ"} for i in range(3)]
    assert _run({"/api/x": (200, rows)})[0] is not True


def test_a_resource_directory_with_opening_hours_is_not_a_leak():
    # cafeteriasense nj_food_banks.json: address/email/phone of food banks, a resource listing (`hours`).
    rows = [{"id": i, "name": "Bank %d" % i, "address": "%d Aid Rd" % i, "email": "info%d@cfbnj.test" % i,
             "phone": "555-030%d" % i, "hours": "9-5", "pickupFrequency": "weekly"} for i in range(10)]
    assert _run({"/api/x": (200, rows)})[0] is not True


# ------------------------------------------------ v18 precision: the four REAL leaks must still fire

def test_a_delivery_manifest_of_named_customers_still_fires():
    # damm-smart-truck delivery_input.json: real street addresses of named customers with order totals. It has
    # lat/lon like a directory, but NO listing marker (no place id / category / hours) -> not a directory -> fires.
    rows = [{"id": i, "name": "Client %d" % i, "address": "Carrer Gran %d, 08506" % i, "lat": 41.9 + i / 1e3,
             "lon": 2.2, "proformaTotal": 100 + i, "deliveryWindow": "AM"} for i in range(15)]
    hit, ev = _run({"/api/x": (200, rows)})
    assert hit is True and "address" in ev["sensitive_columns"]


def test_user_owned_records_with_distinct_emails_still_fire():
    # alertify-unihack /api/reports: 82 rows, 45 distinct submitter emails + Firebase uids. `category` is present
    # (a directory marker) but `submitted_by_uid` is a per-user ownership column -> ownership vetoes -> fires.
    rows = [{"id": i, "category": "pothole", "submitted_by_email": "user%d@gmail.com" % i,
             "submitted_by_uid": "uid%d" % i, "lat": 1.0, "lng": 2.0} for i in range(20)]
    hit, ev = _run({"/api/x": (200, rows)})
    assert hit is True and "submitted_by_email" in ev["sensitive_columns"]


def test_anon_readable_patient_records_still_fire():
    # interim-pc04 /api/patient: 44 rows of name + real dob + diagnosis, readable to a stranger -> PHI leak. The
    # dob values are real dates, distinct per row, and there is no listing marker -> not a directory -> fires.
    rows = [{"id": i, "name": "Pat %d" % i, "dob": "19%02d-05-12" % (50 + i), "diagnosis": "dx%d" % i}
            for i in range(44)]
    hit, ev = _run({"/api/x": (200, rows)})
    assert hit is True and "dob" in ev["sensitive_columns"]


def test_candidate_records_with_an_ownership_column_still_fire():
    # intelliview-liard /api/get-responses: candidate emails + interview transcripts. `candidateId` is a per-user
    # ownership column (normalises to an ownership marker) -> not a directory -> fires on the distinct emails.
    rows = [{"id": i, "candidateEmail": "cand%d@gmail.com" % i, "candidateId": "c%d" % i,
             "interviewType": "tech"} for i in range(13)]
    hit, ev = _run({"/api/x": (200, rows)})
    assert hit is True and "candidateEmail" in ev["sensitive_columns"]


# ---------------------------------------------------------------- schema disclosure

# the signature segment must be >= 8 chars: probes._JWT requires it, and a 3-char "sig" meant
# no key was mined at all, so the probe correctly read N/A and my test blamed the code
_ANON_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.9x2KqLm8QwEr-sig"


def _serve_gateway(root_status=200, tables=("projects", "profiles"), verbose_error=False):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Server", "kong/2.8.1")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path
            if path == "/rest/v1/":
                if root_status != 200:
                    return self._json(root_status, {"message": "permission denied"})
                return self._json(200, {"swagger": "2.0", "paths": {"/" + t: {} for t in tables}})
            if path in ("/", "/app"):
                port = self.server.server_address[1]
                return self._json(200, {"html": 'createClient("http://127.0.0.1:%d","%s")'
                                                % (port, _ANON_JWT)})
            return self._json(404, {"e": "no"})

        def do_POST(self):
            if verbose_error:
                return self._json(400, {"code": "23502", "message": "null value in column violates not-null",
                                        "details": 'Failing row contains (uuid, null, null).'})
            return self._json(401, {"code": "42501", "message": "row-level security"})

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _run_schema(**kw):
    srv = _serve_gateway(**kw)
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    prof = Profile(base_url=base, routes=["/app"], endpoints=[])
    ctx = _Ctx(base, make_client(base, None, timeout=8.0, follow_redirects=True), prof, None)
    try:
        return backend_schema_disclosed(ctx, type("P", (), {"probe": {}})()), dict(ctx.evidence)
    finally:
        ctx.client.close()
        srv.shutdown()


def test_the_openapi_root_listing_tables_is_a_disclosure():
    hit, ev = _run_schema()
    assert hit is True and ev["via"] == "openapi-root"
    assert ev["table_count"] == 2 and "projects" in ev["tables"]


def test_a_verbose_database_error_is_the_same_disclosure():
    # hosted Supabase blocked the root for anon in Apr 2026, so a correct project 403s there -- the error
    # path is what still catches a gateway that leaks column names
    hit, ev = _run_schema(root_status=403, verbose_error=True)
    assert hit is True and ev["via"] == "verbose-db-error"


def test_a_gateway_that_discloses_neither_reads_clean():
    hit, ev = _run_schema(root_status=403, verbose_error=False)
    assert hit is False and ev["disclosed"] is False


def test_the_disclosure_shapes_have_a_FIXED_PRECEDENCE_so_the_finding_is_attributable():
    """THE ABLATION INVARIANT, and it is about attribution rather than detection.

    supavulnbase's hardened reference is not a should-score-zero twin; it is an ablation harness whose
    `HARDEN_CLASS` fixes exactly ONE flaw class so that "the differential against :8090 is attributable to that
    class alone". That only holds if our findings do not move for reasons belonging to another class.

    This probe has two firing shapes and the second one is NOT independent of RLS. `_serve_gateway`'s own dial
    says so: a terse 42501 is RLS refusing the write, a 23502 with `Failing row contains (...)` is RLS passing
    it and a constraint rejecting it. So `HARDEN_CLASS=rls` flips the anon-write response, and if the probe
    consulted the write FIRST, hardening rls would silence a schema-disclosure finding — the rls delta would
    read 52 instead of 40 and the harness would be measuring our coupling instead of their fix.

    The root is checked first (probes.py: the OpenAPI block returns before the write loop), which makes the top
    two rows below immune to the rls dial. Only cell 3 is legitimately coupled, and there the finding is
    genuinely gone. The matrix is asserted in full because three of these four cells already passed by accident
    and nothing named why.

    CONSEQUENCE FOR THE HARNESS: attribution holds while the PostgREST root stays open, which on supavulnbase
    it deliberately does (info-001, stock self-hosted behaviour). A HARDEN_CLASS that closes the root without
    being the schema-disclosure class would make this finding vanish under the wrong label.
    """
    for root_status, verbose, expect_hit, expect_via in ((200, True, True, "openapi-root"),
                                                         (200, False, True, "openapi-root"),
                                                         (403, True, True, "verbose-db-error"),
                                                         (403, False, False, None)):
        hit, ev = _run_schema(root_status=root_status, verbose_error=verbose)
        label = "root=%s verbose_write=%s" % (root_status, verbose)
        assert hit is expect_hit, label
        assert ev.get("via") == expect_via, label

    # stated as its own assertion because it IS the invariant: with the root open, the rls dial changes nothing
    open_root = [_run_schema(root_status=200, verbose_error=v)[0] for v in (True, False)]
    assert open_root[0] == open_root[1] is True, "the rls dial moved a schema-disclosure verdict"


def test_no_managed_backend_is_na_not_clean():
    srv = _serve({"/": (200, "<html>no backend here</html>")})
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    prof = Profile(base_url=base, routes=["/"], endpoints=[])
    ctx = _Ctx(base, make_client(base, None, timeout=8.0, follow_redirects=True), prof, None)
    try:
        verdict, ev = backend_schema_disclosed(ctx, type("P", (), {"probe": {}})()), dict(ctx.evidence)
        assert verdict is None and "na_reason" in ev
    finally:
        ctx.client.close()
        srv.shutdown()
