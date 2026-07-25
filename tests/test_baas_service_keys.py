"""The two BaaS credential leaks that were invisible, and both are the flagship 2026 vibe-coding failure.

Industry write-ups of the AI-slop security crisis name the same shape repeatedly: Row Level Security left off
in Supabase with a service-role key hardcoded in client-side JavaScript, giving an anonymous visitor
unrestricted database access. We could not see either half of the credential story.

1. A regex CANNOT distinguish the two Supabase keys. An anon key and a service_role key are both JWTs starting
   `eyJ`, the same length, visually identical. The anon key is PUBLIC BY DESIGN and is correctly excluded from
   the provider list; service_role bypasses RLS entirely. The difference lives in the base64 PAYLOAD:
   {"role":"anon"} vs {"role":"service_role"}. Decoding is enough -- no signature check, because we are reading
   the app's own claim about which key it shipped.

2. A service-account PEM inside JSON was missed. The private-key body class excluded a literal backslash, so a
   key in a .pem file was caught and the SAME key in firebase-adminsdk-*.json -- where it lives as
   "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIE..." -- read clean. That is the form almost every app
   actually ships.

The precision half of this file is the important half: an anon key, an authenticated user's session token and an
ordinary app JWT must all stay silent, or every Supabase app on the corpus gets a false 35-penalty finding.
"""
import base64
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner import secretscan  # noqa: E402

_PEM_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj" * 3


def _jwt(payload: dict) -> str:
    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{seg({'alg': 'HS256', 'typ': 'JWT'})}.{seg(payload)}.9x2KqLm8QwEr-sig-Tr0ub4dor"


def _supabase(role: str) -> str:
    return _jwt({"iss": "supabase", "ref": "abcdefghijklmnop", "role": role,
                 "iat": 1700000000, "exp": 2000000000})


# ---------------------------------------------------------------- must fire

def test_a_service_role_key_in_the_client_bundle_fires():
    blob = 'const supabase=createClient("https://abcdefghijklmnop.supabase.co","%s");' % _supabase("service_role")
    assert secretscan.scan_blob(blob) == ["supabase-service-role-key"]


def test_a_service_role_key_in_a_committed_file_fires():
    line = "SUPABASE_SERVICE_ROLE_KEY=%s" % _supabase("service_role")
    kinds = [f.kind for f in secretscan._scan_text(line, ".env")]
    assert "supabase-service-role-key" in kinds


def test_the_role_is_read_from_the_payload_not_the_variable_name():
    # a service_role key stored under an innocuous name is the same catastrophe
    blob = 'window.__CFG__={apiKey:"%s"};' % _supabase("service_role")
    assert secretscan.scan_blob(blob) == ["supabase-service-role-key"]


def test_a_service_account_pem_inside_json_fires():
    doc = ('{"type":"service_account","project_id":"acme-prod","private_key":'
           '"-----BEGIN PRIVATE KEY-----\\n' + _PEM_BODY + '\\n-----END PRIVATE KEY-----\\n"}')
    assert "private-key" in secretscan.scan_blob(doc)


def test_a_raw_pem_still_fires():
    pem = "-----BEGIN PRIVATE KEY-----\n" + _PEM_BODY + "\n-----END PRIVATE KEY-----"
    assert "private-key" in secretscan.scan_blob(pem)


# ---------------------------------------------------------------- must stay clean

def test_the_anon_key_is_public_by_design_and_never_fires():
    # THE precision rule. Every Supabase app ships this key in its bundle on purpose; firing here would put a
    # 35-penalty finding on a correctly-built app. Whether the BACKEND is world-readable is a separate probe.
    blob = 'createClient("https://abcdefghijklmnop.supabase.co","%s")' % _supabase("anon")
    assert secretscan.scan_blob(blob) == []


def test_an_authenticated_users_token_never_fires():
    assert secretscan.scan_blob(_supabase("authenticated")) == []


def test_an_ordinary_app_session_jwt_never_fires():
    assert secretscan.scan_blob(_jwt({"sub": "123", "name": "John", "iat": 1700000000})) == []


def test_a_jwt_shaped_string_that_does_not_decode_never_fires():
    for junk in ("eyJnotbase64atall.eyJalsonotvalid.sig",
                 "eyJhbGciOiJIUzI1NiJ9..sig",
                 "eyJ" + "A" * 40):
        assert secretscan.scan_blob(junk) == [], junk


def test_a_bare_begin_marker_with_no_key_material_never_fires():
    # the pre-existing rule this must not regress: every PEM library contains the marker as a constant
    assert secretscan.scan_blob('if (s.startsWith("-----BEGIN PRIVATE KEY-----")) parse(s);') == []


def test_the_role_claim_must_be_exact():
    for role in ("service", "service-role", "serviceRole", "role_service", ""):
        assert secretscan.scan_blob(_supabase(role)) == [], role


def test_a_payload_that_is_not_an_object_never_fires():
    weird = "eyJhbGciOiJIUzI1NiJ9." + base64.urlsafe_b64encode(b'"service_role"').decode().rstrip("=") + ".sig"
    assert secretscan.scan_blob(weird) == []
