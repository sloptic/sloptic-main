"""The generic `<name> = <value>` rule missed the two most common config formats, and discarded secrets
that merely started with the wrong letter.

Three defects, all found by asking why a served terraform.tfstate and a .docker/config.json read clean:

1. A QUOTED key never matched. `_ASSIGN` wanted the name immediately before the `:`, which JSON's closing
   quote sits in the way of. That blinded the scan to appsettings.json, firebase-adminsdk-*.json,
   serviceAccount.json, .docker/config.json and terraform.tfstate.
2. A BARE value never matched, so YAML was out too: config.yaml, docker-compose.yml, values.yaml.
3. `_PLACEHOLDER`'s word list had no right-hand boundary, so `an?` matched the leading "a" of ANY value and
   every credential starting with a/an/my/the was thrown away as a placeholder.

Widening a generic rule is how false positives get manufactured, so the no-fire half of this file is the
point: interpolations, placeholders, prose, and a package.json author line must all stay clean.
"""
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner import secretscan  # noqa: E402


def _kinds(line: str) -> list:
    return [f.kind for f in secretscan._scan_text(line, "config.json")]


# ---------------------------------------------------------------- must fire

def test_a_quoted_json_key_is_matched():
    assert _kinds('  "password": "Tr0ub4dor-3-horse-battery",') == ["hardcoded-password"]
    assert _kinds('  "api_key": "live_9fJ2kQm4XvB8nR1tYw6ZpL0s"') == ["hardcoded-api_key"]


def test_a_docker_registry_auth_blob_is_matched():
    # the exact shape of ~/.docker/config.json, and the reason bare `auth` is in the name list
    line = '{"auths":{"registry.acme.io":{"auth": "YWNtZWJvdDpzM2NyZXQtcHVzaC10b2tlbg=="}}}'
    assert _kinds(line) == ["hardcoded-auth"]


def test_a_bare_yaml_scalar_is_matched():
    assert _kinds("password: Tr0ub4dor-3-horse-battery") == ["hardcoded-password"]
    assert _kinds("      POSTGRES_PASSWORD: pR9x-Kt2vLm8QwEr") == ["hardcoded-password"]


def test_an_upper_snake_prefix_is_not_a_word_boundary():
    # the compose-file spelling: MYSQL_ROOT_PASSWORD / APP_PROD_DB_ADMIN_PASSWORD
    assert _kinds('  MYSQL_ROOT_PASSWORD: "aQ7zX2mKp9vLr4Tn"') == ["hardcoded-password"]
    assert _kinds("APP_PROD_DB_ADMIN_PASSWORD=Xk92mQ7vLp03ZtRw") == ["hardcoded-password"]


def test_a_secret_starting_with_a_placeholder_letter_is_not_discarded():
    # `an?` with no right boundary ate the leading "a" of every value; ~1 in 13 secrets starts with one
    for v in ("aQ7zX2mKp9vLr4Tn", "anK9vLr4TnXm2Qp7wE", "theR9x-Kt2vLm8Qw", "myS3cret-Kt2vLm8Q"):
        assert secretscan._looks_secret(v) is True, v
        assert _kinds(f'password = "{v}"') == ["hardcoded-password"], v


def test_the_established_forms_still_fire():
    assert _kinds('DB_PASSWORD = "Tr0ub4dor-3-horse-battery"') == ["hardcoded-password"]
    assert _kinds('password: "Tr0ub4dor-3-horse-battery"') == ["hardcoded-password"]
    assert _kinds('client_secret: "GOCSPX-aB3dEf7hJk9LmN2pQ"')  # provider + generic both acceptable


# ---------------------------------------------------------------- must stay clean

def test_an_interpolation_is_never_a_secret():
    for line in ('  "password": "${DB_PASSWORD}"',
                 "password: ${{ secrets.DB_PASS }}",
                 "password = env.DB_PASSWORD_SECRET",
                 "const secret = process.env.SESSION_SECRET",
                 'password: "%(db_password)s"'):
        assert _kinds(line) == [], line


def test_a_documented_placeholder_is_never_a_secret():
    for line in ("password: your-password-here", "password: change-me-please",
                 'password: "xxxxxxxxxxxxxxxx"', 'password: "REDACTED_FOR_SECURITY"',
                 '  "access_key": "AKIAIOSFODNN7EXAMPLE"', '  "password": ""',
                 '  "password": null'):
        assert _kinds(line) == [], line


def test_prose_and_slugs_are_not_credentials():
    # the bare-value entropy bar: all-lowercase words joined by separators are prose, and are exactly the
    # shape that false-fired on CSS class names before
    for line in ("api_key: see_the_docs_below", "token: sk-cube-inner-wrapper-item",
                 "auth: https://auth.example.com/callback",
                 "# password: set this in your deployment secrets"):
        assert _kinds(line) == [], line


def test_lookalike_field_names_stay_out():
    # `auth` is broad enough to be dangerous: oauth, author, passwordless must not match
    for line in ('  "author": "Jane Q. Public-Smith"',
                 '  "oauth": "provider-google-workspace"',
                 "passwordless_login_enabled_for_all: true"):
        assert _kinds(line) == [], line


def test_the_name_prefix_cannot_backtrack_catastrophically():
    # a separator-joined prefix is bounded repetition on purpose; the unbounded form would hang here
    evil = "_".join(["a" * 20] * 180)
    start = time.perf_counter()
    secretscan._scan_text(evil, "x")
    assert (time.perf_counter() - start) < 0.5
