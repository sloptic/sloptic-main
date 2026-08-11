"""qa-deploy-001 (v2.0 Family 1, unreachable-backend) precision. The URL patterns fire on a dev / private-IP /
unset-env backend URL shipped to the client, and must NOT fire on a server bind address, a hostname dev-check
string, a real host that merely contains the token, a normal backend, or a relative same-origin call."""
from sloptic.probes import _PRIVATE_HOST, _UNSET_ENV_HOST


def _hit(text):
    return bool(_PRIVATE_HOST.search(text) or _UNSET_ENV_HOST.search(text))


def test_fires_on_real_unreachable_backends():
    for s in ('const API="http://localhost:8000/api"',
              'fetch("http://127.0.0.1:3000/v1")',
              'BASE="http://192.168.1.20/api"',
              'x="http://10.0.0.5:8080/"',
              'u="http://172.16.4.2/health"',
              'CDN="https://undefined/assets"',
              'api="https://null:3000/graphql"'):
        assert _hit(s), s


def test_clean_on_bind_address_and_dev_check_strings():
    # a server bind is a tuple, not a URL; a dev-check compares a bare hostname string -> no `http://` prefix
    for s in ('http.server.ThreadingHTTPServer(("0.0.0.0", PORT))',
              "if (window.location.hostname === 'localhost') {",
              'const isDev = host == "127.0.0.1";'):
        assert not _hit(s), s


def test_clean_on_hosts_that_merely_contain_the_tokens():
    for s in ('api="https://undefined.example.com/v1"',   # a real subdomain literally named "undefined"
              'cdn="https://localhosting.io/assets"',       # host CONTAINS "localhost"
              'x="https://nullify.app/api"',                # host CONTAINS "null"
              'p="http://172.15.0.1/x"',                    # 172.15 is PUBLIC (private is 172.16-31)
              'API="https://api.myapp.com/v2"',             # a normal real backend
              'fetch("/api/items")'):                       # a relative same-origin call
        assert not _hit(s), s
