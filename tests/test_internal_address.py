"""sec-exposure-009 (internal_address_disclosed): the served client bundle leaks a genuinely-INTERNAL address
(an RFC1918 / link-local IP, or an *.internal/.corp/.intranet/.lan hostname). LOOPBACK discloses nothing and must
NOT fire (that presence is qa-deploy-001's availability concern); a PUBLIC host that merely carries an internal
token as a non-final label, or a public IP outside the private ranges, must NOT fire."""
from sloptic.probes import _INTERNAL_ADDR


def _hit(text):
    return bool(_INTERNAL_ADDR.search(text))


def test_fires_on_genuinely_internal_addresses():
    for s in ('API="http://10.0.0.5:8000/api"',
              'x="http://192.168.1.20/health"',
              'u="http://172.16.4.2:3000/v1"',
              'meta="http://169.254.169.254/latest/meta-data/"',   # cloud metadata endpoint
              'base="https://api.internal/graphql"',
              'svc="https://billing.corp/rpc"',
              'db="http://cache.intranet:5432/"',
              'n="https://files.lan/"'):
        assert _hit(s), s


def test_loopback_discloses_nothing_and_does_not_fire():
    # localhost / 127.0.0.1 / [::1] / 0.0.0.0 reveal no topology -> excluded (qa-deploy-001 owns that presence)
    for s in ('API="http://localhost:9999/api"',
              'x="http://127.0.0.1:3000/"',
              'y="http://[::1]:8080/"',
              'z="http://0.0.0.0:8000/"'):
        assert not _hit(s), s


def test_clean_on_public_hosts_and_internal_tokens_as_non_final_labels():
    for s in ('api="https://api.corp.example.com/v1"',   # "corp" is a middle label, not the TLD -> public host
              'x="https://internal.mycompany.com/x"',     # "internal" as a subdomain of a public domain
              'p="http://172.15.0.1/x"',                  # 172.15 is PUBLIC (private is 172.16-31)
              'q="http://11.0.0.1/x"',                    # 11.x is PUBLIC (private is 10.x)
              'API="https://api.myapp.com/v2"',           # a normal real backend
              'fetch("/api/items")'):                     # a relative same-origin call
        assert not _hit(s), s
