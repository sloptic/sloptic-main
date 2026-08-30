"""The egress guard (sloptic/egress.py): the resolver-level chokepoint every outbound connection
passes. These run OFFLINE: hostname cases drive a fake real-resolver (no DNS, no packets), literal
and scope cases refuse before any connect. Mode is pinned per test, overriding the suite's local
lane (tests/conftest.py)."""
import ipaddress
import socket

import httpx
import pytest

from sloptic import egress

GOOD = "93.184.216.34"       # example.com's public v4 (never dialed; fake resolver only)
GOOD2 = "93.184.216.35"


def _ai(ip, port=443, family=socket.AF_INET):
    return (family, socket.SOCK_STREAM, 6, "", (ip, port))


@pytest.fixture(autouse=True)
def _installed():
    egress.install()


@pytest.fixture
def strict(monkeypatch):
    monkeypatch.setenv("SLOPTIC_EGRESS", "on")


@pytest.fixture
def fake_dns(monkeypatch):
    """A recording fake for the REAL resolver under the guard. Returns canned addrinfo per host;
    records every call so tests can assert what the guard passed through vs. dialed."""
    table: dict[str, list] = {}
    calls: list[str] = []

    def _fake(host, port, *args, **kwargs):
        calls.append(host)
        if isinstance(host, str) and host in table:
            return table[host]
        return _real(host, port, *args, **kwargs)

    _real = egress._real_getaddrinfo
    monkeypatch.setattr(egress, "_real_getaddrinfo", _fake)
    return table, calls


# ---------------------------------------------------------------- predicate

@pytest.mark.parametrize("bad", [
    "10.0.0.1", "172.16.0.1", "192.168.1.1",            # RFC1918
    "127.0.0.1",                                          # loopback
    "169.254.169.254",                                    # cloud metadata
    "100.64.0.1",                                         # CGNAT
    "0.0.0.0", "224.0.0.1", "240.0.0.1",                 # this-net / multicast / reserved
    "::1", "fe80::1", "fc00::1",                          # v6 loopback / link-local / ULA
    "::ffff:10.0.0.1",                                    # v4-mapped v6 must normalize, not pass
])
def test_check_ip_refuses_everything_internal(strict, bad):
    assert not egress.check_ip(bad)


@pytest.mark.parametrize("good", ["93.184.216.34", "1.1.1.1", "2606:2800:220:1::1"])
def test_check_ip_allows_public(strict, good):
    assert egress.check_ip(good)


def test_local_mode_allows_loopback_only(monkeypatch):
    monkeypatch.setenv("SLOPTIC_EGRESS", "local")
    assert egress.check_ip("127.0.0.1", allow_loopback=True)
    assert not egress.check_ip("10.0.0.1", allow_loopback=True)   # LAN stays refused


# ---------------------------------------------------------------- literals: attack (a)

def test_private_literal_refused_offline(strict):
    """http://10.0.0.1/ — refused at resolve, so httpx raises ConnectError without a packet
    leaving. This is the integration seam: proves httpx's connect path runs through the guard."""
    with pytest.raises(httpx.ConnectError, match="egress refused"):
        httpx.get("http://10.0.0.1/", timeout=1.0)


def test_loopback_allowed_in_local_mode(monkeypatch):
    monkeypatch.setenv("SLOPTIC_EGRESS", "local")
    infos = socket.getaddrinfo("127.0.0.1", 80)
    assert all(i[4][0] == "127.0.0.1" for i in infos)


# ---------------------------------------------------------------- hostnames: pin + fail-closed

def test_hostname_resolving_private_refused(strict, fake_dns):
    table, _ = fake_dns
    table["evil.test"] = [_ai("10.0.0.9")]
    with pytest.raises(egress.EgressRefused, match="10.0.0.9"):
        socket.getaddrinfo("evil.test", 443)


def test_one_bad_address_refuses_the_whole_host(strict, fake_dns):
    """A DNS reply with one public and one private address is an attacker pattern (rebinding
    setup); the guard is all-or-nothing, fail closed."""
    table, _ = fake_dns
    table["mixed.test"] = [_ai(GOOD), _ai("192.168.0.5")]
    with pytest.raises(egress.EgressRefused):
        socket.getaddrinfo("mixed.test", 443)


def test_pin_the_consumer_dials_the_validated_address(strict, fake_dns):
    """The rebinding defense: what the guard RETURNS is what the consumer connects to, so a TTL-0
    host that alternates answers has no second lookup to lie to. First answer public -> the caller
    receives exactly that sockaddr; a later flip to private is refused as its own lookup."""
    table, calls = fake_dns
    table["rebind.test"] = [_ai(GOOD)]
    out = socket.getaddrinfo("rebind.test", 443)
    assert [i[4] for i in out] == [(GOOD, 443)]
    table["rebind.test"] = [_ai("10.0.0.9")]           # the flip
    with pytest.raises(egress.EgressRefused):
        socket.getaddrinfo("rebind.test", 443)
    assert calls == ["rebind.test", "rebind.test"]     # two lookups, each independently validated


def test_multi_public_answers_preserved_in_order(strict, fake_dns):
    table, _ = fake_dns
    table["multi.test"] = [_ai(GOOD), _ai(GOOD2)]
    out = socket.getaddrinfo("multi.test", 443)
    assert [i[4][0] for i in out] == [GOOD, GOOD2]


# ---------------------------------------------------------------- origin scoping: attack (b)

def test_scoped_offorigin_public_hop_refused(strict, fake_dns):
    """A redirect to a DIFFERENT PUBLIC host is refused while scoped: authorization does not
    travel with a redirect, and the corpus lane only differs by not scoping at all."""
    table, _ = fake_dns
    table["elsewhere.test"] = [_ai(GOOD2)]
    with egress.origin_scope("https://target.test"):
        with pytest.raises(egress.EgressRefused, match="leaves the scoped origin"):
            socket.getaddrinfo("elsewhere.test", 443)


def test_scoped_matching_origin_passes(strict, fake_dns):
    table, _ = fake_dns
    table["target.test"] = [_ai(GOOD)]
    with egress.origin_scope("https://target.test/some/path"):
        assert socket.getaddrinfo("target.test", 443)[0][4][0] == GOOD


def test_scope_enforces_port_too(strict, fake_dns):
    table, _ = fake_dns
    table["target.test"] = [_ai(GOOD)]
    with egress.origin_scope("https://target.test"):
        with pytest.raises(egress.EgressRefused):
            socket.getaddrinfo("target.test", 8443)


# ---------------------------------------------------------------- modes

def test_off_mode_is_a_clean_passthrough(monkeypatch, fake_dns):
    monkeypatch.setenv("SLOPTIC_EGRESS", "off")
    table, calls = fake_dns
    table["any.test"] = [_ai("10.0.0.9")]
    assert socket.getaddrinfo("any.test", 443)[0][4][0] == "10.0.0.9"
    assert calls == ["any.test"]


def test_guard_does_not_recurse_into_itself(strict, fake_dns):
    """The guard's own validation resolve bypasses the patch; a fake that itself calls
    socket.getaddrinfo must not loop."""
    table, _ = fake_dns
    table["ok.test"] = [_ai(GOOD)]
    assert socket.getaddrinfo("ok.test", 443)
