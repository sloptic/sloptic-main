"""Egress sandbox: one resolver-level chokepoint for every outbound connection the grader makes.

The grader fetches URLs it did not choose. Unchecked, a submitted target (or a redirect hop, or a
page-named resource) can walk a fetch toward loopback / RFC1918 / link-local / the cloud metadata
range from whatever machine runs the grader, which turns the service into an SSRF relay and, on the
worker host, a read/act primitive against the LAN. This module narrows every destination to PUBLIC
internet hosts, for every consumer in-process.

WHY THE RESOLVER, NOT A TRANSPORT WRAPPER: httpx (0.28, httpcore via anyio) resolves EVERY
connection through ``socket.getaddrinfo``, including IP-literal hosts (verified empirically; literals
return their own sockaddr through getaddrinfo rather than bypassing it). Guarding that one function
therefore covers, with no per-callsite work:

  * ``net.make_client`` clients AND the ~30 raw ``httpx.Client``/``httpx.get``/``httpx.post`` sites
    in baas.py, auth.py, probes.py, email_verify.py, deploy.py;
  * every REDIRECT hop (each hop is a new request, re-resolved);
  * raw ``socket.create_connection`` users (it resolves through the module-global getaddrinfo).

NOT covered here, by design: the Playwright lane (Chromium is a separate process with its own
resolver; that is the browser route filter, and the OS-level nftables deny is the backstop for
both), and a raw ``sock.socket().connect(("10.0.0.1", 80))`` tuple-literal connect (nothing in this
codebase does that; the nftables tier catches it if one ever appears).

DNS REBINDING / PINNING: the guard resolves through the REAL resolver, validates EVERY returned
address, and returns the original addrinfo list only when all pass. Consumers connect to the
sockaddrs in the list we returned, so the address validated IS the address dialed; there is no
second lookup for a TTL-0 rebind to lie to. One bad address refuses the whole host (fail closed).

MODES (``SLOPTIC_EGRESS`` env, read per call so tests can monkeypatch it):
  * ``on``     default. Public destinations only; loopback included in the refusal.
  * ``local``  the reference-app lane: loopback ALLOWED (DVWA, Juice Shop, the matched pair, the
               local deployers' health gates), everything non-public still refused. The CLI sets
               this for the subprocess/docker lanes; the worker never does.
  * ``off``    bypass, for adversarial experiments only. Never in the worker.

ORIGIN SCOPING: ``origin_scope("https://host:port")`` pins every resolution in the context to that
(host, port) for the duration: a redirect (or anything else) that leaves the submitted origin fails
as a connection error instead of being followed off-site. Independent of the IP predicate: a hop to
another PUBLIC host is refused too while scoped. The web worker wraps a public grade in this; the
corpus lane runs unscoped so its behavior stays identical to the curve it measured.
"""
import contextlib
import contextvars
import ipaddress
import os
import socket
import threading
from urllib.parse import urlparse

_real_getaddrinfo = socket.getaddrinfo
_installed = False
_install_lock = threading.Lock()

# (host, port) the context is pinned to, or None for unscoped (corpus/reference lanes).
_origin_scope: contextvars.ContextVar = contextvars.ContextVar("sloptic_egress_origin", default=None)
# Reentrancy flag: our own validation resolve must use the real resolver, not recurse into the guard.
_in_guard: contextvars.ContextVar = contextvars.ContextVar("sloptic_egress_in_guard", default=False)


class EgressRefused(socket.gaierror):
    """A destination was refused by the egress guard. Subclasses gaierror so existing callers read it
    as a resolution/connection failure (probes catch httpx.HTTPError; httpx maps gaierror to
    ConnectError) rather than crashing, while the message keeps the refusal auditable."""


def mode() -> str:
    """The active egress mode (see module docstring). Read per call, not cached at import."""
    return os.environ.get("SLOPTIC_EGRESS", "on").strip().lower()


_NAT64 = ipaddress.ip_network("64:ff9b::/96")   # RFC 6052 well-known NAT64 prefix (embeds a v4 in the low 32 bits)
_V4COMPAT = ipaddress.ip_network("::/96")        # deprecated IPv4-compatible IPv6 (also embeds a v4)


def check_ip(ip: str, *, allow_loopback: bool = False) -> bool:
    """True only for a PUBLIC unicast address. IPv4-mapped IPv6 is normalized first, so
    ``::ffff:10.0.0.1``, ``64:ff9b::10.0.0.1`` (NAT64), and ``::10.0.0.1`` cannot slip past as v6 literals."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        # Unwrap any IPv6 form that embeds an IPv4 and judge THAT, so a private v4 cannot ride in as a
        # v6 literal: v4-mapped (::ffff:x), NAT64 (64:ff9b::x), and deprecated v4-compatible (::x). A
        # PUBLIC embedded v4 still passes, so grading over a DNS64 network keeps working.
        if addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        elif addr in _NAT64 or (addr in _V4COMPAT and not addr.is_unspecified and not addr.is_loopback):
            addr = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    if allow_loopback and addr.is_loopback:
        return True
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or (isinstance(addr, ipaddress.IPv4Address) and addr in ipaddress.ip_network("100.64.0.0/10"))
    )


def _parse_origin(origin: str) -> tuple[str, int]:
    parts = urlparse(origin if "//" in origin else "//" + origin, scheme="https")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError(f"not an origin: {origin!r}")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return host, port


@contextlib.contextmanager
def origin_scope(origin: str):
    """Pin all resolutions in this context to one origin (scheme+host+port). A hop that leaves it
    raises EgressRefused. Use around a public grade; see the module docstring."""
    tok = _origin_scope.set(_parse_origin(origin))
    try:
        yield
    finally:
        _origin_scope.reset(tok)


def _guarded_getaddrinfo(host, port, *args, **kwargs):
    if host is None or _in_guard.get():
        return _real_getaddrinfo(host, port, *args, **kwargs)

    m = mode()
    if m == "off":
        return _real_getaddrinfo(host, port, *args, **kwargs)
    allow_loop = m == "local"

    scope = _origin_scope.get()
    if scope is not None:
        h = host.lower().rstrip(".") if isinstance(host, str) else host
        if h != scope[0] or (isinstance(port, int) and port != scope[1]):
            raise EgressRefused(
                f"egress refused: {host}:{port} leaves the scoped origin {scope[0]}:{scope[1]}")

    # Resolve through the REAL resolver (guarded against recursion), validate every address, and
    # return the original list only when all pass. Returning this list is the pin: consumers connect
    # to these sockaddrs, which are exactly the addresses just validated.
    tok = _in_guard.set(True)
    try:
        infos = _real_getaddrinfo(host, port, *args, **kwargs)
    finally:
        _in_guard.reset(tok)
    for sockaddr in {info[4] for info in infos}:
        if not check_ip(sockaddr[0], allow_loopback=allow_loop):
            raise EgressRefused(f"egress refused: {host} resolves to non-public {sockaddr[0]}")
    return infos


def install() -> None:
    """Install the resolver guard. Idempotent; called at import of ``sloptic.net`` so every
    entrypoint (CLI, pipeline, worker) is covered without per-caller ceremony."""
    global _installed
    with _install_lock:
        if _installed:
            return
        socket.getaddrinfo = _guarded_getaddrinfo
        _installed = True


# ---------------------------------------------------------------- browser lane

_host_cache: dict[tuple, bool] = {}
_HOST_CACHE_CAP = 2048


def host_allowed(host: str, port: int = 443) -> bool:
    """True if EVERY address `host` resolves to is public (or loopback in local mode).

    For the browser route filter, which asks once per subresource. Two deliberate differences from
    the resolver guard:

      * ORIGIN SCOPE IS NOT APPLIED. A scoped grade pins the GRADER's own fetches to one origin, but
        a normal page legitimately loads fonts, scripts and images cross-origin; enforcing scope on
        subresources would abort half the web and change every measurement. The browser filter is an
        IP-reachability control only.
      * It never raises. A host that does not resolve returns True: there is nothing to protect
        against, and Chromium's own connect will fail naturally, which is the behavior the lane
        already handles.

    Cached per (host, port, mode) since a page pulls many subresources from few hosts.
    """
    key = (host, port, mode())
    cached = _host_cache.get(key)
    if cached is not None:
        return cached

    m = key[2]
    if m == "off":
        return True
    tok = _in_guard.set(True)     # resolve through the REAL resolver: no recursion, no scope
    try:
        infos = _real_getaddrinfo(host, port)
    except socket.gaierror:
        return True               # unresolvable, not cached: DNS may just be flaky right now
    finally:
        _in_guard.reset(tok)

    ok = all(check_ip(i[4][0], allow_loopback=(m == "local")) for i in infos)
    if len(_host_cache) >= _HOST_CACHE_CAP:
        _host_cache.clear()
    _host_cache[key] = ok
    return ok
