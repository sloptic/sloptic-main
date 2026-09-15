"""sec-backend-004: an anon-listable Supabase Storage bucket exposing other users' files.

Storage policies are separate from table RLS, so this is a distinct exposure from sec-backend-001. The rule
under test is the wedge gate: bare listing is intent-dependent (a public gallery lists itself), so it fires
ONLY on sensitivity -- per-user paths, or a private-content bucket -- never on listing alone. A stub client
answers the storage list call; no network.
"""
import json

import httpx
import pytest

from sloptic import probes

_GATEWAY = "https://abcdefghijklmnop1234.supabase.co"
_ANON = "eyJ" + "a" * 40 + ".eyJyb2xlIjoiYW5vbiJ9." + "b" * 20   # JWT-shaped anon key (role read elsewhere)
_BUNDLE = f'const c=createClient("{_GATEWAY}","{_ANON}");c.storage.from("documents").list();'


class _Ctx:
    def __init__(self, blob):
        self._blob = blob
        self.evidence = {}
        self.base_url = "https://app.example"
        self.profile = None


@pytest.fixture
def wire(monkeypatch):
    """Feed a bundle and a routed storage backend. `routes` maps bucket -> list-response (a list of object
    dicts), or an int status for a refusal."""
    def _set(bundle, routes, base=_GATEWAY):
        monkeypatch.setattr(probes, "_client_bundle", lambda ctx: bundle)
        monkeypatch.setattr(probes, "_supabase_base", lambda blob, ctx: base if base else None)

        def handler(request):
            assert "/storage/v1/object/list/" in request.url.path
            bucket = request.url.path.rsplit("/", 1)[-1]
            ans = routes.get(bucket, 404)
            if isinstance(ans, int):
                return httpx.Response(ans, json={"error": "denied"})
            return httpx.Response(200, json=ans)

        real = httpx.Client
        monkeypatch.setattr(probes.httpx, "Client",
                            lambda **kw: real(transport=httpx.MockTransport(handler),
                                              **{k: v for k, v in kw.items() if k == "timeout"}))
    return _set


def _obj(name):
    return {"name": name, "id": "x", "metadata": {"size": 10}}


def test_per_user_uuid_paths_fire(wire):
    """The strongest signal: object paths carry a UUID segment, so anon can enumerate across users. No app
    intends one user to list another's uploads."""
    wire(_BUNDLE, {"documents": [_obj("3f2504e0-4f89-41d3-9a0c-0305e82c3301/passport.pdf"),
                                 _obj("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d/w2.pdf")]})
    ctx = _Ctx(_BUNDLE)
    assert probes.storage_bucket_listable(ctx, None) is True
    assert ctx.evidence["bucket"] == "documents"
    assert "cross-user" in ctx.evidence["reason"]
    assert ctx.evidence["bulk_read"] is True


def test_a_listable_public_asset_bucket_does_not_fire(wire):
    """The intent-dependent case the wedge excludes: a gallery of flat public assets, listable by design."""
    bundle = f'createClient("{_GATEWAY}","{_ANON}");supabase.storage.from("assets").list();'
    wire(bundle, {"assets": [_obj("logo.png"), _obj("hero-banner.jpg"), _obj("favicon.ico")]})
    ctx = _Ctx(bundle)
    assert probes.storage_bucket_listable(ctx, None) is False   # reached, listable, but not sensitive
    assert ctx.evidence["listable"] is False


def test_a_private_content_bucket_name_is_the_weaker_fire(wire):
    """No per-user path, but the bucket itself denotes private content: a weaker but real signal."""
    bundle = f'createClient("{_GATEWAY}","{_ANON}");supabase.storage.from("user-uploads").list();'
    wire(bundle, {"user-uploads": [_obj("scan001.pdf"), _obj("scan002.pdf")]})
    assert probes.storage_bucket_listable(_Ctx(bundle), None) is True


def test_an_email_path_segment_fires(wire):
    wire(_BUNDLE, {"documents": [_obj("alice@example.com/resume.pdf")]})
    ctx = _Ctx(_BUNDLE)
    assert probes.storage_bucket_listable(ctx, None) is True
    assert "@example.com" not in ctx.evidence["sample"]        # the email sample is masked


def test_a_refused_listing_is_clean_not_a_finding(wire):
    """RLS doing its job: the list call is refused. Reached-but-protected is clean, never N/A."""
    wire(_BUNDLE, {"documents": 403})
    assert probes.storage_bucket_listable(_Ctx(_BUNDLE), None) is False


def test_an_empty_bucket_does_not_fire(wire):
    wire(_BUNDLE, {"documents": []})
    assert probes.storage_bucket_listable(_Ctx(_BUNDLE), None) is False


def test_no_supabase_config_is_na(wire):
    wire("<html>a static site</html>", {}, base=None)
    assert probes.storage_bucket_listable(_Ctx("<html>a static site</html>"), None) is None


def test_an_unreachable_storage_host_is_na_not_clean(monkeypatch):
    """A host that never answered is N/A, never a clean verdict: egress blocked is not proof of safety."""
    monkeypatch.setattr(probes, "_client_bundle", lambda ctx: _BUNDLE)
    monkeypatch.setattr(probes, "_supabase_base", lambda blob, ctx: _GATEWAY)

    def boom(request):
        raise httpx.ConnectError("blocked")
    real = httpx.Client
    monkeypatch.setattr(probes.httpx, "Client",
                        lambda **kw: real(transport=httpx.MockTransport(boom),
                                          **{k: v for k, v in kw.items() if k == "timeout"}))
    ctx = _Ctx(_BUNDLE)
    assert probes.storage_bucket_listable(ctx, None) is None
    assert ctx.evidence["reachable"] is False


def test_buckets_are_mined_from_the_bundle():
    assert "documents" in probes._storage_buckets(_BUNDLE)
    b = probes._storage_buckets('a="/storage/v1/object/public/receipts/2024/x.pdf"')
    assert "receipts" in b


def test_the_probe_is_active_only():
    from sloptic import safety
    from sloptic.catalog import load_catalog
    cat = load_catalog("catalog")
    assert "sec-backend-004" in {p.id for p in cat}
    assert not safety.is_passive("sec-backend-004")            # reads a stranger's store: ownership-gated
