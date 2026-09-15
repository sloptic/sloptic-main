"""provider_validate: the tri-state answer from the provider, and what must never leak."""
import httpx
import pytest

from sloptic import provider_validate as pv

_KEY = "AIza" + "SyAb3Cd9Ef2Gh8Ij4Kl7Mn1Op5Qr6St0Uv1"


def _client(status, handler=None):
    return httpx.Client(transport=httpx.MockTransport(handler or (lambda r: httpx.Response(status))))


@pytest.mark.parametrize("status,expected", [
    (200, True),                       # the key reaches Gemini: a live inference credential in public
    (400, False), (401, False), (403, False),   # refused: a Firebase/Maps key, public by design, not a finding
    (429, None), (500, None), (503, None),      # unknown, and unknown is never scored
])
def test_the_provider_answer_is_tri_state(status, expected):
    assert pv.gemini_key_is_live(_KEY, client=_client(status)) is expected


def test_it_asks_the_models_endpoint_which_generates_no_tokens():
    """Listing models authenticates the key without running inference, so the check is free for its owner."""
    seen = {}

    def h(request):
        seen["url"] = request.url
        return httpx.Response(200)
    pv.gemini_key_is_live(_KEY, client=_client(200, h))
    assert seen["url"].host == pv.GEMINI_HOST
    assert seen["url"].path.endswith("/models")
    assert seen["url"].params["key"] == _KEY


def test_a_transport_failure_is_unknown_and_never_re_raises_the_key():
    class Boom(httpx.Client):
        def get(self, *a, **k):
            raise httpx.ConnectError(f"failed talking to host with key={_KEY}")

    assert pv.gemini_key_is_live(_KEY, client=Boom()) is None      # swallowed, so the key cannot reach a log


def test_an_empty_key_asks_nobody():
    called = []
    pv.gemini_key_is_live("", client=_client(200, lambda r: called.append(1) or httpx.Response(200)))
    assert called == []
