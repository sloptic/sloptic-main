"""qa-scaffold-001: a linked page still showing generator boilerplate.

The rule under test is that this stays a STRICT ARTIFACT MATCH, never a completeness judgment: filler and
LLM meta-text and bracket placeholders fire, but real (if sparse) copy does not, and the multi-token template
defaults must co-occur. A stub client serves route bodies; no network.
"""
import httpx
import pytest

from sloptic import probes


class _Ctx:
    def __init__(self, pages):
        self._pages = pages
        self.profile = type("P", (), {"routes": list(pages), "landing_path": "/"})()
        self.evidence = {}
        self.base_url = "https://app.example"
        self.client = httpx.Client(base_url="https://app.example",
                                   transport=httpx.MockTransport(self._h))

    def _h(self, request):
        body = self._pages.get(request.url.path)
        if body is None:
            return httpx.Response(404, text="nope")
        return httpx.Response(200, text=body, headers={"content-type": "text/html"})


def _page(body):
    return f"<!doctype html><html><body>{body}</body></html>"


@pytest.mark.parametrize("filler", [
    "Lorem ipsum dolor sit amet, consectetur.",
    "As an AI language model, I cannot provide real content here.",
    "Contact us at [Your Name] or [Company Name].",
    "Email yourname@example.com for details.",
])
def test_unambiguous_filler_fires(filler):
    ctx = _Ctx({"/": _page("<h1>Home</h1>"), "/about": _page(filler)})
    assert probes.scaffold_content_on_route(ctx, None) is True
    assert ctx.evidence["route"] == "/about"


def test_template_feature_block_needs_both_tokens():
    # a lone "Feature One" heading is real enough copy; the template default is the SEQUENCE unreplaced
    lone = _Ctx({"/": _page("<h2>Feature One: fast sync</h2>")})
    assert probes.scaffold_content_on_route(lone, None) is False
    both = _Ctx({"/": _page("<div>Feature One</div><div>Feature Two</div><div>Feature Three</div>")})
    assert probes.scaffold_content_on_route(both, None) is True


def test_real_content_does_not_fire():
    ctx = _Ctx({"/": _page("<h1>PantryPilot</h1><p>Track what is in your fridge and get recipes.</p>"),
                "/about": _page("<p>We are three students from Waterloo who hate wasting food.</p>")})
    assert probes.scaffold_content_on_route(ctx, None) is False


def test_filler_inside_a_script_does_not_fire():
    """Visible text only: a generator string surviving in a JS string literal is not shown to a user."""
    ctx = _Ctx({"/": _page('<h1>Real</h1><script>const demo="lorem ipsum dolor";</script>')})
    assert probes.scaffold_content_on_route(ctx, None) is False


def test_na_when_no_linked_html_reachable():
    ctx = _Ctx({})                                       # every route 404s
    ctx.profile.routes = ["/", "/about"]
    assert probes.scaffold_content_on_route(ctx, None) is None
    assert "na_reason" in ctx.evidence


def test_it_is_passive():
    from sloptic import safety
    assert safety.is_passive("qa-scaffold-001")          # a normal visitor GET of the app's own linked pages
