"""v2.0 Family 3: widen console capture beyond uncaught throws to the two high-precision classes a throw hook
misses -- a CSP that blocks the app's OWN resource, and a React hydration mismatch. Library log-spam, benign
warnings, and a 404'd third-party beacon must NOT register (the classifier stays curated, not catch-all)."""
import sloptic.probes as probes
from sloptic.browser import _console_failure, _tally_console
from sloptic.probes import _CONSOLE_INTACT_SCALE, console_errors_present

_ORIGIN = "app.example.com"


def test_hydration_errors_are_first_party():
    for t in ("Hydration failed because the initial UI does not match what was rendered on the server",
              "Warning: Text content does not match server-rendered HTML",
              "Uncaught Error: Minified React error #418",
              "There was an error while hydrating"):
        assert _console_failure(t, _ORIGIN) == "first", t


def test_csp_blocking_a_same_origin_resource_is_first_party():
    own = "Refused to load the script 'https://app.example.com/main.js' because it violates the CSP directive"
    assert _console_failure(own, _ORIGIN) == "first"


def test_csp_blocking_inline_is_unattributable_and_dropped():
    # no URL to attribute -> could be an injected third-party inline the CSP correctly stopped -> not first-party
    inline = "Refused to execute inline script because it violates the following Content Security Policy directive"
    assert _console_failure(inline, _ORIGIN) is None


def test_csp_blocking_only_third_party_is_third_party():
    t = "Refused to load the script 'https://cdn.thirdparty.io/widget.js' because it violates the CSP directive"
    assert _console_failure(t, _ORIGIN) == "third"


def test_benign_console_noise_is_ignored():
    for t in ("Failed to load resource: the server responded with a status of 404 (Not Found)",
              "[HMR] Waiting for update signal from WDS...",
              "Download the React DevTools for a better development experience",
              "GET https://analytics.google.com/collect 404"):
        assert _console_failure(t, _ORIGIN) is None, t


def test_tally_folds_console_failures_into_first_party():
    pageerrors = [("TypeError: x is not a function", "at https://app.example.com/app.js:1:1")]
    console = ["Hydration failed because the initial UI does not match",          # first (console)
               "Refused to load the script 'https://cdn.other.io/a.js' ... Content Security Policy",  # third
               "Failed to load resource: 404"]                                    # ignored
    res = _tally_console(pageerrors, console, _ORIGIN)
    assert res["first_party"] == 2          # 1 pageerror + 1 hydration console error
    assert res["third_party"] == 1          # the third-party CSP block
    assert res["total"] == 3                # 1 pageerror + 2 classified console (the 404 is dropped)
    assert res["sources"] == {"pageerror": 1, "console": 1}


def test_tally_without_console_matches_the_old_pageerror_only_behavior():
    # regression: with no console errors, the counts are exactly the pre-widening pageerror split
    pe = [("TypeError", "at https://app.example.com/x.js:1:1"),
          ("Script error.", "")]            # cross-origin sanitized -> third-party
    res = _tally_console(pe, [], _ORIGIN)
    assert res["first_party"] == 1 and res["third_party"] == 1 and res["total"] == 2
    assert res["sources"] == {"pageerror": 1, "console": 0}


# ---- probe-level gating: console-sourced signals require VISIBLE breakage; a throw fires regardless --------

def _run_probe(res):
    orig = probes.browser.console_errors
    probes.browser.console_errors = lambda url, headers=None, **kw: res
    try:
        ctx = type("C", (), {"base_url": "http://app.example.com", "headers": None, "evidence": {},
                             "profile": type("P", (), {"landing_path": "/"})()})()
        pr = type("Pr", (), {"probe": {"target": "/"}, "penalty": 22})()
        return console_errors_present(ctx, pr), ctx.evidence
    finally:
        probes.browser.console_errors = orig


def test_console_only_failure_requires_visible_breakage():
    intact = {"first_party": 1, "third_party": 0, "total": 1, "sources": {"pageerror": 0, "console": 1},
              "content_len": 5000, "error_overlay": False}
    assert _run_probe(intact)[0] is False                       # hydration/CSP on an intact render -> too weak/flaky
    broke = {**intact, "content_len": 10}                       # same signal, but it emptied the body -> real breakage
    fired, ev = _run_probe(broke)
    assert fired is True and ev["render_broken"] is True and ev["penalty_override"] == 22


def test_pageerror_fires_even_on_an_intact_render():
    throw = {"first_party": 1, "third_party": 0, "total": 1, "sources": {"pageerror": 1, "console": 0},
             "content_len": 5000, "error_overlay": False}
    fired, ev = _run_probe(throw)                               # an uncaught throw is high-confidence
    assert fired is True and ev["render_broken"] is False
    assert ev["penalty_override"] == max(1, round(22 * _CONSOLE_INTACT_SCALE))
