"""v2.0 Family 4 browser probes: lazy-loaded LCP image (defers the image that defines first paint) and
excessive DOM size (Lighthouse dom-size). render_metrics is stubbed so the probe logic is tested without a
browser; a render failure is can't-assess (None), not a false clean."""
import sloptic.probes as probes


def _ctx():
    return type("C", (), {"base_url": "http://x", "headers": None, "evidence": {},
                          "profile": type("P", (), {"landing_path": "/"})()})()


def _run(fn, metrics, probe_dict=None):
    orig = probes.browser.render_metrics
    probes.browser.render_metrics = lambda url, headers=None, **kw: metrics
    try:
        ctx = _ctx()
        pr = type("Pr", (), {"probe": probe_dict or {"target": "/"}})()
        return fn(ctx, pr), ctx.evidence
    finally:
        probes.browser.render_metrics = orig


def test_lcp_fires_when_the_lcp_image_is_lazy():
    fired, ev = _run(probes.lcp_image_lazy_loaded, {"lcp_is_img": True, "lcp_loading": "lazy", "dom_nodes": 50})
    assert fired is True and ev["lcp_loading"] == "lazy"


def test_lcp_clean_when_the_lcp_image_loads_eagerly():
    fired, ev = _run(probes.lcp_image_lazy_loaded, {"lcp_is_img": True, "lcp_loading": "", "dom_nodes": 50})
    assert fired is False and ev["lcp_loading"] == "eager"


def test_lcp_na_when_lcp_is_not_an_image():
    assert _run(probes.lcp_image_lazy_loaded, {"lcp_is_img": False, "lcp_loading": "", "dom_nodes": 50})[0] is None


def test_lcp_na_when_render_fails():
    assert _run(probes.lcp_image_lazy_loaded, None)[0] is None


def test_dom_fires_over_the_threshold():
    fired, ev = _run(probes.excessive_dom_size, {"dom_nodes": 2000}, {"target": "/", "max_nodes": 1400})
    assert fired is True and ev["dom_nodes"] == 2000 and ev["threshold"] == 1400


def test_dom_clean_under_the_threshold():
    assert _run(probes.excessive_dom_size, {"dom_nodes": 900}, {"target": "/", "max_nodes": 1400})[0] is False


def test_dom_na_when_render_fails():
    assert _run(probes.excessive_dom_size, None)[0] is None
