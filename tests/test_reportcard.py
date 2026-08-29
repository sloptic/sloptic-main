"""The durability report card: PUBLIC findings render the four fields (expected/actual/indicates/fix),
HIDDEN-pool findings are withheld from the team card (opaque count) but revealed to the organizer, and a
non-functional app is shown as DNF, not a fabricated finding list."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import sloptic.reportcard as rc  # noqa: E402


def _finding(pid, bundle="security", pen=10, reason="an issue", cat="c"):
    return {"probe_id": pid, "bundle": bundle, "category": cat, "penalty": pen, "reason": reason,
            "target": "/", "targets": ["/"], "evidence": {"observed": "yes"}}


def _rec(findings, **kw):
    base = {"url": "http://app", "project": "App", "functional": True,
            "slop_score": sum(f["penalty"] for f in findings), "findings": findings,
            "coverage": {"probes_applicable": 10, "ran_kinds": ["csp", "xss"]}, "axis_slop": {}}
    base.update(kw)
    return base


def test_public_findings_render_four_fields(monkeypatch):
    monkeypatch.setattr(rc, "_pool_map", lambda root: {"sec-headers-002": "public"})
    card = rc.build_card(_rec([_finding("sec-headers-002", pen=12, reason="missing CSP", cat="csp")]), catalog_root="x")
    assert card["dnf"] is False
    entry = card["sections"][0]["entries"][0]
    for field in ("expected", "actual", "indicates", "remediation"):
        assert entry[field], f"{field} must be populated"
    assert "Content-Security-Policy" in entry["expected"]     # used the AUTHORED copy, not the generic fallback
    assert card["hidden"]["count"] == 0


def test_every_scored_probe_has_authored_card_copy_and_no_stale_keys():
    # the report card drifted silently once (new probes fell back to generic copy). Pin it: every SCORED
    # (non-report_only) catalog probe has an authored _CONTENT entry, and _CONTENT has no key for a probe that
    # no longer exists. report_only probes are off-score diagnostics that never render on a card -> exempt.
    from sloptic.catalog import default_catalog_dir, load_catalog
    cat = {p.id: p for p in load_catalog(default_catalog_dir())}
    scored_missing = [pid for pid, p in cat.items()
                      if not p.probe.get("report_only") and pid not in rc._CONTENT]
    stale = [pid for pid in rc._CONTENT if pid not in cat]
    assert not scored_missing, f"scored probes with no report-card copy: {sorted(scored_missing)}"
    assert not stale, f"report-card copy for probes that no longer exist: {sorted(stale)}"


def test_unauthored_probe_degrades_gracefully(monkeypatch):
    # a probe with no authored entry still renders — 'indicates' falls back to the catalog reason, never blank
    monkeypatch.setattr(rc, "_pool_map", lambda root: {})
    card = rc.build_card(_rec([_finding("sec-brandnew-999", reason="a novel weakness")]), catalog_root=None)
    entry = card["sections"][0]["entries"][0]
    assert entry["indicates"] == "a novel weakness" and entry["expected"] and entry["remediation"]


def test_hidden_pool_withheld_from_team_but_shown_to_organizer(monkeypatch):
    monkeypatch.setattr(rc, "_pool_map", lambda root: {"pub": "public", "hid": "hidden"})
    rec = _rec([_finding("pub", pen=5), _finding("hid", pen=7)])

    team = rc.build_card(rec, catalog_root="x", organizer=False)
    assert team["hidden"]["count"] == 1 and team["hidden"]["penalty"] == 7
    assert "entries" not in team["hidden"]                                  # opaque to the team
    assert all(e["probe_id"] != "hid" for s in team["sections"] for e in s["entries"])
    assert "withheld" in rc.to_markdown(team).lower()                       # team is TOLD hidden checks exist

    org = rc.build_card(rec, catalog_root="x", organizer=True)
    assert org["hidden"]["entries"][0]["probe_id"] == "hid"                 # itemized for the organizer


def test_score_counts_hidden_but_disclosure_does_not_change_math(monkeypatch):
    # both tiers count toward the slop score identically; only the DISCLOSURE differs
    monkeypatch.setattr(rc, "_pool_map", lambda root: {"pub": "public", "hid": "hidden"})
    rec = _rec([_finding("pub", pen=5), _finding("hid", pen=7)])
    card = rc.build_card(rec, catalog_root="x")
    visible = sum(e["penalty"] for s in card["sections"] for e in s["entries"])
    assert visible == 5 and card["hidden"]["penalty"] == 7 and card["slop_score"] == 12


def test_dnf_card_is_not_scored(monkeypatch):
    monkeypatch.setattr(rc, "_pool_map", lambda root: {})
    card = rc.build_card(_rec([], functional=False, coverage_audit={"page_state": "broken"}), catalog_root="x")
    assert card["dnf"] is True and card["slop_score"] is None
    assert "non-functional" in rc.to_markdown(card).lower()


def test_html_is_self_contained(monkeypatch):
    monkeypatch.setattr(rc, "_pool_map", lambda root: {"sec-headers-002": "public"})
    card = rc.build_card(_rec([_finding("sec-headers-002", pen=12, cat="csp")]), catalog_root="x")
    h = rc.to_html(card)
    assert '<div class="rc">' in h and "Expected" in h
    assert "<html" not in h.lower() and "http-equiv" not in h.lower()       # body only, no external refs
