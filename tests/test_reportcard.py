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


def test_actual_line_surfaces_list_and_dict_evidence_and_hides_noise():
    """The 'what we saw' line names the SPECIFIC failing detail: an a11y finding must list its failed rules
    and impact counts (previously dropped because they are list/dict), and must NOT leak internal scoring
    noise (penalty_override), the off-score advisory set, the repro request, or the tool-version stamp."""
    a11y = {"probe_id": "qa-a11y-001", "target": "/", "targets": ["/"], "penalty": 20, "reason": "a11y",
            "bundle": "accessibility", "category": "accessibility",
            "evidence": {"violations": 3, "rules": ["color-contrast", "button-name", "image-alt"],
                         "impacts": {"critical": 2, "serious": 1}, "contrast_shortfall": 0.42,
                         "engine": "axe-core", "penalty_override": 20.0,
                         "advisory_a11y": {"rules": ["region"], "impacts": {"moderate": 1}},
                         "repro": {"method": "GET", "url": "https://x"}, "versions": {"lighthouse": "13.4.1"}}}
    line = rc._actual(a11y)
    # the failing rules are named in PLAIN LANGUAGE, not as raw axe ids
    assert "text is too low-contrast to read" in line and "a button has no readable label" in line
    assert "color-contrast" not in line and "button-name" not in line   # the raw slugs are gone
    assert "critical=2" in line and "serious=1" in line                 # impact counts surfaced
    assert "contrast_shortfall = 0.42" in line
    for noise in ("penalty_override", "advisory_a11y", "region", "lighthouse", "GET"):
        assert noise not in line, f"{noise!r} is internal/off-score noise and must not render"


def test_a11y_rule_ids_translate_to_plain_language_with_a_graceful_fallback():
    seen = rc._actual({"probe_id": "qa-a11y-001", "evidence": {"violations": 2,
                        "rules": ["image-alt", "label"], "impacts": {"critical": 2}}})
    assert "an image is missing alt text" in seen and "a form field has no label" in seen
    assert "violations" not in seen                          # the bare count is dropped, the named rules replace it
    # an unmapped (future) axe rule degrades to its de-hyphenated id, never a raw slug or a crash
    assert "some new rule" in rc._actual({"probe_id": "qa-a11y-001", "evidence": {"rules": ["some-new-rule"]}})


def test_actual_line_truncates_long_lists():
    f = {"probe_id": "p", "evidence": {"rules": [f"r{i}" for i in range(12)]}}
    line = rc._actual(f)
    assert "+4 more" in line                                            # 8 shown + "+4 more"


def test_actual_falls_back_to_reason_when_evidence_is_only_request_metadata():
    # a missing-header finding used to read "status = 200; elapsed_ms = 18" -- request metadata that says
    # nothing about the absent header. With metadata skipped, the line falls back to the finding's reason.
    f = {"probe_id": "sec-headers-002", "reason": "missing header: content-security-policy", "penalty": 8,
         "evidence": {"status": 200, "elapsed_ms": 18}}
    assert rc._actual(f).startswith("missing header: content-security-policy")
    assert "status" not in rc._actual(f) and "elapsed_ms" not in rc._actual(f)


def test_actual_drops_bare_boolean_flags():
    # a flag like no_tls=True / render_broken=False only restates the finding in machine terms; the origin
    # (the finding-specific value) stays.
    f = {"probe_id": "sec-tls-001", "reason": "served over plain http", "penalty": 30,
         "evidence": {"no_tls": True, "upgrades_to_https": False, "origin": "http://x.example"}}
    line = rc._actual(f)
    assert "origin = http://x.example" in line
    assert "no_tls" not in line and "upgrades_to_https" not in line
