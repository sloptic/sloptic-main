"""v2 authority-anchored severity: the range + evidence-ladder resolver (SCORING_V2_SPEC.md).

Covers the resolver (`_severity_penalty`), the model's range-consistency validator, and that a Probe
parses a `severity:` block from the same dict shape catalog.py builds (`Probe(**yaml.safe_load(...))`).
"""
import pytest
from pydantic import ValidationError

from sloptic.pipeline import _severity_penalty
from sloptic.schema import Escalator, Probe, Severity


def _sev(**kw):
    base = dict(cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", cvss_score=6.5,
                vrt="P1", range=(30, 85), default=30)
    base.update(kw)
    return Severity(**base)


# --- the resolver: default low, evidence lifts, highest rung wins, clamp ---

def test_default_when_no_evidence():
    # no escalator flag set -> the abstention floor (default = range low)
    sev = _sev(escalators=[Escalator(evidence="cross_user_read", point=55)])
    assert _severity_penalty(sev, {}) == 30


def test_single_escalator_lifts():
    sev = _sev(escalators=[Escalator(evidence="cross_user_read", point=55),
                           Escalator(evidence="sensitive_fields", point=68)])
    assert _severity_penalty(sev, {"cross_user_read": True}) == 55


def test_highest_matched_rung_wins_never_sums():
    sev = _sev(escalators=[Escalator(evidence="cross_user_read", point=55),
                           Escalator(evidence="sensitive_fields", point=68),
                           Escalator(evidence="cross_user_write", point=85)])
    ev = {"cross_user_read": True, "cross_user_write": True}   # two rungs matched
    assert _severity_penalty(sev, ev) == 85                    # the max, not 55+85


def test_top_rung_hits_range_high():
    sev = _sev(escalators=[Escalator(evidence="cross_user_write", point=85)])
    assert _severity_penalty(sev, {"cross_user_write": True}) == 85


def test_falsy_flag_does_not_lift():
    sev = _sev(escalators=[Escalator(evidence="cross_user_read", point=55)])
    assert _severity_penalty(sev, {"cross_user_read": False}) == 30
    assert _severity_penalty(sev, {"cross_user_read": 0}) == 30
    assert _severity_penalty(sev, {"cross_user_read": ""}) == 30


def test_unknown_flag_ignored():
    sev = _sev(escalators=[Escalator(evidence="cross_user_read", point=55)])
    assert _severity_penalty(sev, {"some_other_flag": True}) == 30


# --- the validator: range must be consistent (default and every rung inside [lo, hi]) ---

def test_validator_rejects_default_below_low():
    with pytest.raises(ValidationError):
        Severity(range=(30, 85), default=10)


def test_validator_rejects_default_above_high():
    with pytest.raises(ValidationError):
        Severity(range=(30, 85), default=90)


def test_validator_rejects_escalator_outside_range():
    with pytest.raises(ValidationError):
        Severity(range=(30, 85), default=30, escalators=[Escalator(evidence="x", point=99)])


def test_validator_rejects_inverted_range():
    with pytest.raises(ValidationError):
        Severity(range=(85, 30), default=40)


def test_validator_accepts_default_equal_to_low():
    # the abstention default should equal range low; that is the intended, valid case
    Severity(range=(30, 85), default=30)


# --- Probe parses a severity block from the YAML dict shape catalog.py loads ---

def test_probe_parses_severity_from_yaml_shape():
    data = {
        "id": "sec-idor-001", "bundle": "security", "category": "access-control", "penalty": 30,
        "severity": {
            "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "cvss_score": 6.5,
            "vrt": "P1", "range": [30, 85], "default": 30,
            "escalators": [
                {"evidence": "cross_user_read", "point": 55},
                {"evidence": "sensitive_fields", "point": 68, "vrt_variant": "IDOR view sensitive iterable"},
            ],
        },
    }
    p = Probe(**data)
    assert p.severity is not None
    assert p.severity.range == (30, 85)         # list coerced to tuple[int, int]
    assert len(p.severity.escalators) == 2
    assert p.severity.escalators[1].point == 68
    assert p.severity.escalators[1].vrt_variant == "IDOR view sensitive iterable"
    assert _severity_penalty(p.severity, {"sensitive_fields": True}) == 68


def test_probe_without_severity_is_none():
    # backwards compat: an un-migrated probe (no severity block) parses fine and uses the nominal penalty
    p = Probe(id="sec-x", bundle="security", penalty=40)
    assert p.severity is None


def test_chore_floor_severity_no_escalators():
    # a Tier-4 chore: cvss n/a, tier marked, no ladder -> always the fixed floor
    sev = Severity(cvss="n/a", vrt="P5", range=(8, 8), default=8, tier="chore-floor")
    assert _severity_penalty(sev, {}) == 8
    assert _severity_penalty(sev, {"cross_user_read": True}) == 8   # nothing to lift to


# --- the first migrated class: access-control (sec-idor-001..005), verified end to end ---

def test_idor_class_carries_shared_severity_and_resolves_by_evidence():
    from sloptic.catalog import default_catalog_dir, load_catalog
    by_id = {p.id: p for p in load_catalog(default_catalog_dir())}
    ids = ["sec-idor-001", "sec-idor-002", "sec-idor-003", "sec-idor-004", "sec-idor-005"]
    for pid in ids:
        p = by_id[pid]
        assert p.severity_ref == "access-control", pid                      # DRY: shared block, not inline copy
        assert p.severity is not None, pid                                  # loader resolved the ref
        assert p.severity.range == (30, 85), pid
        assert p.penalty == 30, f"{pid}: nominal synced to severity.default"   # loader keeps them equal
        flags = {e.evidence for e in p.severity.escalators}
        assert {"cross_user_read", "sensitive_fields", "bulk_read", "cross_user_write"} <= flags, pid
    # the ladder differentiates by observed impact (was a flat 40 for all five)
    sev = by_id["sec-idor-003"].severity
    assert _severity_penalty(sev, {}) == 30                                                   # abstention floor
    assert _severity_penalty(sev, {"cross_user_read": True}) == 55                            # bare cross-user read
    assert _severity_penalty(sev, {"cross_user_read": True, "sensitive_fields": True}) == 68  # a PII record
    assert _severity_penalty(sev, {"cross_user_read": True, "bulk_read": True}) == 78         # a collection leak


# --- the DRY severity_ref mechanism (catalog/_severity_classes.yaml) ---

def test_severity_registry_loads_access_control():
    from sloptic.catalog import _load_severity_registry, default_catalog_dir
    reg = _load_severity_registry(default_catalog_dir())
    assert "access-control" in reg
    assert reg["access-control"].range == (30, 85)
    assert reg["access-control"].vrt == "P1"


def test_severity_ref_resolves_and_rejects_bad_input():
    from sloptic.catalog import _apply_severity_ref
    reg = {"access-control": Severity(range=(30, 85), default=30, vrt="P1")}
    # valid: ref resolves into .severity
    p = Probe(id="x", bundle="security", penalty=40, severity_ref="access-control")
    _apply_severity_ref(p, reg)
    assert p.severity is not None and p.severity.range == (30, 85)
    # unknown ref -> loud failure (a catalog typo must not silently fall through to nominal)
    with pytest.raises(ValueError):
        _apply_severity_ref(Probe(id="y", bundle="security", penalty=40, severity_ref="nope"), reg)
    # both inline severity AND a ref -> rejected
    with pytest.raises(ValueError):
        _apply_severity_ref(Probe(id="z", bundle="security", penalty=40, severity_ref="access-control",
                                  severity=Severity(range=(30, 85), default=30)), reg)
    # no ref -> no-op, severity stays None
    p4 = Probe(id="w", bundle="security", penalty=40)
    _apply_severity_ref(p4, reg)
    assert p4.severity is None


# --- the chore-floor batch: fixed-value blocks, unliftable by evidence (weight = breadth, not severity) ---

def test_chore_floor_probes_carry_fixed_severity():
    from sloptic.catalog import default_catalog_dir, load_catalog
    by_id = {p.id: p for p in load_catalog(default_catalog_dir())}
    expected = {
        "sec-headers-001": 3, "sec-headers-002": 8, "sec-headers-003": 5, "sec-headers-004": 5,
        "sec-headers-005": 2, "sec-headers-006": 2, "sec-csp-001": 5,
        "sec-exposure-009": 4, "sec-exposure-006": 15, "sec-mixed-001": 10,
        "sec-session-001": 15, "sec-session-002": 12, "sec-session-003": 12, "sec-session-005": 15,
        "sec-ratelimit-001": 30,
    }
    for pid, val in expected.items():
        p = by_id[pid]
        assert p.severity is not None, pid
        assert p.severity.range == (val, val), pid
        assert not p.severity.escalators, pid            # a chore does not escalate
        # unliftable: even a bag of impact flags returns the fixed floor
        loaded = {"cross_user_read": True, "bulk_read": True, "sensitive_fields": True}
        assert _severity_penalty(p.severity, loaded) == val, pid


# --- the injection/terminal cluster: flat-40 top de-clustered into the 70-98 band ---

def test_injection_cluster_severity_and_resolution():
    from sloptic.catalog import default_catalog_dir, load_catalog
    by_id = {p.id: p for p in load_catalog(default_catalog_dir())}
    refs = {
        "sec-sqli-001": "sql-injection", "sec-sqli-004": "sql-injection",
        "sec-cmdi-001": "command-injection", "sec-ssti-001": "code-injection",
        "sec-xxe-001": "xxe", "sec-lfi-001": "path-traversal",
        "sec-upload-001": "file-upload-rce", "sec-debug-001": "debug-mode",
    }
    for pid, ref in refs.items():
        assert by_id[pid].severity_ref == ref, pid
        assert by_id[pid].severity is not None, pid
    assert by_id["sec-sqli-001"].severity.default == 90        # de-clustered off the old flat 40
    assert by_id["sec-cmdi-001"].severity.range == (90, 98)
    ssti = by_id["sec-ssti-001"].severity                      # our oracle proves execution -> terminal
    assert _severity_penalty(ssti, {"execution_confirmed": True}) == 98
    xxe = by_id["sec-xxe-001"].severity                        # file-read vs oob-ssrf
    assert _severity_penalty(xxe, {"internal_reached": True}) == 82
    assert _severity_penalty(xxe, {"sensitive_fields": True}) == 91
    debug = by_id["sec-debug-001"].severity                    # info-leak base vs Werkzeug RCE
    assert _severity_penalty(debug, {}) == 40
    assert _severity_penalty(debug, {"execution_confirmed": True}) == 98


# --- the disclosed-secret + exposure family ---

def test_exposure_secret_family_severity():
    from sloptic.catalog import default_catalog_dir, load_catalog
    by_id = {p.id: p for p in load_catalog(default_catalog_dir())}
    for pid in ("sec-secrets-001", "sec-secrets-002", "sec-exposure-005", "sec-exposure-007"):
        assert by_id[pid].severity_ref == "disclosed-secret", pid
    assert by_id["sec-exposure-008"].severity_ref == "anon-data-exposure"
    # declarative known-high-priv files: fixed high (repriced off 35/30)
    assert by_id["sec-exposure-001"].severity.default == 90        # served .env
    assert by_id["sec-exposure-004"].severity.default == 90        # served .aws/credentials
    assert by_id["sec-exposure-002"].severity.default == 55        # served .git
    # disclosed-secret resolves: floor 70, high_privilege -> 98, validated_live -> 92
    ds = by_id["sec-secrets-002"].severity
    assert _severity_penalty(ds, {}) == 70
    assert _severity_penalty(ds, {"high_privilege": True}) == 98
    assert _severity_penalty(ds, {"validated_live": True}) == 92
    # anon-data-exposure: sensitive -> 80, bulk -> 90
    ade = by_id["sec-exposure-008"].severity
    assert _severity_penalty(ade, {"sensitive_fields": True, "bulk_read": True}) == 90


def test_encoding_probe_severity_ladder():
    from sloptic.catalog import default_catalog_dir, load_catalog
    by_id = {p.id: p for p in load_catalog(default_catalog_dir())}
    enc = by_id["qa-input-002"].severity                           # international/multibyte robustness
    assert enc.range == (32, 72)
    assert _severity_penalty(enc, {}) == 32                        # round-trip corruption
    assert _severity_penalty(enc, {"server_error": True}) == 72    # 500s on the input -> crash rung


def test_reset_family_severity_scores():
    from sloptic.catalog import default_catalog_dir, load_catalog
    by_id = {p.id: p for p in load_catalog(default_catalog_dir())}
    reset = by_id["qa-reset-001"].severity                          # SCORED (report_only bring-up is over)
    assert reset is not None and reset.range == (24, 60)
    assert _severity_penalty(reset, {"no_reset_email_60s": True}) == 60   # locked out of recovery
    assert _severity_penalty(reset, {"reset_link_dead": True}) == 24      # broken reset page
    assert _severity_penalty(reset, {}) == 24                            # floor


# --- the backend / BaaS class ---

def test_backend_class_severity():
    from sloptic.catalog import default_catalog_dir, load_catalog
    by_id = {p.id: p for p in load_catalog(default_catalog_dir())}
    assert by_id["sec-backend-001"].severity_ref == "anon-data-exposure"
    assert by_id["sec-backend-002"].severity_ref == "access-control"
    assert by_id["sec-backend-003"].severity.default == 12          # schema disclosure = chore floor
    b1 = by_id["sec-backend-001"].severity                          # world-readable DB
    assert _severity_penalty(b1, {"bulk_read": True}) == 90         # anon read
    assert _severity_penalty(b1, {"write_confirmed": True}) == 98   # anon WRITE = terminal
    b2 = by_id["sec-backend-002"].severity                          # authed BOLA (reads everything)
    assert _severity_penalty(b2, {"cross_user_read": True, "bulk_read": True}) == 78


# --- the medium tier: XSS class + the single-severity mid probes + redirect escalation ---

def test_medium_tier_severity():
    from sloptic.catalog import default_catalog_dir, load_catalog
    by_id = {p.id: p for p in load_catalog(default_catalog_dir())}
    for pid in ("sec-xss-001", "sec-xss-002", "sec-domxss-001"):
        assert by_id[pid].severity_ref == "xss", pid
    xss = by_id["sec-xss-001"].severity
    assert _severity_penalty(xss, {}) == 40                             # reflected via heuristic (unproven)
    assert _severity_penalty(xss, {"execution_confirmed": True}) == 61  # reflected/DOM executed
    assert _severity_penalty(xss, {"stored": True}) == 85               # stored (runs for every viewer)
    assert by_id["sec-csrf-001"].severity.default == 45
    assert by_id["sec-cors-001"].severity.default == 45
    assert by_id["sec-hosthdr-001"].severity.default == 40
    assert by_id["sec-session-004"].severity.default == 45
    rd = by_id["sec-redirect-001"].severity                             # open redirect escalation
    assert _severity_penalty(rd, {}) == 25
    assert _severity_penalty(rd, {"external_host": True}) == 40
    assert _severity_penalty(rd, {"external_host": True, "auth_flow": True}) == 55


# --- the three specials ---

def test_specials_severity():
    from sloptic.catalog import default_catalog_dir, load_catalog
    by_id = {p.id: p for p in load_catalog(default_catalog_dir())}
    assert _severity_penalty(by_id["sec-ssrf-001"].severity, {"internal_reached": True}) == 70
    assert by_id["sec-filterinj-001"].severity.default == 75


def test_deps_scores_from_the_cve_own_cvss():
    from sloptic import depscan
    for entry in depscan._DEP_VULNS:
        assert isinstance(entry[4], (int, float)) and 0 < entry[4] <= 10, entry[0]   # the cvss slot
    hb = depscan.scan_deps("/*! Handlebars v4.0.0 */")               # prototype-pollution RCE
    assert hb and hb[0]["cvss"] == 9.8                               # -> penalty_override 98
    ng = depscan.scan_deps("AngularJS v1.6.0")                       # sanitizer-bypass XSS
    assert ng and ng[0]["cvss"] == 5.4                               # -> penalty_override 54


# --- QA / perf: ISO-25010 + Nielsen severity, the 6 evidence ladders, and the QA gate ---

def test_qa_severity_classes_and_ladders():
    from sloptic.catalog import default_catalog_dir, load_catalog
    by_id = {p.id: p for p in load_catalog(default_catalog_dir())}
    assert by_id["qa-race-001"].severity_ref == "race-condition"
    assert by_id["qa-integrity-001"].severity.default == 69          # misleading the user about their own data
    assert by_id["qa-crash-010"].severity.default == 55              # RFC-anchored 5xx
    assert by_id["qa-seo-001"].severity.default == 10                # outlier, corpus-only
    # the six evidence ladders
    assert _severity_penalty(by_id["qa-deploy-001"].severity, {}) == 0                      # presence-only
    assert _severity_penalty(by_id["qa-deploy-001"].severity, {"observed": True}) == 85     # operative
    assert _severity_penalty(by_id["qa-deploy-002"].severity, {}) == 50                     # subpage loop
    assert _severity_penalty(by_id["qa-deploy-002"].severity, {"root_loop": True}) == 80    # root loop
    assert _severity_penalty(by_id["perf-load-001"].severity, {"observed_5xx": True}) == 60
    assert _severity_penalty(by_id["qa-deadctrl-001"].severity, {"primary_cta": True}) == 50
    assert _severity_penalty(by_id["qa-console-001"].severity, {"error_overlay": True}) == 40
    assert _severity_penalty(by_id["qa-errhyg-001"].severity, {"db_error": True}) == 35


def test_every_scored_qa_probe_has_authority_anchored_severity():
    """Every scored qa / non-Lighthouse-perf probe must carry iso_25010 + nielsen. Exempt: the probes scored via
    a computed penalty_override instead of a severity block -- a11y (WCAG via axe), Lighthouse (CWV), and
    broken_links (a CONTINUOUS penalty by dead-nav fraction) -- plus qa-http-001 (report_only off-score)."""
    from sloptic.catalog import default_catalog_dir, load_catalog
    exempt_ids = {"qa-http-001"}
    exempt_preds = {"a11y_violations_present", "a11y_hard_fails", "lighthouse_audit", "lighthouse_perf_score",
                    "broken_links"}
    missing = []
    for p in load_catalog(default_catalog_dir()):
        if p.bundle not in ("qa", "performance"):
            continue
        if p.id in exempt_ids or p.probe.get("predicate") in exempt_preds:
            continue
        s = p.severity
        if s is None or not s.iso_25010 or not s.nielsen:
            missing.append(p.id)
    assert not missing, f"scored qa/perf probes missing iso_25010+nielsen: {sorted(missing)}"


# --- the anti-vibe gate (SCORING_V2_SPEC.md section 7) ---

def test_every_security_probe_has_authority_anchored_severity():
    """Every bundle=security probe must carry a severity block with a non-empty cvss and vrt (n/a is allowed
    for a declared chore / CVSS-only class). A naked penalty with no named authority cannot ship."""
    from sloptic.catalog import default_catalog_dir, load_catalog
    # sec-deps-001 (OWASP A03) computes its penalty from the detected CVE's own NVD CVSS (penalty_override),
    # so it carries no severity block by design.
    exempt = {"sec-deps-001"}
    missing = []
    for p in load_catalog(default_catalog_dir()):
        if p.bundle != "security" or p.id in exempt:
            continue
        s = p.severity
        if s is None or not s.cvss or not s.vrt:
            missing.append(p.id)
    assert not missing, f"security probes missing authority-anchored severity: {sorted(missing)}"
    # and the nominal `penalty` is kept in sync with severity.default by the loader (no vestigial drift)
    drift = [p.id for p in load_catalog(default_catalog_dir())
             if p.severity is not None and p.penalty != p.severity.default]
    assert not drift, f"nominal penalty drifted from severity.default: {sorted(drift)}"
