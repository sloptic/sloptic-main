"""Run cache: a graded Report round-trips through save/load, the key reflects grade-affecting flags (and a
probe/catalog edit) but NOT the output view, and a cache miss/failure is a soft None (never breaks a grade)."""
import os
import pathlib

import pytest

import sloptic
from sloptic import runcache
from sloptic.schema import Outcome, Report


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setattr(runcache, "_CACHE_DIR", tmp_path)
    return tmp_path


def _report():
    return Report(
        slop_score=42, axis_slop={"security": 42},
        outcomes=[Outcome("sec-xss-001", "security", "xss", "slop_detected", 30, target="/s", reason="reflected"),
                  Outcome("sec-headers-001", "security", "security-headers", "clean", 0)],
        surface={"has_login": True}, coverage={"probes_total": 100},
        platform={"host_platform": "vercel"}, bot_challenge=False)


def _key(**over):
    kw = dict(probes=[], passive_only=False, browser=False, headers=[], source_dir=None, harden=False)
    kw.update(over)
    return runcache.cache_key("http://x", "catalog", **kw)


def test_round_trip_preserves_the_report(cache):
    runcache.save("k1", _report(), "http://x")
    got, age = runcache.load("k1")
    assert got.slop_score == 42 and got.axis_slop == {"security": 42}
    assert [o.probe_id for o in got.outcomes] == ["sec-xss-001", "sec-headers-001"]
    assert got.outcomes[0].reason == "reflected" and got.outcomes[0].evidence == {}
    assert got.platform == {"host_platform": "vercel"} and got.bot_challenge is False
    assert age >= 0


def test_missing_key_is_a_soft_none(cache):
    assert runcache.load("does-not-exist") is None


def test_key_reflects_grade_flags_not_the_output_view(cache):
    base = _key()
    assert _key() == base                              # stable across identical grade inputs
    assert _key(passive_only=True) != base             # each grade-affecting flag changes the key
    assert _key(browser=True) != base
    assert _key(probes=["sec-xss-001"]) != base
    assert _key(headers=["Cookie: a=b"]) != base
    # --failed / --json / --report-card / --out are NEVER passed to cache_key -> same target, same key -> HIT


def test_a_probe_edit_invalidates_the_key(cache):
    probes_py = pathlib.Path(sloptic.__file__).resolve().parent / "probes.py"
    orig = os.path.getmtime(probes_py)
    try:
        k1 = _key()
        os.utime(probes_py, (orig + 100, orig + 100))   # simulate editing a probe
        assert _key() != k1                             # the code fingerprint moved -> re-grade, no stale hit
    finally:
        os.utime(probes_py, (orig, orig))               # restore
