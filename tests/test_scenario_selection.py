"""`--only` narrows a GapBench re-check to the scenarios whose probe actually changed.

The driver's full plan is ~9700 requests against a shared third-party host that rate-limits us hard enough
that a run can stall for hours. Re-confirming a handful of fixed probes should cost ~100 requests, so the
correct unit of work after a fix is "re-check these ids", not "re-run all 92".

A pattern matching nothing is FATAL for the same reason --probe's is: a silently empty plan prints a clean
summary, which reads as "nothing left to fix".
"""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
from gapbench_run import ScenarioSelectionError, select_scenarios  # noqa: E402

_SCEN = [{"id": i} for i in ("ssti", "oauth-redirect", "open-redirect", "ssrf-image-proxy",
                             "gcp-metadata-ssrf", "tls-downgrade", "ref0")]


def _ids(only):
    return [s["id"] for s in select_scenarios(_SCEN, only)]


def test_empty_selects_everything():
    for blank in ("", None, "  ", ",,"):
        assert _ids(blank) == [s["id"] for s in _SCEN]


def test_exact_ids_select_only_those():
    assert _ids("ssti,ref0") == ["ssti", "ref0"]


def test_a_glob_selects_the_family():
    assert _ids("*redirect*") == ["oauth-redirect", "open-redirect"]
    assert _ids("*ssrf*") == ["ssrf-image-proxy", "gcp-metadata-ssrf"]


def test_manifest_order_is_preserved_not_pattern_order():
    # the run should still walk the manifest in its own order, so a resume behaves identically
    assert _ids("ref0,ssti") == ["ssti", "ref0"]


def test_globs_and_exact_ids_combine_without_duplicates():
    assert _ids("ssti,*ssrf*,ssti") == ["ssti", "ssrf-image-proxy", "gcp-metadata-ssrf"]


def test_a_pattern_matching_nothing_is_fatal():
    # a typo'd id must never yield an empty plan that reads as success
    with pytest.raises(ScenarioSelectionError) as e:
        select_scenarios(_SCEN, "sstii")
    assert "sstii" in str(e.value)


def test_one_bad_pattern_fails_even_when_others_match():
    with pytest.raises(ScenarioSelectionError):
        select_scenarios(_SCEN, "ssti,nonexistent-scenario")


def test_matching_is_case_sensitive():
    # ids in the manifest are lowercase-kebab; a case-insensitive match would quietly accept a wrong id
    with pytest.raises(ScenarioSelectionError):
        select_scenarios(_SCEN, "SSTI")


def test_the_seven_single_probe_misses_select_cleanly():
    # the actual post-fix re-check: the scenarios where one dedicated probe ran and matched nothing
    only = "oauth-redirect,ssrf-image-proxy,gcp-metadata-ssrf,ssti,tls-downgrade"
    assert len(select_scenarios(_SCEN, only)) == 5
