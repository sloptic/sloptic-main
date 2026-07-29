"""--probe: grade with a SUBSET of the catalog.

Two uses. It answers "why didn't THIS probe fire on that app" in one fast run instead of a full 90 second
grade. And it lets a target whose expected vulnerability class is already known (a labeled benchmark
scenario) be tested without spending the whole battery's traffic on it, which is what keeps a shared host's
WAF out of the picture: ~55 applicable probes with injection fan-out is several hundred requests, three or
four probes is a handful.

The critical property is that an unmatched pattern is FATAL. A silent empty selection would grade every
target with zero probes and report slop 0, which reads as "clean" rather than "nothing ran" — the worst
possible failure for a grader whose output is a score.
"""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from sloptic.catalog import ProbeSelectionError, load_catalog, select_probes  # noqa: E402

_CATALOG = pathlib.Path(__file__).resolve().parent.parent / "catalog"


@pytest.fixture(scope="module")
def probes():
    return load_catalog(_CATALOG)


def test_no_filter_is_the_whole_catalog(probes):
    assert select_probes(probes, None) is probes
    assert select_probes(probes, []) is probes


def test_exact_id_and_glob(probes):
    one = select_probes(probes, ["sec-idor-002"])
    assert [p.id for p in one] == ["sec-idor-002"]
    fam = select_probes(probes, ["sec-sqli-*"])
    assert len(fam) >= 4 and all(p.id.startswith("sec-sqli-") for p in fam)
    sec = select_probes(probes, ["sec-*"])
    assert all(p.bundle == "security" for p in sec) and len(sec) > len(fam)


def test_bundle_and_category_select_groupings_a_glob_cannot(probes):
    # the ui-honesty bundle spans qa-backnav/qa-chunk/qa-deeplink/qa-noerror/qa-staleui — no id glob covers it
    honest = select_probes(probes, ["category:ui-honesty"])
    ids = {p.id for p in honest}
    assert len(ids) >= 4 and all(p.category == "ui-honesty" for p in honest)
    assert not any(i.startswith("qa-a11y") for i in ids)
    perf = select_probes(probes, ["bundle:performance"])
    assert perf and all(p.bundle == "performance" for p in perf)


def test_patterns_are_ored_deduped_and_keep_catalog_order(probes):
    picked = select_probes(probes, ["sec-idor-002", "sec-sqli-*", "sec-idor-002", "category:cors"])
    ids = [p.id for p in picked]
    assert len(ids) == len(set(ids))                                  # a repeat doesn't duplicate the probe
    assert "sec-idor-002" in ids and "sec-cors-001" in ids
    order = [p.id for p in probes if p.id in set(ids)]
    assert ids == order                                               # catalog order preserved, not pattern order


def test_an_unmatched_pattern_is_fatal_not_an_empty_catalog(probes):
    # the footgun this guards: a typo'd id silently selecting nothing -> every target scores 0 -> "clean"
    with pytest.raises(ProbeSelectionError) as e:
        select_probes(probes, ["sec-sqli-999"])
    assert "sec-sqli-999" in str(e.value)
    assert "sec-sqli-" in str(e.value)                                # suggests near matches
    with pytest.raises(ProbeSelectionError):
        select_probes(probes, ["bundle:nope"])
    with pytest.raises(ProbeSelectionError):                          # one good + one bad still fails
        select_probes(probes, ["sec-idor-002", "typo-here"])


def test_run_batch_forwards_the_filter_to_each_child():
    import types

    sys.path.insert(0, str(_CATALOG.parent / "scripts"))
    from run_batch import _build_cmd
    args = types.SimpleNamespace(
        results="r.jsonl", grade_timeout=60, browser=True, audit_coverage=False, proactive=False,
        recon=False, browser_auth=False, controlled_deploy=False, llm_reasoning=False, headers=None,
        model=None, attempts=3, build_timeout=480, inferred_platform_hosts=[], delay=0.0,
        probe=["sec-sqli-*", "category:xss"])
    cmd = _build_cmd({"rec": {"hackathon": "h", "project": "p", "winner": False},
                      "target": "https://x.example", "source": "url"}, args, pathlib.Path("/tmp/ckpt.json"))
    assert cmd.count("--probe") == 2                                  # one flag per pattern
    assert "sec-sqli-*" in cmd and "category:xss" in cmd
