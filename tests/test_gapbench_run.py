"""gapbench_run: grade each GapBench scenario with only the probes for its DECLARED class.

Least privilege, driven by ground truth rather than inference. A full battery is ~685 requests per target
(measured server-side against VAmPI), and even `--probe 'sec-*'` keeps cmdi+sqli+lfi, which are half that
volume and tripped vibe-eval's bot challenge after four scenarios. The manifest already says what each
scenario contains, so nothing needs guessing: median 3 probes instead of 45.

Pinned here: the CWE->probe index comes from the SAME table the scorer uses (they must never disagree about
what covers what), resume retries a 403'd scenario but not a graded one, controls get the full battery and run
last, and uncovered classes are skipped rather than probed pointlessly.
"""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
from gapbench_run import (_REQ_FULL_BATTERY, _est_requests, already_done, build_index,  # noqa: E402
                          probes_for_cwes)

_CATALOG = pathlib.Path(__file__).resolve().parent.parent / "catalog"


def test_index_is_inverted_from_the_scorers_own_table():
    # one table for both directions, so a run can never test a class the scorer won't credit (or vice versa)
    from gapbench_score import _CWE_BY_CATEGORY
    idx = build_index(_CATALOG)
    assert "CWE-89" in idx and any(p.startswith("sec-sqli-") for p in idx["CWE-89"])
    assert "CWE-79" in idx and any(p.startswith("sec-xss-") or p.startswith("sec-domxss") for p in idx["CWE-79"])
    assert "CWE-288" in idx and "sec-authbypass-001" in idx["CWE-288"]      # the probe override is honoured
    assert set(idx) <= set().union(*_CWE_BY_CATEGORY.values()) | {"CWE-288", "CWE-306", "CWE-863"}


def test_declared_cwes_resolve_to_a_small_targeted_set():
    idx = build_index(_CATALOG)
    sqli = probes_for_cwes(["CWE-89"], idx)
    assert sqli and all(p.startswith("sec-sqli-") for p in sqli)
    assert probes_for_cwes([], idx) == [] and probes_for_cwes(None, idx) == []
    assert probes_for_cwes(["CWE-99999"], idx) == []                        # uncovered class -> skipped, not run
    # the real manifest should stay lean: a scenario that pulls the whole battery defeats the point
    man = json.load(open(_CATALOG.parent / "validation/vuln-corpus/gapbench-manifest.json"))["scenarios"]
    sizes = sorted(len(probes_for_cwes(s.get("cwes"), idx)) for s in man)
    assert sizes[len(sizes) // 2] <= 6, sizes[len(sizes) // 2]              # median stays small


def test_the_estimate_reflects_the_measured_injection_cost():
    # cmdi alone is 165 requests; a handful of cheap probes is a few dozen. The dry-run number has to say so,
    # or a delay gets chosen from optimism instead of arithmetic.
    assert _est_requests(["sec-cmdi-001"]) > _est_requests(["sec-headers-001", "sec-headers-002"]) * 5
    assert _est_requests(["sec-sqli-001", "sec-sqli-002"]) > _est_requests(["sec-exposure-001"])
    assert _est_requests([]) == _REQ_FULL_BATTERY                           # empty selection = full battery


def test_resume_skips_graded_scenarios_but_retries_blocked_ones(tmp_path):
    f = tmp_path / "r.jsonl"
    f.write_text("\n".join(json.dumps(r) for r in [
        {"project": "anchor-gapbench-sqli-raw", "slop_score": 40},                    # graded -> done
        {"project": "anchor-gapbench-ref0", "slop_score": 25},                        # graded -> done
        {"project": "anchor-gapbench-nextjs-app", "dead_url": True,
         "deploy_error": "URL DEAD — HTTP 403", "slop_score": None},                  # WAF-blocked -> retry
        {"project": "anchor-gapbench-graphql-api", "slop_score": None},               # never scored -> retry
        {"project": "some-devpost-app", "slop_score": 12},                            # not a scenario
        "not json",
    ]) + "\n")
    assert already_done(f) == {"sqli-raw", "ref0"}
    assert already_done(tmp_path / "missing.jsonl") == set()


def test_a_graded_row_that_later_went_dead_is_not_counted_done(tmp_path):
    # dead_url wins over a stale slop_score: a 403 must be retried, never read as a completed grade
    f = tmp_path / "r.jsonl"
    f.write_text(json.dumps({"project": "anchor-gapbench-x", "slop_score": 10, "dead_url": True}) + "\n")
    assert already_done(f) == set()
