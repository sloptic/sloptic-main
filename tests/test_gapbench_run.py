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
from gapbench_run import (_CHUNK_PROBES, _REQ_FULL_BATTERY, _chunks, _est_requests,  # noqa: E402
                          already_done, build_index,
                          child_cmd, probes_for_cwes)

_CATALOG = pathlib.Path(__file__).resolve().parent.parent / "catalog"


def test_index_is_inverted_from_the_scorers_own_table():
    # one table for both directions, so a run can never test a class the scorer won't credit (or vice versa)
    from gapbench_score import _CWE_BY_CATEGORY
    idx, _nb, _na = build_index(_CATALOG)
    assert "CWE-89" in idx and any(p.startswith("sec-sqli-") for p in idx["CWE-89"])
    assert "CWE-79" in idx and any(p.startswith("sec-xss-") or p.startswith("sec-domxss") for p in idx["CWE-79"])
    assert "CWE-288" in idx and "sec-authbypass-001" in idx["CWE-288"]      # the probe override is honoured
    assert set(idx) <= set().union(*_CWE_BY_CATEGORY.values()) | {"CWE-288", "CWE-306", "CWE-863"}


def test_declared_cwes_resolve_to_a_small_targeted_set():
    idx, _nb, _na = build_index(_CATALOG)
    sqli = probes_for_cwes(["CWE-89"], idx)
    assert sqli and all(p.startswith("sec-sqli-") for p in sqli)
    assert probes_for_cwes([], idx) == [] and probes_for_cwes(None, idx) == []
    assert probes_for_cwes(["CWE-99999"], idx) == []                        # uncovered class -> skipped, not run
    # the real manifest should stay lean: a scenario that pulls the whole battery defeats the point
    man = json.load(open(_CATALOG.parent / "validation/vuln-corpus/gapbench-manifest.json"))["scenarios"]
    sizes = sorted(len(probes_for_cwes(s.get("cwes"), idx)) for s in man)
    assert sizes[len(sizes) // 2] <= 6, sizes[len(sizes) // 2]              # median stays small


def test_capability_sets_name_what_needs_a_browser_or_a_session():
    # the render and the self-registration are the two most expensive things a grade does, so they are
    # per-scenario decisions too, not blanket flags
    _idx, needs_browser, needs_auth = build_index(_CATALOG)
    assert "sec-domxss-001" in needs_browser and "sec-xss-002" in needs_browser
    assert "sec-headers-001" not in needs_browser and "sec-exposure-001" not in needs_browser
    # declared via has_auth_entrypoint ...
    assert {"sec-session-001", "sec-idor-004"} <= needs_auth
    # ... plus the ones that mint their OWN identities without declaring it (the catalog gate under-reports,
    # and a missing session turns a real test into a silent N/A the scorer would score as a miss)
    assert {"sec-idor-002", "sec-backend-002", "qa-integrity-001"} <= needs_auth
    assert "sec-headers-001" not in needs_auth


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
    # keyed by (scenario, chunk): a row written before chunking carries no `chunk` and reads as batch 0
    assert already_done(f) == {("sqli-raw", 0), ("ref0", 0)}
    assert already_done(tmp_path / "missing.jsonl") == set()


def test_resume_is_per_BATCH_so_a_half_finished_scenario_is_not_read_as_finished(tmp_path):
    """A chunked scenario is done only when EVERY batch is. Treating the first recorded batch as 'scenario
    done' would silently drop the rest of its probes on every resume — the same erasure the scorer's merge
    prevents, arriving by a different route."""
    f = tmp_path / "r.jsonl"
    f.write_text("\n".join(json.dumps(r) for r in [
        {"project": "anchor-gapbench-ai-startup", "chunk": 0, "slop_score": 12},   # batch 0 done
        {"project": "anchor-gapbench-ai-startup", "chunk": 1, "dead_url": True,    # batch 1 blocked -> retry
         "deploy_error": "URL DEAD — HTTP 403", "slop_score": None},
    ]) + "\n")
    done = already_done(f)
    assert ("ai-startup", 0) in done
    assert ("ai-startup", 1) not in done, "a blocked batch must be retried, not counted done"


def test_a_graded_row_that_later_went_dead_is_not_counted_done(tmp_path):
    # dead_url wins over a stale slop_score: a 403 must be retried, never read as a completed grade
    f = tmp_path / "r.jsonl"
    f.write_text(json.dumps({"project": "anchor-gapbench-x", "slop_score": 10, "dead_url": True}) + "\n")
    assert already_done(f) == set()


def test_child_cmd_stringifies_the_timeout_as_an_int():
    # deploy_and_grade declares --grade-timeout type=int, so "300.0" is a hard argparse error. That killed
    # every child instantly, and because the parent captured output it reported "no record" with no reason —
    # an unattended run would have burned the whole night on it.
    cmd = child_cmd("sqli-raw", ["sec-sqli-001"], "r.jsonl", 300.0, set(), set())
    assert "--grade-timeout" in cmd and cmd[cmd.index("--grade-timeout") + 1] == "300"
    assert "300.0" not in cmd


def test_child_cmd_asks_only_for_the_capabilities_the_selection_needs():
    nb, na = {"sec-domxss-001"}, {"sec-idor-002"}
    cheap = child_cmd("x", ["sec-exposure-001"], "r.jsonl", 300, nb, na)
    assert "--no-browser" in cheap and "--browser-auth" not in cheap
    rendered = child_cmd("x", ["sec-domxss-001"], "r.jsonl", 300, nb, na)
    assert "--no-browser" not in rendered and "--browser-auth" not in rendered
    authed = child_cmd("x", ["sec-idor-002"], "r.jsonl", 300, nb, na)
    assert "--browser-auth" in authed and "--no-browser" in authed
    # a control runs the full battery, so it keeps BOTH: an FP can come from any probe, render-dependent ones
    # included, and that is the entire purpose of a clean control
    control = child_cmd("ref0", [], "r.jsonl", 300, nb, na)
    assert "--no-browser" not in control and "--browser-auth" in control


def test_child_cmd_targets_the_scenario_and_tags_it_for_the_scorer():
    cmd = child_cmd("supabase-clone", ["sec-backend-001"], "r.jsonl", 300, set(), set())
    assert "https://gapbench.vibe-eval.com/site/supabase-clone/" in cmd
    meta = json.loads(cmd[cmd.index("--meta") + 1])
    assert meta["project"] == "anchor-gapbench-supabase-clone"   # the anchor tag exempts the shared host
    assert cmd[cmd.index("--probe") + 1] == "sec-backend-001"


def test_wait_until_clear_waits_out_the_window_then_proceeds():
    # the challenge clears on a rolling ~5-10 minute window, so waiting is the correct move: a scenario run
    # while blocked is a LOST measurement, and 92 of them is a lost night
    from gapbench_run import wait_until_clear
    calls, slept = {"n": 0}, []

    def blocked():
        calls["n"] += 1
        return calls["n"] <= 3          # blocked for three checks, then clear

    import gapbench_run
    real_sleep, gapbench_run.time.sleep = gapbench_run.time.sleep, lambda s: slept.append(s)
    try:
        assert wait_until_clear(60, 1800, log=lambda *_a: None, blocked=blocked) is True
        assert slept == [60, 60, 60]     # waited exactly as long as it was blocked, no longer
    finally:
        gapbench_run.time.sleep = real_sleep


def test_wait_until_clear_gives_up_rather_than_hanging_forever():
    from gapbench_run import wait_until_clear
    import gapbench_run
    real_sleep, gapbench_run.time.sleep = gapbench_run.time.sleep, lambda s: None
    try:
        # a block that outlasts the budget must STOP the run, not spin: the caller's resume makes stopping free
        assert wait_until_clear(60, 180, log=lambda *_a: None, blocked=lambda: True) is False
    finally:
        gapbench_run.time.sleep = real_sleep


def test_is_blocked_treats_a_challenge_a_rate_limit_and_a_transport_error_alike():
    import gapbench_run
    import httpx as _httpx

    class _R:
        def __init__(self, code):
            self.status_code = code

    real_get = gapbench_run.httpx.get
    try:
        for code, expected in ((403, True), (429, True), (200, False), (404, False)):
            gapbench_run.httpx.get = lambda *a, code=code, **k: _R(code)
            assert gapbench_run.is_blocked() is expected, code
        def boom(*a, **k):
            raise _httpx.ConnectError("refused")
        gapbench_run.httpx.get = boom
        assert gapbench_run.is_blocked() is True     # what a block looks like mid-tighten
    finally:
        gapbench_run.httpx.get = real_get


def test_verdict_separates_a_real_miss_from_an_untested_scenario():
    # THE distinction that makes a recall number readable. A subset grade's slop is meaningless, so the line
    # has to say whether the DECLARED class was caught -- and a miss only counts if the probes actually ran.
    from gapbench_run import verdict
    scen = {"id": "sqli-raw", "cwes": ["CWE-89"]}
    hit = {"slop_score": 40, "coverage": {"applied": ["sec-sqli-004"]},
           "findings": [{"probe_id": "sec-sqli-004", "category": "sql-injection"}]}
    assert verdict(hit, scen, ["sec-sqli-004"])[0] == "HIT"
    ran_clean = {"slop_score": 0, "coverage": {"applied": ["sec-sqli-004"]}, "findings": []}
    assert verdict(ran_clean, scen, ["sec-sqli-004"])[0] == "miss"        # detector ran, found nothing
    nothing_applied = {"slop_score": 0, "coverage": {"applied": []}, "findings": []}
    assert verdict(nothing_applied, scen, ["sec-sqli-004"])[0] == "untested"   # reach problem, not recall
    assert verdict({"slop_score": None, "dead_url": True}, scen, ["x"])[0] == "dead"
    assert verdict(None, scen, ["x"])[0] == "dead"


def test_verdict_does_not_credit_a_wrong_class_fire():
    # firing SOMETHING is not catching the declared bug; an XSS hit on a traversal scenario is not recall
    from gapbench_run import verdict
    scen = {"id": "download-traversal", "cwes": ["CWE-22"]}
    rec = {"slop_score": 35, "coverage": {"applied": ["sec-xss-001"]},
           "findings": [{"probe_id": "sec-xss-001", "category": "xss"}]}
    v, applied, fired = verdict(rec, scen, ["sec-xss-001"])
    assert v == "miss" and applied == 1 and fired == ["sec-xss-001"]


def test_a_control_gets_inverted_vocabulary_not_hit_miss():
    # a control has nothing to catch: a fire is a FALSE POSITIVE and silence is the pass. Labelling that
    # "miss" would read as failure when it is exactly the result we want, and it is how a precision signal
    # gets mistaken for a recall one.
    from gapbench_run import verdict
    ctrl = {"id": "ref0", "vulnerability": "None (true-negative control)", "cwes": []}
    quiet = {"slop_score": 25, "coverage": {"applied": ["sec-lfi-001", "sec-sqli-004"]}, "findings": []}
    assert verdict(quiet, ctrl, [])[0] == "clean"
    # hygiene on a control is not an FP: the benchmark's own edge omits those headers on every scenario
    hygiene = {"slop_score": 25, "coverage": {"applied": ["sec-headers-001"]},
               "findings": [{"probe_id": "sec-headers-001", "category": "security-headers"},
                            {"probe_id": "qa-a11y-001", "category": "accessibility"}]}
    assert verdict(hygiene, ctrl, [])[0] == "clean"
    # a vulnerability CLAIM on a clean site is the precision failure we are hunting
    bad = {"slop_score": 65, "coverage": {"applied": ["sec-lfi-001"]},
           "findings": [{"probe_id": "sec-lfi-001", "category": "path-traversal"}]}
    v, _n, fired = verdict(bad, ctrl, [])
    assert v == "FP(1)" and fired == ["sec-lfi-001"]


# ---------------------------------------------------------------- batching to stay under the challenge

def test_a_selection_is_split_into_batches_no_larger_than_the_measured_threshold():
    """The overnight log split perfectly at 10: 55 scenarios at <=10 probes caused zero blocks, and >=11
    blocked ~always, each block costing a flat 7 minutes."""
    sel = ["p%02d" % i for i in range(23)]
    out = _chunks(sel, _CHUNK_PROBES)
    assert all(len(b) <= _CHUNK_PROBES for b in out)
    assert [p for b in out for p in b] == sel, "batching must not drop or reorder a probe"


def test_an_exact_multiple_does_not_produce_a_trailing_empty_batch():
    assert _chunks(["a", "b"], 2) == [["a", "b"]]


def test_an_empty_selection_stays_one_job():
    """A control expands to an explicit probe list upstream; an empty selection must still be one runnable
    job rather than zero, or the scenario would silently vanish from the plan."""
    assert _chunks([], _CHUNK_PROBES) == [[]]
