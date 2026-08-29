"""The result row's own contract: a version a reader can branch on, and the page the grade actually described.

Both exist for the same reason provenance does — a corpus run is not re-runnable, so anything a future reader
needs must be IN the row. These two were missing:

  * contract_version — nothing in the codebase stated what shape a row was, so a consumer had to guess from
    which keys happened to be present.
  * observed_surface.landing_path — every `target: /` probe (a11y, seo, headers, perf, dev-build) grades the
    resolved landing page, not the origin root. A sub-path deployment is graded at /Project, and without this
    a row cannot say which page its largest findings describe.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from scripts.deploy_and_grade import _verdicts  # noqa: E402
from sloptic import provenance  # noqa: E402
from sloptic.discovery import surface_metrics  # noqa: E402
from sloptic.schema import Outcome, Profile  # noqa: E402


def _o(pid, outcome, bundle="security", evidence=None, target=""):
    return Outcome(probe_id=pid, bundle=bundle, category="c", outcome=outcome, penalty=0,
                   target=target, evidence=evidence or {})


def test_contract_version_is_an_int_a_reader_can_compare():
    assert isinstance(provenance.CONTRACT_VERSION, int)


def test_it_starts_above_1_so_absence_is_unambiguous():
    """Rows written before the field existed carry nothing, and absence is DEFINED as 1. If 1 were also the
    first value ever emitted, a reader could not tell an explicit v1 from an unversioned row."""
    assert provenance.CONTRACT_VERSION >= 2


def test_the_grade_script_stamps_it_on_the_row():
    """Guards silent removal. The row is assembled inside a long function that is expensive to invoke, so this
    checks the assembly site references the constant rather than reconstructing the whole record."""
    src = (pathlib.Path(__file__).resolve().parent.parent / "scripts" / "deploy_and_grade.py").read_text()
    assert '"contract_version": provenance.CONTRACT_VERSION' in src


def test_landing_path_defaults_to_root_for_a_normally_served_app():
    s = surface_metrics(Profile(base_url="http://x", routes=["/"], landing_path="/"))
    assert s["landing_path"] == "/"


def test_landing_path_records_the_sub_path_a_sub_path_deployment_was_graded_at():
    """The case it exists for: user.github.io/Project, whose origin root is the host's 404 shell. The homepage
    probes grade /Project, and the row must say so or its a11y/seo/header findings are unattributable."""
    s = surface_metrics(Profile(base_url="http://x", routes=["/Project"], landing_path="/Project"))
    assert s["landing_path"] == "/Project"


def test_landing_path_is_present_even_on_an_empty_surface():
    """A dead or blank app still produces a row, and a missing key would force every reader to use .get()."""
    assert "landing_path" in surface_metrics(Profile(base_url="http://x"))


# ---- verdicts: applied-but-unfired probes, the dark-recall audit set -----------------------------------------

def test_verdicts_record_clean_and_na_but_not_fires():
    # a fire belongs in `findings`, not here; a clean is a candidate false-negative; an n/a is the coverage map
    outcomes = [_o("sec-a", "slop_detected"),
                _o("sec-b", "clean", evidence={"status": 200}),
                _o("sec-c", "not_applicable", evidence={"na_reason": "requires unmet: at_least_one_form"})]
    v = {x["probe_id"]: x for x in _verdicts(outcomes)}
    assert set(v) == {"sec-b", "sec-c"}                       # the fire is excluded
    assert v["sec-b"]["outcome"] == "clean"
    assert v["sec-c"]["na_reason"].startswith("requires unmet")   # the coverage reason is surfaced


def test_verdicts_collapse_fanout_to_the_strongest_applied_state():
    # a probe judged clean on one target and n/a on another DID judge -> one entry, clean (clean > not_applicable)
    outcomes = [_o("qa-x", "not_applicable", target="/a", evidence={"na_reason": "no form"}),
                _o("qa-x", "clean", target="/b", evidence={"status": 200})]
    v = _verdicts(outcomes)
    assert len(v) == 1 and v[0]["outcome"] == "clean"


def test_a_probe_that_fired_anywhere_is_not_also_a_verdict():
    # fan-out: fired on /a, clean on /b -> it is a FINDING, must not double-list as a clean verdict
    outcomes = [_o("sec-y", "slop_detected", target="/a"), _o("sec-y", "clean", target="/b")]
    assert _verdicts(outcomes) == []


def test_verdict_evidence_is_trimmed_to_the_light_audit_keys():
    # bulky repro/body lives on fires; a verdict keeps only the small audit signal so the row doesn't explode
    outcomes = [_o("sec-z", "clean", evidence={"status": 200, "sensitive_columns": ["email"],
                                               "repro": {"body": "x" * 5000}})]
    ev = _verdicts(outcomes)[0]["evidence"]
    assert ev == {"status": 200, "sensitive_columns": ["email"]}   # repro dropped


def test_the_grade_script_stamps_verdicts_on_the_row():
    """Guards silent removal, mirroring the contract_version guard: the assembly site must reference _verdicts."""
    src = (pathlib.Path(__file__).resolve().parent.parent / "scripts" / "deploy_and_grade.py").read_text()
    assert "verdicts=_verdicts(report.outcomes)" in src
