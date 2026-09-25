"""validation/event-attributes.csv is hand assembled from Devpost, MLH and QS data; these checks hold it to the
coding rules the corpus report states (Section 2.4), so a later edit cannot quietly break them."""
import csv
import pathlib
import re

ROWS = list(csv.DictReader(open(pathlib.Path(__file__).resolve().parent.parent / "validation" / "event-attributes.csv")))
GATE = re.compile(r"accept|admit|approv|apply|application|invited", re.I)


def test_one_row_per_corpus_event():
    slugs = [r["slug"] for r in ROWS]
    assert len(slugs) == 80 and len(set(slugs)) == 80


def test_codes_use_the_fixed_vocabulary():
    for r in ROWS:
        assert r["host_kind"] in ("university", "independent"), r["slug"]
        assert r["format"] in ("in_person", "online"), r["slug"]
        assert r["admissions_gate"] in ("yes", "no"), r["slug"]
        assert r["mlh_member"] in ("yes", "no"), r["slug"]
        assert (r["host_kind"] == "university") == bool(r["host_university"]), r["slug"]
        assert (r["mlh_member"] == "yes") == bool(r["mlh_listing"]), r["slug"]


def test_admissions_gate_follows_the_eligibility_text_rule():
    for r in ROWS:
        assert (r["admissions_gate"] == "yes") == bool(GATE.search(r["devpost_eligibility_text"])), r["slug"]


def test_qs_value_only_for_ranked_university_hosts():
    for r in ROWS:
        if r["qs_2026_value"]:
            assert r["host_kind"] == "university" and r["qs_2026"] not in ("", "not ranked"), r["slug"]
            assert 1 <= float(r["qs_2026_value"]) <= 1500, r["slug"]
        elif r["host_kind"] == "university":
            assert r["qs_2026"] == "not ranked", r["slug"]
