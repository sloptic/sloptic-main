"""Passive/active safety classification. A mis-classification here would fire an attack payload at a target
whose ownership was NOT verified, so this is locked hard: the two sets must PARTITION the live catalog (every
probe consciously classified, new ones forced to choose), the dangerous families can never be passive, and
`passive_catalog` must exclude every active probe."""
import pathlib

from sloptic.catalog import load_catalog
from sloptic.safety import ACTIVE_PROBES, PASSIVE_PROBES, is_passive, passive_catalog

_CATALOG = load_catalog(str(pathlib.Path(__file__).resolve().parent.parent / "catalog"))
_IDS = {p.id for p in _CATALOG}


def test_sets_are_disjoint():
    assert PASSIVE_PROBES.isdisjoint(ACTIVE_PROBES), PASSIVE_PROBES & ACTIVE_PROBES


def test_sets_partition_the_live_catalog():
    classified = PASSIVE_PROBES | ACTIVE_PROBES
    unclassified = _IDS - classified            # a new probe nobody placed -> defaults active, loses coverage
    stale = classified - _IDS                   # an id in a set that no longer exists in the catalog
    assert not unclassified, f"UNCLASSIFIED probes: {sorted(unclassified)}"
    assert not stale, f"stale ids not in catalog: {sorted(stale)}"


def test_dangerous_families_can_never_be_passive():
    # redundant net beyond the explicit lists: anything whose id names a payload / mutation / fault / hammer /
    # multi-account / data-pull must NOT be passive, even if PASSIVE_PROBES is edited wrong.
    # exposure-005/006 are OBSERVED-in-served (passive) so they are NOT here; the FETCHERS 001-004/007/008 are
    DANGER = ("sqli", "cmdi", "xss", "ssti", "lfi", "xxe", "ssrf", "upload", "idor", "filterinj", "hosthdr",
              "split", "redirect", "authbypass", "csrf", "dos", "ratelimit", "crash", "race", "backend",
              "session", "integrity", "staleui", "noerror", "errhyg", "input", "debug", "load-001",
              "exposure-001", "exposure-002", "exposure-003", "exposure-004", "exposure-007", "exposure-008")
    for p in _CATALOG:
        if any(d in p.id for d in DANGER):
            assert not is_passive(p.id), f"{p.id} is a dangerous/active probe but classified PASSIVE"


def test_passive_catalog_excludes_all_active():
    ids = {p.id for p in passive_catalog(_CATALOG)}
    assert ids <= PASSIVE_PROBES
    assert ids.isdisjoint(ACTIVE_PROBES)
    assert ids == (PASSIVE_PROBES & _IDS)


def test_is_passive_is_fail_closed():
    assert is_passive("sec-headers-002") is True
    assert is_passive("sec-cmdi-001") is False
    assert is_passive("brand-new-unclassified-probe") is False   # unknown -> treated active, not run passive
