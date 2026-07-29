"""The catalog and the code that executes it are two files that must agree, and NOTHING checked that they did.

Every failure this locks is SILENT — the probe doesn't error, it reports not_applicable, which reads exactly
like "this app had no surface to test". A probe can therefore be dead across an entire 1,500-app corpus run
while every unit test passes, because unit tests import the predicate function directly and never go through
the catalog at all. That is not hypothetical: qa-devbuild-001 shipped with its predicate missing from
PREDICATES, and graded a live Vite dev server clean.

Three vectors, all the same shape — a name in YAML that no Python object answers to:

  1. predicate: <name> not in PREDICATES  -> KeyError inside _run_probe's guard -> N/A, no reason recorded
  2. requires: [<name>] not a capability  -> capabilities.get(name, False) -> False on EVERY app, forever
  3. predicate with no _PREDICATE_REASONS -> describe() falls back to printing the raw slug at the user

These are cheap, total (they check the whole catalog, not a sample) and they fail at CI time rather than
after a 6-10 hour corpus run.
"""
import ast
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from hacklet_runner.catalog import load_catalog  # noqa: E402
from hacklet_runner.probes import _PREDICATE_REASONS, PREDICATES  # noqa: E402

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CATALOG = load_catalog(str(_ROOT / "catalog"))


def _declared_capabilities() -> set[str]:
    """The capability names discovery actually mints, read from the `capabilities = {...}` literal so this
    test tracks discovery.py instead of restating it (a hand-copied list would rot into a second lie)."""
    mod = ast.parse((_ROOT / "hacklet_runner" / "discovery.py").read_text())
    for node in ast.walk(mod):
        if (isinstance(node, ast.Assign)
                and any(getattr(t, "id", "") == "capabilities" for t in node.targets)
                and isinstance(node.value, ast.Dict)):
            return {k.value for k in node.value.keys if isinstance(k, ast.Constant)}
    raise AssertionError("no `capabilities = {...}` literal in discovery.py — this test needs updating")


def test_the_catalog_is_not_empty():
    """Guards the guards: every other test here is vacuously true over an empty catalog."""
    assert len(_CATALOG) > 50, "only %d probes loaded — the catalog path is wrong" % len(_CATALOG)


def test_every_catalog_predicate_resolves_to_a_function():
    """THE BUG THIS FILE EXISTS FOR. An unregistered name raises KeyError inside _run_probe, which the
    hostile-target guard converts to not_applicable with no evidence — indistinguishable from an app that
    genuinely had nothing to test."""
    missing = sorted((p.id, p.probe["predicate"]) for p in _CATALOG
                     if "predicate" in p.probe and p.probe["predicate"] not in PREDICATES)
    assert not missing, "catalog names a predicate that PREDICATES doesn't define: %r" % (missing,)


def test_every_applicability_requirement_is_a_real_capability():
    """_applicable() is `capabilities.get(req, False)`, so a typo doesn't raise — it returns False on every
    app and disables the probe permanently and invisibly."""
    known = _declared_capabilities()
    bogus = sorted({(p.id, req) for p in _CATALOG for req in p.applicability.requires if req not in known})
    assert not bogus, "probe requires a capability discovery never sets: %r (known: %s)" % (bogus, sorted(known))


def test_every_predicate_has_a_human_reason():
    """describe() falls back to `.get(name, name)`, so a missing entry doesn't crash — it prints the bare
    slug (`development_build_served`) into --failed output and the report where a sentence belongs."""
    unnamed = sorted({p.probe["predicate"] for p in _CATALOG
                      if "predicate" in p.probe and p.probe["predicate"] not in _PREDICATE_REASONS})
    assert not unnamed, "predicate has no _PREDICATE_REASONS entry: %r" % (unnamed,)


def test_probe_ids_are_unique():
    """Two YAML files sharing an id silently shadow one another in every id-keyed dict downstream."""
    ids = [p.id for p in _CATALOG]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, "duplicate probe ids: %r" % (dupes,)
