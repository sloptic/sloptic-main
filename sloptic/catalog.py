"""Load the probe catalog from YAML files (one probe per file, any subdirectory)."""
from __future__ import annotations

import fnmatch
import pathlib

import yaml

from .schema import Probe, Severity


class ProbeSelectionError(ValueError):
    """A --probe pattern matched nothing. Fatal ON PURPOSE: a silent empty selection would grade every
    target with zero probes and report slop 0, which reads as 'clean' rather than 'nothing ran'."""


_PKG = pathlib.Path(__file__).resolve().parent   # the installed sloptic/ directory


def default_catalog_dir() -> pathlib.Path:
    """Where the probe catalog lives. Inside an installed wheel it is bundled at sloptic/catalog (see the
    force-include in pyproject); running from a source checkout it is the repo-root sibling `catalog/`. Prefer
    the packaged copy so a pip-installed grader has its battery; fall back to the sibling for development."""
    packaged = _PKG / "catalog"
    return packaged if packaged.is_dir() else _PKG.parent / "catalog"


def _load_severity_registry(root: pathlib.Path) -> dict[str, Severity]:
    """Shared severity definitions referenced by a probe's `severity_ref` (DRY: one authority-anchored block
    per vulnerability class, not copied into every probe of that class). Lives in catalog/_severity_classes.yaml
    as {class_name: severity-block}. Empty when the file is absent (probes then use inline severity / nominal)."""
    root = pathlib.Path(root)
    reg = root / "_severity_classes.yaml"
    if not reg.is_file():
        # load_catalog may be called from an ANCESTOR of the catalog dir (scripts/benchmark._catalog_index
        # passes the repo root and relies on rglob to find the probe YAMLs deep). Find the registry the same way,
        # or every severity_ref silently fails to resolve against an empty registry.
        reg = next(root.rglob("_severity_classes.yaml"), None)
    if reg is None or not reg.is_file():
        return {}
    raw = yaml.safe_load(reg.read_text()) or {}
    return {name: Severity(**block) for name, block in raw.items()}


def _apply_severity_ref(probe: Probe, registry: dict[str, Severity]) -> None:
    """Resolve a probe's `severity_ref` into its `severity` from the shared registry. A probe sets AT MOST one
    of severity / severity_ref; an unknown ref is a catalog bug (fail loud), not a silent fall-through."""
    if not probe.severity_ref:
        return
    if probe.severity is not None:
        raise ValueError(f"{probe.id}: set either 'severity' or 'severity_ref', not both")
    if probe.severity_ref not in registry:
        raise ValueError(f"{probe.id}: severity_ref '{probe.severity_ref}' not in catalog/_severity_classes.yaml")
    probe.severity = registry[probe.severity_ref]


def load_catalog(root: str | pathlib.Path) -> list[Probe]:
    root = pathlib.Path(root)
    registry = _load_severity_registry(root)
    probes: list[Probe] = []
    for path in sorted(root.rglob("*.yaml")):
        if path.name.startswith("_"):
            continue   # shared/config catalog data (e.g. _severity_classes.yaml), not a probe
        data = yaml.safe_load(path.read_text())
        probe = Probe(**data)
        _apply_severity_ref(probe, registry)
        if probe.severity is not None:
            probe.penalty = probe.severity.default   # keep the nominal in sync with the authority -> no drift,
                                                     # no stale value; the severity block is the single source
        probes.append(probe)
    return probes


def select_probes(probes: list[Probe], patterns: list[str] | None) -> list[Probe]:
    """Subset the catalog. Each pattern is an id GLOB (`sec-sqli-004`, `sec-sqli-*`, `sec-*`), or
    `bundle:<name>` / `category:<name>` for the groupings an id glob can't express (the ui-honesty bundle
    spans qa-backnav/qa-chunk/qa-deeplink/qa-noerror/qa-staleui). Patterns are OR'd, catalog order is kept.

    Use it to answer "why didn't THIS probe fire here" in one fast run, and to grade a target whose expected
    vulnerability class is known (a labeled benchmark scenario) without spending the whole battery's traffic
    on it. A filtered run measures RECALL only: the score is a subset, so it is not comparable to a full
    grade and must not feed a score distribution. Raises ProbeSelectionError on a pattern that matches
    nothing, so a typo fails loudly instead of grading with an empty catalog."""
    if not patterns:
        return probes
    keep: dict[str, Probe] = {}
    misses: list[str] = []
    for pat in patterns:
        raw = pat.strip()
        if not raw:
            continue
        kind, _, value = raw.partition(":")
        if kind in ("bundle", "category") and value:
            hit = [p for p in probes if (p.bundle if kind == "bundle" else p.category) == value]
        else:
            hit = [p for p in probes if fnmatch.fnmatchcase(p.id, raw)]
        if not hit:
            misses.append(raw)
        for p in hit:
            keep[p.id] = p
    if misses:
        near = sorted({p.id for p in probes for m in misses if m.split(":")[-1][:7] in p.id})[:6]
        raise ProbeSelectionError(
            f"--probe matched no probe in the catalog: {', '.join(misses)}"
            + (f" (did you mean: {', '.join(near)}?)" if near else "")
            + ". Use an id glob (sec-sqli-*), bundle:security, or category:xss.")
    return [p for p in probes if p.id in keep]
