"""Load the probe catalog from YAML files (one probe per file, any subdirectory)."""
from __future__ import annotations

import fnmatch
import pathlib

import yaml

from .schema import Probe


class ProbeSelectionError(ValueError):
    """A --probe pattern matched nothing. Fatal ON PURPOSE: a silent empty selection would grade every
    target with zero probes and report slop 0, which reads as 'clean' rather than 'nothing ran'."""


def load_catalog(root: str | pathlib.Path) -> list[Probe]:
    probes: list[Probe] = []
    for path in sorted(pathlib.Path(root).rglob("*.yaml")):
        data = yaml.safe_load(path.read_text())
        probes.append(Probe(**data))
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
