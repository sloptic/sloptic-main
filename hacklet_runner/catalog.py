"""Load the probe catalog from YAML files (one probe per file, any subdirectory)."""
from __future__ import annotations

import pathlib

import yaml

from .schema import Probe


def load_catalog(root: str | pathlib.Path) -> list[Probe]:
    probes: list[Probe] = []
    for path in sorted(pathlib.Path(root).rglob("*.yaml")):
        data = yaml.safe_load(path.read_text())
        probes.append(Probe(**data))
    return probes
