"""Run cache: persist a graded Report keyed by (source + grade-affecting flags + a code/catalog fingerprint),
so a SECOND `sloptic` on the same target -- e.g. to see --failed or --report-card after the summary -- reuses
the grade instead of re-probing the app.

What is and isn't in the key:
  - OUTPUT flags (--json/--failed/--report-card/--organizer/--out/-v/-q) do NOT change the grade -> excluded,
    so switching the view is a cache HIT.
  - GRADE-affecting flags (--probe/--passive-only/--browser/--header/--source/--harden) ARE in the key.
  - A file/dir source folds in its mtime, and the catalog + core probe code fold in theirs, so editing the app,
    a probe, or the catalog re-grades rather than serving a stale result.

--refresh forces a fresh grade and overwrites the entry; --no-cache skips read+write entirely. A cache failure
(unreadable/unwritable) is always swallowed -- the cache must never break a grade."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pathlib
import time

from .schema import Outcome, Report

_CACHE_DIR = pathlib.Path(os.environ.get("SLOPTIC_CACHE_DIR")
                          or (pathlib.Path.home() / ".cache" / "sloptic" / "runs"))
_REPORT_FIELDS = {f.name for f in dataclasses.fields(Report)}


def _code_fingerprint(catalog_dir: str | None) -> str:
    """mtimes of the grade-shaping code + the catalog, so a probe/scoring/catalog edit invalidates the cache."""
    import sloptic
    pkg = pathlib.Path(sloptic.__file__).resolve().parent
    mts: list[int] = []
    for f in ("probes.py", "aggregate.py", "browser.py", "net.py"):
        try:
            mts.append(int(os.path.getmtime(pkg / f)))
        except OSError:
            pass
    if catalog_dir:
        try:
            mts.append(int(max((os.path.getmtime(p) for p in pathlib.Path(catalog_dir).rglob("*.yaml")),
                               default=0)))
        except (OSError, ValueError):
            pass
    return "-".join(map(str, mts))


def cache_key(source: str, catalog_dir: str | None, *, probes, passive_only, browser,
              headers, source_dir, harden, browser_auth=False) -> str:
    parts = [source, catalog_dir or "", "|".join(sorted(probes or [])), str(bool(passive_only)),
             str(bool(browser)), "|".join(sorted(headers or [])), source_dir or "", str(bool(harden)),
             str(bool(browser_auth)),   # browser-auth changes the discovered surface + the probes' session -> distinct
             _code_fingerprint(catalog_dir)]
    for p in (source, source_dir):                 # a file/dir source: an edit (mtime) invalidates the entry
        try:
            parts.append(f"{p}:{os.path.getmtime(p):.0f}")
        except (OSError, TypeError):
            pass
    return hashlib.sha256("\x00".join(parts).encode()).hexdigest()[:20]


def _path(key: str) -> pathlib.Path:
    return _CACHE_DIR / f"{key}.json"


def load(key: str):
    """(Report, age_seconds) from the cache, or None if absent/unreadable/stale-schema."""
    try:
        blob = json.loads(_path(key).read_text())
        d = {k: v for k, v in blob["report"].items() if k in _REPORT_FIELDS}   # drop keys from an old schema
        d["outcomes"] = [Outcome(**o) for o in d.get("outcomes", [])]
        return Report(**d), max(0.0, time.time() - blob.get("saved_at", 0))
    except (OSError, ValueError, KeyError, TypeError):
        return None


def save(key: str, report: Report, source: str) -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _path(key).write_text(json.dumps(
            {"source": source, "saved_at": time.time(), "report": dataclasses.asdict(report)}))
    except OSError:
        pass   # a cache write must never break a grade


def human_age(seconds: float) -> str:
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h"
    return f"{s // 86400}d"
