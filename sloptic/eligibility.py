"""Record-level predicates for WHICH graded rows belong in the reference distribution and the score stats.

Kept in ONE place because the same rules gate several consumers that must agree: scripts/benchmark.py (curve
build + rank) and scripts/stats.py (distribution, fire-frequency, winner split, anomalies). They drifted once
already — stats.py's winner split inlined the graded filter but omitted the entry-challenge exclusion, so
entry-withheld apps (score 0) leaked into it alone and it reported min=0 while the distribution reported min=8.
A shared predicate makes that class of bug unrepresentable.
"""
from __future__ import annotations

# Hosts that render the app into a client-side canvas (websocket-driven) rather than into HTML, so a black-box
# surface probe only ever reaches the framework's uniform shell, never the student's app. Every such grade is
# the SAME framework-shell score (v17: all 66 Streamlit apps -> surface_size 108, forms/inputs 0, an identical
# 14-finding set, ~144), so it measures the framework, not the submission. It must neither fit the reference
# curve (it would plant a fake landmark: 66 apps clustered at p93, outnumbering real peers there 66-to-17) nor
# be ranked against it. The `http://localhost` these apps "call" is Streamlit's own client bundle, so the
# unreachable-backend probe also false-positives on them — a second reason the shell grade is not the app.
SHELL_ONLY_PLATFORMS = frozenset({"streamlit"})


def is_ungradeable_challenge(rec: dict) -> bool:
    """A bot-challenge served at ENTRY (an interstitial on the first fetch) means nothing was graded: the record
    scores 0 and must be excluded. A LATE challenge (all probes ran, THEN the origin challenged) is a valid
    completed grade and is kept. Legacy records carry `bot_challenge` with no `challenge_stage` -> conservatively
    treated as entry (the old behaviour before the stage was recorded)."""
    return rec.get("challenge_stage") == "entry" or (bool(rec.get("bot_challenge")) and not rec.get("challenge_stage"))


def is_shell_only(rec: dict) -> bool:
    """True when the grade is a canvas-shell (Streamlit) capture rather than the real app, so it's excluded from
    the reference distribution and never certifiable. CAPTURE-BASED: once the render-await runs it records a
    `render_state`, and the app is shell-only iff we never reached it — 'error' (Streamlit crash screen) or
    'stuck' (won't come up); 'rendered' is a REAL grade that counts. Legacy records predate render_state, so
    fall back to the platform heuristic (exclude every Streamlit app), the pre-render-fix behaviour."""
    rs = (rec.get("observed_surface") or {}).get("render_state")
    if rs is not None:
        return rs in ("error", "stuck")
    return ((rec.get("platform") or {}).get("host_platform") or "") in SHELL_ONLY_PLATFORMS
