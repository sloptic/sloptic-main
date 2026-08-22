"""Passive vs active probe classification, and the `--passive-only` filter.

SAFETY policy, not detection logic, so it lives here (one auditable place) rather than scattered across the
probe YAML. A PASSIVE probe is safe on a target whose ownership is NOT verified, on TWO counts: (1) it changes
no state, and (2) it never goes FETCHING hidden sensitive data. It reads only what the app already serves to
every visitor (the page, assets, JS bundle, headers, normal responses, a served source map) and reports what
is there, even a leaked secret: it is public anyway, everyone can see it, nobody just looked. An ACTIVE probe
either changes state (mutate / create / register / submit), coerces the server with a payload (injection,
fault induction, resource exhaustion), acts as multiple identities, OR goes fetching data the app does not
serve to normal visitors (guessing /.env or /.git, querying the backend directly, pulling a bulk-data
endpoint). Active probing an origin the caller has not proven they own is unauthorized testing, so the public
web product runs PASSIVE-ONLY on unverified targets (see the sloptic-web handoff).

FAIL-CLOSED: `is_passive` is True only for ids EXPLICITLY in PASSIVE_PROBES. Anything else (a new probe, a
typo) is treated as ACTIVE and excluded from a passive-only run, so forgetting to classify a probe loses
coverage, never opens the active tier on a stranger's site. test_safety.py asserts the two sets PARTITION the
live catalog exactly, so every probe (new ones included) must be consciously placed.
"""

# What a normal visitor/browser does: read the served page, assets, bundle, headers, config; follow links.
PASSIVE_PROBES = frozenset({
    # performance -- all measure timing/weight/requests from ordinary loads (no burst)
    "perf-lighthouse-001",   # reads the already-computed Lighthouse report (an ordinary throttled page load)
    "perf-cache-001", "perf-loadtime-001", "perf-weight-001",
    "perf-requests-001", "perf-ttfb-001", "perf-cwv-001", "perf-cwv-002",
    "perf-lcp-001", "perf-dom-001", "perf-font-001",   # v2.0 Family 4: render/observe or parse CSS -- no state change
    # qa -- render / static-analyse / GET; nothing submitted, created, or malformed
    "qa-a11y-001", "qa-a11y-002", "qa-links-001", "qa-console-001", "qa-ctype-001", "qa-devbuild-001",
    "qa-http-001", "qa-http-002", "qa-seo-001", "qa-backnav-001", "qa-chunk-001", "qa-deeplink-001",
    "perf-minify-001",   # fetches the homepage's same-origin .css/.js and measures minification (plain GETs)
    "qa-deploy-001",   # static-analyses the already-served client bundle for a dev/private backend URL
    "qa-deploy-002",   # follows redirects from the homepage/links like a normal visitor (no mutation/payload)
    "qa-deploy-003",   # reads the served OAuth authorize URL / follows an auth route one hop (never completes it)

    # security -- config/hygiene + leaks OBSERVED in what the app already serves to every visitor (headers,
    # bundle, normal responses, a served source map). No payload, no mutation, no FETCHING of hidden files.
    "sec-headers-001", "sec-headers-002", "sec-headers-003", "sec-headers-004", "sec-headers-005",
    "sec-headers-006", "sec-csp-001", "sec-cors-001", "sec-mixed-001", "sec-deps-001", "sec-secrets-001",
    "sec-secrets-002", "sec-exposure-005", "sec-exposure-006", "sec-exposure-009",
    "sec-tls-001",   # observes the origin's scheme + whether it upgrades to https (a plain GET, no payload)
    "sec-sri-001",   # parses the served homepage HTML for cross-origin subresources without integrity (a GET)
})

# Sends a payload / mutates / induces a fault / hammers / needs accounts / pulls exposed data.
ACTIVE_PROBES = frozenset({
    # performance
    "perf-load-001",                                                            # concurrent burst (mini-DoS)
    # qa -- fault induction, state mutation, hammering, clicking (may submit)
    "qa-crash-010", "qa-errhyg-001", "qa-input-001", "qa-integrity-001", "qa-integrity-002",
    "qa-race-001", "qa-race-002", "qa-noerror-001", "qa-staleui-001", "qa-deadctrl-001",
    "qa-email-001", "qa-email-002",   # register with a controlled address + follow the verification link (mutate)
    "qa-reset-001",                   # request a password reset for our own account + follow the reset link (mutate)
    "qa-input-002",                   # submit international/multibyte values to a writable field (mutate)
    # security -- injection, mutation, auth/multi-account, fault, hammer, data pull
    "sec-cmdi-001", "sec-sqli-001", "sec-sqli-002", "sec-sqli-003", "sec-sqli-004", "sec-sqli-005",
    "sec-xss-001", "sec-xss-002", "sec-domxss-001", "sec-ssti-001", "sec-lfi-001", "sec-xxe-001",
    "sec-ssrf-001", "sec-filterinj-001", "sec-hosthdr-001", "sec-split-001", "sec-redirect-001",
    "sec-upload-001", "sec-upload-002", "sec-csrf-001", "sec-dos-001", "sec-ratelimit-001",
    "sec-authbypass-001", "sec-idor-001", "sec-idor-002", "sec-idor-003", "sec-idor-004", "sec-idor-005",
    "sec-backend-001", "sec-backend-002", "sec-backend-003", "sec-debug-001",
    "sec-session-001", "sec-session-002", "sec-session-003", "sec-session-004", "sec-session-005",
    # exposure FETCHERS: go LOOKING for a sensitive file/data the app does not serve normally (guessed
    # paths, backend queries, bulk pulls). exposure-005/006 + secrets-* are OBSERVED-in-served -> passive.
    "sec-exposure-001", "sec-exposure-002", "sec-exposure-003", "sec-exposure-004", "sec-exposure-007",
    "sec-exposure-008",
})


# The injection / stress probes whose request volume = payloads x fields x targets (or a deliberate burst).
# They generate the bulk of a grade's traffic and are the most likely to trip an adaptive WAF's cumulative-
# volume detection, so they run LAST (see order_weight). NOT a safety tier -- purely a run-ORDER tier; every
# id here is already in ACTIVE_PROBES (test_safety asserts the subset).
HIGH_VOLUME_PROBES = frozenset({
    "sec-cmdi-001", "sec-lfi-001", "sec-ssti-001", "sec-xxe-001", "sec-ssrf-001",
    "sec-sqli-001", "sec-sqli-002", "sec-sqli-003", "sec-sqli-004", "sec-sqli-005",
    "sec-xss-001", "sec-xss-002", "sec-domxss-001", "sec-filterinj-001", "sec-split-001",
    "sec-upload-001", "sec-upload-002", "sec-redirect-001",
    "sec-dos-001", "sec-ratelimit-001", "perf-load-001",
})


def is_passive(probe_id: str) -> bool:
    """True only for explicitly-passive ids. Fail-closed: unknown -> active -> excluded from passive-only."""
    return probe_id in PASSIVE_PROBES


# Probes that ANTAGONIZE a per-app WAF and fire ~never, so they run DEAD LAST — after every injection probe —
# and a WAF trip on THEM blocks only this trailing group (recovered by the post-run retry), not the high-value
# session/idor/injection/qa/perf probes that already ran. The upload burst (webshell multipart) is maximally
# attack-shaped (v18: top re-challenge onset). The exposure FETCHERS guess sensitive-file paths in a burst
# (sec-exposure-007 sends ~22 guesses) and sec-hosthdr-001 forges Host headers -- v19 + v21 showed these are
# the per-app-challenge onset on edge hosts (Vercel), which was blocking the whole tail; moving them here keeps
# the rest of the grade. The served-file GATES (exposure-001/002/003) stay early: they are high-value and
# low-request, so they complete before any trip.
RUN_LAST_PROBES = frozenset({
    "sec-upload-001", "sec-upload-002",
    "sec-exposure-004", "sec-exposure-007", "sec-exposure-008", "sec-hosthdr-001",
})


def order_weight(probe_id: str) -> int:
    """Run-order tier within a grade: PASSIVE (0, lowest volume) first, ordinary active (1) next, HIGH-VOLUME
    injection/stress (2), then the WAF-antagonizing-but-zero-value upload burst (3) DEAD LAST. On an adaptive-WAF
    host the challenge then trips during the tail, so the low-volume probes (headers/a11y/perf + the high-value
    exposure fetchers) AND the injection probes have already completed, and the recovery keeps their outcomes
    (the pipeline scores only PRE-onset). A fully-completed grade's score is order-independent (compute_slop_score
    aggregates by category), so reordering only ever HELPS the WAF case and never changes a clean grade. Fail-safe:
    an unclassified id sorts into the middle tier, never the tail."""
    if probe_id in PASSIVE_PROBES:
        return 0
    if probe_id in RUN_LAST_PROBES:
        return 3
    if probe_id in HIGH_VOLUME_PROBES:
        return 2
    return 1


def passive_catalog(catalog: list) -> list:
    """The subset safe to run on a target whose ownership has NOT been verified."""
    return [p for p in catalog if is_passive(p.id)]
