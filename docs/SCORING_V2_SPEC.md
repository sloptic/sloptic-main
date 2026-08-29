# Sloptic Scoring v2: Authority-Anchored Severity Spec

Status: DRAFT for review. Internal (not synced to the public mirror).

Replaces hand-placed per-probe integers ("freq × sev as a guiding principle" = vibes)
with penalties that derive from named authorities and the probe's own evidence. Every
number below is one of two kinds, marked throughout:

- **[pinned]**: from an authority we pulled: CVSS canonical vector, Bugcrowd VRT baseline
  (github.com/bugcrowd/vulnerability-rating-taxonomy), OWASP Top 10 2025 Factors, CISA KEV.
- **[calib]**: a proposed value to be confirmed against a fresh corpus re-grade + re-freeze.
  Range *bounds* are mostly [pinned] (CVSS/VRT); rung *points inside* a range are [calib].

---

## 1. The anchor and the scale

- **Anchor = 100 = a single total catastrophe** (CVSS 10.0 × 10: unauth RCE, full C/I/A, scope
  change). Nothing a single probe finds exceeds it.
- `penalty = CVSS_or_bounded_severity × 10`. A finding's penalty is its "percent of a catastrophe."
- **Per-probe ceiling only.** The aggregate stays unbounded, deduction-only (an app with three
  catastrophes loses ~250 after damping). We did NOT resurrect the reverted 0-100 total score.
- Perf structurally caps at **90** (`max(0, 0.90 - lighthouse_score) × 100`), so a fully-slow app is
  90% of a catastrophe and a full compromise is 100%. Slowness ranks just under owned. Correct.

## 2. Layer map: which authority does what (they do NOT get summed into one number)

| Layer | Authority | Emits |
|---|---|---|
| Coverage (which probes exist) | OWASP Top 10 2025 rank + CWE Top 25 | the probe set |
| **Severity (the penalty)** | **CVSS magnitude + Bugcrowd VRT web-app cross-check** | **the range** |
| Frequency / exploitation | inside CVSS exploitability; EPSS/KEV for `deps-001` only | (not a multiplier) |
| Aggregate (one app's fires) | existing dampers (variant-group max, category ×0.6) | the sum |
| Population (ranking) | frozen curve | the percentile |

Only the Severity layer emits the per-probe integer. The others live elsewhere in the pipeline.

## 3. Severity model: range + evidence ladder

- Each class has a **`range` [lo, hi]** = its CVSS band intersected/reconciled with its VRT band.
- **`default` = lo** (abstention: charge the floor unless impact is proven).
- The probe sets **evidence flags**; a generic resolver picks the highest matching **escalator**
  rung, clamped to `range`. Divergence between CVSS and VRT *widens* the range; it never triggers
  a manual call. **The rule everywhere: default low, evidence lifts.**

```python
class Escalator(BaseModel):
    evidence: str          # the ctx.evidence flag that must be truthy
    point: int             # penalty if this rung is the highest matched (clamped to range)
    vrt_variant: str = ""  # the VRT variant / CVSS change that justifies this rung (provenance)

class Severity(BaseModel):
    cvss: str                       # canonical vector, or "n/a" for non-scorable chores
    cvss_score: float | None = None
    vrt: str                        # Bugcrowd VRT baseline, e.g. "P1" or "P4->P1"
    range: tuple[int, int]
    default: int
    tier: str = ""                  # "chore-floor" marks the Tier-4 diligence floor
    escalators: list[Escalator] = []

# resolver (in _run_probe, after the predicate runs):
#   lo, hi = sev.range
#   pts = [e.point for e in sev.escalators if ctx.evidence.get(e.evidence)]
#   penalty = min(hi, max(lo, sev.default, *pts))     # default low, evidence lifts, clamp to range
#   (falls back to the nominal `penalty:` int if no severity block: un-migrated probes)
```

`penalty:` in each YAML is demoted to a NOMINAL fallback (exactly what perf-lighthouse-001 already
does). The dampers are untouched: aggregate.py keys off the final `Outcome.penalty`.

## 4. Evidence vocabulary: the flags a probe sets

| Flag | The observation that sets it |
|---|---|
| `unauthenticated` | the finding needed no auth (CVSS PR:N) |
| `cross_user_read` | read another user's record/object |
| `cross_user_write` | modified another user's record/object |
| `sensitive_fields` | the exposed data held PII / secrets / tokens |
| `bulk_read` | many records reachable, not one |
| `data_extracted` | injection returned real DB rows (not just an oracle) |
| `write_confirmed` | injection/mutation changed server state |
| `execution_confirmed` | payload actually executed (XSS ran / SSTI evaluated / upload ran) |
| `internal_reached` | SSRF reached an internal/loopback/metadata host |
| `validated_live` | a found secret authenticates against its provider |
| `high_privilege` | secret/access is admin / service_role / private-key tier |
| `external_host` | redirect/SSRF reached an attacker-controlled external host |
| `no_lockout_confirmed` | N failed logins, no throttle/captcha/MFA observed |

A probe that fires boolean and sets no flag earns `default` (the low end). Correct: unproven impact
is not charged for the high end.

## 5. Per-class ladders

CVSS = [pinned] canonical vector score. VRT = [pinned] baseline (variant top where VRT splits it).
Range bounds [pinned] from CVSS/VRT; rung points [calib]. Probe mappings VERIFIED against the code
2026-08-19 (XSS, backend, and the exposure family were mis-mapped in the first draft; corrected below).

### Tier 1: terminal (VRT P1)

| Class | Probe IDs | CVSS | VRT | Range | Default | Escalators (flag -> point) |
|---|---|---|---|---|---|---|
| SQL injection | sqli-001..005 | 9.8 | P1 | 90-98 | 90 | data_extracted->95, write_confirmed->98 |
| OS cmd inj / RCE | cmdi-001 | 9.8 | P1 | 92-98 | 92 | execution_confirmed->98 |
| Auth bypass | authbypass-001 | 9.1-9.8 | P1 | 88-98 | 88 | high_privilege->95, cross_user_write->98 |
| XXE | xxe-001 | 7.5-9.1 | P1 | 70-91 | 70 | internal_reached->82, sensitive_fields->91 |
| Disclosed secret / served creds | secrets-001/002, exposure-001(.env), exposure-004(.aws), exposure-005(creds-in-response), exposure-007(state/dump/key) | 7.5-9.8 | P1 | 70-98 | 70 | validated_live->92, high_privilege->98 |
| Anon whole-DB / bulk-PII read | backend-001, exposure-008 | 7.5-9 | P1 | 70-90 | 70 | sensitive_fields->80, bulk_read->90 |

### Tier 2: high, evidence-critical (wide ranges; the flat-40 lived here)

| Class | Probe IDs | CVSS | VRT | Range | Default | Escalators |
|---|---|---|---|---|---|---|
| SSTI | ssti-001 | 9.8 | P1 (see note) | 90-98 | 90 | execution_confirmed->98 |
| Unrestricted upload (RCE) | upload-001 | 9.0 | P1 (see note) | 90-98 | 90 | execution_confirmed->98 |
| IDOR / BAC | idor-001..005, backend-002 (authed over-permissive RLS) | 6.5-8.1 | P1 | 30-85 | 30 | cross_user_read->55, sensitive_fields->68, bulk_read->78, cross_user_write->85 |
| SSRF | ssrf-001 | 6.5-9.1 | P2 | 40-91 | 40 | internal_reached->70, sensitive_fields->91 |
| Path traversal / LFI | lfi-001 | 7.5 | n/a* | 50-85 | 50 | sensitive_fields->75, high_privilege->85 |
| PostgREST filter inj | filterinj-001 | 7-9 | n/a* | 55-90 | 55 | cross_user_read->75, write_confirmed->90 |
| Repo exposure (.git) | exposure-002/003 (group exposed-git) | 7-8 | P2 | 40-80 | 40 | sensitive_fields(history secrets)->80 |

### XSS class (ONE category; the composition damper collapses reflected+stored to breadth)

Verified: all three XSS probes CONFIRM BY EXECUTION in a browser (`xss_injectable` reflected+stored,
`stored_xss_api` JSON-API sink, `dom_xss` DOM sink); the no-browser path falls back to a hardened
unescaped-reflection heuristic. So execution is the FIRE gate, not an escalator, and the severity
split is the CONTEXT the probe reports: reflected (needs a victim to click) vs stored (runs for every
viewer). xss-001 covers BOTH contexts; xss-002 is the stored JSON-API sink; domxss-001 is DOM.

| Sub | Probe IDs | CVSS | VRT | Range | Default | Escalators |
|---|---|---|---|---|---|---|
| Reflected / DOM | xss-001 (reflected path), domxss-001 | 6.1 | P3 | 40-61 | 40 (heuristic-only fallback) | execution_confirmed->61 |

**Note (SSTI / upload):** Bugcrowd rates *basic* SSTI P4 and *basic* upload P5, escalating to P1 only on proven
RCE. Our probes fire ONLY on a proven-execution oracle (salt-hash for SSTI, webshell-executed for upload), so
they never fire on the basic variant, which is why their class default is 90 (terminal), not the VRT-basic
floor. `upload-002` is the stored-XSS-via-upload probe and belongs to the XSS class, not here.

**Note (debug-001):** migrated as the `debug-mode` class (range 40-98), not the chore floor: a framework debug
UI is a base 40 info-leak, escalating to 98 (`execution_confirmed`) when it is a live Werkzeug interactive
console (an RCE surface). The Tier-4 "verbose error / banner" row is headers-006 only.
| Stored | xss-002, xss-001 (stored path) | 8.0 | P2 | 55-85 | 55 | execution_confirmed->70, cross_user_read (hits other viewers)->85 |

### Tier 3: medium (VRT P2-P3 / CVSS 5-6.9)

| Class | Probe IDs | CVSS | VRT | Range | Default | Escalators |
|---|---|---|---|---|---|---|
| CSRF | csrf-001 | 4-8 | P2 | 35-65 | 35 | write_confirmed->55, sensitive_fields->65 |
| CORS misconfig | cors-001 | 5.3-7.5 | n/a* | 30-70 | 30 | cross_user_read->50, sensitive_fields->70 |
| Host header inj | hosthdr-001 | 5-7 | n/a* | 30-60 | 30 | write_confirmed(cache/reset)->60 |
| Response splitting | split-001 | 6.0 | n/a* | 30-61 | 30 | execution_confirmed->61 |
| Session fixation | session-fixation | 5-6.5 | P3 | 30-55 | 30 | cross_user_read->55 |
| DoS (decompression bomb) | dos-001 | ~7.5 avail | P4 | 12-30 | 12 | probe never OOMs by design; missing size-cap = fire |

### Tier 4: chore floor (VRT P4-P5): fixed low, weight = OWASP-A02 breadth, no escalators

| Class | Probe IDs | CVSS | VRT | Penalty (fixed) |
|---|---|---|---|---|
| Open redirect | redirect-001 | 6.1 | P4 | 25 (->40 external_host, ->55 auth flow) |
| Missing rate limit | ratelimit-001 | 7.5 | P4 | 30 (throttle confirmed absent at fire; treated like the rest) |
| Backend schema disclosure | backend-003 (group backend-anon-exposure w/ 001) | ~5 | P5 | 12 (subsumed by backend-001 when data also readable) |
| Security headers | headers-001..006, csp-001 | n/a | P5 | keep current spread: CSP 8, nosniff 3, HSTS 5, clickjack 5, referrer 2, x-powered-by 2 |
| Mixed content | mixed-001 | 4-6 | P5 | 10 |
| Sourcemap disclosure | exposure-006 | ~4 | P4 | 15 |
| Verbose error / banner | debug-001, headers-006 | ~5 | P5 | 8 |
| Internal-host recon | exposure-009 | ~3 | P5 | 4 |
| Session cookie flags | session-001..004 | 4-6.5 | P5-ish | httponly 15 / samesite 12 / secure 12 [calib, repriced down from 20/15/15] |

\* Not in the Bugcrowd VRT, AND HackerOne has no per-class priority taxonomy to substitute (it
classifies by CWE and scores by CVSS, so it adds no independent web-app severity): CORS, path
traversal, host-header, splitting, filter-inj stay **CVSS-only anchored**. Hold conservative;
optionally sample HackerOne DISCLOSED REPORTS for a real-world CVSS distribution per class (manual
sampling, not a taxonomy).

## 6. Special case: `deps-001` (the one CVE-shaped probe)

Vulnerable/outdated component (OWASP A03 Software Supply Chain). This is the ONE probe where the
finding actually is a CVE, so **EPSS + CVSS of the detected component set the point**, not a fixed
range. `penalty = round(component_CVSS × 10)`, optionally lifted if the CVE is KEV-listed. EPSS/KEV
are population-correct here and nowhere else.

## 7. CI enforcement: the anti-vibe gate

Extend `test_safety.py`'s partition-style assertion:

- Every `bundle: security` probe MUST have a `severity` block with a non-empty `cvss` and `vrt`
  (or `cvss: "n/a"` + `tier: chore-floor` for a declared chore).
- Every `escalator.point` MUST fall within `[range.lo, range.hi]`.
- `default` MUST equal `range.lo` unless a comment justifies otherwise.

A naked `penalty: 40` with no authorities then fails CI and cannot merge. That is the structural
difference between freq × sev as a *promise* and freq × sev as a *gate*.

## 8. Migration

1. Add `Severity`/`Escalator` to schema.py; add the resolver to `_run_probe`.
2. Write the `severity` blocks into the ~50 security YAMLs (about 20 classes).
3. Upgrade the impact-observing predicates to set the evidence flags (deploy-001 is the prototype;
   XSS-execution / backend-sensitive-fields / secrets-live already set theirs).
4. Add the CI gate (section 7).
5. **Fresh corpus re-grade + re-freeze** (a full rescale changes the curve). Confirm the [calib]
   rung points and that the distribution de-compresses (higher range, lower modal pile-up) so the
   percentile discriminates: the statistical goal, achieved from true findings, not reintroduced FPs.

## 9. Why this design (three reasons, one mechanism)

- **Correctness:** SQLi (90-98) must outweigh a missing header (2-8). The flat 40 made RCE = a slow app.
- **Fairness:** an IDOR that read the table (85) must outweigh one that read a row (55). Evidence, not class.
- **Statistics:** fixed points create modes; evidence-driven ranges dissolve them, spreading scores so
  the frozen curve can rank. The v20 FP fixes compressed the distribution; ranges re-widen it *from truth*.

The evidence ladder serves all three at once, and it reuses the operative-confirmation pattern the
v20 hardening already shipped.
