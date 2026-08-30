# Where Every Penalty Comes From

### How Sloptic prices a finding, and the authority behind each number

Sloptic's score is a sum of penalties, one per finding, and the whole grade is only as trustworthy as those numbers. So none of them is hand placed. Every penalty derives from a named authority, and the exact point inside its range is set by what the probe actually observed, not by taste. This document is the ledger: what each number is, where it came from, and why it sits where it does.

The short version is one sentence. Security penalties come from CVSS magnitude reconciled with the Bugcrowd Vulnerability Rating Taxonomy, quality and performance penalties come from ISO/IEC 25010 crossed with Nielsen severity, and in both cases the probe charges the floor of its class unless it proves worse impact, at which point evidence lifts the number toward the ceiling.

---

## 1. The scale: one catastrophe is 100

Every penalty is a percentage of a single total catastrophe.

- The anchor is **100**, a CVSS 10.0 event scaled by ten: an unauthenticated remote code execution with full confidentiality, integrity, and availability loss and a scope change. Nothing a single probe can find exceeds it.
- So `penalty = severity × 10`. A finding priced at 40 is 40% of a catastrophe, a missing referrer policy at 2 is 2% of one.
- The **ceiling is per probe, not per app**. The aggregate stays unbounded and deductions only, so an app carrying three catastrophes loses roughly 250 after damping. The reverted 0 to 100 total score did not come back.
- Performance caps structurally at **90**, because a fully slow app is close to a catastrophe for the user but is not a compromise. Slowness ranks just under owned, which is correct.

## 2. Which authority sets which number

The authorities do not get summed together. Each one governs a different layer of the pipeline, and only one of them emits the per probe integer.

| layer | authority | what it produces |
|---|---|---|
| coverage, which probes exist | OWASP Top 10 2025 and CWE Top 25 | the probe set |
| **severity, the penalty** | **CVSS magnitude, cross checked against Bugcrowd VRT** | **the range** |
| frequency and exploitation | inside the CVSS exploitability metrics, plus EPSS and CISA KEV for `deps-001` alone | not a separate multiplier |
| aggregate, one app's fires | the dampers (variant group max, per category decay) | the sum |
| population, the ranking | the frozen reference curve | the percentile |

Only the severity layer sets the number this document is about. Coverage decides what to look for, the dampers decide how repeated findings combine, and the curve decides where an app lands against its peers, all elsewhere.

## 3. Default low, evidence lifts

Each security class carries a **range**, its CVSS band reconciled with its VRT band, and a **default** equal to the floor of that range. The probe abstains to the floor and charges more only when it observes worse impact. It sets evidence flags as it runs, and a resolver picks the highest matching rung, clamped to the range. When CVSS and VRT disagree, the range widens rather than forcing a manual call. The rule is the same everywhere: charge the floor, let proof lift it.

These are the flags a probe can set, each tied to a concrete observation.

| flag | the observation that sets it |
|---|---|
| `unauthenticated` | the finding needed no login |
| `cross_user_read` | read another user's record |
| `cross_user_write` | changed another user's record |
| `sensitive_fields` | the exposed data held PII, secrets, or tokens |
| `bulk_read` | many records were reachable, not one |
| `data_extracted` | an injection returned real database rows, not just an oracle |
| `write_confirmed` | an injection or mutation changed server state |
| `execution_confirmed` | the payload actually executed |
| `internal_reached` | a forged request reached an internal or metadata host |
| `validated_live` | a discovered secret authenticated against its provider |
| `high_privilege` | the secret or access was admin, service role, or private key tier |

A probe that fires but proves nothing beyond presence earns the default. That is deliberate: unproven impact is not charged at the high end. It is also what makes the score fair across apps rather than across classes. An access control failure that read a whole table is priced at 85, one that read a single row at 55, and the difference is the evidence, not the label.

## 4. The security ladder, class by class

Every security class below names its CVSS 3.1 vector score and its Bugcrowd VRT baseline. Range bounds are pinned from those authorities; the rung points inside a range are calibrated against the corpus. Where a class is not in the VRT, it is anchored on CVSS alone and held conservative, which is marked.

### Terminal classes (VRT P1, CVSS 9 to 9.8)

| class | probes | CVSS | VRT | penalty (range, default) | evidence lifts to |
|---|---|---:|---|---|---|
| SQL injection | `sqli-001..005` | 9.8 | P1 | 90 to 98, default 90 | rows extracted 95, write confirmed 98 |
| OS command injection (RCE) | `cmdi-001` | 9.8 | P1 | 90 to 98, default 90 | execution confirmed 98 |
| Template injection (SSTI) | `ssti-001` | 9.8 | P1 | 90 to 98, default 90 | execution confirmed 98 |
| Upload to RCE | `upload-001` | 9.0 | P1 | 90 to 98, default 90 | execution confirmed 98 |
| Auth gate bypass | `authbypass-001` | 9.1 | P1 | 88 to 98, default 90 | a protected route reachable with no credentials |
| Disclosed secret or served credentials | `secrets-001/002`, `exposure-001/004/005/007` | 7.5 to 9.8 | P1 | 70 to 98, default 70 | live against provider 92, admin or private key 98 |
| Anonymous whole database read | `backend-001`, `exposure-008` | 7.5 to 9 | P1 | 70 to 98, default 70 | PII fields 80, bulk records 90, anon write 98 |
| XML external entity | `xxe-001` | 7.5 | P1 | 70 to 91, default 70 | reached internal host 82, read a system file 91 |

These map to the OWASP Top 10 2025: A05 Injection (the four execution classes), A01 Broken Access Control (auth bypass, anonymous read), and A04 Cryptographic Failures (disclosed secrets and served credentials). The injection and upload probes fire only on a proven execution oracle, a salt hash the engine must return or a webshell that must run, so they never trip on the basic variant the VRT would rate a P4 or P5, which is why their floor is terminal rather than low.

### High, evidence critical

| class | probes | CVSS | VRT | penalty (range, default) | evidence lifts to |
|---|---|---:|---|---|---|
| IDOR and broken access control | `idor-001..005`, `backend-002` | 6.5 to 8.1 | P1 | 30 to 85, default 30 | read another's record 55, sensitive fields 68, whole collection 78, wrote another's record 85 |
| Server side request forgery | `ssrf-001` | 7.5 | P2 | 40 to 91, default 40 | server made the request 70, reached cloud metadata 91 |
| Path traversal and LFI | `lfi-001` | 7.5 | CVSS only | 50 to 85, default 50 | read a system file 75, read source or secrets 85 |
| PostgREST filter injection | `filterinj-001` | 8.2 | CVSS only (CWE-943) | 75 | fixed, just under SQL injection |
| Cross site scripting | `xss-001/002`, `domxss-001` | 6.1 reflected to 8.0 stored | P3 to P2 | 40 to 85, default 40 | executed in a browser 61, stored for every viewer 85 |
| Framework debug console | `debug-001` | 5.3 to 9.8 | P4 | 40 to 98, default 40 | a live Werkzeug console (RCE surface) 98 |

The XSS probes confirm by executing in a real browser, so execution is the fire gate and the range reflects context: reflected needs a victim to click, stored runs for everyone. Path traversal and filter injection are not in the VRT, so they rest on CVSS alone and are held toward the low end of their band.

### Medium

| class | probes | CVSS | VRT | penalty |
|---|---|---:|---|---|
| CSRF | `csrf-001` | 6.5 | P2 | 45 |
| CORS misconfiguration | `cors-001` | 6.1 | CVSS only | 45 |
| HTTP response splitting | `split-001` | 6.1 | CVSS only | 45 |
| Host header injection | `hosthdr-001` | 6.1 | CVSS only | 40 |
| Session fixation | `session-fixation` | 5 to 6.5 | P3 | 30 to 55, default 30 |
| Open redirect | `redirect-001` | 6.1 | P4 | 25 to 55, default 25 (external host 40, auth flow 55) |
| Cleartext HTTP | `tls-001` | 5.9 | P4 | 30 (CWE-319) |
| Missing rate limit | `ratelimit-001` | 5.3 | P4 | 30 (CWE-770 and CWE-799) |
| Decompression bomb DoS | `dos-001` | 7.5 availability | P4 | 12 to 30 |

## 5. The security header floor, and why it is cheap

Security headers are real hygiene, but each one is a single config change and none of them bites on its own, so the VRT rates the class P5. They sit under OWASP A02 Security Misconfiguration, the second most common risk in the 2025 list yet a purchasable one, and the penalties stay low on purpose.

| header | probe | penalty |
|---|---|---:|
| Content Security Policy missing | `sec-headers-002` | 8 |
| Content Security Policy present but toothless | `sec-csp-001` | 5 |
| HSTS missing | `sec-headers-003` | 5 |
| Clickjacking protection missing | `sec-headers-004` | 5 |
| Nosniff missing | `sec-headers-001` | 3 |
| Referrer policy missing | `sec-headers-005` | 2 |
| Server banner leaked | `sec-headers-006` | 2 |

The CSP penalty leads the group because it is the backstop for the whole XSS class, and the toothless variant is priced below the missing one, since a policy that exists gives a false sense of safety. These numbers were also trimmed deliberately. A corpus audit found the header block firing on roughly 90% of apps and, being one erasable config change, dominating the score, so the header tax was cut from 22% of total slop to 18%. Session cookie flags sit in the same tier, HttpOnly at 15, SameSite and Secure at 12 each, repriced down from 20 and 15 for the same reason.

## 6. Quality and performance: a different authority

Quality and performance failures are not vulnerabilities, so CVSS does not describe them. They are anchored instead on **ISO/IEC 25010**, the product quality standard, which names the characteristic each probe tests, and on **Nielsen's 0 to 4 severity scale** for how much the failure hurts a user, then calibrated against the corpus. The ceiling here is held below the security catastrophe floor of 40, so that a broken feature never outweighs a breach.

| class | probes | ISO 25010 characteristic | penalty |
|---|---|---|---:|
| Silent data loss on save | `integrity-001/002` | functional suitability | 69 |
| Crash on malformed input (5xx) | `crash-010` | reliability | 55 |
| Race condition under concurrency | `race-001/002` | reliability | 50 |
| Dead control | `deadctrl-001` | functional suitability | 30, primary CTA 50 |
| Broken deep link | `deeplink-001` | functional suitability | 15 |
| Dead back button | `backnav-001` | functional suitability | 12 |
| Accessibility barrier | `a11y-001/002` | usability (accessibility) | per rule sum, below |

Data integrity leads, because a save that silently loses or corrupts the user's data breaks the one promise the app made. A crash returns a 5xx where a graceful 4xx belonged, which the RFC treats as a server fault, so it is priced above the every user interface defects but below data loss.

Accessibility is not one number but a sum over distinct barriers, priced by axe-core's own impact rating: **critical 20, serious 12, moderate 7, minor 3**, stacking with decay so the category cannot swamp the score. These were repriced down from 30, 18, 10, and 4 after an audit found accessibility was 34% of all penalty, the single largest category, with one critical barrier costing 30 against a security ceiling of 40. At 20 a critical barrier is half the ceiling, which is the right relative weight. Only axe-core's deterministic WCAG 2 A and AA violations count, so the finding is intent independent: a missing label excludes a real user no matter what the app is for.

The signup and recovery flows use their own evidence ladders, since a broken account flow is a Nielsen 4 defect that locks a user out. A late confirmation email is charged 24, a confirmation that never arrives 36, no email at all within a minute 72, and a dead password reset climbs the same way to 60.

## 7. Performance is Lighthouse, priced by the shortfall

The performance axis defers to a pinned local Lighthouse, and it does so because the first version did not. Sloptic's early performance probes were hand written, and their false positive rates ran off the roof, since timing a page from the outside and inferring a verdict is the kind of judgment a lone tool gets wrong in a hundred ways. Rather than reinvent a wheel that Google has spent years calibrating and battle testing, Sloptic borrows the Lighthouse score outright. The penalty is the distance below Lighthouse's own green line:

```
penalty = round(max(0, 0.90 - lighthouse_score) × 100 × scale)
```

An app at or above the 0.90 green cutoff earns a clean zero, and that cutoff is deliberate. 90 is Lighthouse's own definition of good, the 8th percentile control point in its scoring, so the grade stops there on purpose. There is no slop above the good line, and chasing a perfect 100 is not the bar. An app at 0.84 loses 6, one at 0.25 loses 65. Lighthouse does the scoring off its own weighted metrics, and Sloptic charges only the shortfall below good, measured as the median of three runs so a single noisy load does not swing the grade. The structural cap at 90 keeps the worst possible slow app just below a full compromise.

## 8. The one CVE shaped probe: deps-001

A vulnerable client dependency is the single case where the finding actually is a CVE, so it is the single place EPSS and KEV belong. The penalty is `component_CVSS × 10`, taken from the NVD score of the worst matched component, optionally lifted when the CVE is on the CISA Known Exploited Vulnerabilities list. Everywhere else, exploitation likelihood already lives inside the CVSS exploitability metrics, so a population wide EPSS multiplier would double count it. Here it does not.

## 9. Pinned, calibrated, and the gate that keeps it honest

Every number carries one of two provenances. A **pinned** value comes straight from an authority: a CVSS canonical vector, a VRT baseline, an OWASP factor, a CWE. A **calibrated** value is a point proposed inside a pinned range and confirmed against a corpus regrade. Range bounds are almost all pinned; the rung points inside them are calibrated. The document never hides which is which, and neither does the catalog.

This is enforced, not promised. A continuous integration gate requires every security probe to carry a severity block with a real CVSS vector and a VRT rating, or to declare itself a chore floor. Every escalator point must fall inside its range, and the default must equal the floor unless a comment justifies otherwise. A naked `penalty: 40` with no authority behind it fails the build and cannot merge. That gate is the difference between frequency times severity as a slogan and frequency times severity as a rule.

## 10. Reading one number

Put it together on a real finding. A probe reports 90 on an app. The 90 says the finding is 90% of a total catastrophe. Tracing it back: the class is anonymous data exposure, pinned to CVSS 7.5 and VRT P1, with a range of 70 to 98 and a floor of 70. The probe did not stop at the floor, because it set `bulk_read`, having read many records from a world open database, which lifts the rung to 90. Had those records also carried a password column it would have set `sensitive_fields` too, and had the database also accepted an anonymous write it would have set `write_confirmed` and reached 98. Every step of that is either an authority or an observation. None of it is an opinion, which is the entire point.


## Sources

Every authority named above, so the numbers can be checked against the original.

- CVSS 3.1, the base severity scale: [first.org/cvss](https://www.first.org/cvss/)
- Bugcrowd Vulnerability Rating Taxonomy, the P1 to P5 baseline: [github.com/bugcrowd/vulnerability-rating-taxonomy](https://github.com/bugcrowd/vulnerability-rating-taxonomy)
- OWASP Top 10 2025, the coverage and category map: [owasp.org/Top10](https://owasp.org/Top10/)
- CWE, the weakness catalog: [cwe.mitre.org](https://cwe.mitre.org/), including [CWE-319 cleartext transmission](https://cwe.mitre.org/data/definitions/319.html), [CWE-770 resource allocation without limits](https://cwe.mitre.org/data/definitions/770.html), [CWE-799 interaction frequency](https://cwe.mitre.org/data/definitions/799.html), and [CWE-943 data query logic](https://cwe.mitre.org/data/definitions/943.html)
- ISO/IEC 25010, the software quality characteristics: [iso25000.com](https://iso25000.com/index.php/en/iso-25000-standards/iso-25010)
- Nielsen severity ratings, the 0 to 4 usability scale: [nngroup.com](https://www.nngroup.com/articles/how-to-rate-the-severity-of-usability-problems/)
- Lighthouse performance scoring, the green line and the metric weights: [developer.chrome.com](https://developer.chrome.com/docs/lighthouse/performance/performance-scoring)
- axe-core, the accessibility rule engine, against WCAG 2 A and AA: [github.com/dequelabs/axe-core](https://github.com/dequelabs/axe-core), [w3.org/TR/WCAG21](https://www.w3.org/TR/WCAG21/)
- EPSS and CISA KEV, exploitation likelihood for `deps-001`: [first.org/epss](https://www.first.org/epss/), [cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
