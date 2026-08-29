# The Shape of AI Era Web App Slop

### A black box quality audit of 1,625 live hackathon web apps

**Reference release:** `2026.3` (provisional) · **Instrument:** Sloptic (a deductions only black box grader) · **Population:** live hackathon submissions

---

## TL;DR

- On a corpus of **1,625** live web apps graded from the outside, AI era "slop" is overwhelmingly **chronic**, not **acute**: pervasive missing hygiene, not exploitable holes.
- **98%** ship no Content-Security-Policy, **90%+** miss the other core headers, **67%** have a critical accessibility violation, and **71%** fall below the Lighthouse performance bar. Only **2.9%** expose any exploitable finding, and essentially none an injection or remote code execution class.
- The acute danger did not vanish, it **moved into the managed backend, and the instrument now reaches it**. The single largest exploitable class is a world readable or writable Supabase or Firebase backend (**18 apps, 1.1%**), several carrying plaintext passwords or bulk PII.
- **The AI builder signal changed shape.** The Lovable performance premium of the prior run is no longer statistically significant (**p = 0.056**). What stands out now is that AI built apps, Lovable and Bolt together, leak their managed backend at **13%** (11 of 82), more than ten times the population rate. The risk relocated from heavy bundles to misconfigured backends.
- **Winners ship more slop, not less.** Contest winners carry a median **54.9** against **49.1** for non winners, a 12% premium, so human judged quality does not predict durability.
- The median app realizes under **4%** of its achievable slop (a median score of 50 against a damped worst case of 1,244). Per app, slop is the rare exception, and the app defends nearly everything it exposes.

---

## 1. The question

AI assisted building makes shipping a web app nearly free, and the volume of "looks done" submissions has exploded. The security research is blunt about the tradeoff. Veracode's 2025 report, testing over 100 models on 80 tasks, found that **45%** of AI generated code introduces an OWASP Top 10 vulnerability and that AI written code carries **2.74 times** more flaws than human written code, a pass rate that had not budged by early 2026. The Cloud Security Alliance put the share of AI generated solutions carrying a design flaw or known vulnerability at **62%**. Hackathons feel this directly: when any team can generate a polished UI in minutes, judges report the bar for "impressive" moving from "does it look done" to "does it hold up." So a natural question for anyone grading these apps at scale:

> When you look at a large population of real, deployed, AI era web apps from the outside, **what does the failure actually look like?** A field of exploitable vulnerabilities, or something else?

This report answers that from one instrument's black box view of 1,625 apps.

## 2. The dataset

| property | value |
|---|---|
| Apps attempted | 2,685 |
| Apps successfully graded | **1,625** |
| Attrition | 1,060 dead URLs, pages that are not web apps, WAF withheld grades, and submissions that never came up |
| Each row | one deployed app, graded over HTTP and a headless browser, with no source and no spec |
| Grader version | a frozen catalog of **102 probes** across 3 axes, curve `2026.3` |

Rows that could not be graded, a URL that never answered or a repo that never deployed, are excluded rather than scored, so the population is "apps that presented a working surface." Of the 1,060 that did not grade, dead URLs are the bulk (757); the rest are apps that timed out, were withheld behind a bot challenge, or were not web apps.

### 2.1 Where the apps came from

The corpus is drawn from **80 hackathons** on Devpost, whose public project galleries were scraped for submissions that shipped a live URL. The events span North America (the majority, largely US and Canadian university hackathons), Europe (London, Barcelona, Ireland), Latin America (Monterrey), and Asia Pacific (Singapore, Malaysia, Australia), concentrated in 2025 and 2026, with one 2023 edition included as a pre AI era anchor. From these galleries, 2,685 submissions carried a gradeable URL and 1,625 graded. The full list of 80 events is in Appendix A.

This provenance matters for reading the results. The population is young, collegiate, built against a deadline of a day or a weekend, and built in the AI era, so it is a clean look at what teams ship when speed is everything and the tooling writes much of the code. It is deliberately **not** a sample of production software.

## 3. Method

Sloptic is a **black box** grader. It reads no source, needs no spec, and emits one **slop score**: deductions only, unbounded, lower is better, `0` means nothing was found. The score decomposes into three axes (security, quality, performance) whose subtotals sum exactly to the total. Penalties are risk priced (frequency times severity) and damped, so one root cause counts once.

Because it ignores the stack, the same 102 probes run identically against every app, which is what makes 1,625 unrelated apps **comparable on one axis**. Every grade also ships a coverage report, so a `0` that means "clean" is distinguishable from a `0` that means "we could not reach the surface." The median app had **57%** of the battery apply to it.

Two things this method is honest about up front: it grades the **unauthenticated, observable** surface, and it measures failures that are **independent of intent** only (defects no matter what the app is for).

## 4. Results

### 4.1 The score distribution

| statistic | value |
|---|---|
| mean | 58.5 |
| median | 50.0 |
| max | 239.1 |
| distinct score values | 849 of 1,625 (52% unique) |
| landmarks (p10 / p25 / p50 / p75 / p90 / p95 / p99) | 17.6 / 29.6 / 50.0 / 77.4 / 108.2 / 130.4 / 179.9 |

The overall score is **smooth and right skewed**: a dense cluster of lightly taxed apps, then a long thin tail of the broken. Continuous scoring on the performance and contrast axes spreads the scores further, so 52% of apps land on a distinct value and the largest single spike (64 apps on 13.7, the pure header floor) holds under 4% of the population. This is exactly the property a ranking needs: apps spread out, so a percentile is meaningful.

### 4.2 What drives the score

Penalty mass splits across the three axes like this:

| axis | share of total slop | median | shape |
|---|---:|---:|---|
| quality | **41%** | 20.0 | broad spread, driven by accessibility, dead controls, crashes |
| security | 32% | 13.7 | the header floor dominates: p50 and p75 are both 13.7 |
| performance | 28% | 13.7 | continuous now, so only **29%** score zero (a Lighthouse green) |

Note the shift from the prior run, where security led at 42% and performance was mostly zeros. Continuous performance scoring and the new quality probes (dead controls, crash resistance) moved quality to the top and gave performance a real median.

The probes that fire most often are not exotic. They are missing HTTP headers, then performance, then accessibility:

| prevalence | probe |
|---:|---|
| 98% | missing Content-Security-Policy |
| 97% | no clickjacking defense |
| 90% | missing `X-Content-Type-Options` |
| 90% | missing `Referrer-Policy` |
| 84% | a Core Web Vitals audit below its pass bar |
| 71% | overall Lighthouse performance below the bar |
| 67% | a critical accessibility violation |

A finding at 98% prevalence is nearly a constant: it taxes everyone and separates no one. The **discriminating** signal lives in the middle band, the accessibility tiers, the Core Web Vitals spread, dead controls (13%), and the rare acute classes, which is where apps actually pull apart.

### 4.3 Severity composition: chronic, not acute

This is the headline, and it survives the new run. Split every security finding into **acute** (exploitable now) versus **chronic** (missing mitigation), and the population is lopsided:

| tier | rate | examples |
|---|---:|---|
| any acute finding | **2.9%** | 47 of 1,625 |
| injection or remote code execution | **~0.1%** | 1 blind command injection and 1 stored XSS, both flagged for isolated confirmation |
| **managed backend exposure** | **1.1%** | 18 apps: a world readable or writable Supabase or Firebase table, several with plaintext passwords or emails |
| secret or source file leak | 1.3% | served `.env`, `.git`, or a secret shipped in the bundle |
| access control or data exposure | 0.4% | a protected resource reachable without credentials |
| chronic hygiene (representative) | 67 to 98% | headers, performance, accessibility |

Read the two ends together: **~3% of apps carry an exploitable finding, essentially none an injection hole, while 67 to 98% are missing basic hygiene.** The functionality is mostly there; the nonfunctional floor is pervasively absent. That is the empirical signature of AI era slop from the outside, chronic rot rather than a field of smoking guns.

But the composition of the thin acute slice changed, and this is the new finding. In the prior run the largest acute class was a served secret file, and the exploitable danger was described as having relocated behind authentication where a black box grader could not reach it. This run reaches part of it. The **largest acute class is now managed backend exposure** (18 apps), a Supabase or Firebase backend left readable, or writable, to an anonymous client because row level security was never turned on. The grader confirms these by reading a real row or completing a real anonymous insert: one Firestore `users` collection returned documents carrying a `password` field, a Supabase `profiles` table leaked `email` and `phone`, and a `candidates` table accepted an anonymous insert. The acute danger did not disappear and it did not stay fully hidden. Part of it moved into the managed backend, in plain sight of a probe that knows to ask.

### 4.4 Why the acute surface is still thin

The low acute rate is not "these apps are safe." It is an artifact of **where the modern stack puts the danger.** Of the graded apps, **1,106 exposed observed runtime traffic** we could classify by host tier. An app's traffic routinely spans several tiers at once (a same origin API and a managed backend and a consumed vendor), so the tiers OVERLAP: each row below counts how many of the 1,106 have any host of that tier, not a slice of a pie. They must not be read as shares of a whole.

| host tier | apps with this tier (of 1,106 classified, overlapping) | injectable black box? |
|---|---:|---|
| same origin (static frontend) | 670 (61%) | no backend to inject |
| consumed vendor | 222 (20%) | not the app's surface |
| own backend (attributed) | 203 (18%) | yes |
| opaque, unattributable off origin | 190 (17%) | not probed, flagged, no clean bill credit |
| managed backend (Supabase or Firebase) | 173 (16%) | only through its row level security config |

You cannot inject SQL into a static site, and a managed backend app's only misconfiguration knob is row level security. So the classic injection classes have almost no surface to land on, and the genuine acute risk that remains is disproportionately **backend misconfiguration**, which is exactly where a black box probe can still reach it, and which section 4.3 shows it now does.

By hosting platform, identified from response headers and origin suffix (off score), the population is dominated by Vercel:

| platform | apps (of 1,782 classified) |
|---|---:|
| Vercel | 1,114 (63%) |
| unknown or custom (unattributable) | 140 (8%) |
| Netlify | 115 (6%) |
| GitHub Pages | 96 (5%) |
| Streamlit | 82 (5%) |
| Lovable | 73 (4%) |
| Render | 57 (3%) |
| other (Firebase, Cloud Run, Cloudflare, base44, Railway, ...) | 105 (6%) |

A further 259 apps sit behind a Cloudflare edge and 94 behind Fastly, and a fronting CDN can mask the origin platform, which is why 8% stay unattributable rather than guessed. A population this heavy on Vercel also shapes the mechanics: two thirds of the corpus lives on one platform whose frontend hosting has no server side surface to inject, which is a large part of why the injectable own backend tier is only 18%.

### 4.5 The AI builder signal, changed

Because the platform fingerprint also identifies the **builder** from served markup (Lovable ships `cdn.gpteng.co`, Bolt its own signature), we can test the question the AI slop thesis rests on: do AI built apps carry more slop than hand deployed ones? The answer moved between runs, and where it moved is the interesting part.

| group | n | median slop | security (mean) | quality (mean) | performance (mean) |
|---|---:|---:|---:|---:|---:|
| hand built (no builder signature) | 1,543 | 49.7 | 18.1 | 23.4 | 16.3 |
| Lovable | 71 | 52.6 | 23.0 | 28.9 | 19.0 |
| Bolt | 11 | 68.9 | 41.5 | 44.0 | 6.3 |

Two things stand out, and both differ from the prior run.

First, **the Lovable performance premium is no longer statistically significant.** In the earlier corpus Lovable's median was 72 against 49 hand built, an all performance gap at p = 1.1e-5. Here the gap is 52.6 against 49.7, and a one sided Mann-Whitney test puts it at **p = 0.056**, just outside significance. Hand built apps got a little sloppier too, mostly on the newly continuous performance axis, which closed the gap.

Second, **where AI built apps do stand out now is security, not performance.** Lovable's security mean rose above hand built (23.0 against 18.1) and Bolt's is far higher (41.5), the opposite of the earlier "entirely performance, security marginally lower" reading. The mechanism is concrete: **managed backend exposure fires on 11 of the 82 Lovable and Bolt apps, 13%**, against roughly 1% across the population. The AI builder default of wiring a Supabase or Firebase backend and shipping without configuring row level security is now the dominant AI builder risk, and the new probe makes it visible.

Three bounds on the claim, stated. Bolt's n = 11 is too small to read on its own, though the backend exposure rate pools it with Lovable. Detection is a floor: an AI built app on a custom domain with its signature stripped falls into the hand built bucket, which can only understate the gap. And by host, Streamlit remains a clean auto generation counterexample: it is a frontend only stack with almost no attackable surface, so it scores low despite also being machine generated.

### 4.6 Winners are not cleaner

The corpus carries each app's contest result, which lets us ask whether the apps humans judged best are also the ones that hold up. They are not.

| group | n | median slop | Lighthouse green |
|---|---:|---:|---:|
| winners | 253 | **54.9** | 24.8% |
| non winners | 1,372 | 49.1 | 29.4% |

Winners ship a **12% higher** median slop and are slightly worse on performance, and the gap holds across two independent measures. This is the clean empirical statement of Sloptic's reason to exist: contest judging rewards the idea, the demo, and the execution, and none of those predict whether the deployed thing holds up. The most plausible mechanism is ambition, a winning app tends to attempt more, which exposes more surface to grade, and the extra surface is where the slop lands. Durability and merit are orthogonal, so an objective durability read adds a signal the human judging does not carry.

### 4.7 Measurement validity

A ranking is only trustworthy if the ruler is stable, and this ruler is deterministic by construction. No model sits in the score: the perception and coverage LLM only proposes targets, and a deterministic probe alone decides every fire, at temperature 0 with a cached plan. The two seasoned engines are pinned (axe-core 4.10.2 for accessibility, Lighthouse 13.4.1 for performance), so a repeat run over the same catalog moves only on the probes where black box nondeterminism is unavoidable: stateful browser behavior, Core Web Vitals timing, and the security tail behind authentication. Prior repeat runs on earlier corpora correlated at 0.97 or higher with no systematic drift; the 2026.3 catalog adds probes, not nondeterminism.

A hand audit of this run's fired findings looked for false positives beyond the automated classes. The result is a small and non systematic surface: zero of the automatically recognized false positive classes survived, the backend exposure driver is clean (18 of 18 confirmed by a real read or write with concrete evidence), and the residual is a handful of scope errors at the margin (one Next.js middleware check firing on a Cloudflare path, a cross site request check that confirms acceptance but not a state change). None of it touches the high volume penalty mass or the acute findings.

## 5. Interpretation

One number captures the thesis. The median app's **worst case slop**, the damped score it would carry if every applicable probe fired, is **1,244**, while its actual median score is **50**. The median app therefore realizes under **4%** of its potential failure surface: it defends nearly everything it exposes, and fails on the diffuse hygiene it never thought about.

So the story of this corpus is not "AI writes insecure code that gets exploited." From the black box, it is "AI writes **functional** code that ships without the boring, universal, nonfunctional floor," no headers, slow bundles, broken accessibility, sometimes a dead button or a localhost backend left pointing at the developer's machine. The acute danger is real but rare, and the slice that remains has partly surfaced in the managed backend, which is a finding about the modern stack, where the danger now lives in a configuration toggle, as much as about the apps.

## 6. Limitations, stated not hidden

- **Unauthenticated surface only.** Defects behind a login the grader cannot establish are undercounted. The true acute rate is a floor.
- **Recall is not audited, and precision is vouched, not blanket.** This provisional release guarantees **stability** (the ruler repeats) and **precision on the classes that carry explicit rules or a confirmed read or write**, most visibly the backend exposure findings. Findings elsewhere are **unaudited, not endorsed**. That unaudited mass is dominated by deterministic presence checks (a header is absent, a control is dead, a bundle references a dead chunk) where false positive risk is structurally low, but the audit cannot distinguish "no rule needed" from "no rule written," so we report it as unaudited rather than claim a precision we have not checked.
- **The injection surface is dark, and that is reach, not absence.** The SQLi, SSTI, and file upload classes fired essentially zero times, but on a corpus that is two thirds static frontends there is almost no server side surface for them to land on. A low fire rate for a class can mean "rare" or "unreachable from the outside," and only a corpus with more server native apps would tell them apart.
- **Independent of intent.** Sloptic grades the universal floor, not whether a feature is good. Originality, product quality, and creativity are out of scope by design.
- **Population, not universe.** Hackathon submissions skew toward young, small apps that are heavy on the frontend. The distribution should not be read as representative of production software at large.

## 7. Reproduce

```sh
# freeze the reference distribution from a corpus run
uv run python scripts/benchmark.py build <run>.jsonl --version 2026.3

# place any single app on that curve
uv run python -m sloptic.cli --target https://your-app.example.com --out app.jsonl
uv run python scripts/benchmark.py rank --results app.jsonl
```

## Sources

Background figures on AI generated code are external; the corpus figures are this instrument's own measurements over the 2026.3 population.

- [Veracode 2025 GenAI Code Security Report](https://www.veracode.com/resources/analyst-reports/2025-genai-code-security-report/) (45% of AI generated code introduces an OWASP Top 10 flaw; 2.74x more vulnerabilities than human written code)
- [Veracode, Spring 2026 GenAI Code Security update](https://www.veracode.com/blog/spring-2026-genai-code-security/) (the 45% pass rate had not improved through early 2026)
- [Cloud Security Alliance, AI generated code vulnerability research](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-codegen-vulnerability-debt-20260406-csa/) (62% carry a design flaw or known vulnerability)

## Appendix A: the 80 hackathons

Devpost event slugs, as ingested:

```
hack-brown-2026        ds-x                   bigred-hacks-2025      luddyhacks
innovation-hacks-2     hackgt-12              hacktech-by-caltech-2026  mhacks-2025
hacknyu-2025           vthacks-13             jumbohack-2025         devfest-2026
hack-mit-2023          ai-hackathon-2026      hacktx2025             jumbohack-2026
hackrice-15            hackprinceton-fall-2025  hackdartmouth-xi     hackbeanpot2025
la-hacks-2026          la-hacks-2025          treehacks-2026         bostonhacks-2025
hackharvard-2025       hackduke-code-for-good-2026  hackillinois-2026  hackcwru-012025
beaverhacks            boilermake-xii         terrahacks-2025        hackpsu-spring-2026
uwb-hacks-the-future   civic-hacks-2026       hackumass-xiii         uofthacks-13
deltahacks-12          hack-western-12        nwhacks-2026           hackku26
newhacks-2025          hacknc-2025            hacklondon-2026        hackupc-2026
kenthackit             emory-hacks-2025-fall  interhackbcn           steminate-hacks-2026
hackeurope             hack4her-mty           hackmty2025            hacknroll2026
uncommon-hacks-2026    swamphacks-xi          hack-arizona-2026      wildhacks-2026
nus-fintech-summit-2026  unihack2026          usaii-global-ai-hackathon-2026  hack-ireland-2025
oregonhacks            cs-girlies-wellness-hackathon  imaginehack2026  devleague-2026
vibehack-london-2026   civic-hacks            hack-brooklyn-2026     stem-connect-fall2025
byte-hacks             sb-hacks-xii           diamondhacks-2026      hacklahoma-2026
biggest-little-hackathon-2026  ellehacks-2026  hackrpi-2025          vibe-coder-hackathon
codecrunch-305hackathon-fall25  henhacks-2026  hack-for-humanity-26  hack-for-humanity-2026
```

*All figures are aggregate over the 2026.3 population. No per app identities are stored or reported.*
