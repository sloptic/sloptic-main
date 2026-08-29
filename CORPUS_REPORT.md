# The Shape of AI Era Web App Slop

### A black box quality audit of 1,625 live hackathon web apps

**Reference release:** `2026.3` (provisional) · **Instrument:** Sloptic, a deductions only black box grader · **Population:** live hackathon submissions · **Run:** 2,685 apps attempted, 1,625 graded, 38 hours of wall clock

---

## TL;DR

We pointed one black box grader at every submission we could find from 80 hackathons and asked a single question: from the outside, what does AI era failure actually look like? Here is what we found.

- Slop is overwhelmingly **chronic, not acute**. On 1,625 live apps, the failure is the missing floor (no security headers, slow heavy pages, broken accessibility, a button that does nothing), not exploitable holes. Only **2.9%** carry an exploitable finding, and essentially none an injection or remote code execution class.
- The acute danger that remains **moved into the managed backend, and this run finally reached it.** The single largest exploitable class is a world readable or writable Supabase or Firebase backend, **18 apps**, several of them serving plaintext passwords or bulk emails to any anonymous visitor.
- **The AI builder story flipped.** A year ago Lovable's slop premium was entirely performance. Here it is no longer statistically significant on the score, and what stands out instead is that AI built apps leak their managed backend at **13%** (11 of 82), more than ten times the population rate.
- **Winners are not cleaner.** The apps the judges picked carry **12% more** median slop than the ones they passed over, so human judged merit does not predict whether the thing holds up.
- **The dangerous surface is thin because it is unreachable, not because it is safe.** Only **14%** of apps have a drivable signup we can get behind, only **18%** run an own backend we could inject, and a Vercel bot challenge blocked the deep security tail on **404** apps. The low acute number is a floor.
- The median app realizes about **2.3%** of the slop it could carry if every applicable probe fired. Per app, slop is the exception. It is the diffuse universal floor, spread across the whole population, that adds up.

---

## 1. The question we started with

AI assisted building made shipping a web app nearly free, and the galleries filled up with submissions that look finished. The security research is loud about what that costs. Veracode's 2025 report, over 100 models on 80 tasks, found **45%** of AI generated code introduces an OWASP Top 10 flaw and that AI written code carries **2.74 times** more vulnerabilities than human written code, a number that had not budged by early 2026. The Cloud Security Alliance put the share of AI generated solutions carrying a design flaw or a known vulnerability at **62%**.

Those numbers all come from reading source. We wanted the other view, the one an outsider gets:

> When you look at a large population of real, deployed, AI era web apps from the street, with no source and no spec, **what does the failure actually look like?** A field of exploitable vulnerabilities, or something else?

This is our answer from one instrument's black box view of 1,625 apps.

## 2. The dataset, and how it narrowed

We scraped the public project galleries of **80 hackathons** on Devpost for submissions that shipped a live URL, then graded every URL that answered. The funnel is worth seeing, because the attrition is itself a finding.

| stage | count |
|---|---:|
| submissions with a gradeable URL | 2,685 |
| **graded successfully** | **1,625** |
| dead URL (link rot, 4xx, 5xx) | 757 |
| timed out or ran away, killed | 113 |
| bot challenge withheld the grade | 90 |
| not a web app, or other | 100 |

Read the top of that table against the bottom. Nearly **40%** of everything ever submitted is already gone: expired domains, spun down free tiers, plain link rot. Half a year after a hackathon, a large share of what teams proudly shipped does not resolve. That is a durability fact of its own, though it also means the graded population is a survivor set. The apps here are the ones that stayed up.

The events span North America (the majority, largely US and Canadian university hackathons), Europe (London, Barcelona, Ireland), Latin America (Monterrey), and Asia Pacific (Singapore, Malaysia, Australia), concentrated in 2025 and 2026, with one 2023 edition kept as a pre AI era anchor. The population is young, collegiate, built against a one or two day deadline, and built in the AI era. It is a clean look at what teams ship when speed is everything and the tooling writes much of the code, and it is deliberately not a sample of production software. The 80 events are listed in Appendix A.

## 3. How the grade works, in one breath

Sloptic is a **black box** grader. It reads no source, needs no spec, and returns one **slop score**: deductions only, unbounded, lower is better, `0` means nothing was found. The score splits into three axes (security, quality, performance) whose subtotals sum exactly to the total. Penalties are risk priced (frequency times severity) and damped, so one root cause counts once no matter how many ways we detect it. Because it ignores the stack, the same **102 probes** run identically against every app, which is what makes 1,625 unrelated apps comparable on one number. And every grade ships a coverage report, so a `0` that means "clean" is never confused with a `0` that means "we could not reach the surface." It grades the unauthenticated observable surface, and it grades only failures that are independent of intent, defects no matter what the app is for.

## 4. First look at the number

The first thing we wanted to know is whether the score even behaves like a ruler.

| statistic | value |
|---|---|
| mean | 58.5 |
| median | 50.0 |
| max | 239.1 |
| distinct score values | 849 of 1,625 (52% unique) |
| landmarks (p10 / p25 / p50 / p75 / p90 / p95 / p99) | 17.6 / 29.6 / 50.0 / 77.4 / 108.2 / 130.4 / 179.9 |

It does. The distribution is smooth and right skewed, a dense cluster of lightly taxed apps and a long thin tail of the badly broken. Continuous scoring on the performance and contrast axes spreads it out further, so more than half the apps land on a value no other app shares, and the biggest single pileup, 64 apps sitting on exactly 13.7, is under 4% of the population. That 13.7 is the pure header floor, the score an app carries when the only thing wrong with it is the headers it never set. It is the closest thing this corpus has to a "clean" app, and 64 of them found it.

## 5. What the number is made of

Take the score apart and the shape of the slop appears. Here is where the penalty mass actually lives.

| axis | share of total slop | median | what it looks like |
|---|---:|---:|---|
| quality | **41%** | 20.0 | a broad spread, driven by accessibility, dead controls, and crashes |
| security | 32% | 13.7 | the header floor dominates: the median and the 75th percentile are both 13.7 |
| performance | 28% | 13.7 | continuous now, so only 29% of apps score a clean zero |

That is already a shift from the prior run, where security led at 42% and performance was mostly zeros. Continuous performance scoring and a batch of new quality probes moved quality to the top.

Drill into the single categories and the concentration is stark: **performance 28%, security headers 23%, accessibility 18%**. Three categories are two thirds of all the slop in the corpus. And the probes that fire most often are not exotic at all.

| fires on | probe |
|---:|---|
| 98% | missing Content-Security-Policy |
| 97% | no clickjacking defense |
| 90% | missing `X-Content-Type-Options` |
| 90% | missing `Referrer-Policy` |
| 84% | a Core Web Vitals audit below its bar |
| 71% | the overall Lighthouse score below its bar |
| 67% | a critical accessibility violation |

A finding at 98% is nearly a constant. It taxes everyone and separates no one. The signal that actually ranks apps lives in the middle, the accessibility tiers, the spread of Core Web Vitals, dead controls at 13%, and the rare severe classes below. That middle band is where two apps at "looks done" pull apart.

## 6. Chronic, not acute (the headline)

Now the question we came for. Split every security finding into **acute**, exploitable right now, versus **chronic**, a missing mitigation, and the population is lopsided.

| tier | rate | what it is |
|---|---:|---|
| any acute finding | **2.9%** | 47 of 1,625 apps |
| injection or remote code execution | **~0.1%** | one blind command injection, one stored XSS, both flagged for a rerun in isolation |
| **managed backend exposure** | **1.1%** | 18 apps: a Supabase or Firebase table readable or writable by anyone, several leaking passwords or emails |
| a served secret or source file | 1.3% | a shipped `.env`, a served `.git`, a key baked into the bundle |
| access control or data exposure | 0.4% | a protected resource reachable with no credentials |
| chronic hygiene, representative | 67 to 98% | headers, performance, accessibility |

Read the two ends together and the picture is unmistakable. About **3%** of apps are exploitable, essentially none through an injection hole, while **67 to 98%** are missing basic hygiene. The functionality is mostly there. The boring nonfunctional floor is pervasively absent. That is the empirical signature of AI era slop from the outside: chronic rot, not a field of smoking guns.

But the small acute slice changed shape, and this is the finding that surprised us most. A year ago the largest acute class was a served secret file, and we described the exploitable danger as hidden behind authentication where a black box grader could not reach it. This run reaches part of it. The **largest acute class is now managed backend exposure**, a Supabase or Firebase backend left open to an anonymous client because row level security was never switched on. And we do not guess at these. The probe confirms each one by reading a real row or completing a real anonymous insert. One Firestore `users` collection handed back documents carrying a `password` field. A Supabase `profiles` table leaked `email` and `phone`. A `candidates` table accepted an anonymous insert. The acute danger did not vanish and it did not stay fully hidden. Part of it walked into plain sight, in a database that ships open by default, in front of a probe that knows to ask.

## 7. Why the dangerous surface is so thin

Here is the part that keeps the 3% honest: the acute rate is low because the danger is mostly **unreachable from the street**, not because these apps are safe. Three separate measurements say the same thing.

**First, most apps have no backend to attack.** Of the 1,106 apps whose runtime traffic we could classify, the tiers overlap (one app talks to several at once), so these are memberships, not slices of a pie:

| host tier | apps carrying it (of 1,106) | reachable from the street? |
|---|---:|---|
| same origin static frontend | 670 (61%) | no backend to inject |
| a consumed vendor | 222 (20%) | not the app's surface |
| an own backend | 203 (18%) | yes |
| opaque, unattributable | 190 (17%) | not probed, flagged, no clean bill |
| a managed backend | 173 (16%) | only through its config |

You cannot inject SQL into a static site, and a managed backend's only misconfiguration knob is its access rules. Only **18%** of these apps run an own backend we could reach, so the injection classes have almost nowhere to land.

**Second, we cannot get behind the login.** The authed surface, where the real logic lives, needs an account, and most apps do not give us a drivable one.

| auth shape | share of 1,625 |
|---|---:|
| no auth at all | 56% |
| a drivable password signup | **14%** |
| signup present but not drivable (SSO, SDK, wizard) | 14% |
| SSO only, no signup to drive | 7% |
| a login wall with no signup | 9% |

Only **14%** of apps let us self register and reach the data plane, and of those 233, just **14 carried an authed surface finding** (broken email verification, a weak password reset, a stored XSS). The authenticated half of every app is a surface we mostly cannot open.

**Third, a bot challenge blocked the deep probes on hundreds of apps.** Two thirds of the corpus lives on Vercel, and Vercel's edge threw a challenge at **29% of the whole run** (**66% of the Vercel apps**). Most of those, 690, challenged only after all the probes had run, so the grade is valid. But 90 were withheld outright, and on **404 apps the security axis was left not clean tested**, the challenge tripped exactly on the heavy security probes (`sec-hosthdr`, `sec-cmdi`, `sec-dos`, `sec-upload`). So even where a backend exists, the WAF often stands between us and it.

Put those three together and the message is not "these apps are secure." It is "the modern stack has hidden the dangerous surface behind a static frontend, a login, and a WAF." The 3% acute rate is a floor, and it is a finding about the modern stack as much as about the apps.

## 8. The AI builder question

The whole AI slop thesis rests on one testable claim: are AI built apps sloppier than hand deployed ones? Because the grader fingerprints the builder from served markup (Lovable ships `cdn.gpteng.co`, Bolt its own signature), we can check.

| group | n | median slop | security (mean) | quality (mean) | performance (mean) |
|---|---:|---:|---:|---:|---:|
| hand built | 1,543 | 49.7 | 18.1 | 23.4 | 16.3 |
| Lovable | 71 | 52.6 | 23.0 | 28.9 | 19.0 |
| Bolt | 11 | 68.9 | 41.5 | 44.0 | 6.3 |

Two things jump out, and both differ from last year.

First, **the Lovable performance premium is gone from the score.** In the prior corpus Lovable ran a median of 72 against 49, an all performance gap at p = 1.1e-5. Here it is 52.6 against 49.7, and a one sided Mann-Whitney test lands at **p = 0.056**, just outside significance. Hand built apps got a little sloppier too, mostly on the newly continuous performance axis, and the gap closed.

Second, **where AI built apps stand out now is security, not performance.** Lovable's security mean rose above hand built, Bolt's is far above, and the mechanism is concrete: **managed backend exposure fires on 11 of the 82 Lovable and Bolt apps, 13%**, against roughly 1% across the population. The AI builder habit of wiring a Supabase or Firebase backend and shipping without configuring its access rules is the dominant AI builder risk now, and the new probe is what made it visible. The story moved from heavy bundles to open databases.

## 9. Do the winners hold up?

The corpus carries each app's contest result, which let us ask a question we could not resist: are the apps the judges loved also the ones that hold up?

| group | n | median slop | Lighthouse green |
|---|---:|---:|---:|
| winners | 253 | **54.9** | 24.8% |
| non winners | 1,372 | 49.1 | 29.4% |

They are not. Winners ship a **12% higher** median slop and perform slightly worse, and the gap holds on both measures. The likeliest reason is ambition: a winning app tends to attempt more, and more surface is more room for slop to land. Whatever the cause, the point stands. Judging rewards the idea, the demo, and the execution, and none of those predict durability. This one number is the cleanest case for the whole instrument: an objective durability read carries a signal the human judging does not.

## 10. Under the hood of the two heavy axes

Accessibility and performance are 46% of all the slop, so we opened both up.

**Accessibility is, in practice, a contrast test.** Of the 1,087 apps with an accessibility finding, look what actually fires:

| rule | share of the 1,087 |
|---|---:|
| color contrast | **80%** |
| button name (an unlabeled icon button) | 14% |
| missing viewport meta | 8% |
| a form control with no label | 6% |
| everything else | 3 to 5% each |

Four times out of five, an accessibility finding is text you cannot read against its background. That is not a coincidence. Contrast is the one accessibility failure that no framework can prevent (you pick the colors), that the trendy muted palettes AI reaches for actively cause, and that is checked against every text node on the page. The rest, the missing lang, the empty title, the unlabeled input, barely fire, because every modern scaffold already gets them right. Automation solved the accessibility checklist and left the design judgment, which is exactly where the failures now concentrate.

**Performance is a story of fast servers and heavy fronts.** Pull the Lighthouse metrics apart and the two halves separate cleanly:

| metric | median | tail |
|---|---:|---|
| TTFB (server response) | **20 ms** | fast, most apps sit on a CDN edge |
| CLS (layout stability) | **0.00** | stable, frameworks reserve layout by default |
| LCP (largest paint) | 4.0 s | slow, main content takes four seconds |
| TBT (main thread blocking) | 370 ms | median fine, but the mean is 7.4 seconds and the max is **168 seconds** |

The server is not the problem. Layout is not the problem. The problem is the shipped bundle: a median page weighs **4.0 MB** (one weighs 124 MB), some ship over 2,000 requests, and a handful lock the main thread for minutes. TTFB and CLS the platform and the framework hand you for free. LCP, TBT, and page weight are the parts the builder controls, and they are the parts that are heavy. Performance slop is a bundle discipline problem wearing an infrastructure costume.

## 11. What never fired, and the reach frontier

A grader is as interesting for what it cannot say as for what it can. Four probes never reached a target on any of the 1,625 apps (the two IDOR record probes, one race condition probe), and the entire injection cluster, SQLi, SSTI, file upload, fired essentially zero times. We resisted reading that as "these apps are safe from injection." On a corpus that is two thirds static frontends behind a WAF, the injection probes have almost no reachable surface, and the request volume tells you they tried hard for it: the injection and upload probes are the highest fan out in the battery (one XXE probe sent 864 requests to a single app). A low fire rate for a class here means "unreachable," not "rare," and only a corpus with more server native apps would separate the two.

## 12. A few apps that broke the mold

The anomaly list is where the fuzzer bugs and the truly broken apps hide, so we always read it by hand. Exactly one app scored a clean `0` (a thin landing page with no real surface, not a perfect app, so the 0% clean floor essentially holds). At the other end, the worst 40 apps are a catalog of the acute tail: `theoceanguard.tech` at 239 (a leaked backend plus a crash plus broken accessibility), a run of Lovable and Bolt apps carrying backend exposure at 98, and a cluster of apps failing `availability` at 85 (a page that would not stay up under load). The tail is not random. It is the same few severe classes, stacked.

## 13. Is the ruler trustworthy?

We put the ruler through three honesty checks, because a comparable number is worthless if it drifts or lies.

**Stability.** The score is deterministic by construction. No model sits in the number: the perception LLM only proposes targets, and a deterministic probe alone decides every fire, at temperature 0 with a cached plan. The two seasoned engines are pinned (axe-core 4.10.2, Lighthouse 13.4.1, the latter taken as a median of three runs to tame its timing swing). Repeat runs of the prior engine correlated at 0.97 or higher with no drift, and 2.0 adds probes, not nondeterminism.

**Coverage.** The average app ran **53 of the 102 probes**, a median of 57% of the battery. That is the honest bound on comparability, and it is why every grade ships the number: an app graded on 57% of the battery is legible as "tested on most of what applied," not "clean."

**Parity, and a refusal.** We asked the tool for a cross stack false negative comparison, contrasting SPA against server rendered apps. It refused, and correctly: every app in this corpus arrived as a bare URL with no source, so it is a single stack with nothing to contrast, and the lens says "cannot assess" rather than inventing a clean bill. A tool that tells you when it cannot measure something is worth more than one that always answers.

**Precision.** The automated precision audit recognizes a fixed list of false positive classes and is blunt that it is not a true precision number. Of the 14,561 scored fires, **zero of the known false positive classes survived**, but only 40 are positively vouched and **62% carry no precision rule at all**, dominated by the deterministic presence checks (a header is absent, a control is dead) where false positive risk is structurally low. Eleven fires are flagged as real findings on the wrong owner's page (a rate limit or a bundle secret on a shared catch all host), which dissolve when a team submits its own URL. We also audited the fired findings by hand: the backend exposure driver is clean, **18 of 18** confirmed by a real read or write, and the residual is a handful of scope errors at the margin (one middleware bypass check firing on a Cloudflare path). None of it touches the high volume penalty mass or the acute findings. The audit cannot tell "no rule needed" from "no rule written," and we can, so we report the unaudited mass as unaudited rather than claim a precision we have not measured.

## 14. What it all means

One number holds the thesis. The median app's **worst case slop**, the score it would carry if every applicable probe fired, is around **1,954**, while its actual median score is **50**. The median app realizes about **2.3%** of its potential failure surface. It defends nearly everything it exposes, and it fails on the diffuse hygiene it never thought about.

So the story of this corpus is not "AI writes insecure code that gets exploited." From the outside it is "AI writes **functional** code that ships without the boring universal floor," no headers, heavy bundles, unreadable text, a dead button, sometimes a localhost backend still pointing at the developer's laptop. The acute danger is real but rare, and the slice that remains has partly surfaced in the managed backend, where the danger now lives in a configuration toggle. The apps did not get more dangerous. The danger moved somewhere a grader can, for once, walk right up to it.

## 15. Limitations, stated not hidden

- **Unauthenticated surface only.** A defect behind a login we cannot establish is undercounted. The acute rate is a floor, and Section 7 shows how large a floor.
- **The injection surface is dark, and that is reach, not absence.** Two thirds static frontends behind a WAF is not a place injection can land, so a zero fire rate there proves nothing about the code.
- **Recall is not audited, and precision is vouched, not blanket.** This provisional release guarantees stability and precision on the classes with explicit rules or a confirmed read or write. Everything else is unaudited, not endorsed.
- **Independent of intent.** Sloptic grades the universal floor, not whether a feature is good. Originality and product quality are out of scope by design.
- **Population, not universe.** These are young, small, frontend heavy hackathon apps. Do not read the distribution as production software.

## 16. Reproduce

```sh
# freeze the reference distribution from a corpus run
uv run python scripts/benchmark.py build <run>.jsonl --version 2026.3

# place any single app on that curve
uv run python -m sloptic.cli --target https://your-app.example.com --out app.jsonl
uv run python scripts/benchmark.py rank --results app.jsonl

# read the full picture yourself
uv run python scripts/stats.py <run>.jsonl              # the default report
uv run python scripts/stats.py <run>.jsonl --parity     # cross stack visibility
uv run python scripts/stats.py <run>.jsonl --precision  # the false positive audit
```

## Sources

Background figures on AI generated code are external; every corpus figure is this instrument's own measurement over the 2026.3 population.

- [Veracode 2025 GenAI Code Security Report](https://www.veracode.com/resources/analyst-reports/2025-genai-code-security-report/) (45% of AI generated code introduces an OWASP Top 10 flaw; 2.74x the vulnerabilities of human written code)
- [Veracode, Spring 2026 GenAI Code Security update](https://www.veracode.com/blog/spring-2026-genai-code-security/) (the 45% pass rate had not improved through early 2026)
- [Cloud Security Alliance, AI generated code vulnerability research](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-codegen-vulnerability-debt-20260406-csa/) (62% carry a design flaw or a known vulnerability)

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

*Every figure is aggregate over the 2026.3 population. No per app identities are stored or reported.*
