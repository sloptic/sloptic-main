# Handoff: Sloptic 2.0 for the sloptic-web session

Context to bring sloptic.org up to the 2.0 identity, the current findings, and Ian's voice. Written from the sloptic-main session that just shipped the 2.0 docs. Read this, then read the three source of truth files listed at the bottom.

## The one line status

Sloptic is now **2.0.0** on a **new ruler, curve 2026.3** (provisional). Versions 1.x rode the 2026.1 curve; 2.0 changed what the number measures (new probe families, continuous scoring, a weakest link tiebreak), so a 2.0 score does not compare to a 1.x one. The live site is a pre 2.0 artifact and undersells the tool.

## What the site should sell (and currently does not)

The current site is accurate but stale and under pitched. The two most defensible ideas are missing from it, and they are the pitch:

1. **Intent independence, the fairness invariant.** Sloptic grades only universal durability traits every app should get right, never the app's purpose, taste, or merit. That is why one number is comparable across wildly different apps, and it is the reason the score is fair. Sell this first. Humans carry intent; the score is intent independent.
2. **The honesty apparatus.** Precision first, N/A says why, no model in the score number, a coverage report so a clean 0 is distinguishable from an unreachable surface, and a catastrophe gate that never lets a percentile launder a leaked key. For a credential, the guardrails against a false accusation are the product.

## The findings to lead with

- **Broken far more often than hackable, and it reads at three levels.** Sorting each app by its single worst finding: 26% are acute (a crash, a dead deploy, an unusable page, an open backend), 59% carry at least one significant finding (21 or more on the slop scale, past the cosmetic floor), and every app carries the hygiene floor (headers, mid accessibility, orange performance). Only about 3% are exploitable. The angle to sell: almost nothing in the significant band has an excuse in a day-plus hackathon with an AI, since a dead control, a broken link, or a slow page is a couple of prompts to fix and ships only because the demo never exercised it. Performance is no exception, a 5 to 10 second load has already lost the user whatever the team intended.
- **The star finding: managed backend exposure.** The single largest exploitable class is a world readable or writable Supabase or Firebase backend, 18 apps, several leaking plaintext passwords or emails, because row level security was never turned on. This is the visceral, demo transcending example. Lead security with it, and skip SQL injection, which never fires on this corpus.
- **The demo versus reality gap.** AI made the polished demo free and severed it from a sound build. Sloptic reads the substrate the demo no longer vouches for.
- **Winners ship more slop.** Contest winners carry a 12% higher median slop than non winners, so human judged quality does not predict durability. That is the clean argument for an objective durability signal alongside human judging.
- **Performance defers to Lighthouse.** The perf axis is measured by a pinned local Lighthouse instead of hand written timing probes, because a hand rolled probe cannot match years of calibration and its false positives would poison a score meant to be trusted.

## Two claims on the current site to correct

- **"Grades any live web app"** overstates coverage. It attempts any URL and grades the ones it can reach; about 40% of a historical corpus is dead or unreachable, though a fresh app graded at judging time is far higher. Say "attempts any app, grades the ones it can reach."
- **"0 means no issues"** misleads, because a universal hygiene floor (security headers and the like) means almost no live app reaches 0. Explain the floor instead of implying 0 is common.

Also: never present a catastrophe app (a leaked backend, a served secret) as certifiable or as a good band. The gate overrides the rank. Lead such an app with "Not certified, disqualifying flaw: X", never with a pristine chip.

## Numbers

Rounded on the site, exact in CORPUS_REPORT.md: **1,600+** apps graded, **80** hackathons, **100+** probes, roughly **3%** with an exploitable finding, about **two thirds** on Vercel. The full study with exact figures is CORPUS_REPORT.md.

## Prose and voice rules (apply hardest to public copy)

- **Be assertive.** Lead with the claim, cut the hedging.
- **No em dashes.** Commas, colons, parentheses, periods, or reword.
- **No hyphenated words.** Reword the compound: "web app" not "web-app", "black box" not "black-box", "world readable" not "world-readable". Code identifiers and literal header names are exempt.
- **Avoid "genuinely"** and filler or hedge words generally.
- **Prefer relative clauses over stacking modifier adjectives.** "a grader that measures how well an app holds up" over "a black box HTTP resilience grader".

## Source of truth (read these next)

- `~/Documents/sloptic-main/README.md`: the current identity, the niche, what it grades, the score model.
- `~/Documents/sloptic-main/CORPUS_REPORT.md`: the full data study with exact figures, the findings above with their numbers.
- `~/Documents/sloptic-main/RELEASE_NOTES.md`: the 2.0.0 changes and the frozen curve details.

The site copy should match the substance of these three, in the voice above.
