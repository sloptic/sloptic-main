# Handoff: the builder's seat, for sloptic.org

Bring one idea from the corpus report onto the site: **slop is how an app looks from the seats its team
never sits in.** Written 2026-09-25 from the sloptic-main session. The source is `CORPUS_REPORT.md`, Section 5,
first paragraph. Voice rules are unchanged from `WEB_HANDOFF_2.0.md`: assertive, no em dashes, no hyphenated
words in public copy, no "genuinely", and none of the AI tells the report was cleaned of (no "not X, it's Y"
contrasts, no summary sentence that repeats the one before it).

## Why the site needs it

The most common reaction to a grade is surprise: "it loads instantly for us" or "the text is perfectly
readable." Both are true from the team's seat, and the grade explains a different seat. Without that
explanation, a bad performance or accessibility score reads as a bug in Sloptic. With it, the score reads as
news about their users.

## The rationale

Nearly every major failure Sloptic finds is invisible from where the team works:

| failure | invisible because | what Sloptic does instead |
|---|---|---|
| slow page | the team builds and demos on a fast laptop over good wifi | Lighthouse loads the app as a mid range phone on slow 4G would |
| low contrast text | the team has good eyesight and a bright screen | axe checks every text node against the WCAG contrast ratio |
| unlabeled button or field | the team never hears the page read by a screen reader | axe checks that every control has an accessible name |
| crash on malformed input | nobody on the team types garbage into their own form | probes send malformed input and expect a clean rejection, not a server error |
| button that does nothing | the demo only clicks the buttons that work | the browser clicks the app's controls (skipping destructive ones) and watches for any effect |
| missing security header, leaked key | the page works perfectly without the header, and with the key exposed | probes read the headers and the shipped bundle |

## Where it goes

1. **Results page, per axis.** The highest value placement. Put one line under the performance and
   accessibility subtotals, visible without a click, because that is where the surprise happens. Suggested
   copy:
   - Performance: "Measured as a mid range phone on slow 4G, not your laptop."
   - Accessibility: "Checked the way a low vision or screen reader user meets your app, not the way it looks
     to you."
2. **An explainer**, linked from those lines, for "Why is my score bad when my app is fast?" Two short
   paragraphs: the table above in prose, then the throttling numbers.
3. **Landing page.** One sentence can carry the pitch: "Sloptic shows you your app from the seats your team
   never sits in." Use it near the top, not as the headline, because the headline should still say what
   Sloptic does.

## Facts to use, with sources

Read numbers from the committed files instead of transcribing them where the file carries them.

| fact | value | source |
|---|---|---|
| Lighthouse network throttle | 150 ms round trip, 1.6 Mbps down | Lighthouse 13.4.1 `mobileSlow4G` (`@paulirish/trace_engine/.../simulation/Constants.js`) |
| Lighthouse CPU throttle | CPU work slowed 4 times | same constant, `cpuSlowdownMultiplier: 4` |
| emulated device | Moto G Power screen (412 by 823) | Lighthouse 13.4.1 `core/config/constants.js` |
| apps below 90 on Lighthouse | 62.8% | `validation/corpus-figures-active.json`, `fire_frequency`, `perf-lighthouse-001` |
| median Lighthouse score | 83 | `corpus-figures-active.json`, `lighthouse.overall.median` |
| apps with an accessibility finding | 65.5% | `corpus-figures-active.json`, `fire_frequency`, `qa-a11y-001` |
| contrast share of those | 80.5% | `docs/charts/fig11_a11y_rules.csv` (not in the figures JSON) |
| crash on malformed input | 8.7% of apps | `corpus-figures-active.json`, `fire_frequency`, `qa-crash-010` |
| button that does nothing | 13.6% of apps | `corpus-figures-active.json`, `fire_frequency`, `qa-deadctrl-001` |

## Accuracy guardrails

- **Lighthouse simulates the phone.** It does not run on one, and it does not actually slow the CPU. It
  measures on the grading box and scales CPU time by four. Say "measured as a mid range phone would load it,"
  never "tested on a real phone." (This is also why the curve carries a performance normalization.)
- **Contrast is not colorblindness.** axe's contrast rule measures lightness contrast, which mostly affects
  low vision users and anyone reading in glare. Do not claim Sloptic tests for colorblindness or simulates it.
- **Only the performance axis uses the phone profile.** The other axes are not measured "on slow 4G." Keep
  the phone framing to performance copy.
- **Explain, do not scold.** The team did nothing strange by testing on their own machine. The copy should
  read as "here is the seat you could not see from," not "you should have tested this."
