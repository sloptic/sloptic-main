# Handoff: Sloptic 3.0 for the sloptic-web session

What sloptic.org needs to change to run 3.0, the evidence visibility rule Ian set, and the findings worth
leading with. Written 2026-09-24 from the sloptic-main session that froze the 3.0 full curve. Voice rules are
unchanged from `WEB_HANDOFF_2.0.md` (assertive, no em dashes, no hyphenated words in public copy).

## The one line status

Sloptic **3.0.0** is a **new ruler**: full curve **2026.4** (final, 1,579 curve eligible apps from a 2,685 app
run) and passive curve **passive-2026.2** (frozen from its own passive battery run, in progress now). A 3.0
score does not compare to a 2.x one. Sequencing: the passive run finishes, `passive-2026.2` freezes, Ian pushes
the `v3.0.0` tag (the tag publishes to PyPI automatically), then the site pins it.

## What the site must change to consume 3.0

1. **Pin `sloptic==3.0.0`** once it is on PyPI.
2. **Vendor both new curve files.** The wheel does not ship `validation/`, so copy
   `validation/benchmark-curve.json` (2026.4) and `validation/benchmark-curve-passive.json` (passive-2026.2)
   from the `v3.0.0` tag. Ranking a 3.0 grade against a 2.x curve misranks every grade.
3. **Render four axes.** `axis_slop` now carries `accessibility` alongside `security`, `qa` and `performance`,
   and the four sum exactly to `slop_score`. Any UI that hardcodes three axes silently drops a real subtotal.
4. **Performance normalization.** The curve carries `perf_norm` (`k`, `bi_ref`, `bi_cap`). If the site ranks
   through `benchmark.rank()`, it is applied automatically. If the site ranks on its own, apply the formula in
   `docs/PERF_NORMALIZATION.md`, reading `observed_surface.lighthouse.benchmark_index` from the record.
   Without it, a solo grade on an idle worker ranks about 6.6 Lighthouse points too kind.
5. **Show the record's ruler, never a constant.** Every 3.0 record carries `ruler: {full, passive}`. A record
   without one predates the stamp and must read as unspecified, not as current. `reportcard.build_card`
   already does both.
6. **Report card.** Rendering through `reportcard.build_card` / `to_html` picks up the 3.0 improvements for
   free: the "what we saw" line states the finding, accessibility rules read in plain language with the element
   each violation occurred on, console errors are quoted, the perf audit is named. A custom renderer needs the
   new evidence fields (accessibility `rules` and `locations`, console `examples`).
7. **Re-vendor the corpus figures.** `validation/corpus-figures-active.json` is now `corpus-2026.4` (n=1,579).
   The passive figures refresh when the passive curve freezes. The findings page should read numbers from these
   files, never transcribe them.
8. **Keep the worker as is.** `MAX_CONCURRENT_GRADES=4` with `LIGHTHOUSE_SLOTS=3` matches how the curve was
   measured.

## Evidence visibility rule (Ian, 2026-09-24)

Some findings carry evidence that shows a reader where a flaw lives and how to reproduce it. **Show that
evidence only to a verified owner of the app. Everyone else sees the finding's title, category and
severity.**

- **Which findings:** the secrets family (`sec-secrets-*`), the managed backend family (`sec-backend-*`), and
  the exposure family (`sec-exposure-*`).
- **What is sensitive in them:** for secrets, the location (the asset path where the credential sits); raw
  secret values are never stored, only the kind of secret and its source, verified on the v26 corpus. For
  backend findings, the provider host, table, columns, and a replayable request. For exposure findings, which
  hidden file is served, and the request that fetches it.
- **Where it matters:** anonymous passive grades (the secrets probes run there) and full battery event grades
  whose cards other participants or the public can see. An owner viewing their own grade sees everything.
- **Division of labor:** the grader keeps evidence separable (`findings[].evidence`, including `repro`); the
  site does the gating.
- **Related decision:** the exposure fetchers and `sec-backend-*` stay active, so they never run on an
  anonymous URL submission. Detecting a served `.env` requires fetching a path nothing links to, which is
  reconnaissance against an app the requester may not own. Do not advertise them in the anonymous tier.

## Findings worth leading with (aggregate only, never name apps)

- **Almost nobody ships a content security policy.** 1,550 of 1,579 apps (98%) have none. Ten apps carry a
  complete set of security headers, and exactly one of those is also clean on every other axis: the corpus
  floor, a no account benefits screener that bottoms out the curve on merit.
- **Accessibility is now its own axis**, about 18% of all corpus slop, so the site can finally say "your app
  is inaccessible" separately from "your app is broken."
- **Winners still ship more slop**: median 52.5 against 47.5 for non winners (11% higher), and their
  Lighthouse scores run lower too (median 78 against 83). Polished demos ship more JavaScript.
- **Password recovery that never arrives.** Apps built on a managed auth provider's default mailer, which only
  delivers to the project's own team, lock every real user out of account recovery. Users care that the email
  never came, not why. That is a clean, relatable durability story.

## Operational notes

- **The grader goes down during corpus runs, on purpose**, so every run keeps the whole box at concurrency 4.
  The next window is the v4.0 measurement in November. A maintenance notice beats a silent outage.
- **3.x releases will not move the ruler.** Only 4.0 does (target early December, see `docs/V4_SPRINT.md`), so
  a 3.x pin needs no new curve files.

## Source of truth

- `RELEASE_NOTES.md`, the 3.0.0 section
- `validation/benchmark-curve.json`, `validation/benchmark-curve-passive.json`
- `validation/corpus-figures-active.json`, `validation/corpus-figures-passive.json`
- `docs/PERF_NORMALIZATION.md`, `sloptic/ruler.py`, `sloptic/reportcard.py`
- `docs/V4_SPRINT.md` for what is coming next
