# Proposal: BaaS RPC exposure

Status: proposal, not built. Written 2026-09-05 from a real finding in sloptic-web.

## What happened

sloptic.org shipped three `SECURITY DEFINER` Postgres functions. Postgres grants `EXECUTE` on a new
function to `PUBLIC` by default, and the migrations that created them only ever added the
`service_role` grant, so nobody wrote a revoke. `anon` inherits `PUBLIC`, `anon` is the role behind
the publishable key in the client bundle, and PostgREST mounts every public-schema function at
`/rest/v1/rpc/<name>`.

Verified against production, with the anon key alone:

    POST /rest/v1/rpc/bump_rate_limit   ->  200, "true"

One of the three, `expire_anonymous_reports(retain_days int)`, takes its retention window as a
caller-supplied argument and deletes rows. `{"retain_days": -1}` from anyone who viewed source would
have destroyed every unclaimed report on the service. Being `SECURITY DEFINER`, RLS did not apply.
Fixed in sloptic-web migration `0028`.

The point for the grader: this is chronic hygiene of exactly the kind Sloptic exists to price. It is
a default that is open, a grant nobody wrote, and it is invisible from the application. It is also
not rare. Any Supabase project that adds a function and remembers only the `service_role` grant has
it.

## Why the catalog misses it today

The BaaS machinery is already there, and it is close:

- `sloptic/baas.py` detects the mount (`looks_postgrest`) and lifts the anon key out of the bundle
  (`anon_key`)
- `sec-backend-003` reports the OpenAPI document at the mount root as schema disclosure
- `sec-backend-001` reports anon-READABLE tables, and the anon-write oracle reports anon-WRITABLE
  ones

All of that is about **tables**. Nothing in the catalog looks at **functions**: `grep -rn rpc
catalog/ sloptic/` finds only two route-shape regexes in `discovery.py` and `probes.py` that
classify a URL, never a probe that reads or calls an RPC.

The enumeration is free. The same OpenAPI document `sec-backend-003` already fetches lists the
exposed functions alongside the tables, under `/rpc/` paths. We are already reading the answer and
throwing that half of it away, which is the same shape as the note in `sec-backend-003` about the
schema disclosure having been used as a tool and never surfaced as a finding.

## The hard part: passive or active

This is the whole design question, and it should be settled before any code.

**Enumeration is passive.** Reading the OpenAPI document the app already serves to any visitor
changes no state and fetches nothing hidden. It qualifies under the passive definition as written,
and it is already being fetched.

**Invocation is not.** Calling an unknown function is a state-changing action against someone else's
database, and the whole reason this finding matters is that some of those functions delete rows. A
probe that establishes exposure by invoking is a probe that can destroy the data it is grading. That
is worse than the bug.

So the split should be:

- **Passive finding**: the anon key can enumerate N callable functions at the RPC mount. This is an
  information leak in the same family as `sec-backend-003`, priced as chore-floor, and it should
  probably join the `backend-anon-exposure` variant group rather than double-count with it.
- **Active finding**: a function is confirmed callable by an unauthenticated caller. This requires
  invocation, so it belongs behind the same ownership verification as every other active probe.

Even in the active tier, invocation needs a rule, because "authorized to test" is not "authorized to
wipe". The safest confirmation is one that never runs the function body:

1. Call with a deliberately wrong argument shape. PostgREST answers `404 PGRST202` (no matching
   function) for an unknown signature and `401`/`42501` for permission denied BEFORE it evaluates
   arguments. The distinction between "permission denied" and "function exists but your arguments
   are wrong" is the whole signal, and neither answer executes anything.
2. Never call a function with a plausible-looking argument set. Never retry with corrected arguments
   to "confirm".

That gives a confirmed finding without a single function body running. If that turns out not to hold
across PostgREST versions, the correct outcome is to ship the passive enumeration finding only, not
to start invoking.

## What it cannot see, and should not pretend to

`prosecdef` is not visible from outside. A black-box probe cannot distinguish:

- a `SECURITY DEFINER` policy function accidentally left open (the real bug), from
- a `SECURITY INVOKER` function deliberately exposed to `anon` and correctly bounded by RLS (a
  normal, supported Supabase pattern)

So the finding must be written as exposure, not as vulnerability: "these functions are callable
without authentication" and not "these functions are exploitable". Name heuristics (`delete`,
`expire`, `purge`, `forget`, `reset`, `admin`) are tempting for severity weighting and should be
resisted, or kept strictly to `reason` text: an app with a function called `delete_my_account` that
is correctly scoped would be scored for someone else's naming.

The honest framing is the one the corpus report already uses for chronic slop. This is a default
left open, priced as hygiene, not as an exploit.

## Sketch

- `sec-backend-00X`, bundle `security`, category `backend-exposure`
- `applicability.requires`: a detected PostgREST mount plus a recovered anon key, the same
  precondition `sec-backend-001` uses
- passive predicate: `backend_rpc_enumerable`, evidence = the function names listed to the anon key
  and how many
- active predicate: `backend_rpc_callable_anonymously`, evidence = per function, the status and
  SQLSTATE that distinguished permission-denied from signature-mismatch
- variant group with `backend-anon-exposure`, so a project whose tables are already wide open does
  not get scored three times for one misconfiguration

## Also worth a look while in here

Same root cause, different surface: `ALTER DEFAULT PRIVILEGES` is the durable fix, and its absence
is what lets this recur. Not black-box observable, so it is a documentation point for whatever
guidance Sloptic eventually gives a project rather than a probe.
