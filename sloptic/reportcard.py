"""Team-facing durability REPORT CARD: turn a grade record into per-finding feedback so a team that fails
the fuzzer knows exactly where and how to improve. Every finding renders four fields:

    1. EXPECTED     — what a durable app should have done
    2. ACTUAL       — what we actually observed (from the finding evidence)
    3. INDICATES    — what the failure is symptomatic of (the risk/weakness class)
    4. REMEDIATION  — how to fix it

Two DISCLOSURE tiers, driven by the probe's `pool` (schema.Probe.pool = public | hidden):
  - PUBLIC findings get the full four-field breakdown — teams learn and fix REAL durability, so teaching to
    these tests IS the goal (a real 429, real headers, real escaping = a genuinely more durable app).
  - HIDDEN findings (the hidden pool's anti-gaming set) are WITHHELD from the team card as an opaque count and
    revealed only in the organizer view (`organizer=True`). Teams can't teach-to-the-test on checks they
    can't see, so a team that only surface-patched the public checks still fails the hidden variants and its
    score reflects real durability, not gaming. Both tiers count toward the score identically — only the
    DISCLOSURE differs, never the math.

The authored copy below covers all 92 catalog probes; a future/unauthored probe still degrades gracefully
to its catalog `reason` plus a generic remediation pointer (never blank, never crashes)."""
from __future__ import annotations

import html
import pathlib

from .catalog import load_catalog

# (expected, indicates, remediation) keyed by probe_id. Kept terse + concrete — this is copy a team reads
# while fixing, not spec prose.
_CONTENT: dict[str, tuple[str, str, str]] = {
    # ---- security: headers -------------------------------------------------------------------------
    "sec-headers-001": ("Responses carry `X-Content-Type-Options: nosniff`.",
                        "Without it a browser may MIME-sniff a response and execute it as the wrong type — an XSS/content-confusion vector.",
                        "Send `X-Content-Type-Options: nosniff` on every response (one line in your server/CDN config)."),
    "sec-headers-002": ("A `Content-Security-Policy` restricts where scripts, styles, and frames may load from.",
                        "No CSP means zero defense-in-depth: if any XSS slips through, nothing contains it.",
                        "Add a CSP. Start strict — `default-src 'self'` — then loosen per real need; prefer nonces over `'unsafe-inline'`."),
    "sec-headers-003": ("HTTPS responses send `Strict-Transport-Security` (HSTS).",
                        "Without HSTS a network attacker can downgrade the connection to HTTP and strip TLS (SSL-strip MITM).",
                        "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS."),
    "sec-headers-004": ("A clickjacking defense is present (`X-Frame-Options` or CSP `frame-ancestors`).",
                        "The page can be embedded in a hostile `<iframe>` and used to trick users into clicking through your UI (clickjacking).",
                        "Send `X-Frame-Options: DENY` (or CSP `frame-ancestors 'none'`), relaxing only for frames you actually need."),
    "sec-headers-005": ("A `Referrer-Policy` limits what URL data leaks to third parties.",
                        "Full URLs — which can carry tokens, ids, or private paths — leak to external sites via the `Referer` header.",
                        "Send `Referrer-Policy: strict-origin-when-cross-origin` (or stricter)."),
    "sec-headers-006": ("The stack/version is not advertised in response headers.",
                        "`X-Powered-By` (or `Server` version) tells an attacker your exact framework and version, narrowing their exploit search.",
                        "Strip it — e.g. Express `app.disable('x-powered-by')`, or remove it at the proxy."),
    # ---- security: real vulns ----------------------------------------------------------------------
    "sec-ratelimit-001": ("Repeated failed logins get throttled (HTTP 429/423) after a few attempts.",
                          "No brute-force protection on auth — an attacker can credential-stuff or password-spray unlimited guesses.",
                          "Rate-limit auth endpoints (e.g. `express-rate-limit`); lock or slow down after N failures per IP + account."),
    "sec-csrf-001": ("State-changing requests require a CSRF token or a `SameSite` cookie.",
                     "Cross-site request forgery: a malicious page can make the victim's browser perform authenticated actions.",
                     "Set session cookies `SameSite=Lax` (or Strict) and require a CSRF token on every mutating request."),
    "sec-cors-001": ("CORS does not reflect an arbitrary `Origin` while allowing credentials.",
                     "Any website can read your authenticated API responses on a victim's behalf — an account-takeover class bug.",
                     "Allow-list specific origins; never combine a reflected `Origin` with `Access-Control-Allow-Credentials: true`."),
    "sec-xss-001": ("User input is escaped/encoded before it reaches the HTML.",
                    "Reflected XSS — attacker-controlled markup executes as script in the victim's session.",
                    "Rely on framework auto-escaping, encode output by context, and add a CSP as a backstop."),
    "sec-sqli-004": ("Query parameters are parameterized, not concatenated into SQL.",
                     "SQL injection — an attacker can read/modify/destroy the database or bypass auth.",
                     "Use parameterized queries or an ORM; never string-build SQL from user input."),
    "sec-lfi-001": ("Filename/path parameters cannot escape the intended directory.",
                    "Path traversal / local file inclusion — arbitrary server files (secrets, source, `/etc/passwd`) become readable.",
                    "Canonicalize and validate paths against an allow-list; never pass user input straight to a filesystem read."),
    "sec-exposure-001": ("Dotfiles like `.env` are not served.",
                         "A secrets file is publicly downloadable — API keys, DB credentials, and tokens are exposed.",
                         "Block dotfiles at the server/CDN and keep `.env` out of the deployed artifact. Rotate any exposed secret now."),
    "sec-exposure-002": ("The `.git` directory is not served.",
                         "`.git/config` is public — your full source repository (history, secrets in old commits) is reconstructable.",
                         "Don't deploy `.git`; block it at the web server."),
    "sec-exposure-003": ("The `.git` directory is not served.",
                         "`.git/HEAD` is public — your full source repository is downloadable and reconstructable.",
                         "Don't deploy `.git`; block it at the web server."),
    "sec-exposure-006": ("Production JS bundles do not ship their source maps.",
                         "A served `.map` lets anyone reconstruct your original source — logic, comments, and sometimes embedded secrets.",
                         "Disable source-map emission in the production build, or restrict `.map` access to internal tooling."),
    "sec-secrets-001": ("No private keys or cloud/API tokens appear in client-delivered content.",
                        "A live secret is public — it can be used to run up your bill, read your data, or impersonate your service.",
                        "Move the secret server-side behind a proxy, rotate it immediately, and load it from an env var."),
    "sec-secrets-002": ("No hardcoded server secret (Stripe `sk_`, OpenAI, AWS secret, GitHub PAT, private key) ships in the bundle.",
                        "A server-side secret is embedded in client code — anyone viewing source has full use of it.",
                        "Never put server secrets in the client; call the third party from your backend. Rotate the leaked key now."),
    "sec-hosthdr-001": ("The `Host` / `X-Forwarded-Host` header is not reflected into URLs or redirects.",
                        "Host-header injection — attacker-controlled hosts poison generated links (password-reset hijack, cache poisoning).",
                        "Validate `Host` against an allow-list of known domains; build absolute URLs from config, not the request header."),
    "sec-dos-001": ("Compressed request bodies are size-capped before decompression.",
                    "Zip-bomb DoS — a tiny gzip body inflates to gigabytes and exhausts server memory.",
                    "Cap the decompressed size and set a request-body limit; reject oversized payloads early."),
    "sec-backend-001": ("The managed backend (Supabase/Firebase) enforces row-level security.",
                        "The database is world-readable/writable through the public anon key — anyone can read or modify all rows.",
                        "Enable RLS / security rules and scope the anon key; never rely on client-side checks for authorization."),
    "sec-session-002": ("The session cookie sets a `SameSite` attribute.",
                        "Without `SameSite` the session cookie rides along on cross-site requests — a CSRF exposure.",
                        "Set `SameSite=Lax` (or Strict) plus `Secure` and `HttpOnly` on the session cookie."),
    "sec-session-005": ("The session token lives in an `HttpOnly` cookie, not `localStorage`.",
                        "A token in `localStorage` is readable by any XSS on the origin — one injection steals every session.",
                        "Store the session in an `HttpOnly`, `Secure` cookie so page scripts (and injected ones) can't read it."),
    "sec-cmdi-001": ("User input never reaches an OS shell; commands are not built from request data.",
                     "OS command injection. An attacker runs arbitrary shell commands on your server, a full compromise.",
                     "Never pass user input to a shell. Use library calls or exec with an argument array, never a string-built shell command; validate against a strict allow-list."),
    "sec-ssti-001": ("User input is rendered as data, never evaluated as a template expression or code.",
                     "Server-side template or code injection. Attacker input is executed as code, which is remote code execution.",
                     "Never render user input through the template engine or an eval sink. Pass it as template DATA (context variables), not as template source."),
    "sec-backend-002": ("Row-level security scopes every read to its owner; a logged-in user cannot read another user's rows.",
                        "Broken authenticated access control, the BaaS IDOR: any signed-in user reads everyone else's data.",
                        "Add per-user RLS policies or security rules (`auth.uid() = user_id`) on every table; never let the client filter by owner."),
    "sec-backend-003": ("The managed backend does not expose its schema (no table listing, no column names in errors).",
                        "Schema disclosure. The table and column layout leaks, handing an attacker the map for a targeted attack.",
                        "Disable introspection and table listing on the anon role, and return generic errors instead of raw database messages."),
    "sec-exposure-005": ("Response bodies never contain password or credential material.",
                         "Credential exposure. A password, token, or key is returned in a response, directly usable by anyone who sees it.",
                         "Never serialize secrets into a response. Strip credential fields from API output, and rotate anything that leaked."),
    "sec-exposure-008": ("A data route requires authorization; an anonymous request cannot pull bulk records.",
                         "Unauthenticated data exposure. An anonymous request returned bulk personal or financial records.",
                         "Require auth on every data route and scope results to the caller; never return a whole collection to an anonymous request."),
    "sec-deps-001": ("Client libraries are current and free of known CVEs.",
                     "A shipped dependency carries a public, known vulnerability, a supply-chain risk you inherited.",
                     "Upgrade the flagged library to a patched version, and wire a dependency audit (npm audit / retire.js) into CI."),
    "sec-session-001": ("The session cookie sets `HttpOnly`.",
                        "Without `HttpOnly` the session cookie is readable by any script, so a single XSS steals every session.",
                        "Set `HttpOnly` (plus `Secure` and `SameSite`) on the session cookie."),
    "sec-csp-001": ("The Content-Security-Policy actually constrains scripts (no `'unsafe-inline'`, no wildcard script source).",
                    "A present-but-toothless CSP (`'unsafe-inline'` or `*`) gives a false sense of safety while blocking no real XSS.",
                    "Drop `'unsafe-inline'` and wildcard script sources; use nonces or hashes so the policy genuinely restricts what runs."),
    # ---- security: injection (SQLi variants collapse to one finding; each here is a distinct reach) --
    "sec-sqli-001": ("The login query is parameterized; a crafted username/password cannot alter the SQL.",
                     "SQL injection: a payload in an auth field changed the query's logic (the classic `' OR '1'='1` shape), so an attacker reads or bypasses with no valid credentials.",
                     "Use parameterized queries / an ORM; never build SQL by string-concatenating request data. Same fix clears all SQLi variants."),
    "sec-sqli-002": ("Input reaches SQL only as a bound parameter, so injected operators cannot execute.",
                     "SQL injection reached the database via a second query surface. The engine executed attacker-supplied SQL, exposing read/modify/exfiltrate paths over your data.",
                     "Parameterize every query; validate and type-narrow inputs. Do not concatenate request data into SQL anywhere."),
    "sec-sqli-003": ("A crafted parameter cannot change query structure; the DB treats it strictly as data.",
                     "SQL injection confirmed through a data/search parameter (boolean/union/error-based reach). Attacker-controlled SQL runs against your database.",
                     "Parameterize the query and reject unexpected types; an ORM or prepared statement closes this class."),
    "sec-sqli-005": ("Every query binds its inputs; no request value is spliced into SQL text.",
                     "SQL injection reached the database on a further endpoint. Any reachable concatenated query is a full read/write breach of the data layer.",
                     "Audit for string-built SQL across the whole app and parameterize it; one leftover concatenation reopens the entire class."),
    "sec-xss-002": ("Stored/user-persisted content is encoded on output so a saved payload renders as text.",
                    "Stored XSS: a payload saved through the app was served back executable, so it runs in every viewer's session (session theft, account takeover, worming).",
                    "Encode on output for the HTML context; sanitize rich input server-side; add a script-constraining CSP as defense-in-depth."),
    "sec-domxss-001": ("Client JS treats URL/`location` data as text, never writing it to a live sink.",
                       "DOM-based XSS: client code fed a URL parameter into a sink (`innerHTML` / `document.write` / `eval`), so a crafted link executes script in the victim's browser.",
                       "Write untrusted values with `textContent`, not `innerHTML`; if HTML is required, sanitize with a vetted library (e.g. DOMPurify); avoid `eval`/`new Function`."),
    "sec-xxe-001": ("The XML parser has external-entity resolution disabled.",
                    "XXE: the XML parser resolved an external entity, enabling local file read, SSRF, and in some stacks RCE from a single crafted document.",
                    "Disable DTDs and external entities on the parser (e.g. `defusedxml`, or `setFeature` disallow-doctype-decl); prefer JSON if XML is not required."),
    "sec-ssrf-001": ("URL-shaped parameters are not fetched server-side, or are strictly allowlisted.",
                     "SSRF: a user-supplied URL triggered a server-side request (confirmed out-of-band), letting an attacker reach internal services and cloud metadata (169.254.169.254).",
                     "Allowlist destinations, resolve-then-validate the IP (block private/link-local ranges), disable redirects, and never fetch a raw user URL."),
    "sec-filterinj-001": ("Query/filter parameters are bound as values; a client cannot inject operators into the filter.",
                          "Filter injection: a client controlled a server-side query filter (NoSQL/ORM/search operator), letting it widen a scoped query to read rows it should not see.",
                          "Bind filter values as data, allowlist filterable fields and operators, and never pass raw request objects into a query builder."),
    "sec-split-001": ("User input placed into a response header is stripped of CR/LF, so headers cannot be forged.",
                      "HTTP response splitting: a CRLF payload injected into a header, enabling header forgery, cache poisoning, and reflected-XSS via a spoofed body.",
                      "Strip/reject CR and LF in any value that reaches a header (set-cookie, redirect Location); use a framework API that encodes header values."),
    # ---- security: broken access control (IDOR/BOLA variants -> one finding, five distinct reaches) -
    "sec-idor-001": ("An object fetched by ID is scoped to its owner; user A cannot read user B's record by guessing the ID.",
                     "Horizontal IDOR: changing a resource ID returned another user's record. Broken object-level authorization is the #1 real-world breach class.",
                     "Check ownership on every object access server-side (does this record belong to the caller?); do not rely on unguessable IDs alone."),
    "sec-idor-002": ("A `GET /object/{id}` API enforces ownership; a second account cannot read the first's object.",
                     "BOLA (OWASP API-Security #1): an API object endpoint returned another account's object with no authorization check on the ID.",
                     "Authorize every API object access against the authenticated principal; add an ownership/tenant check in the handler, not just at the route."),
    "sec-idor-003": ("A user-record endpoint returns only the caller's own record.",
                     "IDOR on a user/profile record: one account read another account's personal record by ID, exposing PII and account data.",
                     "Scope the lookup to the session user (`where id = current_user`), or verify ownership before returning the record."),
    "sec-idor-004": ("The managed backend's row-level security scopes each row to its owner (RLS is ON and correct).",
                     "BOLA via the backend: Supabase/Firebase RLS let one account read another's rows. The database, not just the app, is handing out other users' data.",
                     "Enable row-level security and write owner-scoped policies (`auth.uid() = user_id`); never ship with RLS off or a permissive `true` policy."),
    "sec-idor-005": ("An auth-gated LIST endpoint returns only the caller's own objects.",
                     "BOLA at the collection endpoint: a private list route returned every user's objects to any authenticated account (the list-shaped counterpart to per-object IDOR).",
                     "Filter list queries by the authenticated owner server-side; never return an unscoped collection from an endpoint the app declares private."),
    "sec-authbypass-001": ("A protected route requires credentials; it is unreachable with none.",
                           "Auth-gate bypass: a route the app treats as protected was reachable with NO credentials (a middleware/guard bypass), fully defeating access control.",
                           "Enforce auth server-side on the route/handler, not only in middleware or the client; verify the guard actually runs on every protected path."),
    # ---- security: deployment / session / exposure -------------------------------------------------
    "sec-debug-001": ("The framework runs in production mode; no interactive debugger or debug UI is exposed.",
                      "Debug mode shipped to prod: a debugger/debug page leaked source, settings, and env, and a Werkzeug-style console is a direct RCE surface.",
                      "Set the framework to production (`DEBUG=False` / `NODE_ENV=production`); never expose an interactive debugger on a reachable deployment."),
    "sec-redirect-001": ("Redirect targets are validated against an allowlist; the app will not bounce to an arbitrary URL.",
                         "Open redirect: a redirect parameter sent the user to any attacker-chosen URL, enabling convincing phishing and OAuth-token theft under your domain.",
                         "Allowlist redirect destinations or only accept relative paths; reject absolute/external URLs in `next`/`return`/`url` parameters."),
    "sec-mixed-001": ("An HTTPS page loads all subresources over HTTPS.",
                      "Mixed content: an HTTPS page pulled `http://` subresources, so a network attacker can tamper with active content and browsers may block it.",
                      "Serve every script/style/image/font over HTTPS; add `upgrade-insecure-requests` to your CSP to catch stragglers."),
    "sec-exposure-004": ("Sensitive deploy files (terraform state, SQL dumps, tokens, keys) are not served.",
                         "A sensitive file was served at the webroot, handing an anonymous visitor real credentials or a full database dump (proven by the file's own content).",
                         "Remove the file from the deploy artifact and block the path at the server/CDN; rotate anything the file exposed."),
    "sec-exposure-007": ("No sensitive infra/credential file (npm token, docker auth, private key, DB dump) is reachable.",
                         "A credential- or database-bearing file was served to anonymous visitors, a critical exposure equivalent to leaking `.env`.",
                         "Exclude these paths from the build/deploy, deny them at the edge, and rotate every secret they contained."),
    "sec-session-003": ("Session cookies set `Secure` so they never transit over plaintext HTTP.",
                        "A session cookie lacked `Secure`, so an HTTP downgrade can send it in cleartext for a network attacker to capture and hijack the session.",
                        "Add `Secure` to every session/auth cookie (with `HttpOnly` and `SameSite`); serve the whole app over HTTPS with HSTS."),
    "sec-session-004": ("Session identifiers are long, random, and unpredictable.",
                        "Predictable session IDs: tokens were short, numeric, or sequential, so an attacker can guess a valid session and hijack another user.",
                        "Generate session IDs from a CSPRNG (128+ bits) via your framework's session layer; never derive tokens from a counter, timestamp, or user data."),
    "sec-upload-001": ("Uploaded files cannot execute server-side; the upload path does not serve code.",
                       "Upload-to-RCE: an uploaded webshell executed on the server (confirmed by running a marker), the most severe outcome an upload can produce.",
                       "Store uploads outside the webroot on a non-executing path, allowlist content types, randomize names, and never serve user uploads as code."),
    "sec-upload-002": ("Uploaded active content is served inert (as an attachment / `text/plain`), never executed in-origin.",
                       "Stored XSS via upload: an uploaded `.html`/`.svg` was served inline with an executable content-type, so it runs script in your origin for every viewer.",
                       "Serve user uploads with `Content-Disposition: attachment` and a benign content-type (or from a separate origin); strip active content from SVGs."),
    # ---- qa ----------------------------------------------------------------------------------------
    "qa-a11y-001": ("The page has no critical accessibility violations (alt text, form labels, `lang`, control names).",
                    "Broken for screen-reader/keyboard users — and a reliable proxy for a rushed, unfinished UI.",
                    "Add `alt` on images, labels on inputs, a `lang` on `<html>`, and accessible names on controls; verify with axe DevTools."),
    "qa-a11y-002": ("The page passes the baseline accessibility hard-checks (`lang`, alt, form-control names, page title).",
                    "A fundamental accessibility element is missing — the page is unusable for assistive tech.",
                    "Add the missing `lang`/title/label/alt; these are one-line fixes with outsized impact."),
    "qa-seo-001": ("Best-practice meta tags are present (at least `viewport` and `description`).",
                   "Missing `viewport` breaks mobile layout; missing `description` hurts discoverability — signs of an unfinished page.",
                   "Add `<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">` and a `<meta name=\"description\">`."),
    "qa-console-001": ("The page loads with no uncaught JavaScript errors.",
                       "An error is being thrown on load — likely breaking functionality or leaving the UI half-initialized.",
                       "Open the devtools console, reproduce the error, and fix the throwing code path."),
    "qa-crash-010": ("Malformed input is rejected with a graceful 4xx.",
                     "An unhandled exception returns a 5xx — a reliability failure that can also leak stack traces.",
                     "Validate input at the boundary and catch errors; return `400` on bad input, never let it become a `500`."),
    "qa-input-001": ("The server enforces the input rules the form itself declares (a `type=email` / `required` / `min`/`max` field is re-checked server-side, not just in the browser).",
                     "Validation is client-side only — the server accepted a value its own form marks invalid, so anything bypassing the JS (a script, curl, a tweaked request) writes malformed data straight through.",
                     "Re-validate every declared constraint on the server — email shape, number range, required presence — and return a `400` on violation. Never trust the browser's checks."),
    "qa-deadctrl-001": ("Clickable controls actually do something when clicked.",
                        "Buttons/links wired to nothing — a happy-path demo with non-functional UI (the classic AI-generated tell).",
                        "Wire each control to its handler, or remove controls that aren't implemented yet."),
    "qa-http-001": ("A request for a nonexistent asset returns `404`.",
                    "A soft-404 (2xx for missing paths) pollutes caches and crawlers and masks real broken links.",
                    "Return a genuine `404` status for unknown routes/assets instead of falling through to `200`."),
    "qa-http-002": ("HTML responses declare their charset.",
                    "The browser must guess the encoding — causing mojibake and, via UTF-7 tricks, a legacy XSS vector.",
                    "Send `Content-Type: text/html; charset=utf-8`."),
    "qa-links-001": ("Internal links resolve to real pages.",
                     "An internal link leads to a 4xx dead end — broken navigation the user will hit.",
                     "Fix the target or remove the broken link."),
    "qa-deploy-001": ("The shipped client bundle points at a backend real visitors can reach.",
                      "The bundle calls a `localhost` / private-IP / unset-env host: a dev URL frozen into the production build, so the data layer is dead for everyone but you (works-on-my-machine).",
                      "Drive the backend URL from a build-time environment variable and set it in the deploy environment; verify the deployed bundle resolves to your public API origin, not `localhost` or `undefined`."),
    "qa-integrity-002": ("A created object is actually persisted; it appears in its own collection right after a successful create.",
                         "Silent data loss. A create returned success but the object was not saved, so the user's work vanishes.",
                         "Make the write durable and verify it (read-after-write); return an error if the create did not persist, never a false success."),
    "qa-chunk-001": ("Every JS bundle the HTML references resolves and loads.",
                     "A referenced script 404s, so the app cannot render: a stale or mis-deployed build (a blank or broken page).",
                     "Redeploy with matching asset hashes and cache-bust; make sure the HTML references the bundles the build actually emitted."),
    "qa-noerror-001": ("A failed save or create shows the user a clear error.",
                       "Silent failure. An action failed but the UI said nothing, so the user believes their data was saved when it was not.",
                       "Surface a visible error on any failed write; never swallow the failure and leave the happy-path UI in place."),
    "qa-deeplink-001": ("A client-side route loaded directly renders its real content, not just the app shell.",
                        "Broken deep link. Opening a route URL directly shows an empty shell or fallback, so shared and bookmarked links are dead.",
                        "Configure SPA fallback routing (rewrite unknown paths to index.html) and hydrate the route from the URL on first load."),
    "qa-backnav-001": ("The browser back button returns to the prior in-app view.",
                       "Broken SPA history. Back does not restore the previous view, breaking a basic navigation expectation.",
                       "Use the History API (pushState and the router's history) so in-app navigation creates real entries that back can restore."),
    "qa-devbuild-001": ("A production build is served; no dev-server client (HMR) is requested.",
                        "A development build shipped to production: slower, larger, source-leaking, and never meant to face users.",
                        "Build for production (`vite build` / `next build`) and serve that output; never deploy the dev server."),
    "qa-errhyg-001": ("An induced error returns a clean 4xx or 5xx, never a stack trace or database message.",
                      "Error info disclosure. An induced error leaked a stack trace or DB error, exposing internals and a broken error path.",
                      "Catch errors at the boundary and return a generic message; log the detail server-side, never render it to the user."),
    "qa-ctype-001": ("Every response declares the `Content-Type` that matches its actual body.",
                     "A response was served under the wrong `Content-Type` (e.g. JSON as `text/html`), which breaks strict clients and can enable content sniffing.",
                     "Set the correct `Content-Type` per response (`application/json` for JSON, etc.); let the framework infer it rather than hardcoding one type."),
    "qa-integrity-001": ("A value written through the app survives a write-then-read roundtrip unchanged.",
                         "Data-integrity loss: a value did not come back intact after being saved (truncated, coerced, or dropped), so the app silently corrupts user data.",
                         "Match column types/lengths to the input, avoid lossy coercion, and verify with a read-after-write; surface an error rather than storing a mangled value."),
    "qa-race-001": ("Concurrent creates get distinct IDs; the app allocates IDs atomically.",
                    "Race condition: parallel creates collided on the same ID (non-atomic read-then-increment), causing overwrites, oversell, and lost updates under load.",
                    "Allocate IDs atomically: a DB auto-increment/sequence or `INSERT ... RETURNING`, not a read-max-then-add-one in application code."),
    "qa-race-002": ("Concurrent API creates get distinct IDs under a burst.",
                    "Race condition on a JSON create path: simultaneous requests were assigned the same ID, so records clobber each other (the API-shaped counterpart to the form race).",
                    "Let the database assign IDs atomically; wrap the read-modify-write in a transaction or use a sequence, never an app-side counter."),
    "qa-staleui-001": ("After a create, the UI reflects the new object without a manual reload.",
                       "Stale UI: a created object did not appear until a hard refresh, so the interface lies about the current state and users re-submit or assume failure.",
                       "Re-fetch or optimistically update the view after a successful write; invalidate the relevant client cache/query on mutation."),
    # ---- performance -------------------------------------------------------------------------------
    "perf-lighthouse-001": ("Overall Lighthouse performance is green (90+); the app loads fast.",
                            "Lighthouse's weighted performance score is below its green line; slop = the shortfall under 90.",
                            "See the per-metric breakdown (LCP/CLS/TBT/speed-index) for which metric to fix first."),
    "perf-cwv-001": ("First Contentful Paint is within the Core Web Vitals threshold.",
                     "The page paints slowly — users perceive it as sluggish and are more likely to bounce.",
                     "Reduce render-blocking JS/CSS, inline critical CSS, and defer non-essential scripts."),
    "perf-cwv-002": ("Core Web Vitals (LCP, layout stability) pass on the best of several throttled samples.",
                     "Poor real-world loading experience — slow largest paint or janky layout shifts.",
                     "Optimize and size images, reserve space for late content to stop layout shift, and code-split heavy bundles."),
    "perf-loadtime-001": ("The homepage loads under the ~5s user-abandonment ceiling.",
                          "Load time is past the point where a large share of users give up and leave.",
                          "Shrink the payload, lazy-load below-the-fold content, and serve static assets from a CDN."),
    "perf-compress-001": ("Sizeable text assets are served compressed (gzip/brotli).",
                          "Uncompressed text wastes bandwidth and slows every load, especially on mobile.",
                          "Enable gzip/brotli in your server or host settings (usually a one-line toggle)."),
    "perf-weight-001": ("Total page transfer weight is within the performance budget.",
                        "A heavy page is slow on mobile and constrained networks.",
                        "Compress images, tree-shake and minify bundles, and drop unused dependencies."),
    "perf-weight-002": ("Total page transfer weight is within the performance budget.",
                        "A heavy page is slow on mobile and constrained networks.",
                        "Compress images, tree-shake and minify bundles, and drop unused dependencies."),
    "perf-requests-001": ("The homepage renders without an excessive request count.",
                          "Too many requests create a loading waterfall that delays first render.",
                          "Bundle assets, inline what's critical, and lazy-load the rest."),
    "perf-cache-001": ("Static assets are cacheable (validators / sane `Cache-Control`).",
                       "Nothing is cached, so returning visitors re-download every asset each time.",
                       "Set `Cache-Control` with a validator (ETag/Last-Modified) on static assets; fingerprint filenames for long TTLs."),
    "perf-ttfb-001": ("Time-to-first-byte is under ~1s.",
                      "The server is slow to respond — often a cold start or an unoptimized request handler.",
                      "Keep the instance warm, cache expensive work, and profile the slow handler."),
    "perf-ttfb-002": ("On a standardized 1-vCPU profile, the backend returns the first byte under ~800ms.",
                      "The server-side handler is slow on a normalized profile (a slow-server tax), so real users on modest hardware wait before anything renders.",
                      "Profile and cache the request handler, cut synchronous work and N+1 queries on the hot path, and avoid per-request cold starts."),
    "perf-ttfb-003": ("Time-to-first-byte stays under the absolute ~3s ceiling for every request.",
                      "Pathological TTFB: the server took over 3s to send a single byte, which reads as broken to users and crawlers regardless of hardware.",
                      "Find the blocking work in the request path (unindexed query, external call, cold start) and move it off the critical path or cache it."),
    "perf-load-001": ("Endpoints stay up under a short concurrent burst.",
                      "An endpoint 5xx'd under concurrent load — it won't survive even a small crowd of real users.",
                      "Handle concurrency safely (connection pooling, limits, backpressure); don't crash under parallel requests."),
}

# Generic remediation when a probe has no authored entry (keeps the card complete + non-crashing).
_GENERIC = ("A durability check for this issue passed on well-built apps.",
            "",  # filled from the finding's own `reason`
            "Review the observed evidence below and address the underlying issue.")

_AXIS_TITLE = {"security": "Security", "qa": "Quality & Correctness", "performance": "Performance"}


def card_copy(probe_id: str, reason: str = "") -> tuple[str, str, str]:
    """The authored (expected, indicates, remediation) triple for a probe_id, with the same generic fallback
    the report card uses. `reason` (the catalog 'why') fills the 'indicates' line for an unauthored probe.
    Public so `scripts/list_probes.py --verbose` renders the exact copy a team would see, without a finding."""
    expected, indicates, remediation = _CONTENT.get(probe_id, _GENERIC)
    if not indicates:
        indicates = reason or "an issue a durable app avoids"
    return expected, indicates, remediation


def _pool_map(catalog_root: str | pathlib.Path) -> dict[str, str]:
    """probe_id -> pool ('public' | 'hidden'), from the catalog. Missing -> 'public' (fail-open to disclosure
    would over-share, so callers that can't load the catalog should treat everything as public deliberately)."""
    try:
        return {p.id: getattr(p, "pool", "public") for p in load_catalog(catalog_root)}
    except Exception:
        return {}


def _actual(finding: dict) -> str:
    """A plain-language 'what we saw' line from the finding evidence + where it fired."""
    ev = finding.get("evidence") or {}
    parts = [f"{k} = {v}" for k, v in ev.items() if k not in ("engine",) and not isinstance(v, (dict, list))]
    detail = "; ".join(parts) if parts else finding.get("reason", "")
    targets = finding.get("targets") or ([finding["target"]] if finding.get("target") else [])
    where = f"  (seen on: {', '.join(str(t) for t in targets[:5])})" if targets else ""
    return detail + where


def _entry(finding: dict) -> dict:
    """A single public finding rendered as the four fields (+ penalty/title)."""
    pid = finding.get("probe_id", "")
    expected, indicates, remediation = _CONTENT.get(pid, _GENERIC)
    if not indicates:                       # generic fallback: use the catalog reason as the 'indicates' line
        indicates = finding.get("reason", "an issue a durable app avoids")
    return {
        "probe_id": pid,
        "title": finding.get("reason", pid),
        "penalty": finding.get("penalty", 0),
        "expected": expected,
        "actual": _actual(finding),
        "indicates": indicates,
        "remediation": remediation,
    }


def build_card(record: dict, catalog_root: str | pathlib.Path | None = None, organizer: bool = False) -> dict:
    """Turn one grade record into a structured report card. `catalog_root` supplies the pool map for the
    public/hidden split; without it every finding is treated as public. `organizer=True` reveals hidden
    findings in full (for the running org), else they're an opaque count."""
    pool = _pool_map(catalog_root) if catalog_root else {}
    findings = record.get("findings") or []
    url = record.get("url") or record.get("repo") or record.get("project") or "(unknown)"

    # non-functional apps are DNF-classed, not scored — the card says so instead of inventing findings.
    if record.get("functional") is False:
        return {"url": url, "project": record.get("project"), "dnf": True,
                "page_state": (record.get("coverage_audit") or {}).get("page_state"),
                "slop_score": None, "sections": [], "hidden": {"count": 0, "penalty": 0},
                "passed": [], "cov": record.get("coverage") or {}}

    public, hidden = [], []
    for f in findings:
        (hidden if pool.get(f.get("probe_id"), "public") == "hidden" else public).append(f)

    # group public findings by axis (bundle), heaviest axis first
    by_axis: dict[str, list] = {}
    for f in public:
        by_axis.setdefault(f.get("bundle", "other"), []).append(f)
    sections = []
    for axis in sorted(by_axis, key=lambda a: -sum(x.get("penalty", 0) for x in by_axis[a])):
        entries = sorted((_entry(f) for f in by_axis[axis]), key=lambda e: -e["penalty"])
        sections.append({"axis": axis, "title": _AXIS_TITLE.get(axis, axis.title()),
                         "penalty": sum(e["penalty"] for e in entries), "entries": entries})

    cov = record.get("coverage") or {}
    fired_cats = {f.get("category") for f in findings}
    passed_cats = sorted(c for c in (cov.get("ran_kinds") or []) if c not in fired_cats)

    hidden_block = {"count": len(hidden), "penalty": sum(f.get("penalty", 0) for f in hidden)}
    if organizer:                            # organizer view: hidden findings rendered in full, like public
        hidden_block["entries"] = sorted((_entry(f) for f in hidden), key=lambda e: -e["penalty"])

    return {"url": url, "project": record.get("project"), "dnf": False,
            "slop_score": record.get("slop_score"), "axis_slop": record.get("axis_slop") or {},
            "sections": sections, "hidden": hidden_block, "passed": passed_cats, "cov": cov,
            "winner": record.get("winner")}


# ---- renderers -------------------------------------------------------------------------------------

def to_markdown(card: dict) -> str:
    """Portable markdown rendering of a report card."""
    L = []
    name = card.get("project") or card["url"]
    L.append(f"# Durability Report Card — {name}")
    L.append(f"`{card['url']}`\n")
    if card.get("dnf"):
        L.append(f"**Not scored — graded non-functional (`{card.get('page_state')}`).** "
                 "The app didn't present a working surface to test. Get it serving a functional page, then re-grade.")
        return "\n".join(L)

    L.append(f"**Slop score: {card['slop_score']}**  (lower is better — deduction-only)")
    if card.get("axis_slop"):
        L.append("  ·  " + "  ·  ".join(f"{k}: {v}" for k, v in card["axis_slop"].items()))
    cov = card.get("cov") or {}
    if cov:
        n_fail = sum(len(s["entries"]) for s in card["sections"]) + card["hidden"]["count"]
        L.append(f"\n_{cov.get('probes_applicable', '?')} durability checks applied · "
                 f"{n_fail} flagged · {max(cov.get('probes_applicable', 0) - n_fail, 0)} passed._")

    for sec in card["sections"]:
        L.append(f"\n## {sec['title']}  (−{sec['penalty']})")
        for e in sec["entries"]:
            L.append(f"\n### {e['title']}  (−{e['penalty']})")
            L.append(f"- **Expected:** {e['expected']}")
            L.append(f"- **Actual:** {e['actual']}")
            L.append(f"- **Indicates:** {e['indicates']}")
            L.append(f"- **Fix:** {e['remediation']}")

    h = card["hidden"]
    if h.get("entries") is not None:         # organizer view
        L.append(f"\n## Hidden resilience checks (organizer view)  (−{h['penalty']})")
        for e in h["entries"]:
            L.append(f"\n### {e['title']}  (−{e['penalty']})")
            L.append(f"- **Expected:** {e['expected']}")
            L.append(f"- **Actual:** {e['actual']}")
            L.append(f"- **Indicates:** {e['indicates']}")
            L.append(f"- **Fix:** {e['remediation']}")
    elif h["count"]:
        L.append(f"\n## Hidden resilience checks")
        L.append(f"_{h['count']} additional check(s) flagged (−{h['penalty']} total). Details are withheld to "
                 "keep the credential ungameable — you can't teach-to-the-test on checks you can't see. "
                 "Building genuinely durably is the only way to pass them._")

    if card.get("passed"):
        L.append("\n## Passed")
        L.append("Clean on: " + ", ".join(card["passed"]) + ".")
    return "\n".join(L)


def to_html(card: dict) -> str:
    """Self-contained HTML body (no <html>/<head>) for publishing as an Artifact — theme-aware, printable."""
    e = html.escape
    name = card.get("project") or card["url"]
    css = """
    <style>
    :root{--bg:#fff;--fg:#1a1a1a;--muted:#666;--card:#f6f7f9;--line:#e3e6ea;--accent:#c0392b;--good:#1e8e4e}
    @media (prefers-color-scheme:dark){:root{--bg:#15181c;--fg:#e8eaed;--muted:#9aa0a6;--card:#1e2228;--line:#2c313a;--accent:#ff6b5e;--good:#3ecf7b}}
    :root[data-theme=dark]{--bg:#15181c;--fg:#e8eaed;--muted:#9aa0a6;--card:#1e2228;--line:#2c313a;--accent:#ff6b5e;--good:#3ecf7b}
    :root[data-theme=light]{--bg:#fff;--fg:#1a1a1a;--muted:#666;--card:#f6f7f9;--line:#e3e6ea;--accent:#c0392b;--good:#1e8e4e}
    *{box-sizing:border-box}body{margin:0}
    .rc{max-width:820px;margin:0 auto;padding:32px 20px;color:var(--fg);background:var(--bg);
        font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
    .rc h1{font-size:26px;margin:0 0 4px}.rc .url{color:var(--muted);font-family:ui-monospace,monospace;font-size:13px;word-break:break-all}
    .score{font-size:40px;font-weight:700;margin:18px 0 2px}.axes{color:var(--muted);font-size:14px}
    .cov{color:var(--muted);font-size:13px;margin:10px 0 8px}
    .rc h2{font-size:15px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:30px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
    .f{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:8px;padding:14px 16px;margin:10px 0}
    .f .t{font-weight:650;font-size:15px;display:flex;justify-content:space-between;gap:12px}
    .f .pen{color:var(--accent);font-variant-numeric:tabular-nums;font-weight:700;white-space:nowrap}
    .f dl{margin:10px 0 0;display:grid;grid-template-columns:88px 1fr;gap:4px 12px;font-size:14px}
    .f dt{color:var(--muted);font-weight:600}.f dd{margin:0}
    .f dd code,.actual code{font-family:ui-monospace,monospace;font-size:12.5px}
    .actual{font-family:ui-monospace,monospace;font-size:12.5px;word-break:break-word}
    .passed{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--good);border-radius:8px;padding:12px 16px;font-size:14px}
    .hidden{background:var(--card);border:1px dashed var(--line);border-radius:8px;padding:14px 16px;font-size:14px;color:var(--muted)}
    .dnf{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:18px;font-size:15px}
    </style>"""
    out = [css, '<div class="rc">', f"<h1>Durability Report Card</h1>",
           f'<div class="url">{e(card["url"])}</div>']
    if card.get("dnf"):
        out.append(f'<div class="dnf"><b>Not scored — graded non-functional '
                   f'({e(str(card.get("page_state")))}).</b> The app didn\'t present a working surface to test. '
                   "Get it serving a functional page, then re-grade.</div></div>")
        return "".join(out)

    out.append(f'<div class="score">{e(str(card["slop_score"]))}<span style="font-size:15px;color:var(--muted);font-weight:400"> slop · lower is better</span></div>')
    if card.get("axis_slop"):
        out.append('<div class="axes">' + " &nbsp;·&nbsp; ".join(f"{e(k)}: {e(str(v))}" for k, v in card["axis_slop"].items()) + "</div>")
    cov = card.get("cov") or {}
    if cov:
        n_fail = sum(len(s["entries"]) for s in card["sections"]) + card["hidden"]["count"]
        out.append(f'<div class="cov">{e(str(cov.get("probes_applicable","?")))} durability checks applied · '
                   f'{n_fail} flagged · {max(cov.get("probes_applicable",0)-n_fail,0)} passed</div>')

    def block(entry):
        return (f'<div class="f"><div class="t"><span>{e(entry["title"])}</span>'
                f'<span class="pen">−{e(str(entry["penalty"]))}</span></div><dl>'
                f'<dt>Expected</dt><dd>{e(entry["expected"])}</dd>'
                f'<dt>Actual</dt><dd class="actual">{e(entry["actual"])}</dd>'
                f'<dt>Indicates</dt><dd>{e(entry["indicates"])}</dd>'
                f'<dt>Fix</dt><dd>{e(entry["remediation"])}</dd></dl></div>')

    for sec in card["sections"]:
        out.append(f'<h2>{e(sec["title"])} · −{e(str(sec["penalty"]))}</h2>')
        out += [block(x) for x in sec["entries"]]

    h = card["hidden"]
    if h.get("entries") is not None:
        out.append(f'<h2>Hidden resilience checks (organizer) · −{e(str(h["penalty"]))}</h2>')
        out += [block(x) for x in h["entries"]]
    elif h["count"]:
        out.append('<h2>Hidden resilience checks</h2>')
        out.append(f'<div class="hidden">{e(str(h["count"]))} additional check(s) flagged '
                   f'(−{e(str(h["penalty"]))} total). Details are withheld to keep the credential ungameable — '
                   "you can't teach-to-the-test on checks you can't see. Building genuinely durably is the only "
                   "way to pass them.</div>")

    if card.get("passed"):
        out.append('<h2>Passed</h2>')
        out.append('<div class="passed">Clean on: ' + ", ".join(e(c) for c in card["passed"]) + ".</div>")
    out.append("</div>")
    return "".join(out)
