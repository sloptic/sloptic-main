# Vulnerable-app corpus (recall validation)

A set of deliberately-vulnerable apps to point the fuzzer at and confirm it catches known real vulns. This
is the RECALL half of validation (precision.py covers false positives on the scraped cohort; this covers
"does it actually find the SQLi/IDOR/XSS that are definitely there"). It also exercises the deep auth and
IDOR probes that read N/A on scraped static SPAs, because these apps have real self-registerable backends.

**Safety: these apps are built to be hacked.** Every port binds to `127.0.0.1` only. Never expose this
corpus to a network or the internet.

## Bring it up

```sh
docker compose up -d      # pulls + starts DVWA, bWAPP, Juice Shop, VAmPI
bash setup.sh             # one-time: create/reset DVWA + bWAPP databases, populate VAmPI users
docker compose down       # tear down when done
```

| App | URL | Login | What it exercises |
|---|---|---|---|
| DVWA | http://127.0.0.1:8081 | admin / password | classic PHP web vulns (SQLi, XSS, CSRF, LFI, upload, command injection) |
| bWAPP | http://127.0.0.1:8082 | bee / bug | a very wide PHP bug surface |
| Juice Shop | http://127.0.0.1:8083 | (self-register in the app) | modern Node/Angular SPA, form-less, JS-bundle-mined |
| VAmPI | http://127.0.0.1:8084 | name1 / pass1 | vulnerable REST API (OpenAPI spec at /openapi.json) |

## Grade each

**VAmPI** grades out of the box (a JSON API, no auth or browser needed). It is the cleanest recall proof:

```sh
uv run python -m hacklet_runner.cli --target http://127.0.0.1:8084 --failed
# catches sec-idor-002 (BOLA, 40), sec-sqli-004 (40), sec-exposure-005 (35), qa-crash-010 (32)
```

**Juice Shop** is a client-rendered SPA, so it needs the browser (render + JS-bundle mining):

```sh
uv run python -m hacklet_runner.cli --target http://127.0.0.1:8083 --browser --failed
```

**DVWA** only serves its vulnerable surface behind a login, at security level `low`. Grab an authed session
and hand it in with `--header` (the Option-B provided-session path):

```sh
jar=$(mktemp)
tok=$(curl -s -c "$jar" http://127.0.0.1:8081/login.php \
      | grep -oiE 'user_token.{0,20}[0-9a-f]{32}' | grep -oiE '[0-9a-f]{32}' | head -1)
curl -s -b "$jar" -c "$jar" --data "username=admin&password=password&user_token=$tok&Login=Login" \
     http://127.0.0.1:8081/login.php -o /dev/null
sid=$(awk '/PHPSESSID/{print $NF}' "$jar")
uv run python -m hacklet_runner.cli --target http://127.0.0.1:8081 \
     --header "Cookie: PHPSESSID=$sid; security=low" --failed
```

**bWAPP** is the same shape (log in bee / bug, hand in the session cookie). Its security level is a form
field in the app; set it to low for the widest surface.

## Reading the result

`--failed` prints the slop-only table (what fired). For recall, the question is whether the *known* vulns
show up: DVWA's SQLi and command injection, VAmPI's BOLA and SQLi, Juice Shop's DOM-XSS and secret leaks. A
miss on a known vuln is a recall gap worth a discovery or probe investigation. Header/a11y/perf hygiene will
also fire (these apps are not tuned for it) and is expected noise for a recall run.
