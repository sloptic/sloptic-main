"""Ask a provider whether a key found in a client bundle is actually live.

Sloptic decides everything else from what the target itself emits. This module is the one exception, and it
exists because one key format is undecidable from the bundle alone.

Google's `AIza` keys are the same 39 characters whether they are a Firebase web config key (public by
design, Google's own docs say they need not be treated as secrets), a Maps key (likewise), or a Gemini API
key (Google's own docs say treat it like a password). A regex cannot separate them, so `secretscan` returns
them as candidates and scores nothing. Worse, the categories are not even stable: Truffle Security showed in
February 2026 that an existing key embedded in client code exactly as Google instructed silently gains
Gemini access the moment the Generative Language API is enabled on the same project, with no new key and no
warning. HTTP referrer restrictions do not block Gemini either, only API restrictions do.

So the provider is the only oracle. `GET /v1beta/models?key=<key>` lists model names: it authenticates the
key, generates no tokens, and bills no inference, which keeps the check free for the key's owner.

Why this is worth the exception. Without it a team wrapping OpenAI or Anthropic is caught by a format match
while a team wrapping Gemini is invisible, and "Best Use of Gemini API" is a standing hackathon track prize.
That is not a recall gap, it is a bias in the ruler, which is the one thing a comparable score cannot have.

**Active battery only.** This sends a request using a credential belonging to the app's owner, so it runs
only where ownership was attested, never in the passive lane that grades a stranger's URL.
"""
from __future__ import annotations

import httpx

from . import egress

GEMINI_HOST = "generativelanguage.googleapis.com"
_GEMINI_MODELS = f"https://{GEMINI_HOST}/v1beta/models"
_TIMEOUT = 8.0


def gemini_key_is_live(key: str, *, timeout: float = _TIMEOUT, client=None) -> bool | None:
    """Does `key` authenticate to the Gemini API?

    True  the key reaches Gemini. It is a live inference credential in a public bundle, whatever the team
          believed it was for.
    False the provider refused it. It is a Firebase or Maps key that cannot call Gemini, which is the
          public-by-design case and must not be scored.
    None  we could not tell (network failure, timeout, an unexpected status). Never scored: a check that
          did not complete is not evidence of absence, the same rule the Devpost client follows.

    Redirects are not followed, so the provider cannot bounce the credential anywhere we did not choose, and
    the key never enters a log line or an exception message.
    """
    if not key:
        return None
    try:
        with egress.exempt_host(GEMINI_HOST):   # a constant, never target supplied. See egress.exempt_host.
            if client is not None:
                r = client.get(_GEMINI_MODELS, params={"key": key}, timeout=timeout, follow_redirects=False)
            else:
                with httpx.Client(follow_redirects=False) as c:
                    r = c.get(_GEMINI_MODELS, params={"key": key}, timeout=timeout)
    except (httpx.HTTPError, ValueError):       # bare except of the type only: the message could hold the key
        return None
    if r.status_code == 200:
        return True
    if r.status_code in (400, 401, 403):        # invalid, unauthorized, or not permitted to call this API
        return False
    return None                                 # 429 / 5xx / anything else: unknown, not absent
