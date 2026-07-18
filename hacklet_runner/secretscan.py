"""Static secret scan over a submission's SOURCE tree.

This is the ONE high-value AI-slop class a black-box HTTP grader is structurally blind to: a hardcoded
secret used server-side that never reaches a client — an OpenAI/Stripe/AWS key, a DB password, a
service-account private key. `response_leaks_secret` only sees secrets that transit the wire; this sees
the ones baked into code. It runs ONLY when the source is available (a `--submission` zip, or `--source
DIR`); a bare `--target` URL has no source, so the finding is simply absent (N/A for firewalled Tier-A
league runs, which forbid env vars / third-party integrations anyway).

Precision over recall — a false positive wrongly penalizes a real submission — so: only high-confidence
provider patterns plus a tightly-guarded generic `<name> = <value>`, and heavy skip lists (vendored deps,
lockfiles, minified/binary, `*.example` configs, documented placeholders like AWS's ...EXAMPLE key).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# Provider patterns with near-zero false positives. (Google/Firebase `AIza…` web keys and Stripe `pk_…`
# publishable keys are public-BY-DESIGN -> excluded, matching the HTTP probe; whether a Firebase/Supabase
# backend is actually world-readable is judged separately by the exposed-backend probe.)
_PROVIDER = [
    # require ACTUAL key material (base64 body + END) between the markers — a bare `-----BEGIN PRIVATE KEY-----`
    # is just a code constant in every crypto/PEM library (`indexOf("-----BEGIN PRIVATE KEY-----")`), NOT a leak.
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[A-Za-z0-9+/=\s]{100,}-----END")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("stripe-secret", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b")),
    ("stripe-test-secret", re.compile(r"\bsk_test_[0-9A-Za-z]{16,}\b")),
    ("github-pat", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    ("github-fine-grained-pat", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("google-oauth-secret", re.compile(r"\bGOCSPX-[0-9A-Za-z_-]{20,}\b")),
    ("sendgrid-key", re.compile(r"\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b")),
    ("twilio-account-sid", re.compile(r"\bAC[0-9a-fA-F]{32}\b")),
]

# A guarded generic assignment: a credential-ish NAME set to a non-placeholder VALUE (catches DB
# passwords / bespoke API keys the provider list can't know). The value must survive _looks_secret.
_ASSIGN = re.compile(
    r"""(?ix)
    \b(?P<name>secret|token|passwd|password|api[_-]?key|access[_-]?key|private[_-]?key|
       client[_-]?secret|db[_-]?pass\w*|auth[_-]?token|encryption[_-]?key)
    \s* [:=] \s* ['"](?P<val>[^'"\n]{12,120})['"]
    """,
)
_PLACEHOLDER = re.compile(
    r"(?i)^(?:your|my|the|an?|example|sample|placeholder|change[_-]?me|xxx+|todo|dummy|test|fake|"
    r"redacted|hidden|secret|password|passw0rd|none|null|undefined|foo|bar|abc|123|\.\.\.|"
    r"<[^>]*>|\$\{[^}]*\}|%\([^)]*\)|process\.env|os\.environ|import\.meta|env\.)",
)


def _looks_secret(v: str) -> bool:
    if _PLACEHOLDER.search(v) or "example" in v.lower():
        return False
    if len(set(v)) < 5 or v.startswith(("http://", "https://", "/", "./", "../")):
        return False   # low-entropy repetition, or a URL/path — not a secret
    has_alpha = any(c.isalpha() for c in v)
    has_mix = any(c.isdigit() for c in v) or any(not c.isalnum() for c in v)
    return len(v) >= 24 or (has_alpha and has_mix and len(v) >= 16)


_SKIP_DIRS = {"node_modules", ".git", ".hg", ".svn", "venv", ".venv", "env", ".env.d", "__pycache__",
              "dist", "build", ".next", "out", "target", "vendor", "coverage", ".cache", ".idea",
              "bower_components", ".terraform", "site-packages", ".pytest_cache", ".mypy_cache"}
_SKIP_SUFFIX = (".min.js", ".map", ".lock", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
                ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz", ".tar", ".jar", ".class",
                ".pyc", ".so", ".dll", ".dylib", ".bin", ".mp4", ".mp3", ".wasm", ".ipynb")
_SKIP_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "cargo.lock",
               "composer.lock", "gemfile.lock"}
_EXAMPLE = re.compile(r"(?i)(?:\.(?:example|sample|dist|template|tmpl)$|\.env\.(?:example|sample|template))")
_MAX_BYTES = 1_000_000


@dataclass
class SecretFinding:
    file: str
    line: int
    kind: str
    snippet: str   # masked


def _mask(s: str) -> str:
    s = s.strip()
    return s if len(s) <= 12 else s[:6] + "…" + s[-4:]


def _scan_text(text: str, rel: str) -> list[SecretFinding]:
    out: list[SecretFinding] = []
    for i, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:   # a single giant line (leftover minified/bundled content) — skip
            continue
        for kind, pat in _PROVIDER:
            m = pat.search(line)
            if m and "example" not in m.group(0).lower():   # AWS's AKIA…EXAMPLE et al. are docs placeholders
                out.append(SecretFinding(rel, i, kind, _mask(m.group(0))))
        m = _ASSIGN.search(line)
        if m and _looks_secret(m.group("val")):
            name = re.sub(r"[_-]", "_", m.group("name").lower())
            out.append(SecretFinding(rel, i, "hardcoded-" + name, _mask(m.group("val"))))
    return out


def scan_blob(text: str) -> list[str]:
    """Provider-secret KINDS in an arbitrary text blob (a served JS bundle / HTML) — for the black-box HTTP
    probes, which see the CLIENT bundle, not the source tree. Whole-text (NOT line-split: a production bundle is
    minified to one giant line, which _scan_text skips), and PROVIDER formats only — the public-by-design keys
    (Google AIza / Stripe pk_ / Supabase anon) aren't in _PROVIDER, so only a leaked SECRET fires. No generic
    `<name>=<value>` here: it's too false-positive-prone across a minified bundle's sea of key/value pairs."""
    kinds: set[str] = set()
    for kind, pat in _PROVIDER:
        m = pat.search(text)
        if m and "example" not in m.group(0).lower():
            kinds.add(kind)
    return sorted(kinds)


def _walk(root: Path):
    for p in root.rglob("*"):
        if not p.is_file() or set(p.relative_to(root).parts[:-1]) & _SKIP_DIRS:
            continue
        name = p.name.lower()
        if name in _SKIP_NAMES or name.endswith(_SKIP_SUFFIX) or _EXAMPLE.search(name):
            continue
        yield p


def scan_secrets(root) -> list[SecretFinding]:
    """Every hardcoded secret in the source tree at `root` (a dir, or a single file), deduped."""
    root = Path(root)
    files = [root] if root.is_file() else None
    base = root.parent if files else root
    findings: list[SecretFinding] = []
    for path in (files if files is not None else _walk(base)):
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeDecodeError):
            continue   # binary / unreadable
        findings.extend(_scan_text(text, str(path.relative_to(base))))
    seen: set = set()
    uniq: list[SecretFinding] = []
    for f in findings:
        key = (f.file, f.kind, f.snippet)
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq
