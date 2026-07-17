"""depscan — known-vulnerable client-side dependency detection (retire.js-style, focused + high-precision).

Reads the app's OWN shipped bundle (ETHICAL: their code, never a third party's server) and fingerprints a
curated set of common libraries by their license-banner version string, flagging versions with a well-known
CVE. This is the supply-chain slice of app responsibility: the team CHOSE the vulnerable library — 24h is
enough to run `npm audit` — so it's their finding, and the report's remediation (upgrade to X) teaches vendor
due diligence by proxy. Precision-first: fires ONLY on an unambiguous version banner AND an established CVE
range (a false version claim would corrupt the score), and it's a small curated set, NOT a full retire.js.
"""
import re


def _ver(v: str) -> tuple:
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return ()


def _lt(v: str, threshold: str) -> bool:
    a, b = _ver(v), _ver(threshold)
    return bool(a) and a < b


# (library, banner version-regex, is_vulnerable(version)->bool, CVE, issue, fix). Banner strings survive
# minification (the /*! ... */ license comment is kept), so these fingerprint even a bundled/minified app.
_DEP_VULNS = [
    ("jQuery", re.compile(r"jQuery (?:JavaScript Library )?v?(\d+\.\d+\.\d+)"),
     lambda v: _lt(v, "3.5.0"), "CVE-2020-11022", "XSS via HTML passed to DOM-manipulation methods", ">=3.5.0"),
    ("jQuery UI", re.compile(r"jQuery UI[ -]+v?(\d+\.\d+\.\d+)"),
     lambda v: _lt(v, "1.13.2"), "CVE-2022-31160", "XSS in the checkboxradio widget refresh", ">=1.13.2"),
    ("Bootstrap", re.compile(r"Bootstrap v(\d+\.\d+\.\d+)"),
     lambda v: (v.startswith("3.") and _lt(v, "3.4.1")) or (v.startswith("4.") and _lt(v, "4.3.1")),
     "CVE-2019-8331", "XSS in data-* attributes (tooltip / popover)", ">=3.4.1 (3.x) / >=4.3.1 (4.x)"),
    ("Moment.js", re.compile(r"moment\.js version[ :]*(\d+\.\d+\.\d+)"),
     lambda v: _lt(v, "2.29.4"), "CVE-2022-31129", "ReDoS on an untrusted date string", ">=2.29.4"),
    ("Handlebars", re.compile(r"Handlebars[^0-9A-Za-z]{0,12}v?(\d+\.\d+\.\d+)"),
     lambda v: _lt(v, "4.7.7"), "CVE-2019-19919", "prototype pollution -> RCE via a crafted template", ">=4.7.7"),
]


def scan_deps(text: str) -> list[dict]:
    """One entry per DISTINCT vulnerable library found in the bundle text (deduped by library, first match wins)."""
    out, seen = [], set()
    for name, rx, is_vuln, cve, issue, fix in _DEP_VULNS:
        for m in rx.finditer(text):
            if is_vuln(m.group(1)):
                if name not in seen:
                    seen.add(name)
                    out.append({"library": name, "version": m.group(1), "cve": cve, "issue": issue, "fix": fix})
                break
    return out
