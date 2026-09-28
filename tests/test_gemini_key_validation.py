"""A live Gemini key in the client bundle, confirmed against Google rather than inferred from its format.

The only predicate that asks a third party, and it exists because the format is undecidable otherwise: the
same 39 characters serve a public-by-design Firebase web key and a Gemini billing credential, and an
existing Firebase key silently gains Gemini access when that API is enabled on the project. So the rule
under test is that NOTHING is scored on format alone, in either direction: an unconfirmed key never fires,
and a confirmed one is not excused for looking like a Firebase key.

Every test stubs the provider. No test may ever reach Google.
"""
import pytest

from sloptic import probes, provider_validate, safety
from sloptic.catalog import load_catalog
from sloptic.pipeline import _severity_penalty

_LIVE = "AIza" + "SyAb3Cd9Ef2Gh8Ij4Kl7Mn1Op5Qr6St0Uv1"
_OTHER = "AIza" + "SyZz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp9"


class _Ctx:
    def __init__(self):
        self.evidence = {}


@pytest.fixture
def bundle(monkeypatch):
    def _set(text):
        monkeypatch.setattr(probes, "_client_bundle", lambda ctx: text)
    return _set


@pytest.fixture
def provider(monkeypatch):
    """Stub the provider and record which keys were asked about."""
    asked = []

    def _set(answers):
        def fake(key, **kw):
            asked.append(key)
            return answers.get(key, False)
        monkeypatch.setattr(provider_validate, "gemini_key_is_live", fake)
        return asked
    return _set


def test_a_confirmed_key_fires_and_records_the_live_evidence(bundle, provider):
    bundle(f'const cfg={{apiKey:"{_LIVE}"}};')
    provider({_LIVE: True})
    ctx = _Ctx()
    assert probes.gemini_key_live_in_bundle(ctx, None) is True
    assert ctx.evidence["validated_live"] is True          # the rung the ladder prices at 92
    assert ctx.evidence["provider"] == "google-gemini"
    assert _LIVE not in ctx.evidence["key"]                # masked, never the key itself


def test_a_refused_key_does_not_fire(bundle, provider):
    """The public-by-design case. A Firebase or Maps key cannot call Gemini, and must never be scored."""
    bundle(f'const cfg={{apiKey:"{_LIVE}"}};')
    provider({_LIVE: False})
    ctx = _Ctx()
    assert probes.gemini_key_live_in_bundle(ctx, None) is False
    assert ctx.evidence["validated_live"] is False


def test_an_unreachable_provider_is_na_never_clean(bundle, monkeypatch):
    """A check that did not complete is not evidence of absence. Reporting clean here would quietly
    exonerate every app whenever Google was unreachable."""
    bundle(f'const cfg={{apiKey:"{_LIVE}"}};')
    monkeypatch.setattr(provider_validate, "gemini_key_is_live", lambda key, **kw: None)
    ctx = _Ctx()
    assert probes.gemini_key_live_in_bundle(ctx, None) is None
    assert "validated_live" not in ctx.evidence
    assert ctx.evidence["na_reason"] == "provider unreachable"


def test_no_candidate_key_is_na_and_asks_the_provider_nothing(bundle, provider):
    bundle('const cfg={api:"/api",pub:"pk_live_' + "A" * 24 + '"};')
    asked = provider({})
    ctx = _Ctx()
    assert probes.gemini_key_live_in_bundle(ctx, None) is None
    assert asked == []                                     # no key, no request against anyone's quota
    assert ctx.evidence["google_key_candidates"] == 0


def test_an_empty_bundle_is_na(bundle, provider):
    bundle("   ")
    provider({})
    assert probes.gemini_key_live_in_bundle(_Ctx(), None) is None


def test_it_stops_at_the_first_live_key(bundle, provider):
    """Each check spends a request against someone's quota, and the finding is 'at least one is live'."""
    bundle(f'a="{_OTHER}";b="{_LIVE}";')
    asked = provider({_LIVE: True, _OTHER: True})
    assert probes.gemini_key_live_in_bundle(_Ctx(), None) is True
    assert len(asked) == 1                                 # the first hit settles it


def test_it_caps_how_many_keys_it_checks(bundle, provider):
    keys = ["AIza" + f"Sy{i}" + "Ab3Cd9Ef2Gh8Ij4Kl7Mn1Op5Qr6S"[:32] for i in range(6)]
    bundle(";".join(f'k{i}="{k}"' for i, k in enumerate(keys)))
    asked = provider({})                                   # all refused, so it walks the list
    probes.gemini_key_live_in_bundle(_Ctx(), None)
    assert len(asked) <= probes._MAX_GOOGLE_KEY_CHECKS


# ── wiring ──────────────────────────────────────────────────────────────────────────────────────────────
def test_the_probe_is_active_battery_only():
    """It spends a request against the app owner's own credential, so it belongs where ownership was
    attested, never in the passive lane that grades a stranger's URL."""
    cat = load_catalog("catalog")
    assert "sec-secrets-003" in {p.id for p in cat}
    assert "sec-secrets-003" not in {p.id for p in safety.passive_catalog(cat)}
    assert not safety.is_passive("sec-secrets-003")


def test_confirmation_resolves_to_the_validated_live_rung():
    """validated_live was defined in the ladder at 92 and nothing had ever been able to set it."""
    probe = next(p for p in load_catalog("catalog") if p.id == "sec-secrets-003")
    assert _severity_penalty(probe.severity, {"validated_live": True}) == 92
    assert _severity_penalty(probe.severity, {}) == 70      # unconfirmed stays at the floor
