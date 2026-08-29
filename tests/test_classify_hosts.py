"""Host attribution (_classify_hosts): WHOSE is each off-origin host the app's traffic hits. The line between
'own_backend' (the app's responsibility -> probe it) and 'opaque' (unattributable -> never probe, for safety)
must be tight in BOTH directions: attribute the student's real backend (per-project PaaS, sibling deploys),
but NEVER a third party, even when it shares a common word with the app name."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from sloptic.discovery import _classify_hosts  # noqa: E402


def _obs(*urls):
    return [("GET", u, None) for u in urls]


def test_per_project_backend_paas_is_own():
    for be in ("https://user--app.modal.run/api", "https://willhedges-asl-api.hf.space/predict",
               "https://myapp.ondigitalocean.app/api", "https://x.azurewebsites.net/",
               "https://y.us-east-1.elasticbeanstalk.com/", "https://z.pythonanywhere.com/"):
        c = _classify_hosts(_obs(be), "https://front.vercel.app")
        assert c["counts"]["own_backend"] == 1, be
        assert c["counts"]["opaque"] == 0, be


def test_sibling_deploy_attributed_by_distinctive_name():
    assert _classify_hosts(_obs("https://beatsaber-backend.vercel.app/api"),
                           "https://beatsaber-frontend.vercel.app")["counts"]["own_backend"] == 1
    assert _classify_hosts(_obs("https://replate-api.vercel.app/x"),
                           "https://replate-web.vercel.app")["counts"]["own_backend"] == 1


def test_third_party_sharing_a_common_word_is_NOT_attributed():
    # "health" is shared, but health-cdn.com is not a deploy host -> must stay opaque, never probed
    c = _classify_hosts(_obs("https://health-cdn.com/lib.js"), "https://health-tracker.vercel.app")
    assert c["counts"]["own_backend"] == 0
    assert c["counts"]["opaque"] == 1


def test_generic_tokens_never_match():
    # frontend/backend/api/app are generic -> two UNRELATED apps sharing only those must not cross-attribute
    c = _classify_hosts(_obs("https://someone-backend.vercel.app/api"), "https://myproject-frontend.vercel.app")
    assert c["counts"]["own_backend"] == 0
    assert c["counts"]["opaque"] == 1


def test_known_vendor_stays_vendor_and_unrelated_stays_opaque():
    c = _classify_hosts(_obs("https://api.stripe.com/v1/x", "https://random-unrelated.io/y"),
                        "https://myapp.vercel.app")
    assert c["counts"]["vendor"] >= 1        # stripe.com is a known consumed vendor -> never probed
    assert c["counts"]["opaque"] >= 1        # random-unrelated.io -> unattributable -> opaque, never probed
