"""Pure detection logic for the Streamlit render-await. The browser-driven await itself is validated live
(it needs a real Chromium + a websocket-rendering app); these lock the wake / error / ready signals and the
cheap host gate so they can't silently drift, and run without a browser."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from sloptic.browser import _ST_ERROR, _ST_SLEEP, _looks_streamlit  # noqa: E402


def test_sleep_page_phrases_match():
    assert _ST_SLEEP.search("This app has gone to sleep due to inactivity")
    assert _ST_SLEEP.search("Yes, get this app back up!")
    assert not _ST_SLEEP.search("a perfectly awake dashboard with data")


def test_error_screen_phrases_match():
    for t in ("Oh no. Error running app.", "Error running app.", "Connection error"):
        assert _ST_ERROR.search(t)
    assert not _ST_ERROR.search("no errors here, everything rendered fine")


def test_host_gate_matches_streamlit_without_touching_a_page():
    # the *.streamlit.app branch returns True before it ever touches `page`, so page=None is safe
    assert _looks_streamlit(None, "https://crystal-ball.streamlit.app/")
    assert _looks_streamlit(None, "https://foo-bar-xyz.streamlit.app")


def test_host_gate_rejects_non_streamlit_and_never_raises():
    # a non-streamlit host falls through to the DOM probe; with page=None that safely returns False, never raises
    assert not _looks_streamlit(None, "https://myapp.vercel.app/")
    assert not _looks_streamlit(None, "")
