"""The fail-loud browser preflight. browser_preflight() reports whether chromium can actually LAUNCH
(not merely whether playwright imports), so the CLIs abort with an actionable message instead of silently
grading every app browser-less — the failure that turned a browser run into a static-only one. These mock
_launch, so they run even when no real browser BINARY is present (which is exactly when the preflight
matters). They still need the playwright PACKAGE, because browser_preflight() imports it before it ever
reaches _launch: without it the function short-circuits on the import error and never exercises the path
under test. playwright ships in the optional `browser` dependency group, so a default `uv sync` omits it,
and these two skip rather than fail there (a clean checkout must read green, like every other browser
test here)."""
import importlib.util

import pytest

from hacklet_runner import browser

needs_playwright = pytest.mark.skipif(
    importlib.util.find_spec("playwright") is None,
    reason="playwright not installed (optional 'browser' dependency group: uv sync --group browser)")


def test_launch_records_its_last_failure():
    # _launch tries each channel; on total failure it leaves the last exception in _LAST_LAUNCH_ERROR so the
    # preflight can report WHY (the old code swallowed it silently and returned None = "no browser").
    class _P:
        class chromium:
            @staticmethod
            def launch(**kw):
                raise RuntimeError("boom-" + str(kw.get("channel", "default")))
    assert browser._launch(_P) is None
    assert "RuntimeError" in browser._LAST_LAUNCH_ERROR and "boom-" in browser._LAST_LAUNCH_ERROR


@needs_playwright
def test_preflight_flags_a_broken_launch(monkeypatch):
    monkeypatch.setattr(browser, "_LAST_LAUNCH_ERROR", "Error: Executable doesn't exist at chrome-headless-shell")
    monkeypatch.setattr(browser, "_launch", lambda p: None)          # every channel failed
    ok, detail = browser.browser_preflight()
    assert ok is False and "Executable" in detail
    assert browser.browser_available() is False                      # the bool form agrees (real check, not import)


@needs_playwright
def test_preflight_ok_when_a_channel_launches(monkeypatch):
    class _FakeBrowser:
        version = "138.0.7204.0"
        def close(self):
            pass
    monkeypatch.setattr(browser, "_launch", lambda p: _FakeBrowser())
    ok, detail = browser.browser_preflight()
    assert ok is True and "138.0" in detail
    assert browser.browser_available() is True
