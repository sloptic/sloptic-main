"""The render-hang watchdog. render_routes' total_timeout is only checked BETWEEN routes, so a single wedged
op (a goto on a CPU-spun renderer whose Playwright timeout never fires) escapes it and burns to the 900s
external grade kill, leaving an empty record (measured: ~8% of a corpus). _kill_browser_on_stall force-kills
the browser's descendants at the deadline so the blocked call raises and render returns partial. No browser
needed here -- these exercise the /proc descendant walk + the timer against a plain `sleep` child."""
import os
import subprocess
import time

from sloptic import browser


def test_descendant_pids_finds_a_child_and_its_grandchild():
    # bash -> sleep: the sleep is a GRANDCHILD, so a direct-children-only walk would miss it; the BFS must not.
    # The compound command (";true") stops bash from exec-optimizing into sleep, so it really forks a grandchild.
    p = subprocess.Popen(["bash", "-c", "sleep 30 ; true"])
    try:
        time.sleep(0.3)                                  # let bash spawn the sleep grandchild
        desc = browser._descendant_pids(os.getpid())
        assert p.pid in desc                             # the bash child
        assert len(desc) >= 2                            # + the sleep grandchild (BFS reached past direct children)
    finally:
        p.kill()
        p.wait()


def test_kill_browser_on_stall_fires_and_kills_a_wedged_descendant():
    p = subprocess.Popen(["sleep", "60"])                # stands in for a wedged chromium
    try:
        with browser._kill_browser_on_stall(0.3) as hung:
            end = time.monotonic() + 5                    # 'blocked in a render call' until the watchdog kills it
            while p.poll() is None and time.monotonic() < end:
                time.sleep(0.05)
        assert hung["v"] is True                          # the watchdog fired
        assert p.poll() is not None                       # and killed the descendant
    finally:
        if p.poll() is None:
            p.kill()
        p.wait()


def test_kill_browser_on_stall_does_not_fire_when_the_block_is_fast():
    p = subprocess.Popen(["sleep", "30"])                # an innocent child a fast render must NOT kill
    try:
        with browser._kill_browser_on_stall(5.0) as hung:
            pass                                          # returns immediately -> the timer is cancelled
        time.sleep(0.1)
        assert hung["v"] is False
        assert p.poll() is None                           # not killed
    finally:
        p.kill()
        p.wait()


def test_browser_guarded_decorator_kills_a_wedged_lane(monkeypatch):
    # _browser_guarded arms the watchdog around a whole browser lane: if it runs past the deadline (a wedged
    # renderer), the browser descendants are killed so the blocked call raises. Here a sleep stands in for the
    # wedged chromium; the decorated lane must not outlast the (shortened) deadline.
    monkeypatch.setattr(browser, "_BROWSER_LANE_DEADLINE", 0.3)
    holder = {}

    @browser._browser_guarded
    def _fake_lane():
        p = subprocess.Popen(["sleep", "60"])          # stands in for a wedged chromium descendant
        holder["p"] = p
        end = time.monotonic() + 5
        while p.poll() is None and time.monotonic() < end:
            time.sleep(0.05)                            # 'blocked in the wedged browser call'
        return "returned"

    assert _fake_lane() == "returned"                   # the lane returns (its call unblocked by the kill)
    p = holder["p"]
    try:
        assert p.poll() is not None                     # the decorator's watchdog killed the descendant
    finally:
        if p.poll() is None:
            p.kill()
        p.wait()


def test_reveal_hidden_controls_breaks_on_a_passed_deadline():
    # the GIL-cooperative guard: a wall-clock deadline checked BETWEEN elements exits the reveal loop even when a
    # thread-watchdog can't fire (GIL held by a huge DOM deserialize). A past deadline -> break before any element.
    class _P:
        def eval_on_selector_all(self, sel, js):
            return []                                    # no baseline controls

        def query_selector_all(self, sel):
            return [object(), object(), object()]        # non-empty triggers; must NOT be touched
    out = browser._reveal_hidden_controls(_P(), deadline=time.monotonic() - 1)
    assert out == ""                                     # broke immediately, clicked nothing
