"""Target scoping: a third-party link (reddit/discord/github/...) must never be graded or actively probed —
the airtight guard that keeps the fuzzer from firing brute-force/injection at a real production site."""
from hacklet_runner.scope import off_target


def test_off_target_flags_third_party_links():
    # the reddit case that actually slipped through in the Bolt scout, plus the rest of the deny-list
    assert off_target("https://www.reddit.com/r/vibecoding/comments/x") == "reddit.com"
    for u in ["https://reddit.com/r/x", "http://discord.gg/abc", "https://discord.com/invite/x",
              "https://twitter.com/x", "https://x.com/y", "https://youtu.be/abc", "https://vimeo.com/1",
              "https://www.linkedin.com/in/x", "https://figma.com/file/x", "https://t.me/x",
              "https://instagram.com/x", "https://www.tiktok.com/@x", "devpost.com/software/x"]:
        assert off_target(u), u                        # denied -> returns the matched domain (truthy)


def test_off_target_allows_real_app_hosts():
    for u in ["https://myapp.netlify.app/", "https://cool-thing.vercel.app", "https://example.com",
              "https://app.fly.dev/", "https://my-app.onrender.com", "https://foo.pages.dev"]:
        assert off_target(u) is None, u                # a real deployment host -> gradeable
    # the sharp edge: github.com is a REPO (denied), github.io is a real Pages DEPLOYMENT (allowed)
    assert off_target("https://github.com/user/repo") == "github.com"
    assert off_target("https://alice.github.io/project") is None


def test_off_target_handles_junk_without_raising():
    for u in ["", "not a url", "mailto:x@y.com", "ftp://h/x"]:
        assert off_target(u) is None
