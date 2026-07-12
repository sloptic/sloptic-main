"""Target scoping: is a URL the submission's OWN deployed app, or a third-party link that must NEVER be
graded or actively probed? A Devpost project page links the demo alongside social/community/video/repo
links; ingesting one of those means firing active security probes (brute-force login, injection, ...) at
a real third-party production site — an authorization problem AND meaningless data. This is the single
authoritative deny-list, used both by the scraper (drop off-target live-URLs) and as an airtight guard in
deploy_and_grade (a --url ingest of a denied host is recorded out-of-scope, never even fetched).

Deny-list, not allow-list: it targets the HIGH-RISK, high-frequency non-app hosts (social, chat, code,
video/doc/design, the hackathon platform). A stray portfolio link can still slip through — low harm (a
static page), and the list is trivially extended. Registrable domains only; a real app on a subdomain of
an app host (myapp.netlify.app, alice.github.io) is NOT matched — note github.com (a repo) is denied but
github.io (a real Pages deployment) is not.
"""
from urllib.parse import urlparse

OFF_TARGET_HOSTS = frozenset({
    # social — interactive third-party sites we must never actively probe
    "reddit.com", "twitter.com", "x.com", "facebook.com", "instagram.com", "threads.net",
    "linkedin.com", "tiktok.com", "twitch.tv", "mastodon.social", "bsky.app", "pinterest.com",
    # chat / community
    "discord.com", "discord.gg", "slack.com", "t.me", "telegram.me", "whatsapp.com",
    # code / project hosts — a repo to clone, never a deployed app to probe (github.io IS an app host)
    "github.com", "gitlab.com", "bitbucket.org",
    # video / slides / docs / design — a demo ARTIFACT, not an app
    "youtube.com", "youtu.be", "vimeo.com", "loom.com", "figma.com", "canva.com", "pitch.com",
    "docs.google.com", "drive.google.com", "dropbox.com", "notion.so", "notion.site", "slideshare.net",
    # platform / publishing
    "devpost.com", "medium.com", "producthunt.com", "substack.com",
})


def off_target(url: str) -> str | None:
    """The matched deny-list domain if `url` is a known non-app third-party link (so it must not be graded
    or probed), else None (a gradeable app URL). Matches the host exactly or as a subdomain of a denied
    registrable domain — myapp.netlify.app / alice.github.io are NOT matched; www.reddit.com IS."""
    try:
        host = (urlparse(url if "://" in url else "https://" + url).hostname or "").lower()
    except Exception:
        return None
    if not host:
        return None
    for d in OFF_TARGET_HOSTS:
        if host == d or host.endswith("." + d):
            return d
    return None
