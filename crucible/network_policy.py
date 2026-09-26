"""Exact read-only fetches permitted to shared registry infrastructure."""

SAFE_FETCH_URLS = frozenset({
    "https://pypi.org/simple/",
    "https://registry.npmjs.org/-/ping",
})
