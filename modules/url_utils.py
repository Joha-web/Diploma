"""
Shared URL helpers.

`redirect_host` resolves a redirect target's host the way a *browser* would, so
the common open-redirect filter-bypass forms are not missed. Python's urlparse
disagrees with browser behaviour on several of them (e.g. `////host`,
`https:host`, `//host\\@other`), which silently breaks redirect/SSRF detectors —
centralised here so open_redirect_probe and oauth_probe share one correct copy.
"""

from __future__ import annotations

import re

_SCHEME_AND_SLASHES_RE = re.compile(r"\s*(?:[a-z][a-z0-9+.\-]*:)?/*", re.I)


def redirect_host(location: str) -> str:
    """Lowercased host of a redirect target, browser-style.

    Handles: backslashes acting as slashes, leading-slash collapse
    (`////host` → `//host`), missing-slash schemes (`https:host`), and
    `userinfo@host` (resolves to host). Returns '' when no host is present.
    """
    loc = str(location or "").strip().replace("\\", "/")
    match = _SCHEME_AND_SLASHES_RE.match(loc)
    rest = loc[match.end():]
    host_part = re.split(r"[/?#]", rest, maxsplit=1)[0]
    if "@" in host_part:                       # userinfo@host → the real host
        host_part = host_part.rsplit("@", 1)[1]
    return host_part.split(":", 1)[0].strip().strip(".").lower()
