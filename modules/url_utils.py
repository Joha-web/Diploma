"""
Shared URL helpers.

`redirect_host` resolves a redirect target's host the way a *browser* would, so
the common open-redirect filter-bypass forms are not missed. Python's urlparse
disagrees with browser behaviour on several of them (e.g. `////host`,
`https:host`, `//host\\@other`, and TAB/newline obfuscation), which silently
breaks redirect/SSRF detectors — centralised here so open_redirect_probe and
oauth_probe share one correct copy.

`same_site` is the host-scope check (exact host or a proper subdomain) used by
crawlers/probes to keep third-party hosts out of in-scope results.
"""

from __future__ import annotations

import re

# Browsers (per the WHATWG URL spec) remove ASCII TAB / LF / CR from anywhere in
# a URL before parsing, so "//attac\tker.com" navigates to attacker.com. Strip
# them first or an attacker can hide the real host from the detector.
_URL_STRIP_RE = re.compile(r"[\t\n\r]")
# Optional scheme, then any run of slashes, then the remainder.
_SCHEME_RE = re.compile(r"\s*([a-z][a-z0-9+.\-]*:)?(/*)(.*)", re.I | re.DOTALL)


def redirect_host(location: str) -> str:
    """Lowercased host of a redirect target, browser-style.

    Handles: TAB/newline removal, backslashes acting as slashes, leading-slash
    collapse (`////host` → host), missing-slash schemes (`https:host`), and
    `userinfo@host` (resolves to host). Returns '' when there is no host — which
    includes a bare path-absolute reference like `/dashboard` (single leading
    slash with no scheme is a path, not an authority).
    """
    loc = _URL_STRIP_RE.sub("", str(location or "")).strip().replace("\\", "/")
    match = _SCHEME_RE.match(loc)
    if not match:
        return ""
    scheme, slashes, rest = match.group(1), match.group(2), match.group(3)
    # An authority/host follows only when a scheme is present (`https:host`,
    # `https://host`) or the target is protocol-relative (`//host`, 2+ slashes).
    # A single leading slash with no scheme is a same-origin path.
    if not scheme and len(slashes) < 2:
        return ""
    host_part = re.split(r"[/?#]", rest, maxsplit=1)[0]
    if "@" in host_part:                       # userinfo@host → the real host
        host_part = host_part.rsplit("@", 1)[1]
    return host_part.split(":", 1)[0].strip().strip(".").lower()


def same_site(host: str, base: str) -> bool:
    """True only for the exact host or a proper subdomain of `base`.

    A bare ``host.endswith(base)`` would match ``notexample.com`` against
    ``example.com``, and ``endswith("")`` matches everything — both pull
    third-party hosts into in-scope results. Comparison is case-insensitive and
    tolerant of a trailing dot (FQDN form).
    """
    host = str(host or "").strip().strip(".").lower()
    base = str(base or "").strip().strip(".").lower()
    if not host or not base:
        return False
    return host == base or host.endswith("." + base)
