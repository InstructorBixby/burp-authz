"""Deciding what two responses mean. No burp imports, see
authzlib/__init__.py."""

import difflib
import re

SAME = "same"
SIMILAR = "similar"
DIFFERENT = "different"
ERROR = "error"

SIMILAR_RATIO = 0.95

NOISE = [
    re.compile(r'name=["\']_?csrf[^"\']*["\']\s+value=["\'][^"\']+["\']',
               re.I),
    re.compile(r'"csrf_?token"\s*:\s*"[^"]+"', re.I),
    re.compile(r'<input[^>]+name=["\']authenticity_token["\'][^>]*>',
               re.I),
    re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?Z?'),
    re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-'
               r'[0-9a-f]{4}-[0-9a-f]{12}', re.I),
    re.compile(r'\bnonce=["\'][^"\']+["\']', re.I),
]


def scrub(body):
    if not body:
        return body
    for pattern in NOISE:
        body = pattern.sub("", body)
    return body


def similarity(a, b):
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def header(headers, name):
    name = name.lower() + ":"
    for h in headers or []:
        if h.lower().startswith(name):
            return h.split(":", 1)[1].strip()
    return None


def classify(original, replay, limit=8192):
    """Compare two responses.

    `original` and `replay` are (status, headers, body) tuples, with
    replay allowed to be None when the request failed outright.

    A 302 to /login has the same length as a 302 to /dashboard, which
    is how the length-only version called every redirect "same".
    """
    if replay is None:
        return ERROR
    o_status, o_headers, o_body = original
    r_status, r_headers, r_body = replay

    if o_status != r_status:
        return DIFFERENT
    if 300 <= r_status < 400:
        o_loc = header(o_headers, "location")
        r_loc = header(r_headers, "location")
        return SAME if o_loc == r_loc else DIFFERENT

    a = scrub(o_body)
    b = scrub(r_body)
    if a == b:
        return SAME
    if similarity(a[:limit], b[:limit]) >= SIMILAR_RATIO:
        return SIMILAR
    return DIFFERENT
