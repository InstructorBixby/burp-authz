"""Deciding what two responses mean. No burp imports, see
authzlib/__init__.py."""

import difflib
import re

SAME = "same"
SIMILAR = "similar"
DIFFERENT = "different"
ERROR = "error"

SIMILAR_RATIO = 0.95

# things that change on every response and say nothing about whether
# the request was authorized
NOISE = [
    re.compile(r'name=["\']_?csrf[^"\']*["\']\s+value=["\'][^"\']+["\']',
               re.I),
    re.compile(r'"csrf_?token"\s*:\s*"[^"]+"', re.I),
    re.compile(r'<input[^>]+name=["\']authenticity_token["\'][^>]*>',
               re.I),
]


def scrub(body):
    """Blank out per response noise so two renders of the same page
    compare equal."""
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


def classify(original_body, replay_body, limit=8192):
    """Compare two response bodies.

    same      identical once the per response noise is removed
    similar   close enough that it is probably the same page
    different something changed, needs a human
    error     no response at all
    """
    if replay_body is None:
        return ERROR
    a = scrub(original_body)
    b = scrub(replay_body)
    if a == b:
        return SAME
    if similarity(a[:limit], b[:limit]) >= SIMILAR_RATIO:
        return SIMILAR
    return DIFFERENT
