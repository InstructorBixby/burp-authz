"""Deciding what two responses mean. No burp imports, see
authzlib/__init__.py."""

import difflib

SAME = "same"
SIMILAR = "similar"
DIFFERENT = "different"
ERROR = "error"

# two responses this close are the same page with a different
# timestamp or csrf token in it
SIMILAR_RATIO = 0.95


def similarity(a, b):
    """0.0 .. 1.0. SequenceMatcher is slow on big bodies, so this
    only ever sees the first few kilobytes, see classify()."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def classify(original_body, replay_body, limit=8192):
    """Compare two response bodies.

    same      byte for byte identical, the server did not check
    similar   close enough that it is probably the same page
    different something changed, needs a human
    error     no response at all
    """
    if replay_body is None:
        return ERROR
    if original_body == replay_body:
        return SAME
    ratio = similarity(original_body[:limit], replay_body[:limit])
    if ratio >= SIMILAR_RATIO:
        return SIMILAR
    return DIFFERENT
