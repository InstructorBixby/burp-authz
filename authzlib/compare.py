"""Deciding what two responses mean. No burp imports, see
authzlib/__init__.py."""

SAME = "same"
DIFFERENT = "different"
ERROR = "error"


def classify(original_len, replay_len):
    """Compare two response sizes.

    same      the other session got the same bytes back, so the server
              probably never checked who was asking
    different something changed, needs a human
    error     no response at all
    """
    if replay_len is None:
        return ERROR
    if original_len == replay_len:
        return SAME
    return DIFFERENT
