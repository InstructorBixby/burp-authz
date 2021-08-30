"""Deciding what two responses mean. No burp imports, see
authzlib/__init__.py."""

import difflib
import re

SAME = "same"
SIMILAR = "similar"
DIFFERENT = "different"
BLOCKED = "blocked"
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

# plenty of apps answer an unauthorized request with 200 and the login
# form, so status alone is not enough to spot a rejection
LOGIN_MARKERS = [
    re.compile(r'<input[^>]+type=["\']password["\']', re.I),
    re.compile(r'name=["\'](password|passwd|j_password)["\']', re.I),
    re.compile(r'\b(sign in|log ?in) to continue\b', re.I),
]

LOGIN_PATHS = ("/login", "/signin", "/sign_in", "/auth/login",
               "/account/login", "/sessions/new")


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


def looks_like_login(body):
    if not body:
        return False
    for pattern in LOGIN_MARKERS:
        if pattern.search(body):
            return True
    return False


def is_login_redirect(location):
    if not location:
        return False
    path = location.split("?")[0].rstrip("/").lower()
    for known in LOGIN_PATHS:
        if path.endswith(known):
            return True
    return False


def classify(original, replay, limit=8192):
    """Compare two responses.

    `original` and `replay` are (status, headers, body) tuples, with
    replay allowed to be None when the request failed outright.

    same      the other session got the same answer. look at this one
    similar   close enough that it is probably the same page
    blocked   the server sent them to a login page instead
    different something else came back
    error     no response at all
    """
    if replay is None:
        return ERROR
    o_status, o_headers, o_body = original
    r_status, r_headers, r_body = replay

    if 300 <= r_status < 400:
        r_loc = header(r_headers, "location")
        if is_login_redirect(r_loc):
            return BLOCKED
        if o_status == r_status:
            return (SAME if header(o_headers, "location") == r_loc
                    else DIFFERENT)
        return DIFFERENT

    if looks_like_login(r_body) and not looks_like_login(o_body):
        return BLOCKED
    if r_status in (401, 403):
        return BLOCKED
    if o_status != r_status:
        return DIFFERENT

    a = scrub(o_body)
    b = scrub(r_body)
    if a == b:
        return SAME
    if similarity(a[:limit], b[:limit]) >= SIMILAR_RATIO:
        return SIMILAR
    return DIFFERENT
