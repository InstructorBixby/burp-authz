"""Header list rewriting. Burp hands you headers as a list of
strings, so this is all plain string work and can be tested."""

# anything that could carry identity. missing one of these means the
# "unauthenticated" run is not actually unauthenticated, which would
# be a false negative, so this list is deliberately wide
SESSION_HEADERS = (
    "cookie",
    "authorization",
    "x-csrf-token",
    "x-xsrf-token",
    "x-auth-token",
    "x-api-key",
    "api-key",
    "x-access-token",
)


def name_of(header):
    return header.split(":", 1)[0].strip().lower()


def drop(headers, names):
    wanted = set(n.lower() for n in names)
    return [h for h in headers if name_of(h) not in wanted]


def replace(headers, replacements):
    """Swap in the given headers, keeping the request line first."""
    if not headers:
        return list(replacements)
    request_line = headers[0]
    rest = drop(headers[1:], [name_of(r) for r in replacements])
    return [request_line] + rest + list(replacements)


def strip_session(headers):
    """Remove everything that identifies a user."""
    if not headers:
        return []
    return [headers[0]] + drop(headers[1:], SESSION_HEADERS)
