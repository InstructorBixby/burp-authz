"""Which requests are worth replaying. No burp imports so it can be
tested; the extension passes in strings it has already pulled out of
the request."""

STATIC = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
          ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4",
          ".webp", ".pdf")


def is_static(path):
    path = (path or "").lower().split("?")[0]
    for ext in STATIC:
        if path.endswith(ext):
            return True
    return False


def interesting(method, path):
    """True when this request is worth sending as another user."""
    if is_static(path):
        return False
    return True
