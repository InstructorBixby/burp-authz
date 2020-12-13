"""Header list rewriting. Burp hands you headers as a list of
strings, so this is all plain string work and can be tested."""


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
