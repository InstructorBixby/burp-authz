"""Write the results table out as csv. No burp imports."""

from authzlib.columns import COLUMNS


def _quote(value):
    text = u"%s" % (value,)
    if '"' in text or "," in text or "\n" in text:
        return '"' + text.replace('"', '""') + '"'
    return text


def to_csv(rows):
    """Return the table as a csv string.

    The stdlib csv module in jython 2.7 wants byte strings and a file
    object, and the rows here are unicode, so the quoting is done by
    hand instead.
    """
    lines = [",".join(_quote(c) for c in COLUMNS)]
    for row in rows:
        lines.append(",".join(_quote(v) for v in row))
    return "\n".join(lines) + "\n"


def write(path, rows):
    fh = open(path, "w")
    try:
        fh.write(to_csv(rows))
    finally:
        fh.close()
