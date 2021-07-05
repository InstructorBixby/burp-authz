"""Write the results table out as csv. No burp imports."""

import csv
import io

from authzlib.table import COLUMNS


def to_csv(rows):
    """Return the table as a csv string.

    jython 2.7 has the python 2 csv module, which writes bytes, so
    this builds the text itself rather than fighting with it.
    """
    out = []
    out.append(",".join(_quote(c) for c in COLUMNS))
    for row in rows:
        out.append(",".join(_quote(v) for v in row))
    return "\n".join(out) + "\n"


def _quote(value):
    text = u"%s" % (value,)
    if '"' in text or "," in text or "\n" in text:
        return '"' + text.replace('"', '""') + '"'
    return text


def write(path, rows):
    fh = open(path, "w")
    try:
        fh.write(to_csv(rows))
    finally:
        fh.close()
