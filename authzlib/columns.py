"""Result table columns.

Its own module because the swing table and the csv writer both need
it, and `from authzlib.table import COLUMNS` quietly pulled
javax.swing into export.py, so test_export.py could not be collected
outside burp.
"""

COLUMNS = ["#", "method", "url", "status", "as lowpriv", "as nobody"]

# the two columns holding a result, for the renderer
RESULT_COLUMNS = (4, 5)
