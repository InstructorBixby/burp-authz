"""Result table columns.

Its own module because the swing table and the csv writer both need
it, and `from authzlib.table import COLUMNS` quietly pulled
javax.swing into export.py, so test_export.py could not be collected
outside burp.
"""

COLUMNS = ["#", "method", "url", "result", "orig status",
           "lowpriv status"]

RESULT_COLUMN = 3
