"""Guts of the authz extension.

compare.py, headers.py, filters.py and export.py must not import burp
or java. They hold the only logic worth testing and pytest cannot load
anything that needs the burp jar. That also means they have to stay
valid python 2, since jython runs them as 2.7 inside burp.
"""

VERSION = "1.0.0"
