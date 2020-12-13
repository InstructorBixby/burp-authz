"""Guts of the authz extension.

compare.py and headers.py must not import burp or java. they hold the
only logic worth testing and pytest cannot load anything that needs
the burp jar. that also means they have to stay valid python 2, since
jython runs them as 2.7 inside burp.
"""

VERSION = "0.4.0"
