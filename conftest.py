# so pytest can import authzlib from the repo root. the extension does
# the same thing with sys.path when burp loads it
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
