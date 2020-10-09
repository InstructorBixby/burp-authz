# burp-authz

burp extension for checking authorization. it takes a request i have
already made as one user, sends it again with another users session,
and tells me whether the server cared.

this is basically a worse Autorize. i wanted to understand how one of
these works, and reading the extender api by writing something is how
i learn.

## using it

1. Extender -> Extensions -> Add -> Extension type: Python, pick
   `authz.py`
2. set the target scope in Burp, the extension only touches urls that
   are in scope
3. put the low privilege session cookie at the top of `authz.py`
4. browse as the high privilege user and watch the Output tab

## state

- cookie is hardcoded at the top of the file
- output goes to stdout, no ui yet
- "same" means the two responses had the same number of bytes, which
  is a very rough test

## jython

burp runs python extensions on jython, which is python 2.7 and is not
going to be anything else. so no f-strings and no python 3 standard
library in here.
