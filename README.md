# burp-authz

Burp extension for authorization testing. It takes a request made as
one user, replays it with another user's session, and tells me whether
the server cared.

This is basically a worse Autorize. I wanted to understand how one of
these works, and writing one is how I learn an API.

## using it

1. Extender -> Extensions -> Add -> Extension type: Python, pick
   `authz.py`
2. paste the low privilege session headers into the authz tab, one per
   line, and hit save
3. right click a request anywhere in Burp -> "Send to authz", or tick
   the passive box to replay everything in scope as you browse
4. results land in the table

## layout

    authz.py           the extension burp loads
    authzlib/table.py  swing table model
    authzlib/compare.py, authzlib/headers.py
                       no burp or java imports, so pytest can run them

## tests

    python3 -m pytest -q

## jython

Burp runs Python extensions on Jython, which is Python 2.7 and is
never going to be anything else. So `authz.py` and everything under
`authzlib/` is 2.7 syntax, and the tests are the only place Python 3
shows up.
