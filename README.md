# burp-authz

Burp extension for authorization testing. Takes a request you made as
a privileged user, replays it as a second user and as nobody at all,
and tells you whether the server noticed.

This is basically a worse Autorize. I wanted to understand how one of
these works, and writing one is how I learn an API.

## install

See [docs/install.md](docs/install.md). Short version: point Burp at a
Jython 2.7 standalone jar, then load `authz.py` as a Python extension.

## how it reads

| result | meaning |
| --- | --- |
| `same` | the other session got the same answer. look at this by hand |
| `similar` | same page once csrf tokens and timestamps are scrubbed |
| `blocked` | 401, 403, a login page, or a redirect to one |
| `different` | something else came back |
| `error` | no response, usually the host went away |

A `same` is a lead, not a finding. The extension cannot tell the
difference between a missing authorization check and an endpoint that
is genuinely public.

## layout

    authz.py              the file Burp loads: callbacks, listeners, tab
    authzlib/ui.py        swing layout
    authzlib/table.py     table model and renderer
    authzlib/worker.py    thread pool wrapper
    authzlib/compare.py   what two responses mean
    authzlib/headers.py   header list rewriting
    authzlib/filters.py   which requests are worth replaying
    authzlib/export.py    csv

The last four import nothing from burp or java, which is the only
reason any of this is testable:

    python3 -m pytest -q

## jython

Burp runs Python extensions on Jython, which is Python 2.7 and is
never going to be anything else. Everything the extension loads is
2.7 syntax, the stdlib in the standalone jar is the Python 2 one, and
the tests are the only place Python 3 appears. It works, and I would
rather not do the next one this way; the next extension I write is
going to be Java so I can have a build, a type checker and a test
runner that live in the same place as the code.
