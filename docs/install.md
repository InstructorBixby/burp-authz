# installing

## jython

Burp needs a standalone Jython jar to run Python extensions. 2.7.2 is
the one I use.

1. download `jython-standalone-2.7.2.jar`
2. Burp -> Extender -> Options -> Python Environment -> point
   "Location of Jython standalone JAR file" at it
3. in the same panel, set the folder for loading modules to the
   directory holding `authz.py`. Burp puts that folder on `sys.path`,
   which is a second belt to the `sys.path.insert` at the top of
   `authz.py`

## the extension

Extender -> Extensions -> Add

- Extension type: Python
- Extension file: `authz.py`

It should print `authz 0.4.0 loaded` to Output. If instead you get an
`ImportError: No module named authzlib`, the module folder in the
Python Environment options is not set and `__file__` was not what I
expected on your platform. Setting the folder fixes it.

## first run

1. log in as the privileged user in the browser Burp is proxying
2. log in as the low privilege user in a second browser profile, copy
   its `Cookie` header out of any request
3. paste that into the authz tab, one header per line, press save
4. set the Burp target scope to the app and nothing else
5. right click a request -> Send to authz

A `same` in the "as lowpriv" or "as nobody" column means the other
session got the same answer the privileged one did. That is the thing
worth looking at by hand; the extension is not evidence on its own.
