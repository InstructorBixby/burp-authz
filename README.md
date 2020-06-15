# burp-authz

burp extension for checking authorization. the idea is to take a
request i already made as an admin, send it again as a low privilege
user, and tell me if the server actually cared.

doing it in jython because i can write python and i cannot write java.
