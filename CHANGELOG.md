# changelog

## 1.0.0

- second profile: every request is also replayed with all session
  headers stripped ("as nobody")
- `blocked` as a distinct result, including 200 responses that are
  really the login page and 302s to a login path
- csv export
- results coloured by outcome
- `authzlib/filters.py`, with tests
- docs/install.md

## 0.4.0

- split into `authz.py` plus `authzlib/`, with `compare.py`,
  `headers.py`, `filters.py` and `export.py` free of Burp imports so
  pytest can reach them
- worker pool, so replays no longer block Burp's proxy thread
- comparison looks at status, Location and the scrubbed body instead
  of the response length
- csrf tokens, timestamps and uuids scrubbed before comparing
- settings persisted with saveExtensionSetting

## 0.3.0

- Swing tab with a results table
- context menu entry, so requests can be sent from anywhere in Burp
- scope check and a static file filter

## 0.2.0

- replays with a hardcoded cookie and compares response lengths
- output to Burp's own stdout stream

## 0.1.0

- prints every request it sees
