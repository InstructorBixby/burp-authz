# notes

## burp extender api

- the class has to be called `BurpExtender` and implement
  `IBurpExtender`. Burp finds it by reflection.
- `registerExtenderCallbacks` is the only entry point. Anything you
  want to keep hangs off `self` there.
- `processHttpMessage` fires twice per request (`messageIsRequest`
  True then False).
- there is no "set header" helper. You rebuild the whole header list
  and call `buildHttpMessage`. Header zero is the request line.
- `makeHttpRequest` is synchronous, so calling it from
  `processHttpMessage` blocks Burp's own proxy thread. That is what
  the worker pool is for.
- `loadExtensionSetting` returns null the first time, and only stores
  strings, so multi line settings get escaped by hand.
- settings are per project. Moving to a new project file means
  re-pasting the cookie.

## jython

- 2.7 only, forever. No f-strings, no `pathlib`, no `typing`.
- `__file__` is set for the extension, so the extension directory can
  be worked out and pushed onto `sys.path`. Without that,
  `from authzlib import ...` cannot find anything, because Burp loads
  the file by path and not as part of a package.
- requests and responses are java `byte[]`. Slicing them in Jython
  gives an array back, which is what `buildHttpMessage` wants, so do
  not helpfully convert it to a string on the way through. For reading
  a body as text, `helpers.bytesToString`.
- an exception thrown inside a pool thread disappears without a trace.
  Everything submitted goes through `worker.Task`, which catches and
  prints, or the result is a table that silently stops filling.
- the stdlib that ships in the standalone jar is the python 2 one, so
  `csv` writes bytes and fights with unicode. Easier to format the
  three lines of csv by hand.

## swing

- every model change has to happen on the event dispatch thread.
  Adding rows from a worker thread while `setAutoCreateRowSorter` is
  on gives an `IndexOutOfBoundsException` from inside the sorter,
  which looks like a Burp bug and is not.
- `setDefaultRenderer` is keyed on the column class. The model returns
  strings for everything, so one renderer registered for `String`
  covers the table.
