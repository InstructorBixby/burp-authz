# notes

things about the burp extender api that are not obvious from the
javadoc:

- the class has to be called `BurpExtender` and it has to implement
  `IBurpExtender`. burp looks for that name by reflection.
- `registerExtenderCallbacks` is the only entry point you get. anything
  you want to keep has to be hung off `self` there.
- `processHttpMessage` fires twice per request (`messageIsRequest`
  True then False). almost everything i want is on the False pass.
- `analyzeRequest` gives you headers as a list of strings and the
  offset where the body starts. there is no "set header" helper, you
  rebuild the whole header list and call `buildHttpMessage`.
- request and response are java `byte[]`, not python strings. use
  `helpers.bytesToString` and `helpers.stringToBytes` or jython will
  hand java a string and java will refuse it.
- `makeHttpRequest` is synchronous. calling it from inside
  `processHttpMessage` means burp waits for me, which is why the proxy
  feels slow with this loaded.
