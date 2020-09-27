# burp extension for authorization testing
# load it with Extender -> Extensions -> Add -> Extension type: Python

from java.io import PrintWriter

from burp import IBurpExtender, IHttpListener

LOWPRIV_COOKIE = "session=eyJ1aWQiOjQyfQ.XlQ2mw.notarealcookie"


class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._out = PrintWriter(callbacks.getStdout(), True)
        self._err = PrintWriter(callbacks.getStderr(), True)
        callbacks.setExtensionName("authz")
        callbacks.registerHttpListener(self)
        self._out.println("authz loaded")

    def log(self, msg):
        self._out.println(msg)

    def swap_cookie(self, request):
        info = self._helpers.analyzeRequest(request)
        headers = list(info.getHeaders())
        headers = [h for h in headers
                   if not h.lower().startswith("cookie:")]
        headers.append("Cookie: " + LOWPRIV_COOKIE)
        body = request[info.getBodyOffset():]
        return self._helpers.buildHttpMessage(headers, body)

    def processHttpMessage(self, toolFlag, messageIsRequest, message):
        if messageIsRequest:
            return
        info = self._helpers.analyzeRequest(message)
        # i replayed half of google because youtube was open in
        # another tab. target scope only from now on
        if not self._callbacks.isInScope(info.getUrl()):
            return

        replayed = self._callbacks.makeHttpRequest(
            message.getHttpService(),
            self.swap_cookie(message.getRequest()))

        original_len = len(message.getResponse())
        lowpriv_len = len(replayed.getResponse())
        result = "SAME" if original_len == lowpriv_len else "different"
        self.log("%-6s %-60s %-9s %d vs %d" % (
            info.getMethod(), info.getUrl(), result,
            original_len, lowpriv_len))
