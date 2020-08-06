# burp extension for authorization testing
# load it with Extender -> Extensions -> Add -> Extension type: Python

from burp import IBurpExtender, IHttpListener

LOWPRIV_COOKIE = "session=eyJ1aWQiOjQyfQ.XlQ2mw.notarealcookie"


class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("authz")
        callbacks.registerHttpListener(self)
        print "authz loaded"

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
        replayed = self._callbacks.makeHttpRequest(
            message.getHttpService(),
            self.swap_cookie(message.getRequest()))

        original_len = len(message.getResponse())
        lowpriv_len = len(replayed.getResponse())
        # if the low privilege user gets the same number of bytes back
        # then the server probably did not check anything
        if original_len == lowpriv_len:
            result = "SAME - check this"
        else:
            result = "different"
        print "%-6s %-60s %s (%d vs %d)" % (
            info.getMethod(), info.getUrl(), result,
            original_len, lowpriv_len)
