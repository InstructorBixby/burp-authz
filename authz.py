# burp extension for authorization testing
# load it with Extender -> Extensions -> Add -> Extension type: Python

from burp import IBurpExtender, IHttpListener

# low privilege user session. todo: not hardcoded
LOWPRIV_COOKIE = "session=eyJ1aWQiOjQyfQ.XlQ2mw.notarealcookie"


class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("authz")
        callbacks.registerHttpListener(self)
        print "authz loaded"

    def swap_cookie(self, request):
        # analyzeRequest gives you the headers as a list of strings,
        # so drop the Cookie line and put mine in instead
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
        print "%s %s orig=%d lowpriv=%d" % (
            info.getMethod(), info.getUrl(),
            len(message.getResponse()), len(replayed.getResponse()))
