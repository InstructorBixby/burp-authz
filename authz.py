# burp extension for authorization testing
# load it with Extender -> Extensions -> Add -> Extension type: Python

from burp import IBurpExtender, IHttpListener


class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("authz")
        callbacks.registerHttpListener(self)
        print "authz loaded"

    def processHttpMessage(self, toolFlag, messageIsRequest, message):
        # processHttpMessage fires twice for every request, once on the
        # way out and once when the response comes back. we want the
        # response, so skip the request half
        if messageIsRequest:
            return
        info = self._helpers.analyzeRequest(message)
        resp = message.getResponse()
        print "%s %s %d bytes" % (info.getMethod(), info.getUrl(),
                                  len(resp))
