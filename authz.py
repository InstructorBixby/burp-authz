# burp extension for authorization testing
# load it with Extender -> Extensions -> Add -> Extension type: Python

from burp import IBurpExtender, IHttpListener


class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("authz")
        # registerHttpListener means processHttpMessage gets called
        # for everything burp sees, proxy, repeater, scanner, all of it
        callbacks.registerHttpListener(self)
        print "authz loaded"

    def processHttpMessage(self, toolFlag, messageIsRequest, message):
        info = self._helpers.analyzeRequest(message)
        print "%s %s" % (info.getMethod(), info.getUrl())
