# burp extension for authorization testing
# load it with Extender -> Extensions -> Add -> Extension type: Python

from burp import IBurpExtender


class BurpExtender(IBurpExtender):

    # burp calls this once when the extension is loaded. the class
    # has to be called BurpExtender or burp wont find it
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("authz")
        print "authz loaded"
