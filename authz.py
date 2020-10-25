# burp extension for authorization testing
# load it with Extender -> Extensions -> Add -> Extension type: Python

from java.io import PrintWriter

from javax.swing import JPanel, JScrollPane, JTextArea
from java.awt import BorderLayout

from burp import IBurpExtender, IHttpListener, ITab

LOWPRIV_COOKIE = "session=eyJ1aWQiOjQyfQ.XlQ2mw.notarealcookie"

BORING = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
          ".ico", ".woff", ".woff2", ".ttf", ".map")


class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._out = PrintWriter(callbacks.getStdout(), True)
        self._seen = set()

        self._area = JTextArea()
        self._area.setEditable(False)
        self._panel = JPanel(BorderLayout())
        self._panel.add(JScrollPane(self._area), BorderLayout.CENTER)

        callbacks.setExtensionName("authz")
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        self._out.println("authz loaded")

    # ITab
    def getTabCaption(self):
        return "authz"

    def getUiComponent(self):
        return self._panel

    def log(self, msg):
        self._out.println(msg)
        self._area.append(msg + "\n")

    def boring(self, url):
        path = url.getPath().lower()
        for ext in BORING:
            if path.endswith(ext):
                return True
        return False

    def key(self, method, url):
        return "%s %s" % (method, str(url))

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
        url = info.getUrl()
        if not self._callbacks.isInScope(url) or self.boring(url):
            return
        k = self.key(info.getMethod(), url)
        if k in self._seen:
            return
        self._seen.add(k)

        replayed = self._callbacks.makeHttpRequest(
            message.getHttpService(),
            self.swap_cookie(message.getRequest()))

        original_len = len(message.getResponse())
        lowpriv_len = len(replayed.getResponse())
        result = "SAME" if original_len == lowpriv_len else "different"
        self.log("%-6s %-60s %-9s %d vs %d" % (
            info.getMethod(), url, result, original_len, lowpriv_len))
