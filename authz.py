# burp extension for authorization testing
# load it with Extender -> Extensions -> Add -> Extension type: Python

from java.io import PrintWriter

from javax.swing import JPanel, JScrollPane, JTable
from javax.swing.table import AbstractTableModel
from java.awt import BorderLayout

from burp import IBurpExtender, IHttpListener, ITab

LOWPRIV_COOKIE = "session=eyJ1aWQiOjQyfQ.XlQ2mw.notarealcookie"

BORING = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
          ".ico", ".woff", ".woff2", ".ttf", ".map")

COLUMNS = ["#", "method", "url", "result", "orig", "lowpriv"]


class ResultsModel(AbstractTableModel):
    """Swing asks this object what to draw, so the rows live here."""

    def __init__(self):
        self.rows = []

    # AbstractTableModel
    def getRowCount(self):
        return len(self.rows)

    def getColumnCount(self):
        return len(COLUMNS)

    def getColumnName(self, i):
        return COLUMNS[i]

    def getValueAt(self, row, col):
        return self.rows[row][col]

    def add(self, row):
        self.rows.append(row)


class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._out = PrintWriter(callbacks.getStdout(), True)
        self._seen = set()

        self._model = ResultsModel()
        self._table = JTable(self._model)
        self._table.setAutoCreateRowSorter(True)
        self._panel = JPanel(BorderLayout())
        self._panel.add(JScrollPane(self._table), BorderLayout.CENTER)

        callbacks.setExtensionName("authz")
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        self._out.println("authz loaded")

    def getTabCaption(self):
        return "authz"

    def getUiComponent(self):
        return self._panel

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
        self._model.add([len(self._model.rows) + 1, info.getMethod(),
                         str(url), result, original_len, lowpriv_len])
