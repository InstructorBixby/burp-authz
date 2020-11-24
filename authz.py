# burp extension for authorization testing
# load it with Extender -> Extensions -> Add -> Extension type: Python

from java.io import PrintWriter
from java.lang import Runnable
from java.util import ArrayList

from javax.swing import (JMenuItem, JPanel, JScrollPane, JTable,
                         SwingUtilities)
from javax.swing.table import AbstractTableModel
from java.awt import BorderLayout

from burp import (IBurpExtender, IContextMenuFactory, IHttpListener,
                  ITab)

LOWPRIV_COOKIE = "session=eyJ1aWQiOjQyfQ.XlQ2mw.notarealcookie"

BORING = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
          ".ico", ".woff", ".woff2", ".ttf", ".map")

COLUMNS = ["#", "method", "url", "result", "orig", "lowpriv"]


class ResultsModel(AbstractTableModel):

    def __init__(self):
        self.rows = []

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
        i = len(self.rows) - 1
        self.fireTableRowsInserted(i, i)


class AddRow(Runnable):

    def __init__(self, model, row):
        self.model = model
        self.row = row

    def run(self):
        self.model.add(self.row)


class BurpExtender(IBurpExtender, IHttpListener, ITab,
                   IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._out = PrintWriter(callbacks.getStdout(), True)
        self._seen = set()
        # passive mode replays everything in scope as you browse,
        # which is rude on an app that writes things. off by default
        self._passive = False

        self._model = ResultsModel()
        self._table = JTable(self._model)
        self._table.setAutoCreateRowSorter(True)
        self._panel = JPanel(BorderLayout())
        self._panel.add(JScrollPane(self._table), BorderLayout.CENTER)

        callbacks.setExtensionName("authz")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        self._out.println("authz loaded")

    def getTabCaption(self):
        return "authz"

    def getUiComponent(self):
        return self._panel

    # IContextMenuFactory
    def createMenuItems(self, invocation):
        menu = ArrayList()
        item = JMenuItem("Send to authz",
                         actionPerformed=lambda e: self.from_menu(invocation))
        menu.add(item)
        return menu

    def from_menu(self, invocation):
        for message in invocation.getSelectedMessages():
            self.check(message)

    def add_row(self, row):
        SwingUtilities.invokeLater(AddRow(self._model, row))

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

    def check(self, message):
        info = self._helpers.analyzeRequest(message)
        url = info.getUrl()
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
        self.add_row([len(self._model.rows) + 1, info.getMethod(),
                      str(url), result, original_len, lowpriv_len])

    def processHttpMessage(self, toolFlag, messageIsRequest, message):
        if messageIsRequest or not self._passive:
            return
        info = self._helpers.analyzeRequest(message)
        url = info.getUrl()
        if not self._callbacks.isInScope(url) or self.boring(url):
            return
        self.check(message)
