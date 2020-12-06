# burp extension for authorization testing
# load it with Extender -> Extensions -> Add -> Extension type: Python

from java.io import PrintWriter
from java.lang import Runnable
from java.util import ArrayList

from javax.swing import (BorderFactory, BoxLayout, JButton, JCheckBox,
                         JLabel, JMenuItem, JPanel, JScrollPane,
                         JSplitPane, JTable, JTextArea, SwingUtilities)
from javax.swing.table import AbstractTableModel
from java.awt import BorderLayout, Dimension

from burp import (IBurpExtender, IContextMenuFactory, IHttpListener,
                  ITab)

BORING = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
          ".ico", ".woff", ".woff2", ".ttf", ".map")

COLUMNS = ["#", "method", "url", "result", "orig", "lowpriv"]

HINT = ("Cookie or Authorization header for the low privilege user,\n"
        "one header per line, exactly as it appears in a request.")


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

        self._model = ResultsModel()
        self._table = JTable(self._model)
        self._table.setAutoCreateRowSorter(True)

        self._headers_box = JTextArea(4, 80)
        self._headers_box.setToolTipText(HINT)
        self._passive_box = JCheckBox("replay everything in scope "
                                      "as i browse")
        clear = JButton("clear results",
                        actionPerformed=lambda e: self.clear())

        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        top.setBorder(BorderFactory.createTitledBorder("low privilege "
                                                       "session"))
        top.add(JScrollPane(self._headers_box))
        top.add(self._passive_box)
        top.add(clear)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top,
                           JScrollPane(self._table))
        split.setPreferredSize(Dimension(900, 600))
        self._panel = JPanel(BorderLayout())
        self._panel.add(split, BorderLayout.CENTER)

        callbacks.setExtensionName("authz")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        self._out.println("authz loaded")

    def getTabCaption(self):
        return "authz"

    def getUiComponent(self):
        return self._panel

    def createMenuItems(self, invocation):
        menu = ArrayList()
        menu.add(JMenuItem(
            "Send to authz",
            actionPerformed=lambda e: self.from_menu(invocation)))
        return menu

    def from_menu(self, invocation):
        for message in invocation.getSelectedMessages():
            self.check(message)

    def clear(self):
        self._seen = set()
        self._model.rows = []
        self._model.fireTableDataChanged()

    def lowpriv_headers(self):
        lines = self._headers_box.getText().splitlines()
        return [l.strip() for l in lines if l.strip()]

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

    def rewrite(self, request):
        replacements = self.lowpriv_headers()
        names = [h.split(":")[0].lower() for h in replacements]
        info = self._helpers.analyzeRequest(request)
        headers = [h for h in info.getHeaders()
                   if h.split(":")[0].lower() not in names]
        headers.extend(replacements)
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
            self.rewrite(message.getRequest()))

        original_len = len(message.getResponse())
        lowpriv_len = len(replayed.getResponse())
        result = "SAME" if original_len == lowpriv_len else "different"
        self.add_row([len(self._model.rows) + 1, info.getMethod(),
                      str(url), result, original_len, lowpriv_len])

    def processHttpMessage(self, toolFlag, messageIsRequest, message):
        if messageIsRequest or not self._passive_box.isSelected():
            return
        info = self._helpers.analyzeRequest(message)
        url = info.getUrl()
        if not self._callbacks.isInScope(url) or self.boring(url):
            return
        self.check(message)
