# burp-authz. authorization testing extension
# Extender -> Extensions -> Add -> Extension type: Python -> authz.py

import os
import sys

EXT_DIR = os.path.dirname(os.path.abspath(__file__))
if EXT_DIR not in sys.path:
    sys.path.insert(0, EXT_DIR)

from java.io import PrintWriter
from java.util import ArrayList

from javax.swing import (BorderFactory, BoxLayout, JButton, JCheckBox,
                         JMenuItem, JPanel, JScrollPane, JSplitPane,
                         JTable, JTextArea)
from java.awt import BorderLayout, Dimension

from burp import (IBurpExtender, IContextMenuFactory,
                  IExtensionStateListener, IHttpListener, ITab)

from authzlib import VERSION, compare, headers as hdr, worker
from authzlib.table import ResultsModel, add_row

BORING = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
          ".ico", ".woff", ".woff2", ".ttf", ".map")

SETTING_HEADERS = "authz.lowpriv.headers"
SETTING_PASSIVE = "authz.passive"


class BurpExtender(IBurpExtender, IHttpListener, ITab,
                   IContextMenuFactory, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._out = PrintWriter(callbacks.getStdout(), True)
        self._err = PrintWriter(callbacks.getStderr(), True)
        self._seen = set()
        self._pool = worker.pool(4)

        self._model = ResultsModel()
        self._table = JTable(self._model)
        self._table.setAutoCreateRowSorter(True)
        self._headers_box = JTextArea(4, 80)
        self._passive_box = JCheckBox("replay everything in scope "
                                      "as i browse")
        self._panel = self.build_ui()

        self.load()
        callbacks.setExtensionName("authz " + VERSION)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.addSuiteTab(self)
        self._out.println("authz " + VERSION + " loaded")

    # IExtensionStateListener. without this the pool threads keep
    # running after the extension is unloaded and burp has to be
    # restarted to get rid of them
    def extensionUnloaded(self):
        worker.shutdown(self._pool)
        self._out.println("authz unloaded")

    def build_ui(self):
        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
        top.setBorder(
            BorderFactory.createTitledBorder("low privilege session"))
        top.add(JScrollPane(self._headers_box))
        top.add(self._passive_box)
        top.add(JButton("save", actionPerformed=lambda e: self.save()))
        top.add(JButton("clear results",
                        actionPerformed=lambda e: self.clear()))

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top,
                           JScrollPane(self._table))
        split.setPreferredSize(Dimension(900, 600))
        panel = JPanel(BorderLayout())
        panel.add(split, BorderLayout.CENTER)
        return panel

    def load(self):
        saved = self._callbacks.loadExtensionSetting(SETTING_HEADERS)
        if saved:
            self._headers_box.setText(saved.replace("\\n", "\n"))
        passive = self._callbacks.loadExtensionSetting(SETTING_PASSIVE)
        self._passive_box.setSelected(passive == "true")

    def save(self):
        self._callbacks.saveExtensionSetting(
            SETTING_HEADERS,
            self._headers_box.getText().replace("\n", "\\n"))
        self._callbacks.saveExtensionSetting(
            SETTING_PASSIVE,
            "true" if self._passive_box.isSelected() else "false")
        self._out.println("settings saved")

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
            self.submit(message)

    def submit(self, message):
        self._pool.submit(worker.Task(
            self.check, (message,),
            lambda e: self._err.println("check failed: %s" % e)))

    def clear(self):
        self._seen = set()
        self._model.clear()

    def lowpriv_headers(self):
        lines = self._headers_box.getText().splitlines()
        return [l.strip() for l in lines if l.strip()]

    def boring(self, url):
        path = url.getPath().lower()
        for ext in BORING:
            if path.endswith(ext):
                return True
        return False

    def rewrite(self, request):
        info = self._helpers.analyzeRequest(request)
        new_headers = hdr.replace(list(info.getHeaders()),
                                  self.lowpriv_headers())
        body = request[info.getBodyOffset():]
        return self._helpers.buildHttpMessage(new_headers, body)

    def parts(self, response):
        if response is None:
            return None
        info = self._helpers.analyzeResponse(response)
        body = self._helpers.bytesToString(
            response[info.getBodyOffset():])
        return (info.getStatusCode(), list(info.getHeaders()), body)

    def check(self, message):
        info = self._helpers.analyzeRequest(message)
        url = info.getUrl()
        k = "%s %s" % (info.getMethod(), str(url))
        if k in self._seen:
            return
        self._seen.add(k)

        original = self.parts(message.getResponse())
        if original is None:
            return
        try:
            replayed = self._callbacks.makeHttpRequest(
                message.getHttpService(),
                self.rewrite(message.getRequest()))
            lowpriv = self.parts(replayed.getResponse())
        except Exception as e:
            self._err.println("replay failed for %s: %s" % (url, e))
            lowpriv = None

        result = compare.classify(original, lowpriv)
        add_row(self._model,
                [len(self._model.rows) + 1, info.getMethod(), str(url),
                 result, original[0],
                 lowpriv[0] if lowpriv else "-"])

    def processHttpMessage(self, toolFlag, messageIsRequest, message):
        if messageIsRequest or not self._passive_box.isSelected():
            return
        info = self._helpers.analyzeRequest(message)
        url = info.getUrl()
        if not self._callbacks.isInScope(url) or self.boring(url):
            return
        self.submit(message)
