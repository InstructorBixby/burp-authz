# burp-authz. authorization testing extension
# Extender -> Extensions -> Add -> Extension type: Python -> authz.py

import os
import sys
import threading

EXT_DIR = os.path.dirname(os.path.abspath(__file__))
if EXT_DIR not in sys.path:
    sys.path.insert(0, EXT_DIR)

from java.io import PrintWriter
from java.util import ArrayList
from javax.swing import JMenuItem

from burp import (IBurpExtender, IContextMenuFactory,
                  IExtensionStateListener, IHttpListener, ITab)

from authzlib import (VERSION, compare, filters, headers as hdr, ui,
                      worker)
from authzlib.table import ResultsModel, add_row

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
        self._lock = threading.Lock()
        self._pending = 0
        self._pool = worker.pool(4)

        self._model = ResultsModel()
        self._ui = ui.build(self._model, self.save, self.clear)

        self.load()
        callbacks.setExtensionName("authz " + VERSION)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.addSuiteTab(self)
        self._out.println("authz " + VERSION + " loaded")

    def extensionUnloaded(self):
        worker.shutdown(self._pool)
        self._out.println("authz unloaded")

    def load(self):
        saved = self._callbacks.loadExtensionSetting(SETTING_HEADERS)
        if saved:
            self._ui.headers_box.setText(saved.replace("\\n", "\n"))
        passive = self._callbacks.loadExtensionSetting(SETTING_PASSIVE)
        self._ui.passive_box.setSelected(passive == "true")

    def save(self):
        self._callbacks.saveExtensionSetting(
            SETTING_HEADERS,
            self._ui.headers_box.getText().replace("\n", "\\n"))
        self._callbacks.saveExtensionSetting(
            SETTING_PASSIVE,
            "true" if self._ui.passive_box.isSelected() else "false")
        self._out.println("settings saved")

    def getTabCaption(self):
        return "authz"

    def getUiComponent(self):
        return self._ui.panel

    def createMenuItems(self, invocation):
        menu = ArrayList()
        menu.add(JMenuItem(
            "Send to authz",
            actionPerformed=lambda e: self.from_menu(invocation)))
        return menu

    def from_menu(self, invocation):
        # from the menu i asked for it, so no filtering
        for message in invocation.getSelectedMessages():
            self.submit(message)

    def submit(self, message):
        with self._lock:
            self._pending += 1
        self.show_status()
        self._pool.submit(worker.Task(
            self.check, (message,),
            lambda e: self._err.println("check failed: %s" % e)))

    def show_status(self):
        self._ui.set_status("%d queued, %d results"
                            % (self._pending, len(self._model.rows)))

    def first_time(self, key):
        with self._lock:
            if key in self._seen:
                return False
            self._seen.add(key)
            return True

    def clear(self):
        with self._lock:
            self._seen = set()
        self._model.clear()
        self.show_status()

    def lowpriv_headers(self):
        lines = self._ui.headers_box.getText().splitlines()
        return [l.strip() for l in lines if l.strip()]

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
        try:
            self._check(message)
        finally:
            with self._lock:
                self._pending -= 1
            self.show_status()

    def _check(self, message):
        info = self._helpers.analyzeRequest(message)
        url = info.getUrl()
        if not self.first_time("%s %s" % (info.getMethod(), str(url))):
            return

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
        if messageIsRequest or not self._ui.passive_box.isSelected():
            return
        info = self._helpers.analyzeRequest(message)
        url = info.getUrl()
        if not self._callbacks.isInScope(url):
            return
        if not filters.interesting(info.getMethod(), url.getPath()):
            return
        self.submit(message)
