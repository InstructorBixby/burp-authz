"""Swing layout for the authz tab. Kept out of authz.py because
three quarters of that file had become JPanel wiring."""

from java.awt import BorderLayout, Dimension
from java.lang import Runnable, String
from javax.swing import (BorderFactory, BoxLayout, JButton, JCheckBox,
                         JLabel, JPanel, JScrollPane, JSplitPane,
                         JTable, JTextArea, SwingUtilities)

from authzlib.table import ResultRenderer


class Widgets(object):
    """Every component the extension needs to read or write."""

    def __init__(self):
        self.headers_box = JTextArea(4, 80)
        self.passive_box = JCheckBox("replay everything in scope "
                                     "as i browse")
        self.status = JLabel("idle")
        self.table = None
        self.panel = None

    def set_status(self, text):
        SwingUtilities.invokeLater(_SetText(self.status, text))


class _SetText(Runnable):

    def __init__(self, component, text):
        self.component = component
        self.text = text

    def run(self):
        self.component.setText(self.text)


def build(model, on_save, on_clear):
    w = Widgets()
    w.table = JTable(model)
    w.table.setAutoCreateRowSorter(True)
    # setDefaultRenderer is keyed on the column class, and every
    # column here reports String because the model returns strings
    w.table.setDefaultRenderer(String, ResultRenderer())
    w.table.getColumnModel().getColumn(2).setPreferredWidth(420)

    buttons = JPanel()
    buttons.add(JButton("save", actionPerformed=lambda e: on_save()))
    buttons.add(JButton("clear results",
                        actionPerformed=lambda e: on_clear()))
    buttons.add(w.status)

    top = JPanel()
    top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))
    top.setBorder(
        BorderFactory.createTitledBorder("low privilege session"))
    top.add(JScrollPane(w.headers_box))
    top.add(w.passive_box)
    top.add(buttons)

    split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top,
                       JScrollPane(w.table))
    split.setPreferredSize(Dimension(900, 600))
    split.setResizeWeight(0.25)

    w.panel = JPanel(BorderLayout())
    w.panel.add(split, BorderLayout.CENTER)
    return w
