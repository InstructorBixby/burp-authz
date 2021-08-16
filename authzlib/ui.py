"""Swing layout for the authz tab. Kept out of authz.py because
three quarters of that file had become JPanel wiring."""

from java.awt import BorderLayout, Dimension
from java.lang import Runnable, String
from javax.swing import (BorderFactory, BoxLayout, JButton, JCheckBox,
                         JFileChooser, JLabel, JOptionPane, JPanel,
                         JScrollPane, JSplitPane, JTable, JTextArea,
                         SwingUtilities)

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


def ask_for_file(parent):
    """Return a path to save to, or None if the user cancelled."""
    chooser = JFileChooser()
    chooser.setSelectedFile(java_file("authz-results.csv"))
    if chooser.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION:
        return None
    return chooser.getSelectedFile().getAbsolutePath()


def java_file(name):
    from java.io import File
    return File(name)


def warn(parent, message):
    JOptionPane.showMessageDialog(parent, message)


def build(model, on_save, on_clear, on_export):
    w = Widgets()
    w.table = JTable(model)
    w.table.setAutoCreateRowSorter(True)
    w.table.setDefaultRenderer(String, ResultRenderer())
    w.table.getColumnModel().getColumn(2).setPreferredWidth(420)

    buttons = JPanel()
    buttons.add(JButton("save", actionPerformed=lambda e: on_save()))
    buttons.add(JButton("clear results",
                        actionPerformed=lambda e: on_clear()))
    buttons.add(JButton("export csv",
                        actionPerformed=lambda e: on_export()))
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
