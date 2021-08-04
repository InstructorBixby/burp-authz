"""Swing table model and renderer for the results tab."""

from java.awt import Color
from java.lang import Runnable
from javax.swing import SwingUtilities
from javax.swing.table import (AbstractTableModel,
                               DefaultTableCellRenderer)

from authzlib.columns import COLUMNS, RESULT_COLUMN

# pale so the selection highlight still reads
COLOURS = {
    "same": Color(255, 214, 214),
    "similar": Color(255, 240, 200),
    "different": Color(222, 245, 222),
    "error": Color(235, 235, 235),
}


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

    def clear(self):
        self.rows = []
        self.fireTableDataChanged()


class ResultRenderer(DefaultTableCellRenderer):
    """"same" means the low privilege session got the same answer,
    which is the interesting case, so that is the one painted red."""

    def getTableCellRendererComponent(self, table, value, selected,
                                      focused, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, selected, focused, row, col)
        if not selected:
            model_row = table.convertRowIndexToModel(row)
            result = table.getModel().getValueAt(model_row,
                                                 RESULT_COLUMN)
            c.setBackground(COLOURS.get(result, Color.WHITE))
        return c


class _AddRow(Runnable):

    def __init__(self, model, row):
        self.model = model
        self.row = row

    def run(self):
        self.model.add(self.row)


def add_row(model, row):
    """Add a row from any thread. Swing only allows the edt."""
    SwingUtilities.invokeLater(_AddRow(model, row))
