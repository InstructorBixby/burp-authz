"""Swing table model for the results tab."""

from java.lang import Runnable
from javax.swing import SwingUtilities
from javax.swing.table import AbstractTableModel

COLUMNS = ["#", "method", "url", "result", "orig status",
           "lowpriv status"]


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


class _AddRow(Runnable):

    def __init__(self, model, row):
        self.model = model
        self.row = row

    def run(self):
        self.model.add(self.row)


def add_row(model, row):
    """Add a row from any thread. Swing only allows the edt."""
    SwingUtilities.invokeLater(_AddRow(model, row))
