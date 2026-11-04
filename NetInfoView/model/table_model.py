"""The main grid model and its sort/filter proxy."""

from __future__ import annotations

from PyQt6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
)
from PyQt6.QtGui import QColor

from ..ping.result import PingResult
from ..settings import DisplayMode
from ..ui.icons import icon_name_for, status_icon
from .columns import COLUMNS
from .host import HostEntry

#: Carries the natural-typed column value so the proxy sorts numerically.
SORT_ROLE = int(Qt.ItemDataRole.UserRole) + 1

_ROLES = [Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.DecorationRole, SORT_ROLE]


class HostTableModel(QAbstractTableModel):
    """Rows are HostEntry objects; columns come from columns.COLUMNS."""

    def __init__(self) -> None:
        super().__init__()
        self._entries: list[HostEntry] = []
        self._row_by_key: dict[int, int] = {}
        self.mark_odd_even = True
        self.dark_background = False
        #: The column the view is sorted by (-1: unsorted), so apply_results
        #: can tell which rows may have to move. Kept up to date by the proxy.
        self.sort_column = -1

    # -- Qt interface ------------------------------------------------------

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._entries)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return COLUMNS[section].title
        return section + 1

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        entry = self._entries[index.row()]
        column = COLUMNS[index.column()]

        if role == Qt.ItemDataRole.DisplayRole:
            return column.display(entry)
        if role == SORT_ROLE:
            return column.sort_key(entry)
        if role == Qt.ItemDataRole.DecorationRole and index.column() == 0:
            return status_icon(icon_name_for(entry))
        if role == Qt.ItemDataRole.TextAlignmentRole and column.numeric:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        if role == Qt.ItemDataRole.BackgroundRole:
            return self._background(index.row())
        return None

    def _background(self, row: int):
        if not self.mark_odd_even or row % 2 == 0:
            return None
        return QColor(45, 45, 45) if self.dark_background else QColor(245, 245, 245)

    # -- content -----------------------------------------------------------

    def entries(self) -> list[HostEntry]:
        return self._entries

    def entry_at(self, row: int) -> HostEntry | None:
        return self._entries[row] if 0 <= row < len(self._entries) else None

    def entry_for_key(self, key: int) -> HostEntry | None:
        row = self._row_by_key.get(key)
        return None if row is None else self._entries[row]

    def set_entries(self, entries: list[HostEntry]) -> None:
        self.beginResetModel()
        self._entries = entries
        self._reindex()
        self.endResetModel()

    def add_entries(self, entries: list[HostEntry]) -> None:
        if not entries:
            return
        first = len(self._entries)
        self.beginInsertRows(QModelIndex(), first, first + len(entries) - 1)
        self._entries.extend(entries)
        self._reindex()
        self.endInsertRows()

    def remove_rows(self, rows: list[int]) -> None:
        for row in sorted(set(rows), reverse=True):
            if not 0 <= row < len(self._entries):
                continue
            self.beginRemoveRows(QModelIndex(), row, row)
            del self._entries[row]
            self.endRemoveRows()
        self._reindex()

    def _reindex(self) -> None:
        self._row_by_key = {entry.key: row for row, entry in enumerate(self._entries)}

    # -- live updates ------------------------------------------------------

    def apply_results(self, batch: list[tuple[int, PingResult]]) -> None:
        """Fold a batch of results in, repainting only the rows that changed.

        Deliberately avoids a model reset so the user's sort order, scroll
        position and selection survive every update.
        """
        sort_column = COLUMNS[self.sort_column] if 0 <= self.sort_column < len(COLUMNS) else None
        touched: list[int] = []
        moved: list[int] = []
        for key, result in batch:
            row = self._row_by_key.get(key)
            if row is None:
                continue
            entry = self._entries[row]
            before = sort_column.sort_key(entry) if sort_column else None
            entry.apply(result)
            touched.append(row)
            if sort_column and sort_column.sort_key(entry) != before:
                moved.append(row)
        if not touched:
            return
        last_column = len(COLUMNS) - 1
        # The sorting proxy re-places every row of a dataChanged whose columns
        # take in the sort column, through Python lessThan, whatever roles it
        # names. So only a row whose sort value changed is reported with that
        # column, one at a time; the rest is repainted in one span either side
        # of it. Sorted by a column pings don't change (IP Address, the
        # default), nothing is re-sorted at all.
        for row in sorted(set(moved)):
            self.dataChanged.emit(self.index(row, 0), self.index(row, last_column), _ROLES)
        top, bottom = min(touched), max(touched)
        sort_index = self.sort_column if sort_column else -1
        for first, last in ((0, sort_index - 1), (sort_index + 1, last_column)):
            if first <= last:
                self.dataChanged.emit(self.index(top, first), self.index(bottom, last), _ROLES)

    def refresh_row_for_key(self, key: int) -> None:
        row = self._row_by_key.get(key)
        if row is None:
            return
        self.dataChanged.emit(self.index(row, 0), self.index(row, len(COLUMNS) - 1))


class HostFilterProxy(QSortFilterProxyModel):
    """Applies the View menu's display mode and the hide-disabled option."""

    def __init__(self) -> None:
        super().__init__()
        self.setSortRole(SORT_ROLE)
        self.display_mode = DisplayMode.ALL
        self.hide_disabled = False

    def set_display_mode(self, mode: DisplayMode) -> None:
        self.display_mode = mode
        self.invalidateFilter()

    def set_hide_disabled(self, hide: bool) -> None:
        self.hide_disabled = hide
        self.invalidateFilter()

    def sort(self, column: int, order=Qt.SortOrder.AscendingOrder) -> None:
        source = self.sourceModel()
        if isinstance(source, HostTableModel):
            source.sort_column = column
        super().sort(column, order)

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        left_value = left.data(SORT_ROLE)
        right_value = right.data(SORT_ROLE)

        # Qt reverses lessThan for a descending sort, so blanks are pushed the
        # other way here to keep them at the bottom either way.
        if left_value is None or right_value is None:
            if left_value is None and right_value is None:
                return False
            descending = self.sortOrder() == Qt.SortOrder.DescendingOrder
            return descending if left_value is None else not descending

        if isinstance(left_value, str) and isinstance(right_value, str):
            return left_value.casefold() < right_value.casefold()
        try:
            return left_value < right_value
        except TypeError:
            return str(left_value) < str(right_value)

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:
        # Qt re-asks about every row of each dataChanged, several times a
        # second; with nothing to filter out, answer before any lookups.
        if self.display_mode is DisplayMode.ALL and not self.hide_disabled:
            return True
        source = self.sourceModel()
        entry = source.entry_at(row) if isinstance(source, HostTableModel) else None
        if entry is None:
            return True
        if self.hide_disabled and not entry.enabled:
            return False
        if self.display_mode is DisplayMode.ALL:
            return True
        # A host that has not been pinged yet belongs to neither bucket.
        if entry.last_status is None:
            return False
        if self.display_mode is DisplayMode.SUCCEEDED:
            return entry.last_status.succeeded
        return not entry.last_status.succeeded
