"""The lower pane: a capped log of individual pings."""

from __future__ import annotations

import itertools
import time
from collections import deque
from dataclasses import dataclass

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt

from ..ping.result import PingResult, PingStatus
from ..settings import HistoryMode
from .columns import format_ms, format_timestamp

HISTORY_HEADERS = ("Ping Time", "Host Name", "IP Address", "Status", "Ping Time (ms)", "TTL")


@dataclass(slots=True)
class HistoryRecord:
    timestamp: float
    host: str
    ip: str
    status: PingStatus
    rtt_ms: float | None
    ttl: int | None
    #: The HostEntry this record belongs to, so the lower pane can be
    #: filtered down to whatever is selected in the main grid.
    key: int = 0


def _cell(record: HistoryRecord, column: int) -> str:
    return (
        format_timestamp(record.timestamp),
        record.host,
        record.ip,
        record.status.value,
        format_ms(record.rtt_ms),
        "" if record.ttl is None else str(record.ttl),
    )[column]


def _header(section, orientation, role):
    if role != Qt.ItemDataRole.DisplayRole:
        return None
    if orientation == Qt.Orientation.Horizontal:
        return HISTORY_HEADERS[section]
    return section + 1


class HistoryModel(QAbstractTableModel):
    """A ring buffer of ping records, oldest dropped once the cap is reached."""

    def __init__(self, max_records: int = 50000) -> None:
        super().__init__()
        self._records: deque[HistoryRecord] = deque(maxlen=max_records)
        self.mode = HistoryMode.ALL

    # -- Qt interface ------------------------------------------------------

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._records)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(HISTORY_HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        return _header(section, orientation, role)

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None
        return _cell(self._records[index.row()], index.column())

    # -- updates -----------------------------------------------------------

    def set_capacity(self, max_records: int) -> None:
        if self._records.maxlen == max_records:
            return
        self.beginResetModel()
        self._records = deque(self._records, maxlen=max_records)
        self.endResetModel()

    def should_record(self, result: PingResult, previous: PingStatus | None) -> bool:
        """Apply the lower pane's filter mode to one incoming result."""
        if self.mode is HistoryMode.ALL:
            return True
        if self.mode is HistoryMode.FAILED_ONLY:
            return not result.succeeded
        return previous is None or previous.succeeded != result.succeeded

    def append_many(self, records: list[HistoryRecord]) -> None:
        if not records:
            return
        capacity = self._records.maxlen
        if capacity is not None:
            records = records[-capacity:]
            # Once the cap is reached every batch evicts from the front. Report
            # that as a row removal, not a model reset: a reset makes the proxy
            # re-run filterAcceptsRow (Python) over every record on each batch,
            # which at tens of thousands of records froze the GUI thread.
            overflow = len(self._records) + len(records) - capacity
            if overflow > 0:
                self.beginRemoveRows(QModelIndex(), 0, overflow - 1)
                for _ in range(overflow):
                    self._records.popleft()
                self.endRemoveRows()
        first = len(self._records)
        self.beginInsertRows(QModelIndex(), first, first + len(records) - 1)
        self._records.extend(records)
        self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self._records.clear()
        self.endResetModel()

    def record_at(self, row: int) -> HistoryRecord | None:
        return self._records[row] if 0 <= row < len(self._records) else None

    def records(self) -> list[HistoryRecord]:
        return list(self._records)

    def newest(self, count: int) -> list[HistoryRecord]:
        """The last `count` records, oldest first, without walking the rest."""
        return list(itertools.islice(reversed(self._records), count))[::-1]

    def oldest(self, count: int) -> list[HistoryRecord]:
        return list(itertools.islice(self._records, count))


class HistoryFilterProxy(QAbstractTableModel):
    """Shows the ping history for a chosen set of hosts, or nothing at all.

    Selecting a host (or a few) in the main grid narrows the lower pane down
    to just its ping history; clearing the selection shows nothing, since the
    lower pane's point is to drill into a specific host's history rather than
    stream every host at once.

    Not a QSortFilterProxyModel: that one asks filterAcceptsRow (Python) about
    every record each time the selection changes, which over a full history
    of tens of thousands of records held up every click by over 100 ms. This
    keeps its own list of the matching records instead, rebuilt in one pass
    on a new selection and kept in step as the history grows and evicts.
    """

    def __init__(self) -> None:
        super().__init__()
        self.filter_keys: set[int] | None = None
        #: Column index -> header text shown instead of HISTORY_HEADERS.
        self.header_titles: dict[int, str] = {}
        self._source: HistoryModel | None = None
        self._rows: list[HistoryRecord] = []

    def setSourceModel(self, source: HistoryModel) -> None:
        self._source = source
        source.rowsInserted.connect(self._on_inserted)
        source.rowsAboutToBeRemoved.connect(self._on_about_to_be_removed)
        source.modelReset.connect(self._rebuild)
        self._rebuild()

    def sourceModel(self) -> HistoryModel | None:
        return self._source

    # -- Qt interface ------------------------------------------------------

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(HISTORY_HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if (
            role == Qt.ItemDataRole.DisplayRole
            and orientation == Qt.Orientation.Horizontal
            and section in self.header_titles
        ):
            return self.header_titles[section]
        return _header(section, orientation, role)

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None
        return _cell(self._rows[index.row()], index.column())

    # -- filtering ---------------------------------------------------------

    def set_filter_keys(self, keys: set[int] | None) -> None:
        keys = keys or None
        if keys == self.filter_keys:
            return
        self.filter_keys = keys
        self._rebuild()

    def record_at(self, row: int) -> HistoryRecord | None:
        return self._rows[row] if 0 <= row < len(self._rows) else None

    def _rebuild(self) -> None:
        self.beginResetModel()
        keys = self.filter_keys
        if keys and self._source is not None:
            self._rows = [r for r in self._source.records() if r.key in keys]
        else:
            self._rows = []
        self.endResetModel()

    def _on_inserted(self, _parent, first: int, last: int) -> None:
        keys = self.filter_keys
        if not keys or self._source is None:
            return
        if last != self._source.rowCount() - 1:
            self._rebuild()  # HistoryModel only appends; anything else, start over
            return
        added = [r for r in self._source.newest(last - first + 1) if r.key in keys]
        if added:
            row = len(self._rows)
            self.beginInsertRows(QModelIndex(), row, row + len(added) - 1)
            self._rows.extend(added)
            self.endInsertRows()

    def _on_about_to_be_removed(self, _parent, first: int, last: int) -> None:
        keys = self.filter_keys
        if not keys or self._source is None:
            return
        if first != 0:
            # HistoryModel only evicts from the front; anything else, start
            # over once it's gone.
            self._source.rowsRemoved.connect(self._rebuild_once)
            return
        # Evicted from the front, so the matching ones are this list's first.
        count = sum(1 for r in self._source.oldest(last + 1) if r.key in keys)
        if count:
            self.beginRemoveRows(QModelIndex(), 0, count - 1)
            del self._rows[:count]
            self.endRemoveRows()

    def _rebuild_once(self, *_) -> None:
        self._source.rowsRemoved.disconnect(self._rebuild_once)
        self._rebuild()
