"""Speed Test's server picker: a panel that slides in over the right of the
window, with search, region filters, Automatic (Cloudflare's nearest data
centre) and every other server, nearest first, each with its provider's
badge, flag, signal bars and latency."""

from __future__ import annotations

import html

from PyQt6.QtCore import QEasingCurve, QPoint, QPropertyAnimation, QSize, Qt, pyqtSignal
from PyQt6 import sip
from PyQt6.QtGui import QColor, QPixmap
from PyQt6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from . import glyphs
from ..ping.speed_locations import COUNTRY_CHIPS, REGIONS, Location, locate
from ..ping import logos
from ..ping.speedtest import CLOUDFLARE, ServerSpec
from .provider_badge import ProviderBadge, signal_pixmap
from .tracepath_window import country_flag, country_label

BLUE = "#087dff"

PANEL_WIDTH = 460
SLIDE_MS = 180

#: What the picker can choose: Cloudflare, a LibreSpeed server, or a URL.
Choice = ServerSpec | str


def is_url(text: str) -> bool:
    return text.strip().lower().startswith(("http://", "https://"))


class ServerRow(QFrame):
    """One choice, as nPerf lays it out: the provider's badge; the flag and
    country (or province) over the city and the provider; signal bars, the
    latency, and a check mark on the chosen one."""

    clicked = pyqtSignal()

    def __init__(self, choice: Choice, lead: QWidget, title: str, lines: list[str],
                 iso: str = "", ms: float | None = None, show_latency: bool = True,
                 enabled: bool = True, theme: dict | None = None) -> None:
        super().__init__()
        theme = theme or {}
        self.choice = choice
        self.setObjectName("serverRow")
        self.setProperty("selected", False)
        self.setEnabled(enabled)
        self.setCursor(Qt.CursorShape.PointingHandCursor if enabled else Qt.CursorShape.ArrowCursor)
        row = QHBoxLayout(self)
        row.setContentsMargins(10, 8, 12, 8)
        row.setSpacing(12)
        row.addWidget(lead, 0, Qt.AlignmentFlag.AlignVCenter)
        text = QVBoxLayout()
        text.setSpacing(0)
        head = QHBoxLayout()
        head.setSpacing(6)
        self.flag = QLabel()
        flag_icon = country_flag(iso) if iso else None
        if flag_icon is not None and not flag_icon.isNull():
            # Bundled images, as Trace Path MTU uses: Windows' emoji font
            # has no flags (it would show the bare letters).
            self.flag.setPixmap(flag_icon.pixmap(QSize(20, 15)))
            self.flag.setToolTip(country_label(iso))
            head.addWidget(self.flag)
        elif iso:
            self.flag.setText(iso)
            self.flag.setObjectName("isoBadge")
            self.flag.setContentsMargins(4, 0, 4, 0)
            head.addWidget(self.flag)
        self.title = QLabel(title)
        self.title.setObjectName("rowTitle")
        head.addWidget(self.title, 1)
        text.addLayout(head)
        self.lines = [QLabel(line) for line in lines if line]
        for label in [self.title, *self.lines]:
            # Long names give way rather than push the row wider.
            label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            label.setToolTip("\n".join([title, *lines]))
        for label in self.lines:
            label.setObjectName("rowSubtitle")
            text.addWidget(label)
        row.addLayout(text, 1)
        self.bars = QLabel()
        empty = theme.get("border", "#e3e6eb")
        if show_latency:
            self.bars.setPixmap(signal_pixmap(ms, empty))
        row.addWidget(self.bars)
        self.latency = QLabel(f"{ms:.0f} ms" if ms is not None else
                              ("unreachable" if show_latency else ""))
        self.latency.setObjectName("rowLatency")
        self.latency.setMinimumWidth(56)
        self.latency.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        row.addWidget(self.latency)
        self.check = QLabel()
        self.check.setFixedSize(24, 24)
        self.check.setAlignment(Qt.AlignmentFlag.AlignCenter)
        row.addWidget(self.check)
        self.checked = False

    @property
    def subtitle(self) -> QLabel:
        """The first line under the title (the city, or for a local server
        its country and code)."""
        return self.lines[0] if self.lines else self.title

    def set_selected(self, selected: bool) -> None:
        self.checked = selected
        self.check.setPixmap(glyphs.pixmap("check", BLUE, 22) if selected else QPixmap())
        self.setProperty("selected", selected)
        self.style().unpolish(self)
        self.style().polish(self)

    def mousePressEvent(self, event) -> None:
        if self.isEnabled() and event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class Scrim(QFrame):
    """Dims the window behind the panel; a click on it closes the panel."""

    clicked = pyqtSignal()

    def mousePressEvent(self, event) -> None:
        self.clicked.emit()
        event.accept()


def same_choice(a: Choice | None, b: Choice | None) -> bool:
    if isinstance(a, ServerSpec) and isinstance(b, ServerSpec):
        return a.url == b.url
    return a == b


class ServerPicker(QFrame):
    """The panel. `chosen` fires with the choice when its button is pressed."""

    chosen = pyqtSignal(object)

    def __init__(self, window: QWidget) -> None:
        super().__init__(window)
        self.setObjectName("picker")
        self._window = window
        self._ranked: list[tuple[ServerSpec, float | None]] = []
        self._loaded = False
        self._selected: Choice = CLOUDFLARE
        self._region = "All"
        self._rows: list[ServerRow] = []

        # Dims the rest of the window; a click there closes the panel.
        self.scrim = Scrim(window)
        self.scrim.setObjectName("scrim")
        self.scrim.hide()
        self.scrim.clicked.connect(self.close_panel)

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(40)
        shadow.setOffset(-4, 0)
        shadow.setColor(QColor(0, 0, 0, 70))
        self.setGraphicsEffect(shadow)

        title = QLabel("Select server")
        title.setObjectName("pickerTitle")
        subtitle = QLabel("Choose where to test your connection")
        subtitle.setObjectName("pickerSubtitle")
        self.close_button = QPushButton()
        self.close_button.setObjectName("pickerClose")
        self.close_button.setFixedSize(30, 30)
        self.close_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.close_button.setToolTip("Close (Esc)")
        self.close_button.clicked.connect(self.close_panel)
        head = QHBoxLayout()
        heading = QVBoxLayout()
        heading.setSpacing(2)
        heading.addWidget(title)
        heading.addWidget(subtitle)
        head.addLayout(heading, 1)
        head.addWidget(self.close_button, 0, Qt.AlignmentFlag.AlignTop)

        self.search = QLineEdit()
        self.search.setObjectName("pickerSearch")
        self.search.setPlaceholderText("Search country, city or provider — or type a server URL")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._rebuild)
        self._search_action = None

        self.chips = QHBoxLayout()
        self.chips.setSpacing(6)
        self._chip_group = QButtonGroup(self)
        self._chip_group.setExclusive(True)

        self._cloudflare_ms: float | None = None
        #: The nearest Ookla server once the list is timed, with its connect
        #: time: Automatic picks the fastest of the few nearest; until then
        #: it runs on Cloudflare.
        self.nearest: tuple[ServerSpec, float] | None = None
        self.automatic: ServerRow | None = None
        self._auto_slot = QVBoxLayout()
        self._auto_slot.setContentsMargins(0, 0, 0, 0)

        list_head = QHBoxLayout()
        locations = QLabel("AVAILABLE LOCATIONS")
        locations.setObjectName("listHead")
        latency = QLabel("Latency")
        latency.setObjectName("listHead")
        list_head.addWidget(locations)
        list_head.addStretch(1)
        list_head.addWidget(latency)
        list_head.setContentsMargins(4, 6, 4, 0)

        self.list = QWidget()
        self.list.setObjectName("pickerList")
        self.list_layout = QVBoxLayout(self.list)
        self.list_layout.setContentsMargins(0, 0, 12, 0)  # room for the scroll bar
        self.list_layout.setSpacing(2)
        scroll = QScrollArea()
        scroll.setObjectName("pickerScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(self.list)

        note = QLabel("Thai servers from Ookla's list, others from LibreSpeed's · "
                      "latency is a TCP connect time")
        note.setObjectName("pickerNote")
        note.setWordWrap(True)

        rule = QFrame()
        rule.setObjectName("divider")
        rule.setFixedHeight(1)
        self.selected_label = QLabel()
        self.selected_label.setObjectName("pickerSelected")
        self.selected_label.setTextFormat(Qt.TextFormat.RichText)
        self.use_button = QPushButton("Use this server")
        self.use_button.setObjectName("primary")
        self.use_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.use_button.clicked.connect(self._use)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(12)
        layout.addLayout(head)
        layout.addWidget(self.search)
        layout.addLayout(self.chips)
        layout.addLayout(self._auto_slot)
        layout.addLayout(list_head)
        layout.addWidget(scroll, 1)
        layout.addWidget(rule)
        layout.addWidget(self.selected_label)
        layout.addWidget(self.use_button)
        layout.addWidget(note)

        self._animation = QPropertyAnimation(self, b"pos", self)
        self._animation.setDuration(SLIDE_MS)
        self._animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.hide()
        self.apply_theme()
        self._rebuild_chips()
        self._rebuild()

    # -------------------------------------------------------------- theme

    def apply_theme(self) -> None:
        c = getattr(self._window, "theme", {}) or {}
        muted = c.get("muted", "#5f6673")
        self.close_button.setIcon(glyphs.icon("close", muted, 18))
        if self._search_action is not None:
            self.search.removeAction(self._search_action)
        self._search_action = self.search.addAction(
            glyphs.icon("search", muted, 16), QLineEdit.ActionPosition.LeadingPosition)
        if self.automatic is not None:
            self._rebuild()

    # --------------------------------------------------------------- data

    def set_servers(self, ranked: list[tuple[ServerSpec, float | None]]) -> None:
        if sip.isdeleted(self) or sip.isdeleted(self.list_layout):
            return
        self._ranked = list(ranked)
        self._loaded = True
        self._rebuild_chips()
        self._rebuild()

    def set_nearest(self, nearest: tuple[ServerSpec, float] | None) -> None:
        if sip.isdeleted(self) or sip.isdeleted(self.list_layout):
            return
        self.nearest = nearest
        self._rebuild()

    def set_cloudflare_latency(self, ms: float | None) -> None:
        if sip.isdeleted(self) or sip.isdeleted(self.list_layout):
            return  # the window went while the timing was on its way
        self._cloudflare_ms = ms
        self._rebuild()

    def _badge(self, name: str = "", icon: str = "", color: str = BLUE,
               domain: str = "") -> ProviderBadge:
        c = getattr(self._window, "theme", {}) or {}
        badge = ProviderBadge(42)
        badge.set_colors(c.get("panel", "#ffffff"), c.get("border", "#e3e6eb"))
        if icon:
            badge.set_pixmap(glyphs.pixmap(icon, color, 22))
        else:
            badge.set_provider(name, domain, getattr(self._window, "logos", None))
        return badge

    def location_of(self, spec: ServerSpec) -> Location:
        return locate(spec)

    def latency_of(self, spec: ServerSpec) -> float | None:
        return next((ms for s, ms in self._ranked if s.url == spec.url), None)

    def _rebuild_chips(self) -> None:
        while self.chips.count():
            item = self.chips.takeAt(0)
            if item.widget():
                self._chip_group.removeButton(item.widget())
                item.widget().hide()
                item.widget().deleteLater()
        located = [locate(spec) for spec, _ in self._ranked]
        present = {where.region for where in located}
        countries = {where.country for where in located}
        regions = (["All"] + [c for c in COUNTRY_CHIPS if c in countries]
                   + [r for r in REGIONS if r in present])
        if "Other" in present:
            regions.append("Other")
        if self._region not in regions:
            self._region = "All"
        for region in regions:
            chip = QPushButton(region)
            chip.setObjectName("chip")
            chip.setCheckable(True)
            chip.setFixedHeight(30)
            chip.setChecked(region == self._region)
            chip.setCursor(Qt.CursorShape.PointingHandCursor)
            chip.clicked.connect(lambda _=False, r=region: self._set_region(r))
            self._chip_group.addButton(chip)
            self.chips.addWidget(chip)
        self.chips.addStretch(1)

    def _set_region(self, region: str) -> None:
        self._region = region
        self._rebuild()

    def _rebuild(self) -> None:
        theme = getattr(self._window, "theme", {}) or {}
        if self.automatic is not None:
            self._auto_slot.removeWidget(self.automatic)
            self.automatic.hide()
            self.automatic.deleteLater()
        if self.nearest is not None:
            spec, auto_ms = self.nearest
            auto_line = "Fastest of the nearest servers in Thailand"
        else:
            auto_ms = self._cloudflare_ms
            auto_line = "Lowest latency · Cloudflare"
        self.automatic = ServerRow(CLOUDFLARE, self._badge(icon="globe"), "Automatic",
                                   [auto_line], ms=auto_ms,
                                   show_latency=auto_ms is not None, theme=theme)
        self.automatic.setObjectName("autoRow")
        self.automatic.clicked.connect(lambda: self._select(CLOUDFLARE))
        self._auto_slot.addWidget(self.automatic)

        self._rows = []
        while self.list_layout.count():
            item = self.list_layout.takeAt(0)
            if item.widget():
                # Hidden at once: deleteLater leaves it painted until the next loop.
                item.widget().hide()
                item.widget().deleteLater()
        query = self.search.text()
        if is_url(query):
            url = query.strip()
            self._add_row(ServerRow(url, self._badge(icon="link", color="#8b5cf6"),
                                    "Custom server", [url], show_latency=False, theme=theme))
        shown = 0
        for spec, ms in self._ranked:
            where = locate(spec)
            if self._region != "All" and self._region not in (where.region, where.country):
                continue
            if not is_url(query) and not where.matches(query):
                continue
            domain = logos.domain_for(where.sponsor, spec.sponsor_url, spec.url)
            row = ServerRow(spec, self._badge(where.sponsor or where.country, domain=domain),
                            where.title,
                            [where.place, where.sponsor], iso=where.iso, ms=ms,
                            enabled=ms is not None, theme=theme)
            self._add_row(row)
            shown += 1
        if not shown and not is_url(query):
            text = ("Finding servers worldwide…" if not self._loaded
                    else "No servers match." if query or self._region != "All"
                    else "Couldn't load the server list.")
            empty = QLabel(text)
            empty.setObjectName("pickerNote")
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            empty.setMinimumHeight(60)
            self.list_layout.addWidget(empty)
        self.list_layout.addStretch(1)
        self._sync_selection()

    def _add_row(self, row: ServerRow) -> None:
        row.clicked.connect(lambda r=row: self._select(r.choice))
        self._rows.append(row)
        self.list_layout.addWidget(row)

    # ---------------------------------------------------------- selection

    def _select(self, choice: Choice) -> None:
        self._selected = choice
        self._sync_selection()

    def _sync_selection(self) -> None:
        self.automatic.set_selected(same_choice(self._selected, CLOUDFLARE))
        for row in self._rows:
            row.set_selected(same_choice(row.choice, self._selected))
        self.selected_label.setText(
            f"<span style='color:{self._muted()}'>Selected:</span>&nbsp; "
            f"{html.escape(self.selected_text(self._selected))}")

    def _muted(self) -> str:
        return (getattr(self._window, "theme", {}) or {}).get("muted", "#5f6673")

    def selected_text(self, choice: Choice) -> str:
        if same_choice(choice, CLOUDFLARE):
            if self.nearest is not None:
                return "Automatic · fastest nearby server"
            return "Automatic · Cloudflare"
        if isinstance(choice, ServerSpec):
            return locate(choice).short
        return choice

    def selected(self) -> Choice:
        return self._selected

    def _use(self) -> None:
        self.chosen.emit(self._selected)
        self.close_panel()

    # ------------------------------------------------------- show / hide

    def _geometry(self) -> tuple[QPoint, QPoint]:
        w = self._window
        width = min(PANEL_WIDTH, w.width() - 40)
        self.resize(width, w.height())
        return QPoint(w.width() - width, 0), QPoint(w.width(), 0)

    def open_panel(self, current: Choice) -> None:
        self._selected = current
        self.search.clear()
        self._rebuild()
        shown, hidden = self._geometry()
        self.scrim.setGeometry(self._window.rect())
        self.scrim.show()
        self.scrim.raise_()
        self.move(hidden)
        self.show()
        self.raise_()
        self._animation.stop()
        self._animation.setStartValue(hidden)
        self._animation.setEndValue(shown)
        self._animation.start()
        self.search.setFocus()

    def close_panel(self) -> None:
        if not self.isVisible():
            return
        self.hide()
        self.scrim.hide()

    def is_open(self) -> bool:
        return self.isVisible()

    def reposition(self) -> None:
        """Follow the window's size while open (the window calls this)."""
        if self.isVisible():
            self._animation.stop()
            shown, _ = self._geometry()
            self.move(shown)
            self.scrim.setGeometry(self._window.rect())

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key.Key_Escape:
            self.close_panel()
            return
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self._use()
            return
        super().keyPressEvent(event)
