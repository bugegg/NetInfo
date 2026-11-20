"""DNS Check window: a domain's DNS, e-mail and web checks
(ping/dns_check.py, ping/domain_info.py), each graded Passed / Notice /
Failed / Needs input / Info in a pill, with a chip per status above the
table and an "All checks / Needs attention" filter. A row opens to show the
records found and what they mean; DKIM and PTR ask for a selector and a
sending IP."""

from __future__ import annotations

import ipaddress
import re

from PyQt6.QtCore import QEvent, QSize, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QGuiApplication, QPainter
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QStyledItemDelegate,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import fonts, glyphs
from ..ping import dns_check
from .dashboard import BLUE, GREEN, RED, theme_colors
from .threads import retire, track

AMBER = "#d97706"
#: Public DNS servers offered on the DNS menu, besides the system's own.
PUBLIC_DNS = [("Google", "8.8.8.8"), ("Cloudflare", "1.1.1.1"), ("Quad9", "9.9.9.9"),
              ("OpenDNS", "208.67.222.222")]
#: Domains kept in the History menu.
HISTORY_LIMIT = 12
STATUS_COLORS = {dns_check.PASS: GREEN, dns_check.NOTICE: AMBER, dns_check.FAIL: RED,
                 dns_check.ERROR: RED, dns_check.INPUT: "#8a93a1", dns_check.INFO: BLUE}
STATUS_GLYPHS = {dns_check.PASS: "check", dns_check.NOTICE: "info", dns_check.FAIL: "fail",
                 dns_check.ERROR: "fail", dns_check.INPUT: "pending", dns_check.INFO: "info"}
COL_CHECK, COL_STATUS, COL_SUMMARY, COL_ACTION, COL_CHEVRON = range(5)
#: Statuses shown by "Needs attention".
ATTENTION = (dns_check.NOTICE, dns_check.FAIL, dns_check.ERROR, dns_check.INPUT)


class DnsCheckThread(QThread):
    result = pyqtSignal(object)  # dns_check.CheckResult, each as it's ready
    done = pyqtSignal(object)  # dns_check.Report

    def __init__(self, domain: str, server: str, selectors: list[str], ip: str,
                 port: int = dns_check.DNS_PORT) -> None:
        super().__init__()
        self._args = (domain, server, selectors, ip, port)

    def run(self) -> None:
        domain, server, selectors, ip, port = self._args
        self.done.emit(dns_check.check_domain(domain, server, selectors, ip, port=port,
                                              on_result=self.result.emit))


class SingleCheckThread(QThread):
    """Re-runs one check (DKIM with a selector, PTR with an IP)."""
    done = pyqtSignal(object)  # dns_check.CheckResult

    def __init__(self, key: str, domain: str, server: str, selectors: list[str], ip: str,
                 port: int = dns_check.DNS_PORT) -> None:
        super().__init__()
        self._args = (key, domain, server, selectors, ip, port)

    def run(self) -> None:
        key, domain, server, selectors, ip, port = self._args
        resolver = dns_check.Resolver([server] if server else None, port=port)
        self.done.emit(dns_check.run_check(key, domain, resolver, selectors, ip))


def breakable(text: str, every: int = 40) -> str:
    """`text` with zero-width spaces inside very long words (a DKIM key), so
    a wrapped label can break them instead of growing wider than the window."""
    return re.sub(rf"(\S{{{every}}})(?=\S)", "\\1\u200b", text)


def history_list(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip()]


def remember(history: str, domain: str) -> str:
    """`history` (newline-separated) with `domain` moved to the top."""
    domains = [domain] + [d for d in history_list(history) if d != domain]
    return "\n".join(domains[:HISTORY_LIMIT])


def rgba(color: str, alpha: float) -> str:
    """`#rrggbb` as a translucent rgba() for a stylesheet: a tint that works
    on the light and the dark background alike."""
    color = QColor(color)
    return f"rgba({color.red()}, {color.green()}, {color.blue()}, {alpha})"


def _grow(font, by: int) -> None:
    """Make `font` `by` px bigger (stylesheets size fonts in pixels)."""
    if font.pixelSize() > 0:
        font.setPixelSize(font.pixelSize() + by)
    else:
        font.setPointSizeF(font.pointSizeF() + by * 0.75)


def _tint(color: str) -> QColor:
    """A faint wash of `color` for a row's background."""
    tint = QColor(color)
    tint.setAlphaF(0.07)
    return tint


class RowDelegate(QStyledItemDelegate):
    """Paints a check row's attention bar: a strip down its left edge in
    the colour stored on the row (notices and failures)."""

    def paint(self, painter: QPainter, option, index) -> None:
        super().paint(painter, option, index)
        if index.column() != COL_CHECK:
            return
        color = index.data(Qt.ItemDataRole.UserRole)
        if color:
            rect = option.rect
            painter.fillRect(rect.left(), rect.top(), 3, rect.height(), QColor(color))


class DetailWidget(QWidget):
    """An opened row's contents. The tree sizes a row by its widget's
    sizeHint, which for wrapped labels guesses at a width; this one reports
    the height worked out for the real width (DnsCheckWindow._fit_details)."""

    fitted_height = 0

    def sizeHint(self) -> QSize:
        hint = super().sizeHint()
        if self.fitted_height:
            hint.setHeight(self.fitted_height)
        return hint


class DnsCheckWindow(QWidget):
    """A non-modal window: a domain, Run checks, and a row per check."""

    def __init__(self, settings=None, parent: QWidget | None = None) -> None:
        """`settings` (the app's Settings, optional) keeps the History list,
        DKIM selectors and sending IP between runs."""
        super().__init__(parent, Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle("DNS Check")
        self.resize(800, 720)
        self._settings = settings
        self._thread: QThread | None = None
        self._single: dict[str, SingleCheckThread] = {}
        self.report: dns_check.Report | None = None
        #: The DNS port asked (tests point it at a fake server).
        self.dns_port = dns_check.DNS_PORT
        self._items: dict[str, QTreeWidgetItem] = {}
        dark = bool(getattr(settings, "dark_background", False))
        self._colors = c = theme_colors(dark)
        #: DKIM selectors and the sending IP checked for PTR, asked for by the
        #: Add selector / Add IP buttons and kept in Settings.
        self.selectors = getattr(settings, "dns_check_selectors", "")
        self.sending_ip = getattr(settings, "dns_check_ip", "")
        #: The DNS server asked ("" for the system's; tests use a fake one),
        #: picked from the DNS menu under the domain field.
        self.server = getattr(settings, "dns_check_server", "")

        # -- header: brand, what it is, History ------------------------------------
        logo = QLabel()
        logo.setPixmap(glyphs.pixmap("dns", BLUE, 20))
        brand = QLabel("DNS Check")
        brand.setObjectName("dnsBrand")
        divider = QFrame()
        divider.setObjectName("vrule")
        divider.setFixedSize(1, 14)
        tagline = QLabel("Domain diagnostics")
        tagline.setObjectName("muted")
        self.history_button = QToolButton()
        self.history_button.setText("History")
        self.history_button.setIcon(glyphs.icon("clock", c["ink"], 13))
        self.history_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.history_button.setIconSize(QSize(14, 14))
        self.history_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.history_menu = QMenu(self.history_button)
        self.history_menu.aboutToShow.connect(self._fill_history)
        self.history_button.setMenu(self.history_menu)
        header = QHBoxLayout()
        header.setSpacing(10)
        header.addWidget(logo)
        header.addWidget(brand)
        header.addSpacing(4)
        header.addWidget(divider)
        header.addSpacing(4)
        header.addWidget(tagline)
        header.addStretch(1)
        header.addWidget(self.history_button)

        # -- the domain card -------------------------------------------------------
        card = QFrame()
        card.setObjectName("card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(14, 10, 14, 8)
        card_layout.setSpacing(4)
        card_layout.addWidget(QLabel("Domain"))
        self.domain = QLineEdit()
        self.domain.setObjectName("domainField")
        self.domain.setPlaceholderText("example.com")
        self.domain.setClearButtonEnabled(True)
        self.domain.returnPressed.connect(self.start)
        self.check_button = QToolButton()
        self.check_button.setText("Run checks")
        self.check_button.setObjectName("runButton")
        self.check_button.setIcon(glyphs.icon("run", "#ffffff", 13))
        self.check_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.check_button.setIconSize(QSize(14, 14))
        self.check_button.setMinimumWidth(116)
        self.check_button.clicked.connect(self.start)
        domain_row = QHBoxLayout()
        domain_row.setSpacing(8)
        domain_row.addWidget(self.domain, 1)
        domain_row.addWidget(self.check_button)
        card_layout.addLayout(domain_row)
        self.dns_label = QToolButton()
        self.dns_label.setObjectName("dnsServer")
        self.dns_label.setCursor(Qt.CursorShape.PointingHandCursor)
        self.dns_label.setToolTip("Change the DNS server the checks ask")
        self.dns_label.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.dns_menu = QMenu(self.dns_label)
        self.dns_menu.aboutToShow.connect(self._fill_dns_menu)
        self.dns_label.setMenu(self.dns_menu)
        self.dns_label.setStyleSheet(
            f"QToolButton#dnsServer {{ border: none; background: transparent; color: {c['muted']};"
            f" padding: 0; }} QToolButton#dnsServer:hover {{ color: {BLUE}; }}"
            " QToolButton#dnsServer::menu-indicator { image: none; width: 0; }")
        card_layout.addWidget(self.dns_label, 0, Qt.AlignmentFlag.AlignRight)
        QTimer.singleShot(0, self._show_dns_servers)

        # -- results: title, export, chips, filter, table ----------------------------
        self.result_domain = QLabel()
        self.result_domain.setObjectName("resultDomain")
        result_subtitle = QLabel("DNS, email and domain health")
        result_subtitle.setObjectName("muted")
        titles = QVBoxLayout()
        titles.setSpacing(0)
        titles.addWidget(self.result_domain)
        titles.addWidget(result_subtitle)
        self.export_button = QToolButton()
        self.export_button.setText("Export report")
        self.export_button.setIcon(glyphs.icon("save", c["ink"], 13))
        self.export_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.export_button.setIconSize(QSize(14, 14))
        self.export_button.clicked.connect(self.export)
        result_head = QHBoxLayout()
        result_head.addLayout(titles)
        result_head.addStretch(1)
        result_head.addWidget(self.export_button, 0, Qt.AlignmentFlag.AlignTop)

        #: One chip per status present: "9 Passed", "1 Notice", ...
        self.counts = QWidget()
        self._chips = QHBoxLayout(self.counts)
        self._chips.setContentsMargins(0, 0, 0, 0)
        self._chips.setSpacing(6)
        segment = QFrame()
        segment.setObjectName("segment")
        seg = QHBoxLayout(segment)
        seg.setContentsMargins(2, 2, 2, 2)
        seg.setSpacing(2)
        self.filter_group = QButtonGroup(self)
        self.show_all = QPushButton("All checks")
        self.show_attention = QPushButton("Needs attention")
        for button in (self.show_all, self.show_attention):
            button.setObjectName("segmentButton")
            button.setCheckable(True)
            self.filter_group.addButton(button)
            seg.addWidget(button)
        self.show_all.setChecked(True)
        self.filter_group.buttonClicked.connect(lambda _: self._apply_filter())
        chips_row = QHBoxLayout()
        chips_row.addWidget(self.counts)
        chips_row.addStretch(1)
        chips_row.addWidget(segment)

        self.tree = QTreeWidget()
        self.tree.setObjectName("dnsTree")
        self.tree.setColumnCount(5)
        self.tree.setHeaderLabels(["CHECK", "STATUS", "DETAILS", "", ""])
        self.tree.setRootIsDecorated(False)
        self.tree.setIndentation(0)
        self.tree.setUniformRowHeights(False)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.tree.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.tree.setExpandsOnDoubleClick(False)
        self.tree.setItemDelegate(RowDelegate(self.tree))
        self.tree.itemClicked.connect(self._toggle_item)
        self.tree.itemExpanded.connect(lambda item: self._set_chevron(item, True))
        self.tree.itemCollapsed.connect(lambda item: self._set_chevron(item, False))
        self.tree.viewport().installEventFilter(self)
        head = self.tree.header()
        #: Opens or closes every row's details; sits at the header's right end.
        self.expand_button = QToolButton(head)
        self.expand_button.setObjectName("expandAll")
        self.expand_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.expand_button.setStyleSheet(
            f"QToolButton#expandAll {{ border: none; background: transparent; color: {BLUE};"
            f" font-size: 11px; font-weight: 600; padding: 0 4px; }}"
            f" QToolButton#expandAll:hover {{ text-decoration: underline; }}")
        self.expand_button.clicked.connect(self.toggle_all)
        self.expand_button.setVisible(False)
        self._update_expand_button()
        head.installEventFilter(self)
        head.setStretchLastSection(False)
        head.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        for column, mode in ((COL_CHECK, QHeaderView.ResizeMode.Fixed),
                             (COL_STATUS, QHeaderView.ResizeMode.Fixed),
                             (COL_SUMMARY, QHeaderView.ResizeMode.Stretch),
                             (COL_ACTION, QHeaderView.ResizeMode.Fixed),
                             (COL_CHEVRON, QHeaderView.ResizeMode.Fixed)):
            head.setSectionResizeMode(column, mode)
        self.tree.setColumnWidth(COL_CHECK, 130)
        self.tree.setColumnWidth(COL_STATUS, 140)
        self.tree.setColumnWidth(COL_ACTION, 100)
        self.tree.setColumnWidth(COL_CHEVRON, 28)
        self.tree.setStyleSheet(f"""
            QTreeWidget#dnsTree {{ background: {c['surface']}; border: 1px solid {c['border']};
                border-radius: 8px; font-size: 12px; }}
            QTreeWidget#dnsTree::item {{ border-bottom: 1px solid {c['border']}; padding: 4px 6px; }}
            QTreeWidget#dnsTree::item:hover {{ background: {c['hover']}; }}
            QHeaderView::section {{ background: {c['bg']}; color: {c['muted']}; border: none;
                border-bottom: 1px solid {c['border']}; padding: 6px 8px; font-weight: 600;
                font-size: 10px; }}
        """)

        self.results = QWidget()
        results_layout = QVBoxLayout(self.results)
        results_layout.setContentsMargins(0, 0, 0, 0)
        results_layout.setSpacing(8)
        results_layout.addLayout(result_head)
        results_layout.addLayout(chips_row)
        results_layout.addWidget(self.tree, 1)
        self.results.setVisible(False)

        self.placeholder = QLabel("Enter a domain and press Run checks: NS, SOA, A/AAAA, MX, "
                                  "SPF, DMARC, DKIM, PTR, blocklists, SSL and registration.")
        self.placeholder.setObjectName("muted")
        self.placeholder.setWordWrap(True)
        self.placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # -- footer ------------------------------------------------------------------
        self.footer_note = QLabel()
        self.footer_note.setObjectName("muted")
        self.copy_button = QToolButton()
        self.copy_button.setText("Copy summary")
        self.copy_button.setIcon(glyphs.icon("copy", c["ink"], 13))
        self.copy_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.copy_button.setIconSize(QSize(14, 14))
        self.copy_button.clicked.connect(self.copy_summary)
        for button in (self.copy_button, self.export_button):
            button.setEnabled(False)
        footer = QHBoxLayout()
        footer.addWidget(self.footer_note, 1)
        footer.addWidget(self.copy_button)

        rule = QFrame()
        rule.setObjectName("rule")
        rule.setFixedHeight(1)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 12, 18, 12)
        layout.setSpacing(10)
        layout.addLayout(header)
        layout.addWidget(card)
        layout.addWidget(self.results, 1)
        layout.addWidget(self.placeholder, 1)
        layout.addWidget(rule)
        layout.addLayout(footer)

        self.setStyleSheet(f"""
            QWidget {{ font-size: 12px; }}
            QLabel#dnsBrand {{ font-size: 16px; font-weight: 700; }}
            QLabel#resultDomain {{ font-size: 17px; font-weight: 700; }}
            QLineEdit#domainField {{ padding: 5px 8px; border: 1px solid {c['border']};
                border-radius: 7px; background: {c['surface']}; font-size: 13px; }}
            QLineEdit#domainField:focus {{ border: 1px solid {BLUE}; }}
            QToolButton#runButton {{ background: {BLUE}; color: white; border: none;
                border-radius: 6px; font-size: 12px; font-weight: 600; padding: 6px 14px; }}
            QToolButton#runButton:hover {{ background: #006ee6; }}
            QToolButton#runButton:disabled {{ background: {c['border']}; color: {c['muted']}; }}
            QToolButton {{ padding: 4px 9px; }}
            QPushButton#segmentButton {{ padding: 3px 12px; font-size: 12px; }}
            QPushButton#segmentButton:checked {{ background: {rgba(BLUE, 0.16)}; color: {c['ink']};
                font-weight: 600; }}
        """)

    # -- running -----------------------------------------------------------------

    def _show_dns_servers(self) -> None:
        servers = [self.server] if self.server else dns_check.Resolver().servers[:2]
        name = next((n for n, ip in PUBLIC_DNS if ip == self.server), "")
        text = f"DNS: {', '.join(servers)}" if servers else "DNS: none configured"
        self.dns_label.setText(f"{text}{f' ({name})' if name else ''} ▾")

    def _fill_dns_menu(self) -> None:
        menu = self.dns_menu
        menu.clear()
        choices = [("System default", "")] + [(f"{n} ({ip})", ip) for n, ip in PUBLIC_DNS]
        if self.server and self.server not in (ip for _, ip in PUBLIC_DNS):
            choices.append((self.server, self.server))
        for label, server in choices:
            action = menu.addAction(label)
            action.setCheckable(True)
            action.setChecked(server == self.server)
            action.triggered.connect(lambda _=False, s=server: self.set_server(s))
        menu.addSeparator()
        menu.addAction("Custom…").triggered.connect(self._ask_server)

    def _ask_server(self) -> None:
        text, ok = QInputDialog.getText(self, "DNS server", "IP address of the DNS server to ask:",
                                        text=self.server)
        if not ok:
            return
        text = text.strip()
        try:
            ipaddress.ip_address(text)
        except ValueError:
            if text:
                QMessageBox.warning(self, "DNS server", f"\"{text}\" is not an IP address.")
            return
        self.set_server(text)

    def set_server(self, server: str) -> None:
        """Ask `server` ("" for the system's DNS) from now on, and check again."""
        self.server = server
        self._show_dns_servers()
        if self._settings is not None:
            self._settings.dns_check_server = server
        self._save()
        if self.report is not None and self._thread is None:
            self.start()

    def _inputs(self) -> tuple[str, list[str], str]:
        return self.server, dns_check.parse_selectors(self.selectors), self.sending_ip.strip()

    def start(self) -> None:
        if self._thread is not None:
            return
        domain = dns_check.normalise_domain(self.domain.text())
        if not domain:
            self._message(f"\"{self.domain.text().strip()}\" is not a domain name."
                          if self.domain.text().strip() else "Type a domain, e.g. example.com.")
            return
        server, selectors, ip = self._inputs()
        self.domain.setText(domain)
        self._save(domain)
        self.setWindowTitle(f"DNS Check — {domain}")
        self.check_button.setEnabled(False)
        self.check_button.setText("Checking…")
        self._show_pending(domain)
        self._thread = track(DnsCheckThread(domain, server, selectors, ip, self.dns_port))
        self._thread.result.connect(self._show_live)
        self._thread.done.connect(self._show_report)
        self._thread.start()

    def _message(self, text: str) -> None:
        self.placeholder.setText(text)
        self.placeholder.setVisible(True)
        self.results.setVisible(False)

    def _show_pending(self, domain: str) -> None:
        self.placeholder.setVisible(False)
        self.results.setVisible(True)
        self.result_domain.setText(domain)
        muted = self._colors["muted"]
        self._set_chips([("Checking…", muted, "pending", rgba(muted, 0.14))])
        self.tree.clear()
        self._items.clear()
        self.expand_button.setVisible(False)
        for key in dns_check.CHECKS:
            item = QTreeWidgetItem(self.tree, [dns_check.CHECK_TITLES[key], "Checking…", ""])
            self._style_title(item)
            self._set_pill(item, None)
            self._items[key] = item
        #: Results shown so far, while the check runs.
        self._live = dns_check.Report(domain)

    def _show_live(self, result: dns_check.CheckResult) -> None:
        """One check has finished: show it in its row straight away."""
        live = getattr(self, "_live", None)
        if live is None or self._thread is None or live.result(result.key) is not None:
            return
        live.results.append(result)
        old = self._items.get(result.key)
        index = self.tree.indexOfTopLevelItem(old) if old is not None else -1
        if index >= 0:
            self._take_row(index)
        self._add_result(result, index if index >= 0 else None)
        self._update_counts(live, pending=len(dns_check.CHECKS) - len(live.results))
        self._apply_filter()

    def _show_report(self, report: dns_check.Report) -> None:
        self._thread = None
        self.check_button.setEnabled(True)
        self.check_button.setText("Run checks")
        self.report = report
        live, self._live = getattr(self, "_live", None), None
        if not report.exists:
            self.tree.clear()
            self._items.clear()
            self._message(f"{report.domain} doesn't exist.\n\n"
                          "DNS has no record of this domain (NXDOMAIN): check the spelling, "
                          "or it may have expired or never been registered.")
            self.footer_note.setText(f"Checked {report.domain}: not found")
            for button in (self.copy_button, self.export_button):
                button.setEnabled(False)
            return
        # Rows already shown as they came in stay as they are (and stay open
        # if they were opened); any missing are filled in.
        shown = {r.key for r in live.results} if live is not None else set()
        for result in report.results:
            if result.key in shown and result.key in self._items:
                continue
            old = self._items.get(result.key)
            index = self.tree.indexOfTopLevelItem(old) if old is not None else -1
            if index >= 0:
                self._take_row(index)
            self._add_result(result, index if index >= 0 else None)
        self._update_counts()
        self._apply_filter()
        self._update_expand_button()
        self._show_dns_servers()
        self.footer_note.setText(f"Checked {report.domain}")
        for button in (self.copy_button, self.export_button):
            button.setEnabled(True)

    # -- chips and filter ----------------------------------------------------------

    def chip_texts(self) -> list[str]:
        return [chip.property("chipText") for chip in self.counts.findChildren(QFrame, "chip")
                if not chip.property("removed")]  # replaced, awaiting deleteLater

    def _set_chips(self, chips: list[tuple[str, str, str, str]]) -> None:
        """Replace the chips: each (text, colour, glyph, background colour)."""
        while self._chips.count():
            widget = self._chips.takeAt(0).widget()
            if widget is not None:
                # Not setParent(None): that makes the chip a window of its
                # own for a moment, and macOS then activates the main window.
                widget.setProperty("removed", True)
                widget.hide()
                widget.deleteLater()
        for text, color, glyph, background in chips:
            chip = QFrame()
            chip.setObjectName("chip")
            chip.setProperty("chipText", text)
            chip.setStyleSheet(f"QFrame#chip {{ background: {background}; border-radius: 6px; }}"
                               f" QLabel {{ color: {color}; font-weight: 600; }}")
            row = QHBoxLayout(chip)
            row.setContentsMargins(8, 3, 10, 3)
            row.setSpacing(5)
            icon = QLabel()
            icon.setPixmap(glyphs.pixmap(glyph, color, 14))
            row.addWidget(icon)
            row.addWidget(QLabel(text))
            self._chips.addWidget(chip)

    def _update_counts(self, report: dns_check.Report | None = None, pending: int = 0) -> None:
        counts = (report or self.report).counts()
        failed = counts[dns_check.FAIL] + counts[dns_check.ERROR]
        chips = []
        for count, label, status in (
                (counts[dns_check.PASS], "Passed", dns_check.PASS),
                (counts[dns_check.NOTICE], "Notice" if counts[dns_check.NOTICE] == 1 else "Notices",
                 dns_check.NOTICE),
                (failed, "Failed", dns_check.FAIL),
                (counts[dns_check.INPUT], "Needs input", dns_check.INPUT),
                (counts[dns_check.INFO], "Info", dns_check.INFO)):
            if count or status == dns_check.PASS:
                color, background = self._pill_colors(status)
                chips.append((f"{count} {label}", color, STATUS_GLYPHS[status], background))
        if pending:
            muted = self._colors["muted"]
            chips.append((f"Checking {pending}…", muted, "pending", rgba(muted, 0.14)))
        self._set_chips(chips)
        attention = sum(counts[s] for s in ATTENTION)
        self.show_attention.setText(f"Needs attention ({attention})" if attention
                                    else "Needs attention")

    def _apply_filter(self) -> None:
        only_attention = self.show_attention.isChecked()
        report = getattr(self, "_live", None) or self.report  # live while checking
        for key, item in self._items.items():
            result = report.result(key) if report else None
            item.setHidden(bool(only_attention and result and result.status not in ATTENTION))

    # -- rows ----------------------------------------------------------------------

    def _pill_colors(self, status: str | None) -> tuple[str, str]:
        """(text colour, background) of a status pill or chip."""
        if status in (None, dns_check.INPUT):
            return self._colors["ink"], rgba(self._colors["muted"], 0.14)
        color = STATUS_COLORS[status]
        return color, rgba(color, 0.13)

    def _set_pill(self, item: QTreeWidgetItem, status: str | None) -> None:
        """The status cell as a rounded pill (icon and word); the item keeps
        the word too, drawn transparent, for sorting, tests and copy."""
        color, background = self._pill_colors(status)
        label = dns_check.STATUS_LABELS[status] if status else "Checking…"
        item.setText(COL_STATUS, label)
        item.setForeground(COL_STATUS, QBrush(Qt.GlobalColor.transparent))
        holder = QWidget()
        box = QHBoxLayout(holder)
        box.setContentsMargins(0, 0, 0, 0)
        pill = QFrame()
        pill.setObjectName("pill")
        pill.setStyleSheet(f"QFrame#pill {{ background: {background}; border-radius: 9px; }}"
                           f" QLabel {{ color: {color}; font-weight: 600; background: transparent; }}")
        row = QHBoxLayout(pill)
        row.setContentsMargins(6, 2, 10, 2)
        row.setSpacing(5)
        icon = QLabel()
        icon.setPixmap(glyphs.pixmap(STATUS_GLYPHS.get(status, "pending"),
                                     STATUS_COLORS.get(status, self._colors["muted"])
                                     if status != dns_check.INPUT else self._colors["muted"], 14))
        row.addWidget(icon)
        row.addWidget(QLabel(label))
        box.addWidget(pill, 0, Qt.AlignmentFlag.AlignVCenter)
        box.addStretch(1)
        self.tree.setItemWidget(item, COL_STATUS, holder)

    def _style_title(self, item: QTreeWidgetItem) -> None:
        font = item.font(COL_CHECK)
        font.setBold(True)
        _grow(font, 0)
        item.setFont(COL_CHECK, font)

    def _take_row(self, index: int) -> None:
        """Remove a row and delete its widgets (pill, button, details) first:
        taken with them still set, they briefly turn into windows of their
        own, and on macOS that hands focus to the main window, which jumps
        in front of this one."""
        item = self.tree.topLevelItem(index)
        for row in [item] + [item.child(i) for i in range(item.childCount())]:
            for column in range(self.tree.columnCount()):
                if self.tree.itemWidget(row, column) is not None:
                    self.tree.removeItemWidget(row, column)
        self.tree.takeTopLevelItem(index)

    def _add_result(self, result: dns_check.CheckResult, index: int | None = None) -> None:
        item = QTreeWidgetItem([result.title, "", result.summary, "", ""])
        if index is None:
            self.tree.addTopLevelItem(item)
        else:
            self.tree.insertTopLevelItem(index, item)
        self._items[result.key] = item
        self._style_title(item)
        self._set_pill(item, result.status)
        item.setToolTip(COL_SUMMARY, result.summary)
        item.setSizeHint(COL_CHECK, QSize(0, 32))
        # Notices and failures stand out: a tinted row with a bar down its edge.
        if result.status in (dns_check.NOTICE, dns_check.FAIL, dns_check.ERROR):
            color = STATUS_COLORS[result.status]
            item.setData(COL_CHECK, Qt.ItemDataRole.UserRole, color)
            for column in range(self.tree.columnCount()):
                item.setBackground(column, QBrush(_tint(color)))
        if result.records or result.details:
            detail = QTreeWidgetItem(item)
            detail.setFirstColumnSpanned(True)
            detail.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self.tree.setItemWidget(detail, 0, self._detail_widget(result))
            item.setText(COL_CHEVRON, "›")
            item.setTextAlignment(COL_CHEVRON, Qt.AlignmentFlag.AlignCenter)
            font = item.font(COL_CHEVRON)
            _grow(font, 3)
            item.setFont(COL_CHEVRON, font)
            item.setForeground(COL_CHEVRON, QBrush(QColor(self._colors["muted"])))
        if result.key in ("dkim", "ptr"):
            if result.status == dns_check.INPUT:
                label = {"dkim": "Add selector", "ptr": "Add IP"}[result.key]
            else:
                label = {"dkim": "Edit", "ptr": "Change IP"}[result.key]
            button = QPushButton(label)
            button.setToolTip("DKIM selectors to check" if result.key == "dkim"
                              else "The IP address your mail server sends from")
            button.setStyleSheet("padding: 2px 10px;")
            button.clicked.connect(lambda _, key=result.key: self.ask_input(key))
            holder = QWidget()
            box = QHBoxLayout(holder)
            box.setContentsMargins(0, 0, 4, 0)
            box.addStretch(1)
            box.addWidget(button)
            self.tree.setItemWidget(item, COL_ACTION, holder)
        QTimer.singleShot(0, self._fit_details)

    def _fit_details(self) -> None:
        """Give each opened row the height its wrapped text needs at the
        tree's current width (a widget in a tree row doesn't ask for it)."""
        # The row's stylesheet padding (4px 6px) and bottom border sit around
        # the widget, so it gets 12px less width and needs 9px more height.
        width = self.tree.viewport().width() - 12
        for index in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(index)
            for child in range(item.childCount()):
                detail = item.child(child)
                widget = self.tree.itemWidget(detail, 0)
                if widget is None or widget.layout() is None:
                    continue
                # Apply the stylesheets first (the records' monospace font and
                # padding), or the height is worked out for the wrong font.
                widget.ensurePolished()
                for label in widget.findChildren(QWidget):
                    label.ensurePolished()
                widget.layout().invalidate()
                height = widget.layout().totalHeightForWidth(width)
                if height <= 0:
                    height = widget.sizeHint().height()
                if isinstance(widget, DetailWidget):
                    widget.fitted_height = height
                height += 9 + 2  # the row's padding and border, and a little air
                if detail.sizeHint(0).height() != height:
                    detail.setSizeHint(0, QSize(width, height))
        self.tree.scheduleDelayedItemsLayout()

    def eventFilter(self, obj, event):
        if obj is self.tree.viewport() and event.type() == QEvent.Type.Resize:
            QTimer.singleShot(0, self._fit_details)
        elif obj is self.tree.header() and event.type() == QEvent.Type.Resize:
            self._place_expand_button()
        return super().eventFilter(obj, event)

    def _detail_widget(self, result: dns_check.CheckResult) -> QWidget:
        """The opened row: the records (monospace, with a Copy button beside
        them) and the notes under them, each in a plain wrapped label so the
        row's height can be worked out."""
        c = self._colors
        widget = DetailWidget()
        widget.setObjectName("detail")
        # A plain QWidget only paints a stylesheet background with this set;
        # without it the row shows through between the labels.
        widget.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        widget.setStyleSheet(
            f"QWidget#detail {{ background: {c['bg']}; }}"
            f" QLabel {{ background: transparent; }}"
            f" QLabel#records {{ background: {c['hover']}; border-radius: 5px; padding: 4px 8px; }}"
            f" QToolButton#copyRecords {{ border: 1px solid {c['border']}; border-radius: 5px;"
            f" background: {c['surface']}; color: {c['ink']}; padding: 3px 8px; font-size: 11px; }}"
            f" QToolButton#copyRecords:hover {{ border-color: {BLUE}; color: {BLUE}; }}")
        column = QVBoxLayout(widget)
        column.setContentsMargins(20, 8, 12, 10)
        column.setSpacing(6)
        if result.records:
            row = QHBoxLayout()
            row.setSpacing(12)
            caption = QLabel("Record" if len(result.records) == 1 else "Records")
            caption.setStyleSheet(f"color: {c['muted']}; padding-top: 4px;")
            caption.setFixedWidth(56)
            records = QLabel("\n".join(breakable(r) for r in result.records))
            records.setObjectName("records")
            records.setTextFormat(Qt.TextFormat.PlainText)
            records.setWordWrap(True)
            records.setFont(fonts.mono())
            records.setProperty("mono", True)  # the app's stylesheet sets fonts by this
            records.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            copy = QToolButton()
            copy.setObjectName("copyRecords")
            copy.setText("Copy")
            copy.setIcon(glyphs.icon("copy", c["ink"], 12))
            copy.setIconSize(QSize(12, 12))
            copy.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
            copy.setFixedWidth(72)
            copy.setCursor(Qt.CursorShape.PointingHandCursor)
            copy.setToolTip("Copy record" if len(result.records) == 1 else "Copy records")

            def copy_records() -> None:
                QGuiApplication.clipboard().setText("\n".join(result.records))
                copy.setText("Copied")
                # Parented to the button, so it dies with it (a new run).
                timer = QTimer(copy)
                timer.setSingleShot(True)
                timer.timeout.connect(lambda: copy.setText("Copy"))
                timer.start(1200)

            copy.clicked.connect(copy_records)
            row.addWidget(caption, 0, Qt.AlignmentFlag.AlignTop)
            row.addWidget(records, 1)
            row.addWidget(copy, 0, Qt.AlignmentFlag.AlignTop)
            column.addLayout(row)
        def note(text: str) -> QLabel:
            label = QLabel(text)
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setWordWrap(True)
            label.setStyleSheet(f"color: {c['muted']};")
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            return label

        # Plain notes share one label; a line led by a DETAIL_MARKS mark gets
        # its own row with the status icon (as in the pills) in the mark's place.
        plain: list[str] = []
        for line in result.details + [""]:
            status = dns_check.DETAIL_MARKS.get(line[:1]) if line[1:2] == " " else None
            if (status or not line) and plain:
                column.addWidget(note("\n".join(plain)))
                plain = []
            if status:
                row = QHBoxLayout()
                row.setSpacing(6)
                icon = QLabel()
                color = c["muted"] if status == dns_check.INPUT else STATUS_COLORS[status]
                icon.setPixmap(glyphs.pixmap(STATUS_GLYPHS[status], color, 14))
                icon.setFixedWidth(14)
                row.addWidget(icon, 0, Qt.AlignmentFlag.AlignTop)
                row.addWidget(note(line[2:]), 1)
                column.addLayout(row)
            elif line:
                plain.append(line)
        return widget

    def _toggle_item(self, item: QTreeWidgetItem, _column: int) -> None:
        if item.parent() is None and item.childCount():
            item.setExpanded(not item.isExpanded())

    def _set_chevron(self, item: QTreeWidgetItem, expanded: bool) -> None:
        if item.parent() is None and item.childCount():
            item.setText(COL_CHEVRON, "⌄" if expanded else "›")
            if expanded:
                QTimer.singleShot(0, self._fit_details)
        self._update_expand_button()

    def _expandable(self) -> list[QTreeWidgetItem]:
        return [item for item in self._items.values() if item.childCount()]

    def all_expanded(self) -> bool:
        items = self._expandable()
        return bool(items) and all(item.isExpanded() for item in items)

    def toggle_all(self) -> None:
        """Open every row's details, or close them all if all are open."""
        expand = not self.all_expanded()
        for item in self._expandable():
            item.setExpanded(expand)
        self._update_expand_button()

    def _update_expand_button(self) -> None:
        button = getattr(self, "expand_button", None)
        if button is None:
            return
        expanded = self.all_expanded()
        button.setText("Collapse all ⌃" if expanded else "Expand all ⌄")
        button.setToolTip("Hide every row's details" if expanded
                          else "Show every row's details")
        button.setVisible(bool(self._expandable()))
        button.adjustSize()
        self._place_expand_button()

    def _place_expand_button(self) -> None:
        head = self.tree.header()
        button = self.expand_button
        button.move(head.width() - button.width() - 8, (head.height() - button.height()) // 2)
        button.raise_()

    # -- DKIM selector / PTR IP -------------------------------------------------

    def ask_input(self, key: str) -> None:
        if key == "dkim":
            text, ok = QInputDialog.getText(
                self, "DKIM selector",
                "Selector (the s= tag of a DKIM-Signature header);\nseparate several with commas:",
                text=self.selectors)
        else:
            text, ok = QInputDialog.getText(
                self, "Sending IP", "IP address your mail server sends from:",
                text=self.sending_ip)
        if not ok:
            return
        if key == "dkim":
            self.selectors = text.strip()
        else:
            self.sending_ip = text.strip()
        self._save()
        self.rerun(key)

    def rerun(self, key: str) -> None:
        """Run one check again with the current inputs (after the full check)."""
        if self.report is None or key in self._single or self._thread is not None:
            return
        server, selectors, ip = self._inputs()
        item = self._items.get(key)
        if item is not None:
            self.tree.removeItemWidget(item, COL_ACTION)
            self._set_pill(item, None)
        thread = track(SingleCheckThread(key, self.report.domain, server, selectors, ip,
                                         self.dns_port))
        self._single[key] = thread
        thread.done.connect(self._show_single)
        thread.start()

    def _show_single(self, result: dns_check.CheckResult) -> None:
        self._single.pop(result.key, None)
        if self.report is None or self._thread is not None:
            return  # a full check has started since: it brings its own result
        self.report.results = [result if r.key == result.key else r for r in self.report.results]
        old = self._items.get(result.key)
        index = self.tree.indexOfTopLevelItem(old) if old is not None else -1
        if index >= 0:
            self._take_row(index)
        self._add_result(result, index if index >= 0 else None)
        self._update_counts()
        self._apply_filter()

    # -- history, copy, export ---------------------------------------------------

    def _save(self, domain: str = "") -> None:
        settings = self._settings
        if settings is None:
            return
        if domain:
            settings.dns_check_history = remember(settings.dns_check_history, domain)
        settings.dns_check_selectors = self.selectors.strip()
        settings.dns_check_ip = self.sending_ip.strip()
        save = getattr(settings, "save", None)
        if callable(save):
            save()

    def _fill_history(self) -> None:
        self.history_menu.clear()
        domains = history_list(getattr(self._settings, "dns_check_history", ""))
        if not domains:
            self.history_menu.addAction("No domains checked yet").setEnabled(False)
            return
        for domain in domains:
            self.history_menu.addAction(domain, lambda d=domain: self.check(d))
        self.history_menu.addSeparator()
        self.history_menu.addAction("Clear History", self._clear_history)

    def _clear_history(self) -> None:
        if self._settings is not None:
            self._settings.dns_check_history = ""
            self._save()

    def check(self, domain: str) -> None:
        self.domain.setText(domain)
        self.start()

    def copy_summary(self) -> None:
        if self.report is not None:
            QGuiApplication.clipboard().setText(dns_check.summary_text(self.report))

    def export(self) -> None:
        if self.report is None:
            return
        path, chosen = QFileDialog.getSaveFileName(
            self, "Export DNS Check", f"dns-check-{self.report.domain}.txt",
            "Text (*.txt);;JSON (*.json)")
        if not path:
            return
        as_json = path.lower().endswith(".json") or (
            "JSON" in chosen and not path.lower().endswith(".txt"))
        text = dns_check.report_json(self.report) if as_json else dns_check.summary_text(self.report)
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text + "\n")
        except OSError as error:
            self.footer_note.setText(f"Couldn't save: {error.strerror or error}")
            return
        self.footer_note.setText(f"Saved {path}")

    def closeEvent(self, event) -> None:
        for thread in [self._thread, *self._single.values()]:
            if thread is not None:
                thread.done.disconnect()
                retire(thread)
        self._thread = None
        self._single.clear()
        super().closeEvent(event)
