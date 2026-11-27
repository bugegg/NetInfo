"""Number widgets show Western digits whatever the system locale (a Thai
Windows region setting otherwise shows port 443 as ๔๔๓). Qt on macOS can't
reproduce Windows' native-digit setting, so this checks the default locale
the widgets inherit."""

from PyQt6.QtCore import QLocale
from PyQt6.QtWidgets import QSpinBox

from NetInfoView.__main__ import use_western_digits
from test_main_window import qapp  # noqa: F401


def test_widgets_use_an_english_locale(qapp):  # noqa: F811
    previous = QLocale()
    try:
        QLocale.setDefault(QLocale(QLocale.Language.Thai, QLocale.Country.Thailand))
        use_western_digits()
        box = QSpinBox()
        assert box.locale().language() == QLocale.Language.English
        assert box.locale().zeroDigit() == "0"
        box.setRange(1, 65535)
        box.setValue(443)
        assert box.text() == "443"
    finally:
        QLocale.setDefault(previous)
