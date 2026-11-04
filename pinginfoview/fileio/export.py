"""The seven save formats PingInfoView offers, driven by the column table."""

from __future__ import annotations

import csv
import html
import io
import time
from collections.abc import Sequence
from enum import Enum

from ..model.columns import COLUMNS, Column


class ExportFormat(str, Enum):
    TEXT = "stext"
    TAB = "stab"
    CSV = "scomma"
    TABULAR = "stabular"
    HTML = "shtml"
    VERTICAL_HTML = "sverhtml"
    XML = "sxml"

    @property
    def extension(self) -> str:
        return {
            ExportFormat.TEXT: "txt",
            ExportFormat.TAB: "txt",
            ExportFormat.CSV: "csv",
            ExportFormat.TABULAR: "txt",
            ExportFormat.HTML: "html",
            ExportFormat.VERTICAL_HTML: "html",
            ExportFormat.XML: "xml",
        }[self]

    @property
    def label(self) -> str:
        return {
            ExportFormat.TEXT: "Text file",
            ExportFormat.TAB: "Tab delimited text file",
            ExportFormat.CSV: "Comma delimited text file (CSV)",
            ExportFormat.TABULAR: "Tabular text file",
            ExportFormat.HTML: "HTML file (Horizontal)",
            ExportFormat.VERTICAL_HTML: "HTML file (Vertical)",
            ExportFormat.XML: "XML file",
        }[self]


TITLE = "NetInfo"


def render(
    entries: Sequence,
    fmt: ExportFormat,
    columns: Sequence[Column] = COLUMNS,
    include_header: bool = True,
) -> str:
    """Serialise entries in the requested format."""
    renderers = {
        ExportFormat.TEXT: _render_text,
        ExportFormat.TAB: lambda e, c, h: _render_delimited(e, c, h, "\t"),
        ExportFormat.CSV: _render_csv,
        ExportFormat.TABULAR: _render_tabular,
        ExportFormat.HTML: _render_html_horizontal,
        ExportFormat.VERTICAL_HTML: _render_html_vertical,
        ExportFormat.XML: _render_xml,
    }
    return renderers[fmt](entries, columns, include_header)


def save(
    path: str,
    entries: Sequence,
    fmt: ExportFormat,
    columns: Sequence[Column] = COLUMNS,
    include_header: bool = True,
) -> None:
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(render(entries, fmt, columns, include_header))


# -- plain text -----------------------------------------------------------


def _render_text(entries, columns, include_header) -> str:
    width = max((len(column.title) for column in columns), default=0)
    out = io.StringIO()
    for entry in entries:
        for column in columns:
            out.write(f"{column.title.ljust(width)} : {column.display(entry)}\n")
        out.write("=" * 70 + "\n\n")
    return out.getvalue()


def _render_delimited(entries, columns, include_header, delimiter) -> str:
    out = io.StringIO()
    if include_header:
        out.write(delimiter.join(column.title for column in columns) + "\r\n")
    for entry in entries:
        out.write(
            delimiter.join(column.display(entry).replace(delimiter, " ") for column in columns)
            + "\r\n"
        )
    return out.getvalue()


def _render_csv(entries, columns, include_header) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    if include_header:
        writer.writerow([column.title for column in columns])
    for entry in entries:
        writer.writerow([column.display(entry) for column in columns])
    return out.getvalue()


def _render_tabular(entries, columns, include_header) -> str:
    """Fixed-width columns, each sized to its widest cell."""
    rows = [[column.display(entry) for column in columns] for entry in entries]
    widths = [
        max([len(column.title)] + [len(row[index]) for row in rows])
        for index, column in enumerate(columns)
    ]
    out = io.StringIO()
    if include_header:
        out.write(
            " ".join(column.title.ljust(widths[i]) for i, column in enumerate(columns)).rstrip()
            + "\r\n"
        )
    for row in rows:
        out.write(" ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip() + "\r\n")
    return out.getvalue()


# -- HTML -----------------------------------------------------------------

_STYLE = (
    "body{font-family:Arial,Helvetica,sans-serif;font-size:13px}"
    "table{border-collapse:collapse}"
    "td,th{border:1px solid #999;padding:3px 6px}"
    "th{background:#dfdfdf;text-align:left}"
    "h3{font-family:Arial,Helvetica,sans-serif}"
)


def _html_document(body: str) -> str:
    generated = time.strftime("%Y-%m-%d %H:%M:%S")
    return (
        "<html>\n<head>\n<meta charset=\"utf-8\">\n"
        f"<title>{TITLE}</title>\n<style>{_STYLE}</style>\n</head>\n<body>\n"
        f"<h3>{TITLE}</h3>\n{body}"
        f"<p>Created by NetInfo on {generated}</p>\n</body>\n</html>\n"
    )


def _render_html_horizontal(entries, columns, include_header) -> str:
    out = io.StringIO()
    out.write("<table>\n<tr>")
    for column in columns:
        out.write(f"<th>{html.escape(column.title)}</th>")
    out.write("</tr>\n")
    for entry in entries:
        out.write("<tr>")
        for column in columns:
            out.write(f"<td>{html.escape(column.display(entry)) or '&nbsp;'}</td>")
        out.write("</tr>\n")
    out.write("</table>\n")
    return _html_document(out.getvalue())


def _render_html_vertical(entries, columns, include_header) -> str:
    out = io.StringIO()
    for entry in entries:
        out.write("<table>\n")
        for column in columns:
            out.write(
                f"<tr><th>{html.escape(column.title)}</th>"
                f"<td>{html.escape(column.display(entry)) or '&nbsp;'}</td></tr>\n"
            )
        out.write("</table>\n<br>\n")
    return _html_document(out.getvalue())


# -- XML ------------------------------------------------------------------


def _render_xml(entries, columns, include_header) -> str:
    out = io.StringIO()
    out.write('<?xml version="1.0" encoding="UTF-8"?>\n<ping_items>\n')
    for entry in entries:
        out.write("\t<item>\n")
        for column in columns:
            out.write(
                f"\t\t<{column.key}>{html.escape(column.display(entry))}</{column.key}>\n"
            )
        out.write("\t</item>\n")
    out.write("</ping_items>\n")
    return out.getvalue()
