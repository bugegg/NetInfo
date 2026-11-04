import csv
import io
import xml.etree.ElementTree as ET

import pytest

from NetInfoView.fileio.export import ExportFormat, render
from NetInfoView.model.columns import COLUMN_BY_KEY
from NetInfoView.model.host import HostEntry
from NetInfoView.ping.result import PingResult, PingStatus

COLUMNS = [COLUMN_BY_KEY[k] for k in ("host_name", "ip_address", "last_status", "last_rtt")]


@pytest.fixture
def entries():
    a = HostEntry(1, "www.google.com", ip_address="64.233.183.99")
    a.apply(PingResult(PingStatus.SUCCEEDED, 79.0, "64.233.183.99", 112))
    b = HostEntry(2, "192.168.0.5", ip_address="192.168.0.5", description='He said "hi", ok')
    b.apply(PingResult(PingStatus.TIMEOUT))
    return [a, b]


def test_csv_header_and_quoting(entries):
    rows = list(csv.reader(io.StringIO(render(entries, ExportFormat.CSV, COLUMNS))))
    assert rows[0] == ["Host Name", "IP Address", "Last Ping Status", "Last Ping Time"]
    assert rows[1] == ["www.google.com", "64.233.183.99", "Succeeded", "79"]
    assert rows[2] == ["192.168.0.5", "192.168.0.5", "Request Timeout", ""]


def test_csv_header_can_be_omitted(entries):
    rows = list(csv.reader(io.StringIO(render(entries, ExportFormat.CSV, COLUMNS, False))))
    assert rows[0][0] == "www.google.com"


def test_csv_quotes_a_field_containing_a_comma():
    entry = HostEntry(1, "h", description='He said "hi", ok')
    out = render([entry], ExportFormat.CSV, [COLUMN_BY_KEY["description"]])
    assert list(csv.reader(io.StringIO(out)))[1] == ['He said "hi", ok']


def test_tab_delimited_has_no_stray_tabs(entries):
    body = render(entries, ExportFormat.TAB, COLUMNS).splitlines()
    assert body[0].split("\t") == ["Host Name", "IP Address", "Last Ping Status", "Last Ping Time"]
    assert all(len(line.split("\t")) == len(COLUMNS) for line in body)


def test_tabular_columns_line_up(entries):
    lines = render(entries, ExportFormat.TABULAR, COLUMNS).splitlines()
    start = lines[0].index("IP Address")
    assert all(line[start:].startswith(("64.233", "192.168", "IP Address")) for line in lines)


def test_text_format_is_one_block_per_host(entries):
    out = render(entries, ExportFormat.TEXT, COLUMNS)
    assert out.count("=" * 70) == 2
    assert "Host Name        : www.google.com" in out


def test_horizontal_html_is_one_row_per_host(entries):
    out = render(entries, ExportFormat.HTML, COLUMNS)
    assert out.count("<tr>") == 3  # header + two hosts
    assert "<th>Host Name</th>" in out


def test_vertical_html_is_one_table_per_host(entries):
    out = render(entries, ExportFormat.VERTICAL_HTML, COLUMNS)
    assert out.count("<table>") == 2


def test_html_escapes_markup():
    entry = HostEntry(1, "h", description="<script>alert(1)</script>")
    out = render([entry], ExportFormat.HTML, [COLUMN_BY_KEY["description"]])
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_xml_parses_and_uses_column_keys(entries):
    root = ET.fromstring(render(entries, ExportFormat.XML, COLUMNS))
    items = root.findall("item")
    assert len(items) == 2
    assert items[0].findtext("host_name") == "www.google.com"
    assert items[1].findtext("last_status") == "Request Timeout"


def test_xml_escapes_special_characters():
    entry = HostEntry(1, "h", description="a & b < c")
    root = ET.fromstring(render([entry], ExportFormat.XML, [COLUMN_BY_KEY["description"]]))
    assert root.findtext("item/description") == "a & b < c"


def test_every_format_renders_an_empty_list():
    for fmt in ExportFormat:
        assert isinstance(render([], fmt, COLUMNS), str)
