import pytest

from pinginfoview.ping.arp import is_locally_administered

# Every MAC prefix that showed a vendor or not in the user's real screenshot,
# used here as a cross-check that the U/L bit math matches reality exactly.
REAL_WORLD_CASES = [
    ("E8:13:6E:FB:77:BF", False),  # router, vendor found (HUAWEI)
    ("CC:F4:11:C6:29:11", False),  # vendor found (Google)
    ("F0:09:0D:6D:5B:B4", False),  # vendor found (TP-Link)
    ("B0:19:21:4F:EC:2B", False),  # vendor found (TP-Link)
    ("78:20:51:42:4E:D4", False),  # vendor found (TP-Link)
    ("5C:02:14:B8:63:A9", False),  # vendor found (Xiaomi)
    ("EA:F1:17:D1:35:87", True),   # this Mac's own IP, no vendor found
    ("72:33:B1:F9:68:91", True),   # no vendor found
    ("26:48:3B:AF:DD:0B", True),   # no vendor found
]


@pytest.mark.parametrize("mac,expected", REAL_WORLD_CASES)
def test_matches_real_world_vendor_lookup_outcomes(mac, expected):
    assert is_locally_administered(mac) == expected


def test_accepts_bare_hex_and_mixed_separators():
    assert is_locally_administered("EAF11 7D13587".replace(" ", "")) is True
    assert is_locally_administered("EA-F1-17-D1-35-87") is True
    assert is_locally_administered("e8:13:6e:fb:77:bf") is False


def test_too_short_to_tell_is_not_treated_as_locally_administered():
    assert is_locally_administered("") is False
    assert is_locally_administered("E") is False
