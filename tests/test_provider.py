from NetInfoView.ping import provider
from NetInfoView.ping.provider import brand_name, initials, parse_rdap

APNIC = {
    "name": "AWN-CO-LTD-TH", "country": "TH",
    "remarks": [{"title": "description", "description": ["Advanced Wireless Network Company Limited"]}],
    "entities": [
        {"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "IRT-AWN-CO-LTD-TH"]]]},
        {"roles": ["registrant"],
         "vcardArray": ["vcard", [["fn", {}, "text", "ADVANCED WIRELESS NETWORK COMPANY LIMITED"]]]},
    ],
}


def test_parse_rdap_prefers_the_registrant():
    assert parse_rdap(APNIC) == ("ADVANCED WIRELESS NETWORK COMPANY LIMITED", "AWN-CO-LTD-TH", "TH")


def test_parse_rdap_falls_back_to_description_then_name():
    no_registrant = dict(APNIC, entities=[])
    assert parse_rdap(no_registrant)[0] == "Advanced Wireless Network Company Limited"
    assert parse_rdap({"name": "NET-1"})[0] == "NET-1"
    assert parse_rdap("nonsense") == ("", "", "")


def test_brand_names_for_thai_providers_and_tidied_others():
    assert brand_name("ADVANCED WIRELESS NETWORK COMPANY LIMITED") == "AIS"
    assert brand_name("True Internet Corporation Co., Ltd.") == "True Online"
    assert brand_name("Triple T Broadband Public Company Limited") == "3BB"
    assert brand_name("National Telecom Public Company Limited") == "NT"
    assert brand_name("Clouvider Limited") == "Clouvider"
    assert brand_name("HETZNER ONLINE GMBH") == "Hetzner Online"


def test_initials():
    assert initials("AIS") == "AIS"
    assert initials("3BB") == "3BB"
    assert initials("True Online") == "TO"
    assert initials("Clouvider") == "CL"
    assert initials("TrueMove H") == "TM"
    assert initials("ReadyIDC") == "RID"
    assert initials("") == "?"


def test_public_ips_asks_each_version(monkeypatch):
    def fake(timeout, url):
        return {"https://1.1.1.1/cdn-cgi/trace": "198.51.100.7",
                "https://[2606:4700:4700::1111]/cdn-cgi/trace": "2001:db8::7"}[url]
    monkeypatch.setattr(provider, "public_ip", fake)
    assert provider.public_ips() == ("198.51.100.7", "2001:db8::7")


def test_public_ips_falls_back_to_the_usual_trace(monkeypatch):
    def fake(timeout, url):
        if url == provider.TRACE_URL:
            return "2001:db8::8"
        raise OSError("blocked")
    monkeypatch.setattr(provider, "public_ip", fake)
    assert provider.public_ips() == ("", "2001:db8::8")


def test_fetch_provider_keeps_the_addresses_without_a_registry(monkeypatch):
    monkeypatch.setattr(provider, "public_ips", lambda timeout=6.0: ("198.51.100.7", ""))
    monkeypatch.setattr(provider, "lookup", lambda ip, timeout=8.0: None)
    online, found = provider.fetch_provider()
    assert online and found.name == "" and found.ipv4 == "198.51.100.7"


def test_fetch_provider_offline(monkeypatch):
    def fail(*a, **k):
        raise OSError("offline")
    monkeypatch.setattr(provider, "urlopen", fail)
    assert provider.fetch_provider() == (False, None)


def test_lookup_tries_the_next_registry(monkeypatch):
    import io, json
    calls = []

    def fake(request, timeout):
        calls.append(request.full_url)
        if "rdap.org" in request.full_url:
            raise OSError("down")
        return io.BytesIO(json.dumps(APNIC).encode())
    monkeypatch.setattr(provider, "urlopen", fake)
    found = provider.lookup("2407:b1c0::1")
    assert found.name == "AIS" and found.network == "AWN-CO-LTD-TH"
    assert len(calls) == 2


def test_tidy_name_keeps_unknown_brands():
    assert provider.tidy_name("ReadyIDC Co., Ltd.") == "ReadyIDC"
    assert provider.tidy_name("TrueMove H") == "TrueMove H"
