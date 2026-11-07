from NetInfoView.ping.speed_locations import country_info, flag, locate
from NetInfoView.ping.speedtest import ServerSpec


def spec(name, sponsor=""):
    return ServerSpec(name, "https://x.example", "librespeed", sponsor=sponsor)


def test_locate_reads_city_country_code_and_region():
    where = locate(spec("Tokyo, Japan (A573)", "A573"))
    assert (where.country, where.city, where.code, where.iso, where.region) == (
        "Japan", "Tokyo", "NRT", "JP", "Asia")
    assert where.subtitle == "Tokyo · NRT · A573"


def test_locate_drops_every_parenthesis_and_maps_aliases_and_states():
    assert locate(spec("Los Angeles, United States (1) (Clouvider)")).country == "United States"
    assert locate(spec("Chicago, USA (Sharktech)")).iso == "US"
    assert locate(spec("Grand Rapids, Michigan (RackGenius)")).country == "United States"
    assert locate(spec("London, England (Clouvider)")).country == "United Kingdom"
    assert locate(spec("Argalasti, Magnesia, Greece (Cosmote)")).city == "Argalasti"


def test_unknown_country_lands_in_other():
    where = locate(spec("Somewhere, Atlantis"))
    assert (where.country, where.iso, where.region) == ("Atlantis", "", "Other")
    assert country_info("Czechia") == ("Czech Republic", "CZ", "Europe")


def test_flag_emoji():
    assert flag("JP") == "\U0001F1EF\U0001F1F5"
    assert flag("") == "" and flag("1A") == ""


def test_search_matches_country_city_code_and_sponsor():
    where = locate(spec("Frankfurt, Germany (Clouvider)", "Clouvider"))
    for query in ("germ", "frank", "FRA", "clouv", "europe", ""):
        assert where.matches(query)
    assert not where.matches("japan")


def test_thai_ookla_server_location():
    where = locate(ServerSpec("Bangkok, Thailand (True Online)", "https://x:8080", "ookla",
                              sponsor="True Online"))
    assert (where.country, where.city, where.code, where.iso, where.region) == (
        "Thailand", "Bangkok", "BKK", "TH", "Asia")
    assert where.matches("true") and where.matches("thai")


def test_place_and_short_lines():
    tokyo = locate(ServerSpec("Tokyo, Japan (A573)", "https://x", "librespeed", sponsor="A573"))
    assert (tokyo.place, tokyo.short) == ("Tokyo · NRT", "Tokyo · A573")
    bkk = locate(ServerSpec("Bangkok, Thailand (3BB)", "https://x", "ookla", sponsor="3BB"))
    assert (bkk.title, bkk.place, bkk.short) == ("Bangkok", "Thailand · BKK", "Bangkok · 3BB")
