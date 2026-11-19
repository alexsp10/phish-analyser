from __future__ import annotations

import pytest

from phishcheck.lookalike import BrandCatalog, levenshtein, skeleton
from phishcheck.urls import defang, domain_in_text, find_urls, host_of, is_ip, registrable_domain, reveal

REAL = BrandCatalog.load()


@pytest.mark.parametrize(
    "host,expected",
    [
        ("mail.paypal.com", "paypal.com"),
        ("www.amazon.co.uk", "amazon.co.uk"),
        ("a.b.example.com.cy", "example.com.cy"),
        ("localhost", "localhost"),
        ("192.0.2.1", "192.0.2.1"),
    ],
)
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


def test_url_helpers():
    assert host_of("HTTPS://Login.Example.com:8443/x") == "login.example.com"
    assert host_of("http://[::1/") is None
    assert is_ip("203.0.113.5") and is_ip("3232235777") and not is_ip("example.com")
    assert find_urls("go to https://a.example/x, or www.b.example.") == ["https://a.example/x", "www.b.example"]
    assert domain_in_text("https://www.PayPal.com/signin") == "paypal.com"
    assert domain_in_text("Click here") is None
    assert domain_in_text("invoice.pdf") is None


def test_defang_and_reveal():
    assert defang("https://evil.example/a.b") == "hxxps://evil[.]example/a.b"
    assert defang("http://bank.example@203.0.113.9/") == "hxxp://bank[.]example@203[.]0[.]113[.]9/"
    assert reveal("xn--pypal-4ve.com") == "p<U+0430>ypal.com"


def test_skeleton_and_distance():
    assert skeleton("pаypa1") == "paypal"  # Cyrillic а + digit 1
    assert skeleton("rnicrosoft") == "microsoft"
    assert levenshtein("kitten", "sitting") == 3


@pytest.mark.parametrize(
    "host,brand",
    [
        ("paypa1.com", "PayPal"),  # digit swap
        ("rnicrosoft.com", "Microsoft"),  # rn -> m
        ("xn--pypal-4ve.com", "PayPal"),  # Cyrillic а (punycode)
        ("amazom.com", "Amazon"),  # one-letter typo
        ("paypal.com.account-review.example", "PayPal"),  # brand in subdomain
        ("secure-paypal-login.example", "PayPal"),  # brand embedded
        ("dhl-parcel.example", "DHL"),  # short brand as a token
        ("netflix.example", "Netflix"),  # right name, wrong domain
        ("micros0ft-support.example", "Microsoft"),  # homoglyph inside one word of the domain
    ],
)
def test_impersonation_detected(host, brand):
    result = REAL.impersonation(host)
    assert result is not None and result.brand == brand


@pytest.mark.parametrize(
    "host",
    [
        "www.paypal.com",
        "accounts.google.com",
        "mail.google.com",
        "amazon.co.uk",
        "login.microsoftonline.com",
        "applebees.com",
        "live-music.example",
        "office-supplies.example",
        "contact-me.example",
        "example.com",
        "googleusercontent.com",
        "news.bbc.co.uk",
    ],
)
def test_no_false_impersonation(host):
    assert REAL.impersonation(host) is None


def test_brand_keywords_in_display_names():
    assert [b.name for b in REAL.brands_named_in("PayPal Service")] == ["PayPal"]
    assert REAL.brands_named_in("Steamboat Tours") == []
    assert REAL.brands_named_in("John Smith") == []


def test_extra_brands_file(tmp_path):
    extra = tmp_path / "brands.json"
    extra.write_text('{"My Bank": {"keywords": ["mybank"], "domains": ["mybank.example"]}}')
    catalog = BrandCatalog.load(extra)
    assert catalog.impersonation("mybank-secure.example").brand == "My Bank"
    assert catalog.impersonation("paypa1.com").brand == "PayPal"  # built-ins still loaded
