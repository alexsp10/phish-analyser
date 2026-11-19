from __future__ import annotations

import json

from conftest import DEMO_BRANDS, SAMPLES, build

from phishcheck.checks import analyse
from phishcheck.cli import main
from phishcheck.intel import IntelClient
from phishcheck.report import render_html

# --------------------------------------------------------------------------- intel (no network)


class FakeApi:
    def __init__(self, responses):
        self.responses = responses
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, url, headers):
        self.calls.append((url, headers))
        for fragment, response in self.responses.items():
            if fragment in url:
                return response
        return 404, None


def vt_stats(malicious, suspicious=0):
    return 200, {"data": {"attributes": {"last_analysis_stats": {"malicious": malicious, "suspicious": suspicious}}}}


def test_virustotal_flags_domain_and_sends_no_full_urls(catalog):
    email = build(html='<a href="https://bad.example/reset?token=SECRET&email=me@example.com">x</a>')
    api = FakeApi({"domains/bad.example": vt_stats(5)})
    findings = IntelClient("key", fetch=api).lookup(email, catalog)
    assert findings[0].check == "intel.virustotal" and findings[0].points == 40
    assert all("SECRET" not in url and "me@example.com" not in url for url, _ in api.calls)
    assert api.calls[0][1] == {"x-apikey": "key"}


def test_official_domains_are_not_looked_up(catalog):
    email = build(sender="PayPal <service@paypal.com>", html='<a href="https://www.paypal.com/">x</a>')
    api = FakeApi({})
    IntelClient("key", fetch=api).lookup(email, catalog)
    assert api.calls == []


def test_lookup_budget_and_errors(catalog):
    html = "".join(f'<a href="https://site{i}.example/">x</a>' for i in range(10))
    api = FakeApi({})
    findings = IntelClient("key", max_lookups=3, fetch=api).lookup(build(html=html), catalog)
    assert len(api.calls) == 3
    assert any("limit reached" in f.detail for f in findings)

    rejected = IntelClient("bad", fetch=FakeApi({"virustotal": (401, None)})).lookup(build(html=html), catalog)
    assert "rejected the API key" in rejected[-1].detail


def test_attachment_hash_lookup(catalog):
    email = build(attachments=[("a.bin", b"data", "application/octet-stream")])
    api = FakeApi({"files/": vt_stats(1)})
    findings = IntelClient("key", fetch=api).lookup(email, catalog)
    assert findings[0].points == 20 and "attachment" in findings[0].detail


def test_abuseipdb(catalog):
    email = build(headers={"Received": "from x (x [8.8.8.8]) by mx.google.com"})
    api = FakeApi({"abuseipdb": (200, {"data": {"abuseConfidenceScore": 90, "totalReports": 12, "countryCode": "NL"}})})
    findings = IntelClient(abuseipdb_key="k", fetch=api).lookup(email, catalog)
    assert findings[0].check == "intel.abuseipdb" and findings[0].points == 25
    assert "ipAddress=8.8.8.8" in api.calls[0][0]


def test_intel_points_count_towards_score(catalog):
    email = build()
    api = FakeApi({"domains/sender.example": vt_stats(4)})
    analysis = analyse(email, catalog, IntelClient("key", fetch=api).lookup(email, catalog))
    assert analysis.score == 40 and analysis.verdict == "suspicious"


# --------------------------------------------------------------------------- CLI and reports


def test_cli_text_and_summary(capsys):
    assert main([str(SAMPLES / "phishing"), "--brands", str(DEMO_BRANDS)]) == 0
    out = capsys.readouterr().out
    assert "10 email(s): 7 likely phishing, 3 suspicious, 0 no strong indicators" in out
    assert "Showing the summary only" in out  # more than 5 emails -> summary mode


def test_cli_single_file_details(capsys):
    main([str(SAMPLES / "phishing" / "01-lookalike-sender.eml"), "--brands", str(DEMO_BRANDS)])
    out = capsys.readouterr().out
    assert "Sender domain imitates Northwind Bank" in out
    assert "hxxps://northwlndbank[.]example/statement" in out  # defanged


def test_cli_json(capsys):
    main([str(SAMPLES / "clean" / "01-bank-statement.eml"), "--json", "--brands", str(DEMO_BRANDS)])
    data = json.loads(capsys.readouterr().out)
    assert data[0]["verdict"] == "clean" and data[0]["authentication"]["dmarc"] == "pass"


def test_cli_fail_on_and_html(tmp_path):
    report = tmp_path / "r.html"
    code = main([str(SAMPLES), "--brands", str(DEMO_BRANDS), "--fail-on", "phishing", "--html", str(report)])
    assert code == 2
    html = report.read_text(encoding="utf-8")
    assert "Phishing analysis" in html and "northwlndbank[.]example" in html
    assert 'href="https://northwlndbank' not in html  # nothing clickable


def test_cli_errors(tmp_path, capsys, monkeypatch):
    assert main([str(tmp_path / "missing.eml")]) == 1
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    assert main([str(SAMPLES / "clean"), "--online"]) == 1
    assert "needs VT_API_KEY" in capsys.readouterr().err


def test_html_escapes_email_content(catalog):
    payload = "<script>alert(1)</script>"
    analysis = analyse(
        build(subject=payload, sender=f'"{payload}" <x@y.example>', html=f'<a href="https://a.example/">{payload}</a>'),
        catalog,
    )
    html = render_html([analysis])
    assert payload not in html and "&lt;script&gt;" in html
