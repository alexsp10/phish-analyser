from __future__ import annotations

import hashlib

from conftest import SAMPLES, build

from phishcheck.parser import iter_file, origin_ip, parse_auth_results, parse_bytes, scan_html

GMAIL_AUTH = (
    "mx.google.com; dkim=pass header.i=@shop.example header.s=s1 header.b=abc; "
    "dkim=fail header.i=@other.example; spf=softfail (google.com: domain of x@bounce.example does not designate) "
    "smtp.mailfrom=x@bounce.example; dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=shop.example"
)


def test_auth_results_parsing():
    auth = parse_auth_results([GMAIL_AUTH])
    assert auth.authserv_id == "mx.google.com"
    assert auth.spf == "softfail" and auth.spf_domain == "bounce.example"
    assert auth.dkim == "pass" and auth.dkim_domains == ["shop.example"]
    assert auth.dmarc == "fail" and auth.dmarc_from == "shop.example"
    assert auth.duplicate_count == 0


def test_only_top_auth_header_is_trusted():
    forged = "mx.google.com; spf=pass smtp.mailfrom=a@x.example; dkim=pass header.i=@x.example; dmarc=pass header.from=x.example"
    real = "mx.google.com; spf=fail smtp.mailfrom=a@x.example; dkim=none; dmarc=fail header.from=x.example"
    auth = parse_auth_results([real, forged])
    assert auth.dmarc == "fail" and auth.spf == "fail"
    assert auth.duplicate_count == 1


def test_received_spf_fallback_and_missing():
    assert parse_auth_results([], "Pass (sender SPF authorized)").spf == "pass"
    assert parse_auth_results([]).authserv_id is None


def test_origin_ip_skips_private_addresses():
    received = [
        "by 2002:a05:6a10::1 with SMTP id x",
        "from internal (internal [10.0.0.5]) by mx.google.com",
        "from mail.sender (mail.sender [8.8.4.4]) by internal",
    ]
    assert origin_ip(received) == "8.8.4.4"
    assert origin_ip(["from a (a [192.168.1.1])"]) is None


def test_html_scanner_links_forms_and_hidden_text():
    scanner = scan_html(
        '<style>.x{}</style><a href="https://a.example/x">Click <b>here</b></a>'
        '<form action="https://collect.example/p"><input type="password"></form>'
        '<meta http-equiv="refresh" content="0; url=https://redirect.example/">'
        "<a href='https://unclosed.example/'>open"
    )
    urls = {(link.url, link.text, link.source) for link in scanner.links}
    assert ("https://a.example/x", "Click here", "html") in urls
    assert ("https://collect.example/p", "", "form") in urls
    assert ("https://redirect.example/", "", "meta-refresh") in urls
    assert ("https://unclosed.example/", "open", "html") in urls
    assert scanner.password_form
    assert ".x{}" not in "".join(scanner.text)


def test_full_email_parsing():
    email = build(
        sender='"Support Team" <help@shop.example>',
        subject="=?utf-8?q?Caf=C3=A9_menu?=",
        text="See www.shop.example/help or mailto:x@y.example.",
        html='<p>Hi</p><a href="https://shop.example/a">Account</a><a href="mailto:x@y.example">mail</a>',
        headers={"Reply-To": "Other <other@elsewhere.example>", "Return-Path": "<bounce@mailer.example>"},
        attachments=[("report.pdf", b"%PDF-1.4", "application/pdf")],
    )
    assert email.from_name == "Support Team"
    assert email.from_domain == "shop.example"
    assert email.reply_to == ["other@elsewhere.example"]
    assert email.return_path == "bounce@mailer.example"
    urls = [link.url for link in email.links]
    assert "https://shop.example/a" in urls and "www.shop.example/help" in urls
    assert not any(u.startswith("mailto:") for u in urls)
    assert email.attachments[0].filename == "report.pdf"
    assert email.attachments[0].sha256 == hashlib.sha256(b"%PDF-1.4").hexdigest()
    assert email.subject == "Café menu"  # RFC 2047 encoded subject is decoded


def test_malformed_input_does_not_crash():
    email = parse_bytes(b"From: <<<broken\nSubject: x\nContent-Type: text/plain; charset=nonexistent\n\n\xff\xfe body")
    assert email.subject == "x"
    assert "body" in email.text


def test_mbox_reading():
    emails = list(iter_file(SAMPLES / "mbox" / "takeout-sample.mbox"))
    assert len(emails) == 2
    assert emails[0].source.endswith("#1")
    assert emails[1].from_domain == "northwlndbank.example"
