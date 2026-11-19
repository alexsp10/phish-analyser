"""Unit tests for individual checks and scoring, using emails built in memory."""

from __future__ import annotations

import io
import zipfile

from conftest import build

from phishcheck.checks import analyse, score, verdict_for
from phishcheck.models import Finding


def checks_for(email, catalog):
    return {f.check for f in analyse(email, catalog).findings}


def test_clean_email_scores_zero(catalog):
    analysis = analyse(build(), catalog)
    assert analysis.score == 0 and analysis.verdict == "clean"
    assert any("DMARC pass" in p for p in analysis.positives)


def test_missing_auth_is_informational(catalog):
    analysis = analyse(build(auth=None), catalog)
    assert analysis.findings[0].check == "auth.missing" and analysis.findings[0].points == 0


def test_auth_failures(catalog):
    email = build(
        auth="mx.google.com; dkim=fail header.i=@x.example; spf=fail smtp.mailfrom=a@x.example; dmarc=fail header.from=x.example"
    )
    assert {"auth.dmarc_fail", "auth.spf_fail", "auth.dkim_fail"} <= checks_for(email, catalog)


def test_reply_to_freemail_bec(catalog):
    email = build(sender="CEO <ceo@company.example>", headers={"Reply-To": "ceo.company@gmail.com"})
    assert {"sender.reply_to_mismatch", "sender.reply_to_freemail"} <= checks_for(email, catalog)


def test_display_name_tricks(catalog):
    assert "sender.display_name_brand" in checks_for(build(sender="PayPal Service <help@random.example>"), catalog)
    assert "sender.display_name_address" in checks_for(
        build(sender='"security@paypal.com" <x@random.example>'), catalog
    )
    # A real brand domain with the brand in the display name is fine.
    assert "sender.display_name_brand" not in checks_for(build(sender="PayPal <service@paypal.com>"), catalog)


def test_lookalike_sender_suppresses_duplicate_display_finding(catalog):
    found = checks_for(build(sender="PayPal <service@paypa1.com>"), catalog)
    assert "sender.lookalike_domain" in found and "sender.display_name_brand" not in found


def test_link_checks(catalog):
    html = (
        '<a href="https://bit.ly/abc">a</a>'
        '<a href="https://promo.example.top/">b</a>'
        '<a href="https://my-site.pages.dev/login">c</a>'
        '<a href="http://shop.example/account/login">d</a>'
        '<a href="https://evil.example/">https://www.paypal.com/</a>'
        '<a href="https://www.shop.example/">shop.example</a>'
    )
    found = checks_for(build(html=html), catalog)
    assert {
        "links.shortener",
        "links.suspicious_tld",
        "links.free_hosting",
        "links.insecure_login",
        "links.text_mismatch",
    } <= found


def test_same_domain_link_text_is_not_a_mismatch(catalog):
    html = '<a href="https://www.shop.example/x">shop.example</a><a href="https://shop.example/">Visit our shop</a>'
    assert "links.text_mismatch" not in checks_for(build(html=html), catalog)


def test_link_findings_are_aggregated(catalog):
    html = "".join(f'<a href="https://bit.ly/{i}">x</a>' for i in range(20))
    findings = [f for f in analyse(build(html=html), catalog).findings if f.check == "links.shortener"]
    assert len(findings) == 1 and "+17 more" in findings[0].detail


def test_attachment_checks(catalog):
    exe_stub = b"MZ" + b"\x00" * 10
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("readme.txt", b"x")
        z.writestr("setup.vbs", b"x")
    email = build(
        attachments=[
            ("statement.pdf.exe", exe_stub, "application/octet-stream"),
            ("photo.jpg", exe_stub, "image/jpeg"),
            ("budget.xlsm", b"PK\x03\x04", "application/octet-stream"),
            ("old.doc", b"\xd0\xcf\x11\xe0", "application/msword"),
            ("files.dat", archive.getvalue(), "application/octet-stream"),  # zip detected by content
            ("evil‮gpj.exe", exe_stub, "application/octet-stream"),
        ]
    )
    found = checks_for(email, catalog)
    assert {
        "attachments.dangerous_type",
        "attachments.double_extension",
        "attachments.type_mismatch",
        "attachments.macro_document",
        "attachments.legacy_office",
        "attachments.archive_dangerous_content",
        "attachments.rtl_override",
    } <= found


def test_office_documents_are_not_treated_as_archives(catalog):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("word/vbaProject.bin.exe", b"x")
    found = checks_for(build(attachments=[("letter.docx", archive.getvalue(), "application/octet-stream")]), catalog)
    assert not any(f.startswith("attachments.") for f in found)


def test_content_is_capped(catalog):
    text = (
        "Dear customer, URGENT: act now, within 24 hours, final notice. Verify your account and "
        "confirm your password. Pay by gift card or wire transfer."
    )
    analysis = analyse(build(text=text), catalog)
    content = [f for f in analysis.findings if f.category == "content"]
    assert len(content) == 4
    assert analysis.score == 25  # 35 content points capped at 25: wording alone is never "phishing"
    assert analysis.verdict == "suspicious"


def test_password_form_is_not_capped(catalog):
    analysis = analyse(build(html='<form><input type="password"></form>'), catalog)
    assert analysis.score >= 30


def test_scoring_and_verdicts():
    def f(points, category="links"):
        return Finding("x", category, "t", "d", points)

    assert score([f(60), f(60)]) == 100
    assert score([f(10, "content")] * 5) == 25
    assert [verdict_for(p) for p in (0, 19, 20, 49, 50)] == ["clean", "clean", "suspicious", "suspicious", "phishing"]
    assert (
        f(30).severity == "high" and f(15).severity == "medium" and f(5).severity == "low" and f(0).severity == "info"
    )
