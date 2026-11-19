"""Phishing checks and scoring.

Each check looks at one kind of evidence and returns :class:`Finding` objects
with a points value. Points are added up (content checks are capped, because
wording alone is weak evidence) into a 0-100 risk score:

* 50+   -> likely phishing
* 20-49 -> suspicious
* < 20  -> no strong phishing indicators

Link findings are aggregated per check, so an email with 40 tracking links
does not score 40 times for the same issue.
"""

from __future__ import annotations

import io
import re
import zipfile
from collections.abc import Callable

from .lookalike import BrandCatalog
from .models import Analysis, Finding, ParsedEmail
from .parser import scan_html
from .urls import (
    defang,
    domain_in_text,
    has_userinfo,
    host_of,
    is_idn,
    is_ip,
    registrable_domain,
    reveal,
    scheme_of,
)

PHISHING_THRESHOLD = 50
SUSPICIOUS_THRESHOLD = 20
CONTENT_CAP = 25

FREEMAIL = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "ymail.com",
    "aol.com",
    "icloud.com",
    "me.com",
    "proton.me",
    "protonmail.com",
    "gmx.com",
    "gmx.de",
    "gmx.net",
    "mail.com",
    "yandex.com",
    "yandex.ru",
    "zoho.com",
    "mail.ru",
    "tutanota.com",
}
SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "rb.gy",
    "tiny.cc",
    "s.id",
    "t.ly",
    "v.gd",
    "qrco.de",
    "short.io",
    "bl.ink",
}
SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "top",
    "xyz",
    "click",
    "link",
    "country",
    "gq",
    "tk",
    "ml",
    "cf",
    "ga",
    "work",
    "support",
    "rest",
    "cam",
    "sbs",
    "cfd",
    "icu",
    "buzz",
    "monster",
    "quest",
    "lol",
    "bond",
    "online",
}
FREE_HOSTING = {
    "firebaseapp.com",
    "web.app",
    "pages.dev",
    "workers.dev",
    "github.io",
    "glitch.me",
    "netlify.app",
    "vercel.app",
    "ngrok.io",
    "ngrok-free.app",
    "000webhostapp.com",
    "weebly.com",
    "wixsite.com",
    "blogspot.com",
    "r2.dev",
    "ipfs.io",
    "azurewebsites.net",
    "web.core.windows.net",
    "trycloudflare.com",
    "repl.co",
    "onrender.com",
    "fly.dev",
    "surge.sh",
    "forms.gle",
}
DANGEROUS_EXT = {
    "exe",
    "scr",
    "com",
    "pif",
    "bat",
    "cmd",
    "js",
    "jse",
    "vbs",
    "vbe",
    "wsf",
    "wsh",
    "hta",
    "ps1",
    "psm1",
    "lnk",
    "msi",
    "msp",
    "jar",
    "iso",
    "img",
    "vhd",
    "vhdx",
    "cpl",
    "reg",
    "dll",
    "chm",
    "appx",
    "msix",
    "application",
    "xll",
    "one",
    "url",
    "scf",
    "inf",
    "sys",
    "apk",
}
HTML_EXT = {"html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam", "sldm"}
LEGACY_OFFICE_EXT = {"doc", "xls", "ppt", "rtf"}
ZIP_BASED_DOCUMENTS = {"docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "odt", "ods", "odp", "jar", "apk", "epub"}
DECOY_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "txt", "csv", "mp3", "mp4"}
EXECUTABLE_EXT = {"exe", "dll", "scr", "com", "sys", "cpl", "msi"}
LOGIN_WORDS = re.compile(r"login|log-in|signin|sign-in|verify|account|password|secure|update|wallet|banking|auth", re.I)

URGENCY = (
    "urgent",
    "immediately",
    "within 24 hours",
    "within 48 hours",
    "act now",
    "final notice",
    "last warning",
    "will be closed",
    "will be suspended",
    "has been suspended",
    "has been locked",
    "unusual activity",
    "unusual sign-in",
    "action required",
    "expires today",
    "limited time",
    "failure to",
)
CREDENTIAL_ASKS = (
    "verify your account",
    "confirm your password",
    "update your payment",
    "confirm your identity",
    "verify your identity",
    "log in to your account",
    "login to your account",
    "sign in to your account",
    "reset your password",
    "validate your account",
    "unlock your account",
    "update your billing",
    "confirm your account",
    "re-enter your password",
    "enter your password",
)
MONEY_ASKS = (
    "gift card",
    "wire transfer",
    "bank transfer",
    "bitcoin",
    "crypto wallet",
    "western union",
    "outstanding payment",
    "overdue invoice",
    "refund",
    "change of bank details",
    "new bank details",
)
GENERIC_GREETINGS = (
    "dear customer",
    "dear user",
    "dear client",
    "dear account holder",
    "dear member",
    "valued customer",
    "dear sir/madam",
    "dear sir or madam",
)


def _f(check: str, category: str, title: str, detail: str, points: int) -> Finding:
    return Finding(check=check, category=category, title=title, detail=detail, points=points)


def _ext(filename: str) -> str:
    name = filename.strip().rstrip(".").lower()
    return name.rsplit(".", 1)[1].strip() if "." in name else ""


# --------------------------------------------------------------------------- authentication


def check_authentication(email: ParsedEmail, catalog: BrandCatalog) -> list[Finding]:
    auth = email.auth
    findings: list[Finding] = []
    if auth.authserv_id is None and auth.spf is None:
        return [
            _f(
                "auth.missing",
                "authentication",
                "No authentication results",
                "The email has no Authentication-Results header, so SPF/DKIM/DMARC can't be checked. "
                "Download the original message from Gmail to include them.",
                0,
            )
        ]
    if auth.dmarc in ("fail", "permerror"):
        findings.append(
            _f(
                "auth.dmarc_fail",
                "authentication",
                "DMARC failed",
                f"The From domain ({auth.dmarc_from or email.from_domain}) did not authenticate. "
                "The sender address is probably forged.",
                30,
            )
        )
    if auth.spf in ("fail", "softfail", "permerror"):
        findings.append(
            _f(
                "auth.spf_fail",
                "authentication",
                f"SPF {auth.spf}",
                f"The sending server ({email.origin_ip or 'unknown IP'}) is not authorised to send for "
                f"{auth.spf_domain or 'the envelope domain'}.",
                20 if auth.spf != "softfail" else 10,
            )
        )
    if auth.dkim in ("fail", "permerror"):
        findings.append(
            _f(
                "auth.dkim_fail",
                "authentication",
                "DKIM signature failed",
                "The message signature is invalid: the email may have been altered or forged.",
                15,
            )
        )
    elif auth.dkim in (None, "none", "neutral", "temperror", "policy"):
        findings.append(
            _f(
                "auth.dkim_missing",
                "authentication",
                "No valid DKIM signature",
                "Almost all legitimate bulk and corporate mail is DKIM-signed.",
                5,
            )
        )
    if auth.duplicate_count:
        findings.append(
            _f(
                "auth.forged_header",
                "authentication",
                "Possible forged authentication header",
                f"{auth.duplicate_count} extra Authentication-Results header(s) claim to come from "
                f"{auth.authserv_id}. Only the top one is genuine; the others were added by the sender.",
                15,
            )
        )
    return findings


# --------------------------------------------------------------------------- sender


def check_sender(email: ParsedEmail, catalog: BrandCatalog) -> list[Finding]:
    findings: list[Finding] = []
    from_domain = email.from_domain
    from_reg = registrable_domain(from_domain) if from_domain else ""

    if from_domain and is_idn(from_domain):
        findings.append(
            _f(
                "sender.idn_domain",
                "sender",
                "Internationalised sender domain",
                f"{from_domain} decodes to '{reveal(from_domain)}'. Non-Latin characters are used to imitate real names.",
                20,
            )
        )

    impersonation = catalog.impersonation(from_domain) if from_domain else None
    if impersonation:
        findings.append(
            _f(
                "sender.lookalike_domain",
                "sender",
                f"Sender domain imitates {impersonation.brand}",
                f"{from_domain}: {impersonation.reason}.",
                35,
            )
        )

    name = email.from_name
    if name:
        embedded = re.search(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", name)
        if embedded and registrable_domain(embedded.group(1).lower()) != from_reg:
            findings.append(
                _f(
                    "sender.display_name_address",
                    "sender",
                    "Display name contains a different address",
                    f"The name shows '{embedded.group(0)}' but the real address is {email.from_address}.",
                    25,
                )
            )
        if not impersonation:
            for brand in catalog.brands_named_in(name):
                if from_reg not in {registrable_domain(d) for d in brand.domains}:
                    findings.append(
                        _f(
                            "sender.display_name_brand",
                            "sender",
                            f"Display name claims to be {brand.name}",
                            f"'{name}' but the address is {email.from_address}, which is not a {brand.name} domain.",
                            25,
                        )
                    )
                    break

    reply_domains = {registrable_domain(a.rsplit("@", 1)[1].lower()) for a in email.reply_to if "@" in a}
    other = sorted(d for d in reply_domains if d != from_reg)
    if other and from_reg:
        findings.append(
            _f(
                "sender.reply_to_mismatch",
                "sender",
                "Replies go to a different domain",
                f"From {from_reg}, but Reply-To is {', '.join(other)}. Your reply would go to someone else.",
                15,
            )
        )
        if any(d in FREEMAIL for d in other) and from_reg not in FREEMAIL:
            findings.append(
                _f(
                    "sender.reply_to_freemail",
                    "sender",
                    "Reply-To is a free webmail account",
                    "A company address with replies redirected to Gmail/Outlook/etc. is a classic "
                    "business email compromise (BEC) pattern.",
                    10,
                )
            )

    if email.return_path and "@" in email.return_path and from_reg:
        return_reg = registrable_domain(email.return_path.rsplit("@", 1)[1].lower())
        if return_reg != from_reg:
            findings.append(
                _f(
                    "sender.return_path_mismatch",
                    "sender",
                    "Envelope sender differs from From",
                    f"Return-Path is {return_reg}. Common for newsletters sent through a mailing service; "
                    "only meaningful together with other findings.",
                    5,
                )
            )
    return findings


# --------------------------------------------------------------------------- links


def check_links(email: ParsedEmail, catalog: BrandCatalog) -> list[Finding]:
    hits: dict[str, list[str]] = {}
    notes: dict[str, str] = {}

    def hit(check: str, url: str, note: str = "") -> None:
        hits.setdefault(check, [])
        if defang(url) not in hits[check]:
            hits[check].append(defang(url))
        if note and check not in notes:
            notes[check] = note

    for link in email.links:
        url = link.url.strip()
        scheme = scheme_of(url)
        if scheme in ("javascript", "data", "vbscript"):
            hit("links.script_uri", url[:60])
            continue
        if scheme and scheme not in ("http", "https"):
            continue
        host = host_of(url)
        if not host:
            continue
        registrable = registrable_domain(host)

        if is_ip(host):
            hit("links.ip_host", url)
        if has_userinfo(url):
            hit("links.userinfo", url)
        if is_idn(host):
            hit("links.idn", url, f"{host} decodes to '{reveal(host)}'")
        impersonation = catalog.impersonation(host)
        if impersonation:
            hit("links.lookalike", url, f"{impersonation.brand}: {impersonation.reason}")
        if registrable in SHORTENERS:
            hit("links.shortener", url)
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            hit("links.suspicious_tld", url)
        if registrable in FREE_HOSTING or any(host.endswith("." + h) for h in FREE_HOSTING):
            hit("links.free_hosting", url)
        if scheme == "http" and LOGIN_WORDS.search(url.split(host, 1)[-1]):
            hit("links.insecure_login", url)
        shown = domain_in_text(link.text)
        if shown and registrable_domain(shown) != registrable:
            hit("links.text_mismatch", url, f"text says '{link.text[:60]}'")

    meta = {
        "links.script_uri": (
            "Script or data link",
            "Links that run code or embed a page are not used by legitimate email.",
            25,
        ),
        "links.ip_host": (
            "Link points to a raw IP address",
            "Legitimate services link to domain names, not IP addresses.",
            20,
        ),
        "links.userinfo": (
            "Link uses the user@host trick",
            "Everything before '@' is ignored by the browser; it only disguises the real destination.",
            20,
        ),
        "links.idn": (
            "Link uses an internationalised (punycode) domain",
            "Non-Latin characters can imitate a real domain.",
            20,
        ),
        "links.lookalike": ("Link imitates a known brand", "The domain is not owned by the brand it imitates.", 35),
        "links.shortener": ("Shortened link", "URL shorteners hide the real destination.", 10),
        "links.suspicious_tld": (
            "Link to a high-abuse top-level domain",
            "These TLDs are cheap and heavily used for phishing.",
            10,
        ),
        "links.free_hosting": ("Link to free web hosting", "Phishing pages are often hosted on free platforms.", 10),
        "links.insecure_login": (
            "Unencrypted login-style link",
            "Login, verify or account pages should always use HTTPS.",
            10,
        ),
        "links.text_mismatch": (
            "Link text shows a different domain",
            "The visible link says one website but goes to another.",
            25,
        ),
    }
    findings = []
    for check, urls in hits.items():
        title, explanation, points = meta[check]
        examples = ", ".join(urls[:3]) + (f" (+{len(urls) - 3} more)" if len(urls) > 3 else "")
        note = f" {notes[check]}." if check in notes else ""
        findings.append(_f(check, "links", title, f"{explanation}{note} {examples}", points))

    if email.password_form:
        actions = [defang(a) for a in email.form_actions if a][:2]
        findings.append(
            _f(
                "content.password_form",
                "content",
                "Email contains a password form",
                "Legitimate companies never ask for your password inside an email."
                + (f" Form submits to {', '.join(actions)}." if actions else ""),
                30,
            )
        )
    return findings


# --------------------------------------------------------------------------- attachments


def _zip_findings(filename: str, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()[:1000]  # only the directory is read; nothing is extracted
    except (zipfile.BadZipFile, ValueError, OSError):
        return findings
    if any(info.flag_bits & 0x1 for info in infos):
        findings.append(
            _f(
                "attachments.encrypted_archive",
                "attachments",
                "Password-protected archive",
                f"{filename} is encrypted, which stops mail scanners from looking inside.",
                20,
            )
        )
    risky = [i.filename for i in infos if _ext(i.filename) in DANGEROUS_EXT | HTML_EXT | MACRO_EXT]
    if risky:
        findings.append(
            _f(
                "attachments.archive_dangerous_content",
                "attachments",
                "Archive contains risky files",
                f"{filename} contains {', '.join(risky[:5])}.",
                30,
            )
        )
    return findings


def check_attachments(email: ParsedEmail, catalog: BrandCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for attachment in email.attachments:
        name = attachment.filename
        ext = _ext(name)
        parts = [p.strip() for p in name.lower().split(".")]
        data = attachment.data

        if "‮" in name:
            findings.append(
                _f(
                    "attachments.rtl_override",
                    "attachments",
                    "Filename hides its real extension",
                    f"'{name!r}' uses a right-to-left override character to reverse how the extension is displayed.",
                    35,
                )
            )
        if ext in DANGEROUS_EXT:
            findings.append(
                _f(
                    "attachments.dangerous_type",
                    "attachments",
                    f"Dangerous attachment type (.{ext})",
                    f"{name} can run code when opened.",
                    35,
                )
            )
        if len(parts) >= 3 and parts[-2] in DECOY_EXT and ext in DANGEROUS_EXT | HTML_EXT:
            findings.append(
                _f(
                    "attachments.double_extension",
                    "attachments",
                    "Double file extension",
                    f"{name} pretends to be a .{parts[-2]} but is really a .{ext}.",
                    30,
                )
            )
        if ext in HTML_EXT:
            findings.append(
                _f(
                    "attachments.html_file",
                    "attachments",
                    "HTML attachment",
                    f"{name} opens in your browser. Attached web pages are a common way to deliver fake login pages.",
                    30,
                )
            )
            scanner = scan_html(data.decode("utf-8", errors="replace"))
            if scanner.password_form:
                findings.append(
                    _f(
                        "attachments.html_credential_form",
                        "attachments",
                        "Attached page asks for a password",
                        f"{name} contains a password field: a local credential-harvesting page.",
                        20,
                    )
                )
        if ext in MACRO_EXT:
            findings.append(
                _f(
                    "attachments.macro_document",
                    "attachments",
                    "Macro-enabled Office document",
                    f"{name} can contain macros, a common malware delivery method.",
                    25,
                )
            )
        elif ext in LEGACY_OFFICE_EXT:
            findings.append(
                _f(
                    "attachments.legacy_office",
                    "attachments",
                    "Legacy Office format",
                    f"{name} uses an old format that can carry macros.",
                    10,
                )
            )
        if data[:2] == b"MZ" and ext not in EXECUTABLE_EXT:
            findings.append(
                _f(
                    "attachments.type_mismatch",
                    "attachments",
                    "Attachment is a disguised program",
                    f"{name} is named .{ext or '(none)'} but its content is a Windows executable.",
                    35,
                )
            )
        # Recognised by content, not by name: renamed archives are inspected too.
        if data[:4] == b"PK\x03\x04" and ext not in ZIP_BASED_DOCUMENTS:
            findings.extend(_zip_findings(name, data))
    return findings


# --------------------------------------------------------------------------- content


def _matches(text: str, phrases: tuple[str, ...]) -> list[str]:
    return [p for p in phrases if p in text]


def check_content(email: ParsedEmail, catalog: BrandCatalog) -> list[Finding]:
    text = " ".join(f"{email.subject} {email.text}".lower().split())
    findings = []
    urgency = _matches(text, URGENCY)
    if urgency:
        findings.append(
            _f(
                "content.urgency",
                "content",
                "Pressure / urgency language",
                "Phrases: " + ", ".join(f"'{p}'" for p in urgency[:5]),
                10 if len(urgency) >= 2 else 5,
            )
        )
    if asks := _matches(text, CREDENTIAL_ASKS):
        findings.append(
            _f(
                "content.credential_request",
                "content",
                "Asks you to log in or confirm details",
                "Phrases: " + ", ".join(f"'{p}'" for p in asks[:5]),
                10,
            )
        )
    if money := _matches(text, MONEY_ASKS):
        findings.append(
            _f(
                "content.payment_request",
                "content",
                "Mentions payments or money transfers",
                "Phrases: " + ", ".join(f"'{p}'" for p in money[:5]),
                10,
            )
        )
    if generic := _matches(text, GENERIC_GREETINGS):
        findings.append(
            _f(
                "content.generic_greeting",
                "content",
                "Generic greeting",
                f"'{generic[0]}': companies you have an account with usually use your name.",
                5,
            )
        )
    return findings


# --------------------------------------------------------------------------- positives & scoring


def positive_signals(email: ParsedEmail, catalog: BrandCatalog) -> list[str]:
    signals = []
    auth = email.auth
    if auth.dmarc == "pass":
        signals.append(f"DMARC pass: the From domain ({auth.dmarc_from or email.from_domain}) is authenticated")
    if auth.dkim == "pass" and auth.dkim_domains:
        signals.append(f"DKIM signature valid ({', '.join(sorted(set(auth.dkim_domains)))})")
    if auth.spf == "pass":
        signals.append("SPF pass: sent from a server authorised by the envelope domain")
    brand = catalog.brand_for_domain(email.from_domain) if email.from_domain else None
    if brand and auth.dmarc == "pass":
        signals.append(f"Sent from an official {brand.name} domain")
    return signals


CHECKS: list[Callable[[ParsedEmail, BrandCatalog], list[Finding]]] = [
    check_authentication,
    check_sender,
    check_links,
    check_attachments,
    check_content,
]


def score(findings: list[Finding]) -> int:
    content = sum(f.points for f in findings if f.category == "content" and f.check != "content.password_form")
    other = sum(f.points for f in findings if f.category != "content" or f.check == "content.password_form")
    return min(100, other + min(content, CONTENT_CAP))


def verdict_for(points: int) -> str:
    if points >= PHISHING_THRESHOLD:
        return "phishing"
    if points >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "clean"


def analyse(email: ParsedEmail, catalog: BrandCatalog | None = None, extra: list[Finding] | None = None) -> Analysis:
    catalog = catalog or BrandCatalog.load()
    findings = [finding for check in CHECKS for finding in check(email, catalog)]
    findings.extend(extra or [])
    findings.sort(key=lambda f: (-f.points, f.category, f.check))
    total = score(findings)
    return Analysis(email, findings, positive_signals(email, catalog), total, verdict_for(total))
