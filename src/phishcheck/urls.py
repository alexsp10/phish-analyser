"""URL and domain helpers."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

# Two-label public suffixes we care about. A full Public Suffix List is out of
# scope; this covers the common country-code second levels.
_MULTI_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "ltd.uk",
    "plc.uk",
    "me.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.nz",
    "co.jp",
    "ne.jp",
    "co.in",
    "co.za",
    "com.br",
    "com.mx",
    "com.ar",
    "com.tr",
    "com.cn",
    "com.hk",
    "com.sg",
    "com.gr",
    "gov.gr",
    "edu.gr",
    "com.cy",
    "ac.cy",
    "gov.cy",
    "co.il",
    "co.kr",
}

_URL_IN_TEXT = re.compile(r"(?:https?://|www\.)[^\s<>\"'()\[\]{}]+", re.IGNORECASE)
_DOMAIN_LIKE = re.compile(r"^(?:https?://)?(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[:/?#].*)?$", re.IGNORECASE)


def find_urls(text: str) -> list[str]:
    urls = []
    for match in _URL_IN_TEXT.findall(text):
        urls.append(match.rstrip(".,;:!?'\""))
    return urls


def normalise(url: str) -> str:
    url = url.strip()
    if url.lower().startswith("www."):
        return "http://" + url
    return url


def scheme_of(url: str) -> str:
    match = re.match(r"^\s*([a-zA-Z][a-zA-Z0-9+.-]*):", url)
    return match.group(1).lower() if match else ""


def host_of(url: str) -> str | None:
    try:
        parts = urlsplit(normalise(url))
        host = parts.hostname
    except ValueError:
        return None
    if not host:
        return None
    return host.rstrip(".").lower()


def has_userinfo(url: str) -> bool:
    try:
        netloc = urlsplit(normalise(url)).netloc
    except ValueError:
        return False
    return "@" in netloc


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    # Integer / hex encoded IPv4 such as http://3232235777/ or 0xC0A80101
    return bool(re.fullmatch(r"(0x[0-9a-f]+|\d{8,10})", host))


def to_unicode(host: str) -> str:
    """Decode punycode labels (xn--) so homoglyphs become visible."""
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                labels.append(label.encode("ascii").decode("idna"))
                continue
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def is_idn(host: str) -> bool:
    return any(label.startswith("xn--") for label in host.split(".")) or not host.isascii()


def registrable_domain(host: str) -> str:
    """Best-effort 'organisational' domain: mail.paypal.co.uk -> paypal.co.uk."""
    host = host.rstrip(".").lower()
    if is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def domain_in_text(text: str) -> str | None:
    """If link text *looks like* a URL or domain, return that domain."""
    candidate = " ".join(text.split()).strip().lower()
    if not candidate or " " in candidate:
        return None
    match = _DOMAIN_LIKE.match(candidate)
    if not match:
        return None
    domain = match.group(1)
    # "file.pdf" or "v2.0" are not domains.
    if domain.rsplit(".", 1)[-1] in {
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "png",
        "jpg",
        "zip",
        "html",
        "htm",
        "php",
        "aspx",
    }:
        return None
    return domain


def defang(url: str) -> str:
    """Make a URL non-clickable for safe display: hxxps://evil[.]com/path."""
    url = url.strip()
    try:
        netloc = urlsplit(normalise(url)).netloc
    except ValueError:
        netloc = ""
    if netloc:
        url = url.replace(netloc, netloc.replace(".", "[.]"), 1)
    return re.sub(r"^http", "hxxp", url, flags=re.IGNORECASE)


def reveal(host: str) -> str:
    """Decode punycode and spell out every non-ASCII character: northw<U+0456>ndbank.example."""
    return "".join(c if c.isascii() else f"<U+{ord(c):04X}>" for c in to_unicode(host))
