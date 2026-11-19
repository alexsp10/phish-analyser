"""Parse .eml files and Gmail Takeout .mbox archives into :class:`ParsedEmail`.

Nothing in an email is executed or fetched: links are only read as text and
attachments are only hashed and inspected byte-wise.
"""

from __future__ import annotations

import hashlib
import ipaddress
import mailbox
import re
from collections.abc import Iterator
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from pathlib import Path

from .models import Attachment, AuthResults, Link, ParsedEmail
from .urls import find_urls

_IP_IN_BRACKETS = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:.]+)\]")
_SKIP_SCHEMES = ("mailto:", "tel:", "cid:", "sms:", "#")


# --------------------------------------------------------------------------- HTML


class _HTMLScanner(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.text: list[str] = []
        self.form_actions: list[str] = []
        self.password_form = False
        self._href: str | None = None
        self._anchor_text: list[str] = []
        self._skip = 0

    def _close_anchor(self) -> None:
        if self._href is not None:
            self.links.append(Link(self._href, " ".join("".join(self._anchor_text).split()), "html"))
        self._href = None
        self._anchor_text = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style", "head", "title"):
            self._skip += 1
        if tag == "a" and attributes.get("href"):
            self._close_anchor()
            self._href = attributes["href"].strip()
        elif tag == "area" and attributes.get("href"):
            self.links.append(Link(attributes["href"].strip(), attributes.get("alt", ""), "html"))
        elif tag == "form":
            action = attributes.get("action", "").strip()
            self.form_actions.append(action)
            if action:
                self.links.append(Link(action, "", "form"))
        elif tag == "input" and attributes.get("type", "").lower() == "password":
            self.password_form = True
        elif tag == "meta" and attributes.get("http-equiv", "").lower() == "refresh":
            match = re.search(r"url\s*=\s*['\"]?([^'\";]+)", attributes.get("content", ""), re.IGNORECASE)
            if match:
                self.links.append(Link(match.group(1).strip(), "", "meta-refresh"))
        elif tag in ("br", "p", "div", "tr", "li"):
            self.text.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "head", "title") and self._skip:
            self._skip -= 1
        if tag == "a":
            self._close_anchor()

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._anchor_text.append(data)

    def close(self) -> None:
        super().close()
        self._close_anchor()


def scan_html(html: str) -> _HTMLScanner:
    scanner = _HTMLScanner()
    try:
        scanner.feed(html)
        scanner.close()
    except Exception:  # noqa: BLE001 - malformed HTML must never crash the analysis
        scanner._close_anchor()
    return scanner


# --------------------------------------------------------------------------- headers


def _first_address(msg: EmailMessage, name: str) -> tuple[str, str]:
    try:
        header = msg[name]
        if header is None:
            return "", ""
        addresses = getattr(header, "addresses", ())
        if addresses:
            return str(addresses[0].display_name or ""), str(addresses[0].addr_spec or "")
        return parseaddr(str(header))
    except Exception:  # noqa: BLE001 - defective headers are common in spam
        raw = msg.get(name, failobj="")
        return parseaddr(str(raw))


def _all_addresses(msg: EmailMessage, name: str) -> list[str]:
    try:
        values = [str(v) for v in msg.get_all(name, [])]
    except Exception:  # noqa: BLE001
        return []
    return [addr for _, addr in getaddresses(values) if addr]


def domain_of(address: str) -> str:
    return address.rsplit("@", 1)[1].strip(" <>").lower() if "@" in address else ""


def parse_auth_results(values: list[str], received_spf: str | None = None) -> AuthResults:
    """Parse RFC 8601 Authentication-Results.

    Only the top-most header is trusted: it is added by the receiving server
    (mx.google.com for Gmail). Anyone can put a fake "all pass" header further
    down, so headers below it are only used to detect such forgeries.
    """
    if not values:
        auth = AuthResults()
        if received_spf:
            match = re.match(r"\s*(\w+)", received_spf)
            auth.spf = match.group(1).lower() if match else None
        return auth

    raw = " ".join(values[0].split())
    segments = [s.strip() for s in raw.split(";")]
    auth = AuthResults(authserv_id=segments[0].split()[0].lower() if segments[0] else None, raw=raw)
    dkim_results: list[str] = []

    for segment in segments[1:]:
        match = re.match(r"(spf|dkim|dmarc)\s*=\s*([a-z]+)(.*)$", segment, re.IGNORECASE | re.DOTALL)
        if not match:
            continue
        method, result, rest = match.group(1).lower(), match.group(2).lower(), match.group(3)
        if method == "spf" and auth.spf is None:
            auth.spf = result
            if m := re.search(r"smtp\.mailfrom=([^\s;]+)", rest):
                auth.spf_domain = domain_of(m.group(1)) or m.group(1).lower()
        elif method == "dkim":
            dkim_results.append(result)
            if result == "pass" and (m := re.search(r"header\.(?:d|i)=@?([^\s;]+)", rest)):
                auth.dkim_domains.append(m.group(1).lower().lstrip("@"))
        elif method == "dmarc" and auth.dmarc is None:
            auth.dmarc = result
            if m := re.search(r"header\.from=([^\s;]+)", rest):
                auth.dmarc_from = m.group(1).lower()

    if dkim_results:
        auth.dkim = "pass" if "pass" in dkim_results else dkim_results[0]
    if auth.authserv_id:
        auth.duplicate_count = sum(1 for v in values[1:] if v.strip().lower().startswith(auth.authserv_id))
    return auth


def origin_ip(received: list[str]) -> str | None:
    """First public IP in the Received chain, read top-down (closest to our mail server)."""
    for header in received:
        for candidate in _IP_IN_BRACKETS.findall(header):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if ip.is_global:
                return str(ip)
    return None


# --------------------------------------------------------------------------- bodies


def _text_content(part: EmailMessage) -> str:
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
    except Exception:  # noqa: BLE001, S110 - unknown charsets/bad encodings fall back to raw bytes below
        pass
    payload = part.get_payload(decode=True) or b""
    return payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else str(payload)


def _dedupe(links: list[Link]) -> list[Link]:
    seen: set[tuple[str, str]] = set()
    unique = []
    for link in links:
        key = (link.url, link.text)
        if key not in seen:
            seen.add(key)
            unique.append(link)
    return unique


def from_message(msg: EmailMessage, source: str) -> ParsedEmail:
    from_name, from_address = _first_address(msg, "From")
    received = [" ".join(str(r).split()) for r in msg.get_all("Received", [])]
    parsed = ParsedEmail(
        source=source,
        subject=" ".join(str(msg.get("Subject", "")).split()),
        date=str(msg.get("Date", "")),
        message_id=str(msg.get("Message-ID", "")).strip(),
        from_name=from_name.strip(),
        from_address=from_address.strip(),
        from_domain=domain_of(from_address),
        reply_to=_all_addresses(msg, "Reply-To"),
        return_path=str(msg.get("Return-Path", "")).strip(" <>"),
        received=received,
        origin_ip=origin_ip(received),
        auth=parse_auth_results(
            [str(v) for v in msg.get_all("Authentication-Results", [])],
            str(msg.get("Received-SPF", "")) or None,
        ),
    )

    texts: list[str] = []
    htmls: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        content_type = part.get_content_type()
        if filename or disposition == "attachment":
            data = part.get_payload(decode=True) or b""
            if not isinstance(data, bytes):
                data = str(data).encode("utf-8", errors="replace")
            parsed.attachments.append(
                Attachment(
                    filename=str(filename or "(unnamed)"),
                    content_type=content_type,
                    size=len(data),
                    sha256=hashlib.sha256(data).hexdigest(),
                    data=data,
                )
            )
        elif content_type == "text/plain":
            texts.append(_text_content(part))
        elif content_type == "text/html":
            htmls.append(_text_content(part))

    links: list[Link] = []
    html_text: list[str] = []
    for html in htmls:
        scanner = scan_html(html)
        links.extend(scanner.links)
        html_text.append("".join(scanner.text))
        parsed.form_actions.extend(scanner.form_actions)
        parsed.password_form = parsed.password_form or scanner.password_form
    plain = "\n".join(texts)
    for url in find_urls(plain):
        links.append(Link(url, "", "text"))

    parsed.links = [link for link in _dedupe(links) if link.url and not link.url.lower().startswith(_SKIP_SCHEMES)]
    parsed.text = "\n".join([plain, *html_text]).strip()
    parsed.html = "\n".join(htmls)
    return parsed


def parse_bytes(data: bytes, source: str = "<bytes>") -> ParsedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(data)
    return from_message(msg, source)  # type: ignore[arg-type]


def is_mbox(path: Path) -> bool:
    if path.suffix.lower() == ".mbox":
        return True
    with path.open("rb") as handle:
        return handle.read(5) == b"From "


def iter_file(path: str | Path) -> Iterator[ParsedEmail]:
    """Yield every email in a .eml file or an mbox archive (Gmail Takeout)."""
    path = Path(path)
    if is_mbox(path):
        box = mailbox.mbox(str(path), create=False)
        try:
            for index, message in enumerate(box, start=1):
                yield parse_bytes(message.as_bytes(), f"{path}#{index}")
        finally:
            box.close()
    else:
        yield parse_bytes(path.read_bytes(), str(path))
