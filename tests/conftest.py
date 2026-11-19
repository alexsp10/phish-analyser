from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path

import pytest

from phishcheck.lookalike import BrandCatalog
from phishcheck.parser import parse_bytes

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
DEMO_BRANDS = SAMPLES / "demo-brands.json"


@pytest.fixture(scope="session")
def catalog() -> BrandCatalog:
    return BrandCatalog.load(DEMO_BRANDS)


def build(
    *,
    sender: str = "Alice <alice@sender.example>",
    subject: str = "Hello",
    text: str = "Hi",
    html: str | None = None,
    auth: str | None = "mx.google.com; dkim=pass header.i=@sender.example; spf=pass smtp.mailfrom=b@sender.example; "
    "dmarc=pass header.from=sender.example",
    headers: dict[str, str] | None = None,
    attachments: list[tuple[str, bytes, str]] | None = None,
):
    """Build an email in memory and parse it."""
    msg = EmailMessage()
    if auth:
        msg["Authentication-Results"] = auth
    for name, value in (headers or {}).items():
        msg[name] = value
    msg["From"] = sender
    msg["To"] = "you@example.com"
    msg["Subject"] = subject
    msg.set_content(text)
    if html is not None:
        msg.add_alternative(html, subtype="html")
    for filename, data, mime in attachments or []:
        maintype, subtype = mime.split("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    return parse_bytes(bytes(msg), "<test>")
