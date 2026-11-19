"""Data model shared by the parser, the checks and the reports."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Link:
    url: str
    text: str = ""
    source: str = "html"  # html | text | form | meta-refresh


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    data: bytes = field(default=b"", repr=False)


@dataclass
class AuthResults:
    """Sender authentication verdicts recorded by the receiving server (Gmail: mx.google.com)."""

    authserv_id: str | None = None
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    spf_domain: str | None = None
    dkim_domains: list[str] = field(default_factory=list)
    dmarc_from: str | None = None
    raw: str | None = None
    duplicate_count: int = 0  # extra headers claiming the same authserv-id (possible forgery)


@dataclass
class ParsedEmail:
    source: str
    subject: str = ""
    date: str = ""
    message_id: str = ""
    from_name: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to: list[str] = field(default_factory=list)
    return_path: str = ""
    received: list[str] = field(default_factory=list)
    origin_ip: str | None = None
    auth: AuthResults = field(default_factory=AuthResults)
    text: str = ""
    html: str = ""
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    password_form: bool = False
    form_actions: list[str] = field(default_factory=list)


SEVERITIES = ("info", "low", "medium", "high")


@dataclass
class Finding:
    check: str
    category: str  # authentication | sender | links | attachments | content | intel
    title: str
    detail: str
    points: int

    @property
    def severity(self) -> str:
        if self.points >= 30:
            return "high"
        if self.points >= 15:
            return "medium"
        if self.points > 0:
            return "low"
        return "info"


VERDICTS = {
    "phishing": "Likely phishing",
    "suspicious": "Suspicious",
    "clean": "No strong phishing indicators",
}


@dataclass
class Analysis:
    email: ParsedEmail
    findings: list[Finding]
    positives: list[str]
    score: int
    verdict: str  # phishing | suspicious | clean

    @property
    def verdict_label(self) -> str:
        return VERDICTS[self.verdict]

    def has(self, check: str) -> bool:
        return any(f.check == check for f in self.findings)
