"""Optional reputation lookups (VirusTotal, AbuseIPDB). Off unless ``--online`` is given.

Privacy: only domains, attachment SHA-256 hashes and the sending server's IP
are sent. Full URLs are never sent, because they often contain personal
tokens (password-reset links, unsubscribe links with your address).
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from urllib.parse import quote, urlencode

from .lookalike import BrandCatalog
from .models import Finding, ParsedEmail
from .urls import host_of, is_ip, registrable_domain

VT_API = "https://www.virustotal.com/api/v3"
ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"
_DOMAIN = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

Fetch = Callable[[str, dict[str, str]], tuple[int, dict | None]]


def _urllib_fetch(url: str, headers: dict[str, str]) -> tuple[int, dict | None]:
    request = urllib.request.Request(  # noqa: S310 - only the fixed https API hosts above are used
        url, headers={**headers, "Accept": "application/json", "User-Agent": "phishcheck"}
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, None


class IntelClient:
    def __init__(
        self,
        vt_key: str | None = None,
        abuseipdb_key: str | None = None,
        max_lookups: int = 4,
        fetch: Fetch | None = None,
    ):
        self.vt_key = vt_key
        self.abuseipdb_key = abuseipdb_key
        self.remaining = max_lookups
        self.fetch = fetch or _urllib_fetch

    @classmethod
    def from_env(cls, max_lookups: int = 4) -> IntelClient:
        return cls(os.environ.get("VT_API_KEY"), os.environ.get("ABUSEIPDB_API_KEY"), max_lookups)

    @property
    def enabled(self) -> bool:
        return bool(self.vt_key or self.abuseipdb_key)

    # ------------------------------------------------------------------ lookups

    def _vt(self, path: str) -> tuple[int, dict | None]:
        self.remaining -= 1
        return self.fetch(f"{VT_API}/{path}", {"x-apikey": self.vt_key or ""})

    def _targets(self, email: ParsedEmail, catalog: BrandCatalog) -> list[tuple[str, str]]:
        targets: list[tuple[str, str]] = []
        for attachment in email.attachments:
            if _SHA256.match(attachment.sha256):
                targets.append(("file", attachment.sha256))
        domains: list[str] = []
        for link in email.links:
            host = host_of(link.url)
            if host and not is_ip(host):
                domains.append(registrable_domain(host))
        if email.from_domain:
            domains.append(registrable_domain(email.from_domain))
        for domain in dict.fromkeys(domains):
            if _DOMAIN.match(domain) and not catalog.is_official(domain):
                targets.append(("domain", domain))
        return targets

    def lookup(self, email: ParsedEmail, catalog: BrandCatalog) -> list[Finding]:
        findings: list[Finding] = []
        flagged: list[tuple[str, int, int]] = []
        notes: list[str] = []
        try:
            if self.vt_key:
                for kind, value in self._targets(email, catalog):
                    if self.remaining <= 0:
                        notes.append("lookup limit reached (raise it with --max-lookups)")
                        break
                    path = f"files/{value}" if kind == "file" else f"domains/{quote(value, safe='')}"
                    status, body = self._vt(path)
                    if status == 401:
                        notes.append("VirusTotal rejected the API key")
                        break
                    if status == 429:
                        notes.append("VirusTotal rate limit reached (free tier: 4 lookups per minute)")
                        break
                    if status == 404:
                        if kind == "file":
                            notes.append(f"attachment {value[:12]}... is unknown to VirusTotal")
                        continue
                    stats = (((body or {}).get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
                    malicious, suspicious = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
                    if malicious or suspicious >= 2:
                        flagged.append(
                            (value if kind == "domain" else f"attachment {value[:12]}...", malicious, suspicious)
                        )
            if self.abuseipdb_key and email.origin_ip:
                findings.extend(self._abuseipdb(email.origin_ip))
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            notes.append(f"lookup failed: {exc}")

        if flagged:
            worst = max(m for _, m, _ in flagged)
            points = 40 if worst >= 3 else 20 if worst >= 1 else 10
            detail = "; ".join(f"{name}: {m} malicious, {s} suspicious" for name, m, s in flagged)
            findings.append(Finding("intel.virustotal", "intel", "Flagged by VirusTotal engines", detail, points))
        if notes:
            findings.append(Finding("intel.notes", "intel", "Online lookup notes", "; ".join(notes), 0))
        return findings

    def _abuseipdb(self, ip: str) -> list[Finding]:
        try:
            if not ipaddress.ip_address(ip).is_global:
                return []
        except ValueError:
            return []
        query = urlencode({"ipAddress": ip, "maxAgeInDays": 90})
        status, body = self.fetch(f"{ABUSEIPDB_API}?{query}", {"Key": self.abuseipdb_key or ""})
        if status != 200 or not body:
            return [Finding("intel.notes", "intel", "Online lookup notes", f"AbuseIPDB returned HTTP {status}", 0)]
        data = body.get("data") or {}
        confidence = int(data.get("abuseConfidenceScore", 0))
        if confidence < 25:
            return []
        points = 25 if confidence >= 75 else 10
        detail = (
            f"Sending server {ip} has an abuse confidence of {confidence}% "
            f"({data.get('totalReports', 0)} reports, country {data.get('countryCode') or '?'})."
        )
        return [Finding("intel.abuseipdb", "intel", "Sending server is reported for abuse", detail, points)]
