"""Text, JSON and HTML output. Links are always shown defanged (hxxps://evil[.]com)."""

from __future__ import annotations

import html
import textwrap
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .models import Analysis
from .urls import defang

ADVICE = {
    "phishing": (
        "Do not click links, open attachments or reply. In Gmail, open the three-dot menu and choose "
        "'Report phishing', then delete the email. If you already entered a password, change it now "
        "(and anywhere you reused it) and turn on 2-Step Verification."
    ),
    "suspicious": (
        "Don't use the links or attachments in this email. If it claims to be from a company, go to its "
        "website or app yourself (type the address) and check there. If it's from someone you know, "
        "confirm with them another way, e.g. by phone."
    ),
    "clean": (
        "No strong signs of phishing were found. That is not a guarantee: be careful with any unexpected "
        "request for money, passwords or verification codes."
    ),
}


# --------------------------------------------------------------------------- text


def _wrap(text: str, indent: int, width: int = 100) -> str:
    return textwrap.fill(text, width=width, initial_indent=" " * indent, subsequent_indent=" " * indent)


def render_text(analysis: Analysis) -> str:
    email = analysis.email
    sender = f"{email.from_name} <{email.from_address}>" if email.from_name else email.from_address
    lines = [
        "=" * 100,
        email.source,
        f"Subject : {email.subject or '(none)'}",
        f"From    : {sender or '(none)'}",
        f"Verdict : {analysis.verdict_label.upper()}   (risk score {analysis.score}/100)",
        "-" * 100,
    ]
    if analysis.findings:
        lines.append("Findings")
        for finding in analysis.findings:
            points = f"+{finding.points}" if finding.points else "  "
            lines.append(f"  {finding.severity.upper():<6} {points:>4}  {finding.title}")
            lines.append(_wrap(finding.detail, 15))
    else:
        lines.append("Findings: none")
    if analysis.positives:
        lines.append("Good signs")
        lines += [f"  + {p}" for p in analysis.positives]
    if email.links:
        lines.append(f"Links ({len(email.links)}, shown defanged)")
        for link in email.links[:10]:
            text = f'  "{link.text[:40]}"' if link.text else ""
            lines.append(f"  - {defang(link.url)[:110]}{text}")
        if len(email.links) > 10:
            lines.append(f"  ... {len(email.links) - 10} more")
    if email.attachments:
        lines.append("Attachments")
        for a in email.attachments:
            lines.append(f"  - {a.filename} ({a.content_type}, {a.size:,} bytes) sha256 {a.sha256}")
    lines.append("What to do")
    lines.append(_wrap(ADVICE[analysis.verdict], 2))
    return "\n".join(lines)


def render_summary(analyses: list[Analysis]) -> str:
    rows = [f"{'VERDICT':<12} {'SCORE':>5}  {'FROM':<38} SUBJECT"]
    for a in sorted(analyses, key=lambda x: -x.score):
        sender = (a.email.from_address or "?")[:38]
        rows.append(f"{a.verdict.upper():<12} {a.score:>5}  {sender:<38} {a.email.subject[:60]}")
    counts = {v: sum(1 for a in analyses if a.verdict == v) for v in ("phishing", "suspicious", "clean")}
    rows.append(
        f"\n{len(analyses)} email(s): {counts['phishing']} likely phishing, "
        f"{counts['suspicious']} suspicious, {counts['clean']} no strong indicators"
    )
    return "\n".join(rows)


# --------------------------------------------------------------------------- JSON


def to_dict(analysis: Analysis) -> dict[str, Any]:
    email = analysis.email
    return {
        "source": email.source,
        "subject": email.subject,
        "from": {"name": email.from_name, "address": email.from_address, "domain": email.from_domain},
        "reply_to": email.reply_to,
        "return_path": email.return_path,
        "origin_ip": email.origin_ip,
        "authentication": {"spf": email.auth.spf, "dkim": email.auth.dkim, "dmarc": email.auth.dmarc},
        "verdict": analysis.verdict,
        "verdict_label": analysis.verdict_label,
        "score": analysis.score,
        "advice": ADVICE[analysis.verdict],
        "findings": [
            {
                "check": f.check,
                "category": f.category,
                "severity": f.severity,
                "points": f.points,
                "title": f.title,
                "detail": f.detail,
            }
            for f in analysis.findings
        ],
        "good_signs": analysis.positives,
        "links": [{"url": defang(link.url), "text": link.text} for link in email.links],
        "attachments": [
            {"filename": a.filename, "content_type": a.content_type, "size": a.size, "sha256": a.sha256}
            for a in email.attachments
        ],
    }


# --------------------------------------------------------------------------- HTML

_CSS = """
:root { --bg:#f6f7f9; --panel:#fff; --text:#1b1f24; --muted:#5d6673; --border:#dde1e6; --code:#f0f2f5; --link:#2f5bd3;
  --phishing:#b3261e; --suspicious:#b46a00; --clean:#2f7d4f; --high:#b3261e; --medium:#c25e00; --low:#8a7300; --info:#5d6673; }
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) {
  --bg:#111418; --panel:#1a1f25; --text:#e6e9ed; --muted:#9aa4b1; --border:#2b323b; --code:#232a32; --link:#7ea2ff;
  --phishing:#ff6b61; --suspicious:#f0a640; --clean:#5cc98a; --high:#ff6b61; --medium:#ff8c4a; --low:#e8bf3a; --info:#9aa4b1; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
main { max-width:1000px; margin:0 auto; padding:28px 16px 60px; }
h1 { font-size:26px; margin:0 0 4px; } h2 { font-size:18px; margin:0 0 6px; overflow-wrap:anywhere; } h3 { font-size:14px; margin:16px 0 6px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }
.muted { color:var(--muted); }
a { color:var(--link); }
.card { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:18px; margin:16px 0; }
.verdict { display:inline-block; padding:3px 10px; border-radius:999px; color:#fff; font-weight:650; font-size:13px; }
.verdict.phishing { background:var(--phishing); } .verdict.suspicious { background:var(--suspicious); } .verdict.clean { background:var(--clean); }
.meter { height:8px; background:var(--code); border-radius:4px; margin:10px 0 4px; overflow:hidden; }
.meter span { display:block; height:100%; }
.meter .phishing { background:var(--phishing); } .meter .suspicious { background:var(--suspicious); } .meter .clean { background:var(--clean); }
table { width:100%; border-collapse:collapse; font-size:14px; }
th, td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--border); vertical-align:top; }
th { color:var(--muted); font-size:12px; text-transform:uppercase; }
.sev { font-weight:700; font-size:12px; text-transform:uppercase; }
.sev.high { color:var(--high); } .sev.medium { color:var(--medium); } .sev.low { color:var(--low); } .sev.info { color:var(--info); }
code { font-family:ui-monospace,Consolas,monospace; font-size:12.5px; background:var(--code); padding:1px 5px; border-radius:4px; overflow-wrap:anywhere; }
.advice { border-left:4px solid var(--border); padding:6px 12px; margin-top:12px; }
.advice.phishing { border-color:var(--phishing); } .advice.suspicious { border-color:var(--suspicious); } .advice.clean { border-color:var(--clean); }
ul { margin:4px 0; padding-left:20px; }
@media (max-width:640px) { th:nth-child(2), td:nth-child(2) { display:none; } }
"""


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _card(index: int, analysis: Analysis) -> str:
    email = analysis.email
    sender = f"{email.from_name} <{email.from_address}>" if email.from_name else email.from_address
    findings = (
        "".join(
            f'<tr><td><span class="sev {f.severity}">{_e(f.severity)}</span></td>'
            f"<td>{'+' + str(f.points) if f.points else ''}</td>"
            f'<td><strong>{_e(f.title)}</strong><br><span class="muted">{_e(f.detail)}</span></td></tr>'
            for f in analysis.findings
        )
        or '<tr><td colspan="3" class="muted">No findings.</td></tr>'
    )
    positives = "".join(f"<li>{_e(p)}</li>" for p in analysis.positives)
    links = "".join(
        f"<li><code>{_e(defang(link.url))}</code>{' &ldquo;' + _e(link.text[:60]) + '&rdquo;' if link.text else ''}</li>"
        for link in email.links[:30]
    )
    attachments = "".join(
        f'<li>{_e(a.filename)} <span class="muted">({_e(a.content_type)}, {a.size:,} bytes)</span><br>'
        f"<code>sha256 {_e(a.sha256)}</code></li>"
        for a in email.attachments
    )
    auth = email.auth
    return (
        f'<section class="card" id="email-{index}">'
        f'<span class="verdict {analysis.verdict}">{_e(analysis.verdict_label)}</span>'
        f'<h2 style="margin-top:10px">{_e(email.subject or "(no subject)")}</h2>'
        f'<div class="muted">From {_e(sender or "(none)")} · {_e(email.date)}</div>'
        f'<div class="meter"><span class="{analysis.verdict}" style="width:{max(analysis.score, 2)}%"></span></div>'
        f'<div class="muted">Risk score {analysis.score}/100 · SPF {_e(auth.spf or "n/a")} · DKIM {_e(auth.dkim or "n/a")} · '
        f"DMARC {_e(auth.dmarc or 'n/a')}{' · sent from ' + _e(email.origin_ip) if email.origin_ip else ''}</div>"
        f"<h3>Findings</h3><table><thead><tr><th>Severity</th><th>Points</th><th>Finding</th></tr></thead><tbody>{findings}</tbody></table>"
        + (f"<h3>Good signs</h3><ul>{positives}</ul>" if positives else "")
        + (f"<h3>Links ({len(email.links)}, defanged)</h3><ul>{links}</ul>" if links else "")
        + (f"<h3>Attachments</h3><ul>{attachments}</ul>" if attachments else "")
        + f'<div class="advice {analysis.verdict}"><strong>What to do:</strong> {_e(ADVICE[analysis.verdict])}</div>'
        f'<p class="muted" style="margin-bottom:0">File: <code>{_e(email.source)}</code></p></section>'
    )


def render_html(analyses: list[Analysis]) -> str:
    ordered = sorted(analyses, key=lambda a: -a.score)
    rows = "".join(
        f'<tr><td><span class="verdict {a.verdict}">{_e(a.verdict)}</span></td><td>{a.score}</td>'
        f'<td><a href="#email-{i}">{_e(a.email.subject or "(no subject)")}</a><br>'
        f'<span class="muted">{_e(a.email.from_address)}</span></td></tr>'
        for i, a in enumerate(ordered)
    )
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    summary = (
        f'<section class="card"><table><thead><tr><th>Verdict</th><th>Score</th><th>Email</th></tr></thead>'
        f"<tbody>{rows}</tbody></table></section>"
        if len(ordered) > 1
        else ""
    )
    cards = "".join(_card(i, a) for i, a in enumerate(ordered))
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>Phishing Analysis</title><style>{_CSS}</style></head><body><main>"
        f'<h1>Phishing analysis</h1><div class="muted">{len(ordered)} email(s) · generated {generated} · '
        f"phishcheck {__version__} · links are defanged and not clickable</div>"
        f"{summary}{cards}</main></body></html>"
    )
