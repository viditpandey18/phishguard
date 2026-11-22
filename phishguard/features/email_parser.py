"""Safe email parsing (.eml bytes or pasted headers+body).

Security notes:
* HTML is *never rendered*. We tokenise it with the stdlib HTMLParser purely
  to extract visible text, links, forms, scripts and images.
* Attachments are never decoded to disk or executed; we only read names,
  declared types and approximate sizes.
* All extracted strings are length-capped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html import unescape
from html.parser import HTMLParser

MAX_PARTS = 200
MAX_BODY_CHARS = 200_000


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int


@dataclass
class Anchor:
    href: str
    text: str


@dataclass
class EmailDoc:
    subject: str = ""
    from_display: str = ""
    from_addr: str = ""
    reply_to: list[str] = field(default_factory=list)
    return_path: str = ""
    message_id: str = ""
    auth_results: list[str] = field(default_factory=list)
    received_spf: list[str] = field(default_factory=list)
    received: list[str] = field(default_factory=list)
    text_body: str = ""
    html_text: str = ""
    anchors: list[Anchor] = field(default_factory=list)
    forms: int = 0
    scripts: int = 0
    images: int = 0
    attachments: list[Attachment] = field(default_factory=list)
    has_headers: bool = False
    parse_errors: list[str] = field(default_factory=list)

    @property
    def body(self) -> str:
        """Best text view of the body (plain part preferred, else HTML-derived)."""
        if self.text_body.strip():
            return self.text_body
        return self.html_text


class _SafeHTMLExtractor(HTMLParser):
    """Collects visible text and security-relevant elements. Never executes anything."""

    _SKIP = {"script", "style", "head", "title", "noscript", "template"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.anchors: list[Anchor] = []
        self.forms = self.scripts = self.images = 0
        self._skip_depth = 0
        self._anchor_href: str | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in self._SKIP:
            self._skip_depth += 1
            if tag == "script":
                self.scripts += 1
        elif tag == "a":
            self._anchor_href = a.get("href", "")[:2048]
            self._anchor_text = []
        elif tag == "form":
            self.forms += 1
        elif tag in ("input",) and a.get("type", "").lower() == "password":
            self.forms += 1
        elif tag == "img":
            self.images += 1
            alt = a.get("alt", "")
            if alt:
                self.text.append(alt)
        elif tag in ("br", "p", "div", "tr", "li", "h1", "h2", "h3", "table"):
            self.text.append("\n")
        # inline event handlers are script too
        if any(k.startswith("on") for k in a):
            self.scripts += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP and self._skip_depth:
            self._skip_depth -= 1
        elif tag == "a" and self._anchor_href is not None:
            self.anchors.append(Anchor(self._anchor_href, " ".join(self._anchor_text).strip()[:300]))
            self._anchor_href = None

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self.text.append(data)
        if self._anchor_href is not None:
            self._anchor_text.append(data)


def html_to_text(html: str) -> _SafeHTMLExtractor:
    ext = _SafeHTMLExtractor()
    try:
        ext.feed(html[:MAX_BODY_CHARS])
        ext.close()
    except Exception:  # malformed HTML must never crash analysis
        pass
    return ext


_HEADER_LINE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{1,40}:", re.M)
_KNOWN_HEADERS = re.compile(
    r"^(from|to|subject|date|received|return-path|reply-to|message-id|authentication-results|"
    r"dkim-signature|received-spf|mime-version|content-type|delivered-to|x-[a-z0-9-]+):",
    re.I | re.M,
)


def looks_like_email(text: str) -> bool:
    head = text[:4000]
    return len(_KNOWN_HEADERS.findall(head)) >= 2 and bool(re.search(r"^(from|subject):", head, re.I | re.M))


def _safe_header(msg: Message, name: str) -> list[str]:
    try:
        vals = msg.get_all(name) or []
        return [str(v)[:2000] for v in vals]
    except Exception as exc:  # malformed header defects
        return [f"<unparseable: {type(exc).__name__}>"]


def _decode_part(part: Message) -> str:
    try:
        if isinstance(part, EmailMessage):
            content = part.get_content()
            if isinstance(content, str):
                return content[:MAX_BODY_CHARS]
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        return payload[:MAX_BODY_CHARS].decode(charset, errors="replace")
    except Exception:
        payload = part.get_payload(decode=False)
        return payload[:MAX_BODY_CHARS] if isinstance(payload, str) else ""


def parse_email(raw: bytes | str) -> EmailDoc:
    if isinstance(raw, str):
        # pasted content: normalise line endings, encode for the byte parser
        raw = raw.replace("\r\n", "\n").encode("utf-8", errors="replace")
    doc = EmailDoc()
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:
        doc.parse_errors.append(f"parse failure: {type(exc).__name__}")
        doc.text_body = raw.decode("utf-8", errors="replace")[:MAX_BODY_CHARS]
        return doc

    doc.has_headers = bool(msg.keys())
    doc.subject = (_safe_header(msg, "Subject") or [""])[0]
    from_raw = (_safe_header(msg, "From") or [""])[0]
    doc.from_display, doc.from_addr = parseaddr(from_raw)
    doc.from_addr = doc.from_addr.lower()
    doc.reply_to = [a.lower() for _, a in getaddresses(_safe_header(msg, "Reply-To")) if a]
    doc.return_path = parseaddr((_safe_header(msg, "Return-Path") or [""])[0])[1].lower()
    doc.message_id = (_safe_header(msg, "Message-ID") or [""])[0]
    doc.auth_results = _safe_header(msg, "Authentication-Results") + _safe_header(msg, "ARC-Authentication-Results")
    doc.received_spf = _safe_header(msg, "Received-SPF")
    doc.received = _safe_header(msg, "Received")
    doc.parse_errors.extend(type(d).__name__ for d in getattr(msg, "defects", [])[:10])

    plain_parts: list[str] = []
    html_parts: list[str] = []
    for i, part in enumerate(msg.walk()):
        if i >= MAX_PARTS:
            doc.parse_errors.append("too many MIME parts")
            break
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        filename = part.get_filename() or part.get_param("name") or ""
        disposition = (part.get("Content-Disposition") or "").lower()
        if filename or "attachment" in disposition:
            raw_payload = part.get_payload(decode=False)
            size = len(raw_payload) * 3 // 4 if isinstance(raw_payload, str) else 0
            doc.attachments.append(Attachment(str(filename)[:255], ctype, size))
            continue
        if ctype == "text/plain":
            plain_parts.append(_decode_part(part))
        elif ctype == "text/html":
            html_parts.append(_decode_part(part))

    doc.text_body = "\n".join(plain_parts)[:MAX_BODY_CHARS]
    if html_parts:
        ext = html_to_text("\n".join(html_parts))
        doc.html_text = re.sub(r"[ \t]+", " ", unescape("".join(ext.text)))[:MAX_BODY_CHARS]
        doc.anchors, doc.forms, doc.scripts, doc.images = ext.anchors[:200], ext.forms, ext.scripts, ext.images
    if not doc.has_headers or (not plain_parts and not html_parts and not doc.attachments):
        # Pasted plain text with no MIME structure: treat payload as the body.
        body = msg.get_payload(decode=False)
        if isinstance(body, str) and not doc.text_body:
            doc.text_body = body[:MAX_BODY_CHARS]
    return doc
