"""Email header, attachment and HTML-structure analysis.

Trust model for headers: everything below the *first* (top-most)
Authentication-Results / Received header can be forged by the sender. We
therefore only trust the top-most Authentication-Results, which was added by
the receiving MTA. In a deployment, configure ``authserv-id`` checking so
only your own MTA's results are trusted (see docs/THREAT_MODEL.md).
"""

from __future__ import annotations

import re

from phishguard.features import typosquat
from phishguard.features.domain import registered_domain_of
from phishguard.features.email_parser import EmailDoc
from phishguard.features.resources import (
    ATTACHMENT_ARCHIVE,
    ATTACHMENT_DISK_IMAGE,
    ATTACHMENT_EXECUTABLE,
    ATTACHMENT_HTML,
    ATTACHMENT_MACRO_OFFICE,
    ATTACHMENT_ONENOTE,
    BENIGN_LOOKING_EXTENSIONS,
    BRAND_DISPLAY_TERMS,
    BRAND_DOMAINS,
    FREE_MAIL_DOMAINS,
    TRUSTED_DOMAINS,
)
from phishguard.features.url_features import extract_urls
from phishguard.sanitize import deconfuse, strip_invisibles, truncate
from phishguard.signals import Signal

_EMAIL_RE = re.compile(r"[\w.+-]+@([\w-]+\.)+[\w-]{2,}", re.I)
_ESP_MESSAGE_ID_DOMAINS = {
    "amazonses.com", "sendgrid.net", "mcsv.net", "mailchimp.com", "mailgun.org", "google.com",
    "gmail.com", "outlook.com", "prod.outlook.com", "sparkpostmail.com", "mandrillapp.com",
    "postmarkapp.com", "exacttarget.com", "salesforce.com", "hubspot.com", "zendesk.com",
}


def _domain_of(addr: str) -> str:
    return registered_domain_of(addr.rpartition("@")[2]) if "@" in addr else ""


def _auth_value(text: str, mech: str) -> str | None:
    m = re.search(rf"\b{mech}\s*=\s*([a-z]+)", text, re.I)
    return m.group(1).lower() if m else None


def analyze_headers(doc: EmailDoc) -> list[Signal]:
    signals: list[Signal] = []
    add = signals.append
    from_dom = _domain_of(doc.from_addr)

    # --- SPF / DKIM / DMARC (top-most Authentication-Results only) -------------
    if doc.auth_results:
        ar = doc.auth_results[0]
        spf, dkim, dmarc = _auth_value(ar, "spf"), _auth_value(ar, "dkim"), _auth_value(ar, "dmarc")
    else:
        spf = dkim = dmarc = None
    if spf is None and doc.received_spf:
        spf = doc.received_spf[0].strip().split()[0].lower() if doc.received_spf[0].strip() else None
    if spf in ("fail", "hardfail", "permerror"):
        add(Signal("hdr.spf_fail", f"spf={spf}"))
    elif spf == "softfail":
        add(Signal("hdr.spf_softfail", "spf=softfail"))
    if dkim in ("fail", "permerror"):
        add(Signal("hdr.dkim_fail", f"dkim={dkim}"))
    if dmarc in ("fail", "permerror"):
        add(Signal("hdr.dmarc_fail", f"dmarc={dmarc}"))
    elif dmarc == "pass":
        add(Signal("hdr.dmarc_pass", f"dmarc=pass for {from_dom or 'sender'}"))

    # --- sender identity ---------------------------------------------------------
    display = strip_invisibles(doc.from_display)[0]
    display_l = deconfuse(display)
    brand = None
    for term, b in sorted(BRAND_DISPLAY_TERMS.items(), key=lambda kv: -len(kv[0])):
        if re.search(rf"(?<![a-z]){re.escape(term)}(?![a-z])", display_l):
            brand = b
            break
    if brand and from_dom:
        official = BRAND_DOMAINS.get(brand, set())
        # Free-mail first: gmail.com is "official" for Google *URLs*, but no brand
        # (Google included) sends corporate notices from a consumer webmail address.
        if from_dom in FREE_MAIL_DOMAINS:
            add(Signal("hdr.freemail_brand", f"'{truncate(display, 40)}' sent from {from_dom}"))
        elif from_dom not in official and from_dom not in TRUSTED_DOMAINS:
            add(Signal("hdr.display_name_spoof", f"'{truncate(display, 40)}' <{doc.from_addr}>"))
    elif from_dom in FREE_MAIL_DOMAINS and re.search(
        r"\b(bank|support|security|team|service|department|helpdesk|admin|billing|customer care)\b", display_l
    ):
        add(Signal("hdr.freemail_brand", f"'{truncate(display, 40)}' sent from {from_dom}"))

    m = _EMAIL_RE.search(display)
    if m and m.group(0).lower() != doc.from_addr:
        add(Signal("hdr.display_name_has_email", f"display shows {m.group(0)}, real sender {doc.from_addr}"))

    if from_dom and from_dom not in TRUSTED_DOMAINS and from_dom not in FREE_MAIL_DOMAINS:
        squat = typosquat.check_label(from_dom.split(".")[0], from_dom)
        if squat and squat.kind in ("homoglyph", "typosquat") or (squat and "-" in squat.label):
            add(Signal("hdr.sender_typosquat", f"{from_dom} imitates {squat.brand}"))

    # --- Reply-To / Return-Path --------------------------------------------------
    for rt in doc.reply_to:
        rt_dom = _domain_of(rt)
        if from_dom and rt_dom and rt_dom != from_dom:
            strength = 1.3 if rt_dom in FREE_MAIL_DOMAINS else 1.0
            add(Signal("hdr.reply_to_mismatch", f"From {from_dom}, Reply-To {rt_dom}", strength=strength))
            break
    rp_dom = _domain_of(doc.return_path)
    if from_dom and rp_dom and rp_dom != from_dom:
        add(Signal("hdr.return_path_mismatch", f"From {from_dom}, Return-Path {rp_dom}"))

    # --- Received chain ---------------------------------------------------------
    anomalies = []
    if len(doc.received) > 15:
        anomalies.append(f"{len(doc.received)} relay hops")
    for r in doc.received[:8]:
        rl = r.lower()
        if "(unknown [" in rl or re.search(r"from\s+\[?\d{1,3}(\.\d{1,3}){3}\]?\s", rl) or "helo=[" in rl:
            anomalies.append("relay with unidentified hostname")
            break
    if anomalies:
        add(Signal("hdr.received_anomaly", "; ".join(anomalies)))

    mid = re.search(r"@([\w.-]+)>?", doc.message_id or "")
    if mid and from_dom:
        mid_dom = registered_domain_of(mid.group(1))
        if mid_dom != from_dom and mid_dom not in _ESP_MESSAGE_ID_DOMAINS and not mid.group(1).endswith(".outlook.com"):
            add(Signal("hdr.message_id_mismatch", f"Message-ID domain {mid_dom}"))
    return signals


def analyze_attachments(doc: EmailDoc) -> list[Signal]:
    signals: list[Signal] = []
    seen: set[str] = set()
    for att in doc.attachments:
        raw_name = att.filename
        name, hidden = strip_invisibles(raw_name)
        name_l = re.sub(r"\s+(?=\.)", "", name.lower().strip())  # "invoice.pdf     .exe"
        exts = re.findall(r"\.[a-z0-9]{1,12}", name_l)
        last = exts[-1] if exts else ""
        sid = None
        if hidden or (len(exts) >= 2 and exts[-2] in BENIGN_LOOKING_EXTENSIONS
                      and last in ATTACHMENT_EXECUTABLE | ATTACHMENT_HTML | ATTACHMENT_ARCHIVE | ATTACHMENT_DISK_IMAGE):
            sid = "att.double_extension"
        elif last in ATTACHMENT_EXECUTABLE:
            sid = "att.executable"
        elif last in ATTACHMENT_HTML or att.content_type == "text/html":
            sid = "att.html"
        elif last in ATTACHMENT_DISK_IMAGE:
            sid = "att.disk_image"
        elif last in ATTACHMENT_ONENOTE:
            sid = "att.onenote"
        elif last in ATTACHMENT_MACRO_OFFICE:
            sid = "att.macro_office"
        elif last in ATTACHMENT_ARCHIVE:
            sid = "att.archive"
        if sid and sid not in seen:
            seen.add(sid)
            signals.append(Signal(sid, truncate(name, 60)))
    return signals


def analyze_html(doc: EmailDoc) -> list[Signal]:
    signals: list[Signal] = []
    for a in doc.anchors:
        href = a.href.strip()
        if not href or href.lower().startswith(("mailto:", "tel:", "#")):
            continue
        shown = extract_urls(a.text, limit=1)
        if not shown:
            continue
        shown_dom = registered_domain_of(re.sub(r"^[a-z]+://", "", shown[0], flags=re.I).split("/")[0].split(":")[0])
        href_dom = registered_domain_of(re.sub(r"^[a-z]+://", "", href, flags=re.I).split("/")[0].split("@")[-1].split(":")[0])
        if shown_dom and href_dom and shown_dom != href_dom:
            signals.append(Signal("text.link_text_mismatch", f"shows '{truncate(shown_dom, 40)}' but goes to '{truncate(href_dom, 40)}'"))
            break
    if doc.forms:
        signals.append(Signal("text.html_form", f"{doc.forms} form/password field(s)"))
    if doc.scripts:
        signals.append(Signal("text.html_script", f"{doc.scripts} script element(s)/handler(s)"))
    visible = re.sub(r"\s+", " ", doc.html_text).strip()
    if doc.images >= 1 and len(visible) < 60 and len(doc.text_body.strip()) < 60:
        signals.append(Signal("text.image_only", f"{doc.images} image(s), {len(visible)} characters of text"))
    return signals
