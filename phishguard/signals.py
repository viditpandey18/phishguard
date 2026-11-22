"""Signal registry: the shared vocabulary between detectors and the ensemble.

Design trade-off
----------------
Detectors only *emit* named signals with evidence; they never decide weights.
The ensemble owns the weights (hand-set defaults below, overridable by
weights learned with ``training/train_ensemble.py``). This keeps:
  * explanations exact - a verdict is a sum of named contributions,
  * retraining cheap - re-fit weights without touching detector code,
  * auditing easy - every weight lives in one reviewed table.

Weights are log-odds contributions. +0.7 is roughly "doubles the odds";
negative weights are mitigating evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Layer(str, Enum):
    URL = "url"
    TEXT = "text"
    HEADER = "header"
    MODEL = "model"
    INTEL = "intel"


class Kind(str, Enum):
    """Which malicious label a signal points towards (used for phishing vs scam)."""

    PHISHING = "phishing"  # credential theft / impersonated login / malware delivery
    SCAM = "scam"  # social-engineering fraud: prizes, fees, OTP, jobs, threats
    NEUTRAL = "neutral"


@dataclass(frozen=True)
class SignalSpec:
    id: str
    layer: Layer
    kind: Kind
    weight: float
    description: str  # plain-language, shown to end users


@dataclass
class Signal:
    """A fired signal instance with evidence. ``strength`` scales the weight (0..1+)."""

    id: str
    evidence: str = ""
    strength: float = 1.0
    extra: dict = field(default_factory=dict)


def _s(id_: str, layer: Layer, kind: Kind, weight: float, description: str) -> SignalSpec:
    return SignalSpec(id_, layer, kind, weight, description)


U, T, H, M, I = Layer.URL, Layer.TEXT, Layer.HEADER, Layer.MODEL, Layer.INTEL
P, S, N = Kind.PHISHING, Kind.SCAM, Kind.NEUTRAL

SIGNAL_SPECS: dict[str, SignalSpec] = {
    s.id: s
    for s in [
        # ---------------- URL layer ----------------
        _s("url.ip_host", U, P, 2.5, "The link points to a raw IP address instead of a domain name."),
        _s("url.at_symbol", U, P, 1.8, "The link contains '@', which hides the real destination."),
        _s("url.punycode", U, P, 1.0, "The domain uses punycode (internationalised characters) that can imitate other sites."),
        _s("url.homoglyph_brand", U, P, 3.5, "The domain uses look-alike characters to imitate a well-known brand."),
        _s("url.typosquat", U, P, 3.2, "The domain is a misspelling of a well-known brand's domain."),
        _s("url.combosquat", U, P, 2.4, "The domain combines a brand name with extra words but is not owned by that brand."),
        _s("url.brand_in_subdomain", U, P, 2.2, "A brand name appears in the subdomain, but the real domain belongs to someone else."),
        _s("url.brand_in_path", U, P, 0.9, "A brand name appears in the link path on an unrelated domain."),
        _s("url.shortener", U, N, 0.9, "The link uses a URL shortener that hides the real destination."),
        _s("url.suspicious_tld", U, P, 1.0, "The domain uses a top-level domain frequently abused for phishing."),
        _s("url.free_hosting", U, P, 1.0, "The page is hosted on a free hosting/tunnelling service often used for phishing kits."),
        _s("url.many_subdomains", U, P, 0.8, "The link has an unusually deep chain of subdomains."),
        _s("url.many_hyphens", U, P, 0.6, "The domain contains many hyphens, common in fake domains."),
        _s("url.long_url", U, N, 0.4, "The link is unusually long, which can hide its true destination."),
        _s("url.high_entropy_domain", U, P, 0.7, "The domain looks randomly generated."),
        _s("url.digits_in_domain", U, N, 0.4, "The domain contains many digits."),
        _s("url.no_tls", U, N, 0.4, "The link does not use HTTPS."),
        _s("url.nonstandard_port", U, P, 0.9, "The link uses a non-standard network port."),
        _s("url.sensitive_keywords", U, P, 0.9, "The link contains words like 'login', 'verify' or 'kyc' typical of credential phishing."),
        _s("url.dangerous_scheme", U, P, 4.5, "The link uses a scheme (javascript:/data:) that can run code."),
        _s("url.executable_download", U, P, 1.8, "The link downloads an executable or app installer."),
        _s("url.encoded_obfuscation", U, P, 1.0, "The link uses encoding tricks to obscure its destination."),
        _s("url.embedded_redirect", U, N, 0.6, "The link contains another URL inside it (open-redirect pattern)."),
        _s("url.trusted_domain", U, N, -2.5, "The link points to a well-known, established domain."),
        # ---------------- Text layer ----------------
        _s("text.urgency", T, S, 0.9, "Creates urgency or a short deadline to rush you."),
        _s("text.threat", T, S, 1.3, "Threatens account blocking, penalties or other consequences."),
        _s("text.law_enforcement", T, S, 2.0, "Invokes police, courts, customs or 'digital arrest' to frighten you."),
        _s("text.prize", T, S, 1.6, "Claims you have won a prize, lottery, reward or cashback."),
        _s("text.credential_request", T, P, 2.6, "Asks for an OTP, PIN, password, CVV or bank/card details."),
        _s("text.kyc_update", T, P, 1.8, "Asks you to update KYC/PAN/Aadhaar details - a common bank-impersonation lure."),
        _s("text.impersonation", T, N, 0.6, "Mentions a bank, government agency, courier or payment brand."),
        _s("text.payment_request", T, S, 1.0, "Asks you to pay a fee, transfer money or make a payment."),
        _s("text.job_investment", T, S, 2.0, "Promises easy money, part-time jobs or guaranteed investment returns."),
        _s("text.gift_card_crypto", T, S, 2.2, "Asks for payment via gift cards or cryptocurrency."),
        _s("text.remote_access", T, S, 2.6, "Asks you to install a remote-access app (AnyDesk, TeamViewer...)."),
        _s("text.utility_disconnect", T, S, 2.4, "Claims your electricity/gas/mobile service will be disconnected."),
        _s("text.secrecy", T, S, 1.0, "Asks you to keep the request secret or not tell anyone."),
        _s("text.call_to_action", T, N, 0.6, "Pushes you to click a link or open an attachment."),
        _s("text.contact_number", T, S, 1.0, "Asks you to call an unfamiliar mobile number or move the chat to WhatsApp/Telegram."),
        _s("text.generic_greeting", T, N, 0.5, "Uses a generic greeting like 'Dear Customer'."),
        _s("text.grammar_anomaly", T, N, 0.5, "Contains unusual spelling, capitalisation or punctuation."),
        _s("text.invisible_chars", T, P, 1.6, "Contains hidden zero-width characters used to evade filters."),
        _s("text.mixed_script", T, P, 2.0, "Contains words mixing alphabets (e.g. Cyrillic letters inside English words)."),
        _s("text.security_advice", T, N, -1.6, "Contains standard security advice ('never share your OTP')."),
        _s("text.link_text_mismatch", T, P, 2.6, "A link's visible text shows a different address than where it actually goes."),
        _s("text.html_form", T, P, 2.4, "The email contains an embedded form that can capture what you type."),
        _s("text.html_script", T, P, 1.5, "The email contains embedded scripts."),
        _s("text.image_only", T, N, 1.2, "The email is almost entirely images, a trick to evade text filters."),
        # ---------------- Header layer ----------------
        _s("hdr.spf_fail", H, P, 1.5, "SPF check failed: the sending server is not authorised for this domain."),
        _s("hdr.spf_softfail", H, P, 0.7, "SPF soft-fail: the sending server is probably not authorised."),
        _s("hdr.dkim_fail", H, P, 1.2, "DKIM signature check failed: the message may have been altered or forged."),
        _s("hdr.dmarc_fail", H, P, 2.0, "DMARC check failed: the sender domain does not authenticate this email."),
        _s("hdr.dmarc_pass", H, N, -1.5, "DMARC passed: the sender domain authenticated this email."),
        _s("hdr.reply_to_mismatch", H, P, 1.2, "Replies would go to a different domain than the sender's."),
        _s("hdr.return_path_mismatch", H, N, 0.3, "The bounce address domain differs from the sender's domain."),
        _s("hdr.display_name_spoof", H, P, 2.6, "The sender's display name claims a brand, but the address is not from that brand."),
        _s("hdr.display_name_has_email", H, P, 1.6, "The display name contains a different email address than the real sender."),
        _s("hdr.freemail_brand", H, P, 1.6, "Claims to be an organisation but was sent from a free webmail account."),
        _s("hdr.sender_typosquat", H, P, 3.0, "The sender's domain imitates a well-known brand."),
        _s("hdr.received_anomaly", H, N, 0.5, "The server relay chain contains unusual or unidentified hops."),
        _s("hdr.message_id_mismatch", H, N, 0.3, "The Message-ID domain does not match the sender."),
        _s("att.executable", H, P, 3.0, "Has an executable or script attachment."),
        _s("att.double_extension", H, P, 3.0, "Has an attachment with a disguised double extension (e.g. invoice.pdf.exe)."),
        _s("att.html", H, P, 2.0, "Has an HTML attachment, often used for fake login pages."),
        _s("att.macro_office", H, P, 1.8, "Has a macro-capable Office attachment."),
        _s("att.archive", H, N, 0.8, "Has a compressed archive attachment that can hide malware."),
        _s("att.disk_image", H, P, 2.0, "Has a disk-image attachment (.iso/.img) used to bypass security warnings."),
        _s("att.onenote", H, P, 2.0, "Has a OneNote attachment, a recent malware delivery vector."),
        # ---------------- Model / intel ----------------
        _s("model.text_classifier", M, N, 1.0, "The machine-learning text model rates the wording as fraud-like."),
        _s("intel.blocklisted", I, P, 5.0, "The link is listed on a threat-intelligence blocklist."),
        _s("intel.young_domain", I, P, 1.5, "The domain was registered very recently."),
        _s("intel.redirect_offsite", I, N, 0.8, "The link redirects through several different domains."),
        _s("intel.cert_new", I, N, 0.6, "The site's TLS certificate was issued very recently."),
    ]
}

DEFAULT_BIAS = -3.2  # prior: most traffic is legitimate (~4% at zero evidence)
