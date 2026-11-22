"""Message-text heuristic layer (English, Hindi/Devanagari, romanised Hinglish).

Each rule maps to a signal in ``phishguard.signals``. Patterns run on the
*deconfused* view of the text (NFKC, zero-width stripped, Cyrillic/Greek
look-alikes mapped to Latin, lower-cased), so "Ⓤⓡⓖⓔⓝⓣ" or "urg​ent"
still match.

Trade-off: regexes are transparent and multilingual-friendly with zero
training data, but brittle against paraphrase. That is why they are combined
with an ML text model in the ensemble rather than used alone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from phishguard.features.resources import BRAND_DISPLAY_TERMS
from phishguard.features.url_features import mask_urls
from phishguard.sanitize import NormalizedText, truncate
from phishguard.signals import Signal


def _rx(*patterns: str) -> list[re.Pattern]:
    return [re.compile(p, re.IGNORECASE | re.UNICODE) for p in patterns]


# Devanagari has no \b word boundaries in Python's re for combining marks, so
# Hindi patterns are written without \b.
RULES: dict[str, list[re.Pattern]] = {
    "text.urgency": _rx(
        r"\burgent(ly)?\b", r"\bimmediate(ly)?\b", r"\bact now\b", r"\bright away\b", r"\basap\b",
        r"\bwithin \d+\s*(hours?|hrs?|minutes?|mins?|days?)\b", r"\bin (the )?next \d+\s*(hours?|hrs?|minutes?)\b",
        r"\b(expires?|expiring|valid) (today|tonight|soon|in \d+)", r"\blast (chance|day|reminder|warning)\b",
        r"\bfinal (notice|warning|reminder|attempt)\b", r"\blimited[- ]time\b", r"\bbefore it'?s too late\b",
        r"\b(by|before) (tonight|today|midnight)\b", r"\btoday only\b", r"\bdon'?t (delay|wait|ignore)\b",
        r"\blimited (slots?|seats?|offer|period)\b", r"\bhurry\b", r"\b(join|apply|register|respond) now\b",
        # Hinglish
        r"\b(turant|turat|fauran|jaldi( se)?|jald se jald)\b", r"\baaj (hi|raat)\b", r"\babhi turant\b",
        # Hindi
        r"तुरंत|तुरन्त|फौरन|जल्दी|आज ही|आज रात|\d+ घंटे",
    ),
    "text.threat": _rx(
        r"\b(account|card|sim|number|wallet|upi|service|connection|profile|id)\b.{0,40}\b(will|would|shall|has|have|is|are|may|being)\b.{0,15}\b(suspend|block|deactivat|clos|terminat|lock|froz|restrict|disabl|cancel|delet|hold)\w*",
        r"\b(suspend|block|deactivat|terminat|freez|lock)\w*\b.{0,10}\b(your|ur)\b.{0,15}\b(account|card|sim|number|wallet|services?)\b",
        r"\b(penalty|penalties|fine of|legal action|lawsuit|legal proceedings|court case|blacklist(ed)?)\b",
        r"\bpermanently (deleted|blocked|closed|suspended|disabled)\b",
        # Hinglish
        r"\b(band|block|bandh|suspend)\s+(ho|kar)\s*(jayega|jaega|jaayega|diya jayega|di jayegi|jayegi)\b",
        r"\b(account|khata|sim|card)\s+(band|block)\b",
        # Hindi
        r"बंद (हो|कर) (जाएगा|जायेगा|जाएगी|दिया जाएगा)|ब्लॉक (हो|कर)|निलंबित|जुर्माना|कानूनी कार्रवाई",
    ),
    "text.law_enforcement": _rx(
        r"\b(police|cbi|ncb|narcotics|enforcement directorate|cyber ?(cell|crime) (department|branch|police)|crime branch)\b",
        r"\b(arrest(ed)? warrant|digital arrest|under arrest|money laundering|fir (has been )?(registered|lodged|filed))\b",
        r"\b(parcel|package|courier|shipment)\b.{0,60}\b(seized|illegal|drugs|contraband|passports?|mdma)\b",
        r"\b(customs (department|officer|duty)|court (summons|notice)|trai\b.{0,40}(disconnect|block|suspend))",
        r"\baadhaa?r\b.{0,40}\b(misused|illegal|crime|suspicious activit)",
        r"पुलिस|गिरफ्तार|डिजिटल अरेस्ट|सीबीआई|नारकोटिक्स|कस्टम विभाग",
    ),
    "text.prize": _rx(
        r"\bcongratulation|\bcongrats\b", r"\byou('ve| have)? (won|been selected|been chosen)\b",
        r"\b(lucky )?(winner|draw)\b", r"\blottery\b", r"\bjackpot\b", r"\bprize\b",
        r"\bclaim (your|the|ur) (reward|prize|gift|cash ?back|bonus|refund)\b",
        r"\b(free|complimentary) (gift|iphone|i-phone|recharge|laptop|scooty|car)\b",
        r"\bkbc\b|\bkaun banega crorepati\b", r"\bcash ?back of\b", r"\breward points?\b.{0,40}\b(expir|redeem|claim)",
        r"\b(aapne|apne|aap ne)\b.{0,30}\b(jeet|jeeta|jita|jeete)\b", r"\b(inaam|inam)\b",
        r"बधाई|जीत(ा|े|ी)|इनाम|लॉटरी|पुरस्कार|लकी ड्रॉ|कैशबैक",
    ),
    "text.kyc_update": _rx(
        r"\b(e-?kyc|re-?kyc|kyc)\b.{0,50}\b(updat|expir|pending|verif|complet|suspend|block|incomplet|link|fail|reject|karein|kare|karo|nahi)",
        r"\b(update|complete|verify|link|submit)\b.{0,20}\b(your |ur )?(e-?kyc|kyc|pan( card)?|aadhaa?r)\b",
        r"\bpan( card)?\b.{0,30}\b(not linked|blocked|expired|update|deactivat|suspend)",
        r"केवाईसी|kyc अपडेट|पैन.{0,20}(अपडेट|लिंक)",
    ),
    "text.payment_request": _rx(
        r"\bpay\b.{0,25}\b(fee|fees|amount|charge|charges|fine|dues|deposit)\b",
        r"\b(processing|registration|activation|clearance|delivery|re-?delivery|handling|verification|release|security) (fee|fees|charge|charges)\b",
        r"\b(transfer|send|deposit)\b.{0,20}\b(rs\.?|inr|₹|money|amount|funds|payment)\b",
        r"\b(advance|refundable) (payment|deposit|fee)\b", r"\bcustoms (fee|duty|charges)\b",
        r"\b(unpaid|outstanding|overdue) (toll|bill|amount|invoice|fine|challan)\b",
        r"\b(paise|paisa|payment|fees?)\s+(bhejo|bhejein|bhej do|karo|karein|bharo|jama karein)\b",
        r"भुगतान करें|शुल्क|फीस|पैसे भेज",
    ),
    "text.job_investment": _rx(
        r"\b(work|job) from home\b", r"\bpart[- ]?time (job|work|income|opportunit)",
        r"\bearn\b.{0,15}(rs\.?|₹|inr|\$|usd)?\s?[\d,]+\s?k?\b.{0,20}\b(per|a|each|/|daily|every)\s?(day|daily|week|hour|task)",
        r"\b(daily|weekly) (income|earning|profit|payout)\b", r"\blike (youtube )?(videos?|posts?) (and|&) earn\b",
        r"\b(rate|review) (hotels|products|movies) (and|&|to) earn\b", r"\btelegram\b.{0,30}\b(task|group|channel|job)\b",
        r"\bguaranteed (returns?|profit|income)\b", r"\bdouble (your|ur) (money|investment|amount)\b",
        r"\b\d{1,3}\s?% (daily|weekly|monthly|guaranteed) (returns?|profit)\b",
        r"\b(crypto|forex|bitcoin|stock|share market)\b.{0,30}\b(trading|investment|tips|signals)\b.{0,40}\b(profit|returns?|earn)",
        r"\bghar baithe\b", r"\b(roz|rozana|daily)\b.{0,20}\b(kamaye|kamao|kamayein|kamai)\b",
        r"घर बैठे|कमाएं|कमाई करें|रोज़ाना|गारंटीड रिटर्न",
    ),
    "text.gift_card_crypto": _rx(
        r"\b(buy|purchase|send|pay|scratch|share)\b.{0,40}\b(gift ?cards?|itunes( card)?|google play (card|gift|code)|steam (card|wallet)|bitcoin|btc|usdt|crypto)\b",
        r"\b(gift ?card|itunes|google play) (code|pin|number)s?\b",
    ),
    "text.remote_access": _rx(
        r"\b(anydesk|any desk|teamviewer|team viewer|quick ?support|rustdesk|ultraviewer|airdroid|alpemix|ammyy)\b",
        r"\bscreen ?shar(e|ing)\b.{0,30}\b(app|application)\b",
        r"\b(install|download)\b.{0,30}\.apk\b", r"\bremote (access|desktop|support) (app|application|tool)\b",
    ),
    "text.utility_disconnect": _rx(
        r"\b(electricity|power|bijli|light|gas|connection)\b.{0,60}\b(disconnect|cut|band|deactivat|suspend|terminat)",
        r"\b(disconnect|cut[- ]?off)\w*\b.{0,60}\b(tonight|today|9[:.]30|10[:.]00|by \d)",
        r"\b(sim|mobile number|mobile service)\b.{0,40}\b(deactivat|disconnect|suspend|block)",
        r"बिजली.{0,40}(कट|काट|बंद)",
    ),
    "text.secrecy": _rx(
        r"\bkeep (this|it|the matter)\b.{0,20}\b(confidential|secret|private|between us)\b",
        r"\b(don'?t|do not) (tell|inform|discuss (this )?with) (anyone|anybody|your family|the bank)\b",
        r"\bkisi ko (mat|na) (batana|bataye|batayein)\b", r"किसी को (मत|न) बताएं",
    ),
    "text.call_to_action": _rx(
        r"\b(click|tap|press)\b.{0,15}\b(here|link|below|button|this)\b", r"\bopen the (link|attachment|file)\b",
        r"\b(visit|follow|use) (the |this |below )?link\b", r"\b(login|log in|sign in|verify|update) (here|now|below|immediately)\b",
        r"\bdownload (the |our )?(app|attachment|file|apk)\b",
        r"\blink (pe|par|par jaake)\b", r"\b(niche|neeche) (diye|di) (gaye|gayi) link\b",
        r"लिंक पर क्लिक|क्लिक करें|लिंक खोलें",
    ),
    "text.generic_greeting": _rx(
        r"\bdear (valued |respected )?(customer|user|client|member|account ?holder|sir/madam|sir|madam|beneficiary|card ?holder|subscriber|applicant|winner)\b",
        r"\bdear (sbi|hdfc|icici|axis|kotak|paytm|phonepe|pnb|bob|amazon|flipkart|netflix|paypal) (bank )?(customer|user|account ?holder)\b",
        r"\b(hello|hi) (customer|user)\b", r"\bpriya grahak\b", r"प्रिय ग्राहक|प्रिय उपभोक्ता",
    ),
}

# Credential requests need special handling: "never share your OTP" is advice,
# "share your OTP to receive the refund" is an attack.
_CRED_TERMS = re.compile(
    r"\b(otp|one[- ]time (password|pin|code)|upi pin|atm pin|m-?pin|pin(?! ?code)|cvv|cvc|passwords?|passcode|"
    r"card (number|no|details)|debit card|credit card|bank (details|account details)|account (number|details|no)|"
    r"net ?banking (id|password|credentials|details)|login (details|credentials)|security code|verification code|"
    r"\d{1,2}[- ]?digit (code|number|pin)|(access|anydesk|remote|session) (code|id))\b"
    r"|ओटीपी|पिन|पासवर्ड|सीवीवी|कार्ड नंबर|खाता संख्या",
    re.IGNORECASE,
)
_REQUEST_VERBS = re.compile(
    r"\b(share|send|provide|enter|tell|give|confirm|submit|reply( with)?|forward|type|fill( in)?|update|"
    r"batao|bataye|bataiye|bataein|bhejo|bhejein|bhej do|de do|dein|share karo|share karein|share kare)\b"
    r"|बताएं|बताइए|भेजें|शेयर करें|दें|दर्ज करें",
    re.IGNORECASE,
)
_NEGATION_BEFORE = re.compile(
    r"\b(do not|don't|dont|never|not to|nobody|no one|will never|would never|won't|refrain from|avoid)\b"
    r"|कभी|मत", re.IGNORECASE,
)
_NEGATION_AFTER = re.compile(
    r"^.{0,40}?(\b(na|mat|nahi|nahin)\s+(karein|kare|karen|karo|kariye|dein|de|bataye|batayein|bataen)\b|न करें|ना करें|न दें|ना दें|न बताएं|साझा न)",
    re.IGNORECASE,
)
_SECURITY_ADVICE = _rx(
    r"\b(do not|don't|dont|never)\b.{0,25}\b(share|disclose|tell|give)\b.{0,30}\b(otp|pin|password|cvv|it|this|code|details)\b",
    r"\b(never|will never|does not|doesn't|do not)\b.{0,10}\b(asks?|call|request)\b.{0,25}\b(for )?(your )?(otp|pin|password|cvv)",
    r"\bkisi (ke saath|ke sath|se|ko)\b.{0,25}\b(share|batana|bataye|na|mat)\b",
    r"किसी (के साथ|को|से).{0,25}(साझा|शेयर|न बताएं|ना बताएं)",
    r"\bif (this was )?not (you|initiated by you|done by you)\b",
)

_COMMON_MISSPELLINGS = re.compile(
    r"\b(acount|accont|acccount|verfy|verifiy|veryfy|suspened|suspeneded|recieve|recieved|immediatly|imediately|"
    r"notifcation|pasword|passwrd|informations|costumer|custmer|adress|clik|bloked|blokced|dear valued costumer|"
    r"kindly do the needful|securty|secuirty|confirmation required immediatly|kyc updation pending|"
    r"youre account|you account|has been blocked today|unusuall|activiti|identiy)\b",
    re.IGNORECASE,
)
_PHONE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)|(?<!\d)\+\d{1,3}[\s-]?\d[\d\s-]{7,12}\d(?!\d)")
_CONTACT_VERBS = re.compile(
    r"\b(call|contact|whatsapp|dial|ring|message|sms|reach|helpline|customer care|sampark)\b|संपर्क|कॉल", re.IGNORECASE
)
_TOLL_FREE = re.compile(r"^(1800|1860|1600)")
# Moving the conversation to an unmonitored messenger is a classic job/investment-scam step.
_MOVE_TO_MESSENGER = re.compile(
    r"\b(contact|message|ping|join|dm|text|connect with|reach)\b.{0,25}\b(on|via|through|at)\s+(telegram|whatsapp|signal)\b"
    r"|\b(telegram|whatsapp) (pe|par)\b.{0,20}\b(contact|message|baat|sampark)", re.IGNORECASE,
)

_IMPERSONATION_TERMS = re.compile(
    r"\b(" + "|".join(re.escape(t) for t in sorted(BRAND_DISPLAY_TERMS, key=len, reverse=True)) + r"|"
    r"bank|rbi|reserve bank|income tax|it department|gst|customs|courier|india post|electricity board|bses|"
    r"msedcl|tneb|bescom|trai|npci|upi|government of india|govt|ministry|sarkari|epfo|pf account|"
    r"customer care|support team|security team|irs|hmrc)\b|बैंक|आयकर|सरकार|भारत सरकार",
    re.IGNORECASE,
)


@dataclass
class TextReport:
    signals: list[Signal]
    impersonated: list[str]


def _first_match(patterns: list[re.Pattern], text: str) -> tuple[int, str]:
    hits, first = 0, ""
    for p in patterns:
        m = p.search(text)
        if m:
            hits += 1
            first = first or m.group(0)
    return hits, first


def _credential_request(text: str) -> str | None:
    """Return evidence if text *asks for* a credential (not merely warns about it)."""
    for m in _CRED_TERMS.finditer(text):
        s, e = m.span()
        if re.search(r"(wi-?fi|wifi|guest|hotspot|router|zip|pdf|file)\s*$", text[max(0, s - 12): s]):
            continue  # "wifi password", "pdf password" are not account credentials
        window = text[max(0, s - 60): min(len(text), e + 60)]
        if not _REQUEST_VERBS.search(window):
            continue
        before = text[max(0, s - 60): s]
        # Only consider the clause the term is in (split on sentence punctuation).
        before_clause = re.split(r"[.!?।\n]", before)[-1]
        after_clause = re.split(r"[.!?।\n]", text[e: e + 80])[0]
        if _NEGATION_BEFORE.search(before_clause) or _NEGATION_AFTER.search(after_clause):
            continue
        # "OTP for login is 123456" with no request verb in the same clause = informational
        clause = before_clause + m.group(0) + after_clause
        if not _REQUEST_VERBS.search(clause):
            continue
        return truncate(clause.strip(), 80)
    return None


def _grammar_anomalies(clean: str) -> list[str]:
    reasons = []
    m = _COMMON_MISSPELLINGS.search(clean)
    if m:
        reasons.append(f"misspelling '{m.group(0)}'")
    letters = [c for c in clean if c.isalpha() and c.isascii()]
    if len(letters) >= 25:
        caps = sum(c.isupper() for c in letters) / len(letters)
        if caps > 0.55:
            reasons.append(f"{int(caps * 100)}% capital letters")
    if re.search(r"[!?]{3,}", clean):
        reasons.append("excessive punctuation")
    return reasons


def analyze_text(norm: NormalizedText) -> TextReport:
    text = mask_urls(norm.deconfused)
    signals: list[Signal] = []
    for sid, patterns in RULES.items():
        hits, evidence = _first_match(patterns, text)
        if hits:
            # several independent phrasings of the same tactic are stronger evidence
            # than one (1 hit -> 1.0, 2 -> 1.25, 3+ -> 1.5); capped to limit stacking.
            signals.append(Signal(sid, f'"{truncate(evidence, 60)}"', strength=min(1.5, 0.75 + 0.25 * hits)))

    cred = _credential_request(text)
    if cred:
        signals.append(Signal("text.credential_request", f'"{cred}"'))

    advice_hits, advice = _first_match(_SECURITY_ADVICE, text)
    if advice_hits and not cred:
        signals.append(Signal("text.security_advice", f'"{truncate(advice, 60)}"'))

    # Calls to action involving a phone number (excluding toll-free bank lines).
    for m in _PHONE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        local = digits[2:] if digits.startswith("91") and len(digits) == 12 else digits
        if _TOLL_FREE.match(local):
            continue
        ctx = text[max(0, m.start() - 50): m.end() + 30]
        if _CONTACT_VERBS.search(ctx):
            signals.append(Signal("text.contact_number", "asks you to contact a personal mobile number"))
            break
    else:
        m = _MOVE_TO_MESSENGER.search(text)
        if m:
            signals.append(Signal("text.contact_number", f'"{truncate(m.group(0), 60)}"'))

    impersonated = sorted({m.group(0).lower() for m in _IMPERSONATION_TERMS.finditer(text)})[:5]
    if impersonated:
        signals.append(Signal("text.impersonation", ", ".join(impersonated)))

    anomalies = _grammar_anomalies(norm.clean)
    if anomalies:
        signals.append(Signal("text.grammar_anomaly", "; ".join(anomalies), strength=min(1.5, 0.7 + 0.3 * len(anomalies))))

    if norm.invisible_count >= 2:
        signals.append(Signal("text.invisible_chars", f"{norm.invisible_count} hidden characters removed"))
    if norm.mixed_script_words:
        signals.append(Signal("text.mixed_script", ", ".join(truncate(w, 20) for w in norm.mixed_script_words[:3])))

    return TextReport(signals=signals, impersonated=impersonated)
