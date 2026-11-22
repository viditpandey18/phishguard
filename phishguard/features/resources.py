"""Static reference data used by the heuristic layers.

Kept in one module so it can be reviewed / extended without touching logic.
All lists are intentionally conservative: they are *signals* fed to a
weighted ensemble, never a sole basis for a verdict.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Brands commonly impersonated (global + India-specific banks/payments/govt).
# key   = canonical brand token used for typosquat comparison
# value = registered domains that legitimately belong to the brand
# ---------------------------------------------------------------------------
BRAND_DOMAINS: dict[str, set[str]] = {
    # Global tech / payments
    "paypal": {"paypal.com", "paypal.me"},
    "google": {"google.com", "google.co.in", "gmail.com", "youtube.com", "goo.gl", "g.co"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com", "office365.com",
                  "microsoftonline.com", "sharepoint.com", "onedrive.com", "hotmail.com"},
    "outlook": {"outlook.com", "live.com", "office.com"},
    "office365": {"office.com", "office365.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com", "amazon.jobs"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net", "wa.me"},
    "linkedin": {"linkedin.com"},
    "twitter": {"twitter.com", "x.com"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "adobe": {"adobe.com"},
    "yahoo": {"yahoo.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "dhl": {"dhl.com", "dhl.de", "dhl.co.in"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "usps": {"usps.com"},
    # Global banks
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "citibank": {"citi.com", "citibank.com"},
    "hsbc": {"hsbc.com", "hsbc.co.in", "hsbc.co.uk"},
    "barclays": {"barclays.co.uk", "barclays.com"},
    # India: banks, payments, e-commerce, government
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "bank.sbi"},
    "onlinesbi": {"onlinesbi.sbi", "onlinesbi.com", "sbi.co.in"},
    "hdfcbank": {"hdfcbank.com", "hdfc.com"},
    "icicibank": {"icicibank.com"},
    "axisbank": {"axisbank.com"},
    "kotak": {"kotak.com"},
    "yesbank": {"yesbank.in"},
    "pnbindia": {"pnbindia.in"},
    "bankofbaroda": {"bankofbaroda.in"},
    "paytm": {"paytm.com", "paytmbank.com"},
    "phonepe": {"phonepe.com"},
    "gpay": {"google.com"},
    "bhim": {"bhimupi.org.in", "npci.org.in"},
    "npci": {"npci.org.in"},
    "flipkart": {"flipkart.com"},
    "myntra": {"myntra.com"},
    "irctc": {"irctc.co.in"},
    "incometax": {"incometax.gov.in", "incometaxindia.gov.in"},
    "uidai": {"uidai.gov.in"},
    "aadhaar": {"uidai.gov.in"},
    "indiapost": {"indiapost.gov.in"},
    "epfo": {"epfindia.gov.in"},
    "jio": {"jio.com"},
    "airtel": {"airtel.in", "airtel.com"},
}

# Brands too short / too generic to search for as substrings inside URLs
# (e.g. "ups" occurs in "groups", "sbi" in random strings). They are still
# used for exact-label typosquat checks.
SHORT_BRANDS: set[str] = {b for b in BRAND_DOMAINS if len(b) <= 4}

# Human-readable display names, used for display-name spoofing in emails and
# brand mentions in message text.
BRAND_DISPLAY_TERMS: dict[str, str] = {
    "paypal": "paypal", "google": "google", "microsoft": "microsoft", "outlook": "outlook",
    "office 365": "office365", "apple": "apple", "icloud": "icloud", "amazon": "amazon",
    "netflix": "netflix", "facebook": "facebook", "instagram": "instagram",
    "whatsapp": "whatsapp", "linkedin": "linkedin", "dropbox": "dropbox",
    "docusign": "docusign", "adobe": "adobe", "coinbase": "coinbase", "binance": "binance",
    "dhl": "dhl", "fedex": "fedex", "usps": "usps", "chase": "chase",
    "wells fargo": "wellsfargo", "bank of america": "bankofamerica", "citibank": "citibank",
    "hsbc": "hsbc", "barclays": "barclays", "sbi": "sbi", "state bank of india": "sbi",
    "hdfc": "hdfcbank", "hdfc bank": "hdfcbank", "icici": "icicibank", "icici bank": "icicibank",
    "axis bank": "axisbank", "kotak": "kotak", "yes bank": "yesbank", "pnb": "pnbindia",
    "bank of baroda": "bankofbaroda", "paytm": "paytm", "phonepe": "phonepe",
    "google pay": "gpay", "bhim": "bhim", "npci": "npci", "flipkart": "flipkart",
    "irctc": "irctc", "income tax": "incometax", "uidai": "uidai", "aadhaar": "aadhaar",
    "india post": "indiapost", "epfo": "epfo", "jio": "jio", "airtel": "airtel",
}

# ---------------------------------------------------------------------------
# Domains that are very unlikely to host phishing *as the registered domain*.
# Deliberately excludes free-hosting / user-content platforms (see below).
# In production replace with a Tranco top-N snapshot (data/download.py).
# ---------------------------------------------------------------------------
TRUSTED_DOMAINS: set[str] = set().union(*BRAND_DOMAINS.values()) | {
    "wikipedia.org", "github.com", "stackoverflow.com", "reddit.com", "bbc.co.uk",
    "nytimes.com", "zoom.us", "slack.com", "gov.in", "nic.in", "rbi.org.in",
    "india.gov.in", "mozilla.org", "python.org", "cloudflare.com", "bing.com",
    "duckduckgo.com", "swiggy.com", "zomato.com", "makemytrip.com", "uber.com",
    "ola.com", "olacabs.com", "hotstar.com", "jiocinema.com", "spotify.com",
    "googleusercontent.com", "gstatic.com", "googleapis.com", "googlemail.com",
    "microsoft365.com", "office.net", "applecard.apple", "paypal-community.com",
    "paypalobjects.com", "amazontrust.com", "media-amazon.com", "fbcdn.net", "whatsapp.com",
}

# Free hosting / tunnelling / user-content platforms abused for phishing kits.
FREE_HOSTING_SUFFIXES: set[str] = {
    "000webhostapp.com", "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com",
    "glitch.me", "repl.co", "replit.app", "weebly.com", "wixsite.com", "firebaseapp.com",
    "web.app", "pages.dev", "workers.dev", "r2.dev", "netlify.app", "vercel.app",
    "herokuapp.com", "blogspot.com", "github.io", "ipfs.io", "dweb.link", "webflow.io",
    "square.site", "godaddysites.com", "mystrikingly.com", "framer.app", "surge.sh",
    "azurewebsites.net", "web.core.windows.net", "storage.googleapis.com", "s3.amazonaws.com",
}

URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "v.gd", "bitly.com",
    "shorte.st", "adf.ly", "lnkd.in", "qr.ae", "short.io", "bl.ink", "tny.im", "clck.ru",
    "u.to", "x.co", "urlz.fr", "surl.li", "inx.lv", "1url.com", "shrtco.de", "wa.link",
}

# TLDs with disproportionate abuse rates (Spamhaus / Interisle reports).
# This is a *weak* signal: plenty of legitimate sites use these.
SUSPICIOUS_TLDS: set[str] = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "icu", "cyou", "rest", "click",
    "link", "work", "loan", "win", "bid", "zip", "mov", "country", "kim", "party",
    "review", "stream", "download", "racing", "date", "faith", "cricket", "science",
    "men", "monster", "sbs", "cfd", "quest", "lol", "bond", "support", "beauty", "hair",
    "autos", "mom", "skin", "boats", "yachts", "makeup", "online", "site", "vip",
    # NOTE: popular general TLDs (.app, .info, .shop, .live ...) are deliberately excluded
    # to keep false positives low; re-add if your evaluation data says otherwise.
}

# Multi-label public suffixes we need to understand to compute the
# registered domain without a network-fetched PSL. tldextract (with an
# offline snapshot) can be swapped in via features/domain.py.
MULTI_PART_SUFFIXES: set[str] = {
    "co.in", "net.in", "org.in", "gov.in", "nic.in", "ac.in", "edu.in", "res.in", "firm.in",
    "gen.in", "ind.in", "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au", "co.nz", "co.za", "co.jp", "ne.jp",
    "com.br", "com.cn", "com.sg", "com.my", "com.pk", "com.bd", "com.np", "com.lk",
    "co.id", "or.id", "com.mx", "com.tr", "com.ua", "co.kr", "com.hk", "com.tw", "com.ar",
    "com.ng", "co.ke", "com.eg", "com.sa", "ae.org", "us.com", "uk.com", "eu.org",
} | FREE_HOSTING_SUFFIXES  # treat hosting platforms as suffixes: user part is the "domain"

# A pragmatic set of TLDs for spotting *bare* domains in free text
# (e.g. "visit sbi-kyc.top now"). Prevents matching things like "e.g" or "Rs.500".
COMMON_TLDS: set[str] = SUSPICIOUS_TLDS | {
    "com", "net", "org", "in", "io", "co", "me", "us", "uk", "de", "fr", "ru", "cn", "jp",
    "br", "au", "ca", "eu", "biz", "gov", "edu", "ly", "gl", "gd", "at", "cc", "tv", "ai",
    "pk", "bd", "np", "lk", "ae", "sa", "ng", "ke", "za", "id", "my", "sg", "ph", "vn",
    "pw", "su", "ws", "to", "nu", "li", "sh", "sbi", "bank", "money", "help", "email",
    "dev", "page", "tech", "store", "website", "space", "pro", "news", "app", "info", "shop",
    "live", "life", "club", "fun",
}

# Keywords that frequently appear in credential-phishing URLs.
SENSITIVE_URL_TOKENS: set[str] = {
    "login", "log-in", "signin", "sign-in", "verify", "verification", "account", "update",
    "secure", "security", "banking", "ebanking", "netbanking", "kyc", "wallet", "confirm",
    "password", "credential", "unlock", "suspend", "suspended", "reactivate", "validate",
    "authenticate", "auth", "billing", "invoice", "payment", "refund", "reward", "claim",
    "bonus", "gift", "prize", "webscr", "cmd=_", "recover", "recovery", "support", "helpdesk",
    "otp", "upi", "pan-card", "aadhaar", "aadhar", "tax-refund", "customs", "parcel",
}

RISKY_DOWNLOAD_EXTENSIONS: set[str] = {
    ".exe", ".apk", ".scr", ".msi", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".hta",
    ".ps1", ".jar", ".dll", ".lnk", ".iso", ".img", ".xapk", ".appx", ".msix",
}

# Attachment risk classes (email header/attachment layer).
ATTACHMENT_EXECUTABLE = {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs",
                         ".vbe", ".wsf", ".wsh", ".hta", ".ps1", ".msi", ".jar", ".lnk",
                         ".dll", ".cpl", ".apk", ".reg", ".application", ".msix", ".appx"}
ATTACHMENT_HTML = {".html", ".htm", ".shtml", ".xhtml", ".svg", ".mht", ".mhtml"}
ATTACHMENT_ARCHIVE = {".zip", ".rar", ".7z", ".gz", ".tar", ".ace", ".cab", ".arj", ".xz"}
ATTACHMENT_MACRO_OFFICE = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam",
                           ".xlsb", ".doc", ".xls", ".ppt"}  # legacy formats can carry macros
ATTACHMENT_DISK_IMAGE = {".iso", ".img", ".vhd", ".vhdx"}
ATTACHMENT_ONENOTE = {".one", ".onepkg"}
BENIGN_LOOKING_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png",
                             ".txt", ".csv", ".ppt", ".pptx", ".gif"}

FREE_MAIL_DOMAINS: set[str] = {
    "gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com", "live.com",
    "aol.com", "proton.me", "protonmail.com", "icloud.com", "gmx.com", "mail.com",
    "yandex.com", "yandex.ru", "zoho.com", "rediffmail.com", "tutanota.com",
}
