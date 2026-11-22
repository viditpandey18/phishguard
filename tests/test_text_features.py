import pytest

from phishguard.features.text_features import analyze_text
from phishguard.sanitize import normalize_text


def ids(text):
    return {s.id for s in analyze_text(normalize_text(text, 20_000)).signals}


@pytest.mark.parametrize("text", [
    "Do not share this OTP with anyone.",
    "HDFC Bank never asks for your PIN or password.",
    "OTP kisi ke saath share na karein.",
    "आपका ओटीपी 551234 है। इसे किसी के साथ साझा न करें।",
    "Can you send me the wifi password?",
])
def test_negated_or_benign_credential_mentions_are_not_requests(text):
    assert "text.credential_request" not in ids(text)


@pytest.mark.parametrize("text", [
    "Please share the OTP you received to cancel the transaction.",
    "Enter your card number and CVV to receive the refund.",
    "OTP batao warna account block ho jayega",
    "अपना ओटीपी बताएं",
    "Reply with your UPI PIN to verify.",
])
def test_credential_requests_detected(text):
    assert "text.credential_request" in ids(text)


@pytest.mark.parametrize("text,signal", [
    ("Act now! Offer expires today", "text.urgency"),
    ("Your account will be suspended", "text.threat"),
    ("aapka account band ho jayega", "text.threat"),
    ("आपका खाता बंद हो जाएगा", "text.threat"),
    ("You have won a lottery prize", "text.prize"),
    ("Aapne 10 lakh ka inaam jeeta", "text.prize"),
    ("Your KYC is pending, update now", "text.kyc_update"),
    ("Install AnyDesk for support", "text.remote_access"),
    ("Earn Rs 2000 per day work from home", "text.job_investment"),
    ("Your electricity will be disconnected tonight", "text.utility_disconnect"),
    ("Dear Customer, greetings", "text.generic_greeting"),
    ("Keep this confidential and buy gift cards", "text.secrecy"),
    ("Call our officer at 98765 43210 now", "text.contact_number"),
    ("Contact HR on Telegram for details", "text.contact_number"),
    ("Your parcel was seized with illegal drugs", "text.law_enforcement"),
])
def test_rule_fires(text, signal):
    assert signal in ids(text)


def test_url_tokens_do_not_trigger_text_rules():
    # 'kyc-update' inside a domain is scored by the URL layer; counting it twice inflates risk.
    assert "text.kyc_update" not in ids("See sbi-kyc-update.xyz/login for details")
    assert "text.kyc_update" in ids("Please update your KYC today")


def test_toll_free_numbers_are_not_flagged():
    assert "text.contact_number" not in ids("Not you? Call 1800 123 4567 to block your card.")


def test_obfuscation_signals():
    assert "text.invisible_chars" in ids("Your acc​ount is su​spended")
    assert "text.mixed_script" in ids("Your Аррle ID is locked")  # Cyrillic А, р, р
    # spaced letters and fullwidth still match keyword rules after normalisation
    assert "text.credential_request" in ids("Please share the O T P now")
    assert "text.urgency" in ids("ＵＲＧＥＮＴ action needed")


def test_hinglish_latin_devanagari_mix_is_not_mixed_script():
    assert "text.mixed_script" not in ids("Kal मिलते hain, ok?")
