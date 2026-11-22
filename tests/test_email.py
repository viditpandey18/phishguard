from phishguard.eval.adversarial import IMAGE_ONLY_EMAIL_TEMPLATE
from phishguard.features.email_parser import html_to_text, looks_like_email, parse_email
from phishguard.features.header_features import analyze_attachments, analyze_headers, analyze_html


def _email(headers: str, body: str = "Hello", ctype: str = "text/plain") -> str:
    return f"{headers}\nMIME-Version: 1.0\nContent-Type: {ctype}; charset=utf-8\n\n{body}\n"


def sig_ids(signals):
    return {s.id for s in signals}


def test_auth_results_parsing():
    doc = parse_email(_email("Authentication-Results: mx; spf=softfail; dkim=fail; dmarc=fail\nFrom: a@example.com\nSubject: x"))
    assert {"hdr.spf_softfail", "hdr.dkim_fail", "hdr.dmarc_fail"} <= sig_ids(analyze_headers(doc))


def test_only_topmost_auth_results_trusted():
    # An attacker-inserted lower header claiming "pass" must not override the receiver's verdict.
    raw = _email("Authentication-Results: mx.receiver; dmarc=fail\nAuthentication-Results: fake; dmarc=pass\n"
                 "From: a@example.com\nSubject: x")
    ids = sig_ids(analyze_headers(parse_email(raw)))
    assert "hdr.dmarc_fail" in ids and "hdr.dmarc_pass" not in ids


def test_display_name_spoofing_and_freemail():
    ids = sig_ids(analyze_headers(parse_email(_email('From: "SBI Bank" <alerts@sbi-notify.info>\nSubject: x'))))
    assert "hdr.display_name_spoof" in ids
    ids = sig_ids(analyze_headers(parse_email(_email('From: "Amazon Support" <amazon.help99@gmail.com>\nSubject: x'))))
    assert "hdr.freemail_brand" in ids
    ids = sig_ids(analyze_headers(parse_email(_email('From: "security@paypal.com" <x@evil.example>\nSubject: x'))))
    assert "hdr.display_name_has_email" in ids


def test_legit_brand_sender_not_spoof():
    ids = sig_ids(analyze_headers(parse_email(_email('From: "Amazon.in" <order-update@amazon.in>\nSubject: x'))))
    assert not ids & {"hdr.display_name_spoof", "hdr.freemail_brand", "hdr.sender_typosquat"}


def test_reply_to_mismatch():
    ids = sig_ids(analyze_headers(parse_email(_email("From: a@corp.example\nReply-To: b@gmail.com\nSubject: x"))))
    assert "hdr.reply_to_mismatch" in ids


def test_attachments():
    raw = ("From: a@example.com\nSubject: x\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=B\n\n"
           "--B\nContent-Type: text/plain\n\nsee attached\n"
           "--B\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename=\"scan.pdf.exe\"\n\nAA==\n"
           "--B\nContent-Type: text/html\nContent-Disposition: attachment; filename=\"login.html\"\n\nAA==\n"
           "--B\nContent-Type: application/vnd.ms-excel\nContent-Disposition: attachment; filename=\"q3.xlsm\"\n\nAA==\n"
           "--B\nContent-Type: application/x-iso9660-image\nContent-Disposition: attachment; filename=\"doc.iso\"\n\nAA==\n"
           "--B\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename=\"inv‮fdp.exe\"\n\nAA==\n"
           "--B--\n")
    ids = sig_ids(analyze_attachments(parse_email(raw)))
    assert {"att.double_extension", "att.html", "att.macro_office", "att.disk_image"} <= ids


def test_html_link_mismatch_form_and_script():
    html = ('<html><body><a href="http://evil.example/login">https://www.hdfcbank.com</a>'
            '<form action="http://evil.example/p"><input type="password"></form>'
            '<script>alert(1)</script><img src="x" onerror="alert(1)"></body></html>')
    doc = parse_email(_email("From: a@x.example\nSubject: hi", html, "text/html"))
    ids = sig_ids(analyze_html(doc))
    assert {"text.link_text_mismatch", "text.html_form", "text.html_script"} <= ids
    assert "alert(1)" not in doc.html_text  # script content never becomes "visible text"


def test_image_only_email():
    doc = parse_email(IMAGE_ONLY_EMAIL_TEMPLATE.format(domain="acct-notice.example"))
    assert "text.image_only" in sig_ids(analyze_html(doc))


def test_malformed_input_never_crashes():
    for raw in [b"\x00\xff\xfe garbage", "From: <<<>>>\nSubject: =?utf-8?B?broken?=\n\nbody", "", "<html><a href="]:
        parse_email(raw)
    html_to_text("<div><a href='x'>unclosed <script>")


def test_looks_like_email():
    assert looks_like_email("From: a@b.com\nTo: c@d.com\nSubject: hi\n\nbody")
    assert not looks_like_email("From: me. Subject of the day: lunch")
