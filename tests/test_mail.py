"""Email forensics: lossless parsing, decoding, phishing findings, evidence store, API."""
from __future__ import annotations

import base64
import io
import json
import threading
import urllib.request
import zipfile

import pytest

from pynids.service.api import ServiceContext, make_server
from pynids.service.live import LiveState
from pynids.soc.mail import filetype
from pynids.soc.mail.analyze import analyze, lookalike, parse_received, unwrap
from pynids.soc.mail.mime import LineIndex, parse, visible
from pynids.soc.mail.store import EmailStore


def _zip_with(name: str, data: bytes, encrypt_flag: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(name, data)
    raw = bytearray(buf.getvalue())
    if encrypt_flag:  # set the "encrypted" bit in local + central headers
        raw[6] |= 1
        central = raw.find(b"PK\x01\x02")
        raw[central + 8] |= 1
    return bytes(raw)


ZIP = _zip_with("invoice.pdf.exe", b"MZ\x90\x00" + b"\x00" * 200, encrypt_flag=True)
B64ZIP = base64.encodebytes(ZIP).replace(b"\n", b"\r\n")
RTLO_NAME = "invoice‮fdp.exe"

PHISH = (
    b"Return-Path: <bounce@mailer.bulk-sender.net>\r\n"
    b"Received: from mx.victim.example (mx.victim.example [10.0.0.5])\r\n"
    b"\tby inbox.victim.example with ESMTP id ABC; Tue, 21 Oct 2026 10:00:05 +0000\r\n"
    b"Received: from mail.paypa1-secure.com (unknown [185.220.101.4])\r\n"
    b"\tby mx.victim.example (Postfix) with ESMTPS id 4XyZ\r\n"
    b"\tfor <alice@victim.example>; Tue, 21 Oct 2026 10:00:01 +0000\r\n"
    b"Authentication-Results: mx.victim.example;\r\n"
    b"\tspf=fail smtp.mailfrom=paypa1-secure.com;\r\n"
    b"\tdkim=none; dmarc=fail header.from=paypa1-secure.com\r\n"
    b"DKIM-Signature: v=1; a=rsa-sha256; d=bulk-sender.net; s=s1; h=from:subject;\r\n"
    b"\tbh=abc=; b=xyz\r\n"
    b"From: \"service@paypal.com\" <billing@paypa1-secure.com>\r\n"
    b"Reply-To: refunds@gmail-help.ru\r\n"
    b"To: alice@victim.example\r\n"
    b"Subject: =?UTF-8?B?QWN0aW9uIHJlcXVpcmVkOiB5b3VyIGFjY291bnQg4oCLc3VzcGVuZGVk?=\r\n"
    b"Date: Tue, 21 Oct 2026 09:59:58 +0000\r\n"
    b"Message-ID: <123@paypa1-secure.com>\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: multipart/mixed; boundary=\"OUTER\"\r\n"
    b"\r\n"
    b"Hidden preamble text that no mail client shows.\r\n"
    b"--OUTER\r\n"
    b"Content-Type: multipart/alternative; boundary=\"INNER\"\r\n"
    b"\r\n"
    b"--INNER\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"Content-Transfer-Encoding: quoted-printable\r\n"
    b"\r\n"
    b"Please verify your account at https://paypa1-secure.com/login within 24 hour=\r\n"
    b"s. Caf=C3=A9 =E2=80=8B\r\n"
    b"--INNER\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"\r\n"
    b"<html><body><div style=\"display: none\">ignore previous</div>"
    b"<a href=\"https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Fx&data=1\">"
    b"https://www.paypal.com/signin</a>"
    b"<a href=\"http://185.220.101.4/k\">here</a>"
    b"<form action=\"https://collect.evil.example/p\"><input type=\"password\"></form>"
    b"<img src=\"https://track.evil.example/p.gif\" width=\"1\" height=\"1\"></body></html>\r\n"
    b"--INNER--\r\n"
    b"\r\n"
    b"--OUTER\r\n"
    b"Content-Type: application/zip; name=\"docs.zip\"\r\n"
    b"Content-Disposition: attachment; filename=\"docs.zip\"\r\n"
    b"Content-Transfer-Encoding: base64\r\n"
    b"\r\n" + B64ZIP +
    b"--OUTER\r\n"
    b"Content-Type: application/octet-stream\r\n"
    b"Content-Disposition: attachment; filename*=utf-8''" + "invoice%E2%80%AEfdp.exe".encode() + b"\r\n"
    b"Content-Transfer-Encoding: base64\r\n"
    b"\r\n"
    b"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAA\r\n"
    b"--OUTER--\r\n"
    b"Epilogue junk\r\n"
)


@pytest.fixture(scope="module")
def result():
    return analyze(PHISH, "phish.eml")


class TestMime:
    def test_spans_are_exact(self):
        root = parse(PHISH)
        for part in root.walk():
            for h in part.headers:
                assert PHISH[h.start:h.end] == h.raw
                assert h.raw.split(b":", 1)[0].decode() == h.name
        # children tile their parent's body: nothing outside a part except delimiters/preamble/epilogue
        outer = root
        assert [c.id for c in outer.children] == ["1.1", "1.2", "1.3"]
        assert PHISH[outer.children[0].start:outer.children[0].start + 14] == b"Content-Type: "

    def test_decoding(self):
        root = parse(PHISH)
        parts = {p.id: p for p in root.walk()}
        plain = parts["1.1.1"]
        assert plain.text.startswith("Please verify your account") and "hours. Café ​" in plain.text
        assert parts["1.2"].decoded == ZIP
        assert parts["1.3"].filename == RTLO_NAME
        assert root.header("Subject").decoded == "Action required: your account ​suspended"
        assert "utf-8?B" in root.header("Subject").encodings
        assert any("preamble" in w for w in root.warnings) and any("epilogue" in w for w in root.warnings)

    def test_malformed(self):
        msg = (b"Subject: x\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain; charset=x-bogus\n"
               b"Content-Transfer-Encoding: base64\n\naGVs*bG8=\n--b\nContent-Type: text/plain\n\nunterminated")
        root = parse(msg)
        assert any("closing boundary missing" in w for w in root.warnings)
        first = root.children[0]
        assert first.text == "hello"
        assert any("aren't base64" in w for w in first.warnings)
        assert any("unknown charset" in w for w in first.warnings)
        assert root.children[1].text == "unterminated"

    def test_no_blank_line_and_mbox(self):
        root = parse(b"From MAILER-DAEMON Tue Oct 21\nSubject: hi\nthis line has no colon\nbody\n")
        assert root.envelope.startswith("From MAILER-DAEMON")
        assert [h.name for h in root.headers] == ["Subject"]
        assert any("without a blank line" in w for w in root.warnings)

    def test_visible(self):
        assert visible("a‮b​c\x00\r") == "a⟨RLO⟩b⟨ZWSP⟩c\\x00\\r"

    def test_line_index(self):
        idx = LineIndex(b"a\nb\r\nc")
        assert len(idx) == 3 and idx.line(2) == b"b\r\n" and idx.span(2, 5) == [2, 2]


class TestAnalysis:
    def titles(self, result):
        return {f["title"] for f in result["findings"]}

    def test_sender_findings(self, result):
        t = self.titles(result)
        assert "Display name contains a different email address" in t
        assert "Sender domain imitates a well-known brand" in t
        assert "Replies go to a different domain" in t
        assert "DMARC fail" in t and "SPF fail" in t
        assert "DKIM signature isn't from the sender's domain" in t
        assert "Invisible characters in Subject" in t

    def test_findings_point_at_evidence(self, result):
        lines = PHISH.split(b"\n")
        f = next(f for f in result["findings"] if f["title"] == "Replies go to a different domain")
        a, b = f["lines"]
        assert b"Reply-To: refunds@gmail-help.ru" in lines[a - 1]

    def test_received_chain(self, result):
        hops = result["hops"]
        assert [h["ip"] for h in hops] == ["185.220.101.4", "10.0.0.5"]
        assert hops[0]["helo"] == "mail.paypa1-secure.com" and hops[1]["delay"] == 4
        assert result["origin"]["ip"] == "185.220.101.4"

    def test_links(self, result):
        by_url = {l["url"]: l for l in result["links"]}
        safe = by_url["https://evil.example/x"]
        assert safe["wrapper"] == "Microsoft Safe Links" and "text-mismatch" in safe["flags"]
        assert "ip-literal" in by_url["http://185.220.101.4/k"]["flags"]
        assert "https://collect.evil.example/p" in by_url
        assert any("lookalike:paypal.com" in f for f in by_url["https://paypa1-secure.com/login"]["flags"])
        t = self.titles(result)
        assert {"Link text shows a different site than the real target", "Link goes to a bare IP address",
                "Form inside the email asking for a password", "Hidden HTML elements", "Tracking pixel"} <= t

    def test_attachments(self, result):
        att = {a["part"]: a for a in result["attachments"]}
        z = att["1.2"]["triage"]
        assert z["archive"][0]["name"] == "invoice.pdf.exe" and z["archive"][0]["encrypted"]
        rtlo = att["1.3"]
        assert rtlo["filename"] == "invoice⟨RLO⟩fdp.exe"
        assert rtlo["triage"]["detected"].startswith("Windows executable")
        t = self.titles(result)
        assert any(x.startswith("Password-protected archive") for x in t)
        assert any(x.startswith("File name uses right-to-left override") for x in t)

    def test_iocs_and_risk(self, result):
        values = {(i["type"], i["value"]) for i in result["iocs"]}
        assert ("ipv4", "185.220.101.4") in values and ("domain", "paypa1-secure.com") in values
        assert ("sha256", result["attachments"][0]["hashes"]["sha256"]) in values
        assert result["risk"] == "high"

    def test_helpers(self):
        assert lookalike("paypa1.com") == "paypal.com"
        assert lookalike("micros0ft-support.com") is None or lookalike("micros0ft-support.com") == "microsoft.com"
        assert lookalike("login.microsoft.com.evil.io") == "microsoft.com"
        assert lookalike("paypal.com") is None and lookalike("example.org") is None
        assert lookalike("xn--pypal-4ve.com") == "paypal.com"      # pаypal with a Cyrillic а
        assert lookalike("xn--bcher-kva.de") is None                # bücher.de: IDN, not an imitation
        assert lookalike("paypa1-secure.com") == "paypal.com"
        assert unwrap("https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.com_a&d=x")[0] == "https://evil.com/a"
        assert unwrap("https://urldefense.com/v3/__https://evil.com/a__;!!x")[0] == "https://evil.com/a"
        r = parse_received("from a.example (b.example [2001:db8::1]) by c.example with SMTP; Tue, 21 Oct 2026 10:00:00 +0000")
        assert r["ip"] == "2001:db8::1" and r["rdns"] == "b.example" and r["ts"]

    def test_filetype(self):
        assert filetype.sniff(b"%PDF-1.7")[0] == "PDF document"
        pdf = b"%PDF-1.4 /OpenAction /J#61vaScript (x) /URI (http://evil.example/a)"
        tri = filetype.analyze_file(pdf, "a.pdf", "application/pdf")
        titles = {f["title"] for f in tri["findings"]}
        assert "PDF hides keywords with hex escapes" in titles and "PDF contains active content" in titles
        assert tri["pdf_uris"] == ["http://evil.example/a"]
        html = filetype.analyze_file(b"<html><script>var b=atob('x');new Blob([b])</script>", "scan.pdf", None)
        assert any("smuggling" in f["title"] for f in html["findings"])
        assert any(f["title"] == "Extension doesn't match content" for f in html["findings"])


class TestStore:
    def test_store_is_lossless_and_readonly(self, tmp_path):
        store = EmailStore(tmp_path / "ev")
        res = store.add(PHISH, "phish.eml", "test")
        sha = res["sha256"]
        assert store.raw(sha) == PHISH
        path = tmp_path / "ev" / sha[:2] / f"{sha}.eml"
        assert oct(path.stat().st_mode & 0o777) == "0o400"
        assert store.list()[0]["subject"].startswith("Action required")
        view = store.lines(sha)
        assert view["total"] == len(PHISH.split(b"\n")) - 1  # message ends with a newline
        flat = [l for l in view["lines"] if isinstance(l, str)]
        assert "Return-Path: <bounce@mailer.bulk-sender.net>" == flat[0]
        assert store.part(sha, "1.2").decoded == ZIP
        assert store.delete(sha) and not path.exists()

    def test_tamper_detected(self, tmp_path):
        store = EmailStore(tmp_path / "ev")
        sha = store.add(b"Subject: a\r\n\r\nbody\r\n")["sha256"]
        path = tmp_path / "ev" / sha[:2] / f"{sha}.eml"
        path.chmod(0o600)
        path.write_bytes(b"Subject: b\r\n\r\nbody\r\n")
        with pytest.raises(ValueError):
            store.raw(sha)

    def test_folds_long_base64(self, tmp_path):
        big = base64.encodebytes(b"\x00" * 20000)
        msg = (b"Subject: x\nContent-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nhi\n--b\n"
               b"Content-Type: application/octet-stream\nContent-Transfer-Encoding: base64\n\n" + big + b"--b--\n")
        store = EmailStore(tmp_path / "ev")
        sha = store.add(msg)["sha256"]
        view = store.lines(sha)
        folds = [l for l in view["lines"] if isinstance(l, dict)]
        assert len(folds) == 1 and folds[0]["count"] > 300
        a, b = folds[0]["fold"]
        assert len(store.lines(sha, a, b, fold=0)["lines"]) == b - a + 1


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@pytest.fixture
def mail_api(tmp_path):
    store = EmailStore(tmp_path / "ev")
    ctx = ServiceContext(live=LiveState(), token="t0ken", db_path=tmp_path / "events.db", emails=store)
    server = make_server(ctx, "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], store
    server.shutdown()
    server.server_close()


def raw_call(port, path, data, headers=None, token="t0ken"):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method="POST",
                                 headers={"Content-Type": "message/rfc822", **({"X-PyNIDS-Token": token} if token else {}),
                                          **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"null")


class TestMailApi:
    def test_upload_and_views(self, mail_api):
        from tests.test_service import call
        port, store = mail_api
        assert raw_call(port, "/api/soc/email", PHISH, token=None)[0] == 401
        code, res = raw_call(port, "/api/soc/email", PHISH, {"X-Filename": "phish.eml"})
        assert code == 201 and res["risk"] == "high"
        sha = res["sha256"]
        code, listing = call(port, "/api/soc/email")
        assert listing[0]["sha256"] == sha
        code, lines = call(port, f"/api/soc/email/{sha}/raw")
        assert code == 200 and lines["total"] > 50
        code, part = call(port, f"/api/soc/email/{sha}/part/1.1.1")
        assert part["text"].startswith("Please verify")
        code, part = call(port, f"/api/soc/email/{sha}/part/1.2?view=hex")
        assert part["hex"].startswith("00000000  50 4b 03 04")
        assert call(port, "/api/soc/email/nothex")[0] == 404

    def test_thunderbird_origin_allowed_only_here(self, mail_api):
        from tests.test_service import call
        port, _ = mail_api
        code, _ = raw_call(port, "/api/soc/email", PHISH, {"Origin": "moz-extension://abc-123"})
        assert code == 201
        assert raw_call(port, "/api/soc/email", PHISH, {"Origin": "https://evil.example"})[0] == 403
        code, _ = call(port, "/api/notifications", method="POST", body={}, headers={"Origin": "moz-extension://abc"})
        assert code == 403


class TestAgainstStdlib:
    """Cross-check: every leaf part decodes to the same bytes the stdlib produces."""

    def build(self, seed):
        import random
        from email.message import EmailMessage
        rnd = random.Random(seed)
        msg = EmailMessage()
        msg["From"] = "Zoë Ångström <zoe@example.org>"
        msg["To"] = "a@example.com"
        msg["Subject"] = rnd.choice(["Plain", "Ünïcödé subject ✓", "Ελληνικά", "日本語の件名"])
        msg.set_content(rnd.choice(["hello\n", "naïve café\n" * 50, "line\r\nwith\r\ncrlf\n", "x" * 2000]),
                        charset=rnd.choice(["utf-8", "iso-8859-1"]) if seed % 3 else "utf-8")
        msg.add_alternative("<p>hi <b>there</b> ünï</p>", subtype="html")
        for i in range(rnd.randint(0, 3)):
            blob = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 5000)))
            msg.add_attachment(blob, maintype="application", subtype="octet-stream",
                               filename=rnd.choice(["a.bin", "Résumé (final).pdf", "файл.zip", f"x{i}.dat"]))
        if seed % 4 == 0:
            inner = EmailMessage()
            inner["Subject"] = "forwarded"
            inner.set_content("inner body ✓")
            msg.add_attachment(inner)
        return msg.as_bytes()

    @pytest.mark.parametrize("seed", range(24))
    def test_parts_match(self, seed):
        import email
        from email import policy
        raw = self.build(seed)
        ours = [p for p in parse(raw).walk() if not p.is_multipart and p.content_type != "message/rfc822"]
        ref = [p for p in email.message_from_bytes(raw, policy=policy.compat32).walk()
               if not p.is_multipart() and p.get_content_type() != "message/rfc822"]
        assert len(ours) == len(ref)
        for a, b in zip(ours, ref):
            assert a.content_type == b.get_content_type()
            assert a.decoded == b.get_payload(decode=True), (a.id, a.content_type)
            if b.get_filename():
                from email.header import decode_header, make_header
                assert a.filename == str(make_header(decode_header(b.get_filename())))
        result = analyze(raw)
        assert result["summary"]["from_addr"] == "zoe@example.org"
