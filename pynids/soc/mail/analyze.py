"""
Phishing analysis of a parsed message.

Every finding carries the raw line range it is based on, so the analyst can
jump from "Reply-To differs from From" straight to the header lines that
prove it.  Findings are observations, not verdicts: a mismatch is often
legitimate (newsletters, ticketing systems), and the detail says so.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import time
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlsplit

from ..ioc import classify, defang, extract
from ..sources.free import registered_domain
from . import filetype
from .mime import LineIndex, Part, eol_stats, invisible_chars, parse, visible

SEV_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}

BRANDS = [
    "paypal.com", "microsoft.com", "office.com", "office365.com", "outlook.com", "live.com", "microsoftonline.com",
    "sharepoint.com", "onedrive.com", "apple.com", "icloud.com", "google.com", "gmail.com", "amazon.com",
    "netflix.com", "facebook.com", "instagram.com", "linkedin.com", "dhl.com", "fedex.com", "ups.com", "usps.com",
    "docusign.com", "docusign.net", "dropbox.com", "adobe.com", "wellsfargo.com", "chase.com", "bankofamerica.com",
    "americanexpress.com", "coinbase.com", "binance.com", "irs.gov", "zoom.us", "steamcommunity.com", "ebay.com",
    "booking.com", "airbnb.com", "spotify.com", "twitter.com", "x.com", "whatsapp.com", "yahoo.com", "intuit.com",
]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at", "ow.ly",
              "buff.ly", "tiny.cc", "rb.gy", "t.ly", "s.id", "v.gd", "qrco.de", "lnkd.in", "bl.ink", "short.io"}
ABUSED_HOSTING = ("web.app", "firebaseapp.com", "pages.dev", "workers.dev", "netlify.app", "vercel.app", "glitch.me",
                  "herokuapp.com", "github.io", "blogspot.com", "weebly.com", "wixsite.com", "000webhostapp.com",
                  "ngrok.io", "ngrok-free.app", "trycloudflare.com", "ipfs.io", "dweb.link", "r2.dev", "azurewebsites.net",
                  "windows.net", "googleapis.com", "appspot.com", "sites.google.com", "forms.gle", "typeform.com",
                  "jotform.com", "notion.site", "replit.app", "framer.app", "webflow.io", "square.site")
URGENCY = re.compile(r"\b(urgent|immediately|suspend(?:ed)?|verify|verification|confirm your|unusual (?:sign[- ]?in|activity)|"
                     r"password (?:expire|reset)|account (?:locked|disabled|closed)|invoice|payment|wire transfer|"
                     r"gift ?cards?|bitcoin|final notice|action required|within 24 hours|click here)\b", re.I)


def _f(severity: str, category: str, title: str, detail: str = "", lines: Optional[List[int]] = None,
       part: Optional[str] = None) -> Dict[str, Any]:
    return {"severity": severity, "category": category, "title": title, "detail": detail,
            "lines": lines, "part": part}


# ---------------------------------------------------------------------------
# Addresses & domains
# ---------------------------------------------------------------------------

def _addr(value: str) -> Tuple[str, str, str]:
    name, addr = parseaddr(value)
    dom = addr.rpartition("@")[2].lower().strip(">") if "@" in addr else ""
    return name, addr, dom


_CONFUSABLE = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s", "!": "i", "|": "l"})


# Non-Latin letters that render like Latin ones (the common IDN-spoofing set).
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ԁ": "d", "ӏ": "l",
    "ɡ": "g", "ո": "n", "ս": "u", "ѕ": "s", "һ": "h", "ԛ": "q", "ԝ": "w", "ɑ": "a", "ο": "o", "ρ": "p", "ν": "v",
    "κ": "k", "τ": "t", "ι": "i", "α": "a", "ε": "e", "ӧ": "o", "ë": "e", "é": "e", "á": "a", "í": "i", "ó": "o",
    "ú": "u", "ı": "i", "ł": "l", "ß": "b",
})


def _skeleton(label: str) -> str:
    s = label.lower().translate(_CONFUSABLE)
    return s.replace("rn", "m").replace("vv", "w").replace("cl", "d").replace("-", "").replace("ii", "u")


def _distance(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike(domain: str) -> Optional[str]:
    """The brand domain this one imitates, if it looks like an imitation.

    Checks every label and hyphen-separated token (``paypa1-secure.com``,
    ``login.microsoft.com.evil.io``) against brand names: exact, after
    undoing common character swaps (0→o, rn→m …), or one edit away.
    """
    if not domain:
        return None
    domain = domain.lower().rstrip(".")
    if registered_domain(domain) in BRANDS:
        return None
    try:
        uni = domain.encode("ascii").decode("idna") if "xn--" in domain else domain
    except UnicodeError:
        uni = domain
    tokens = [t for t in re.split(r"[.\-_]", domain)[:-1] if t]
    for brand in BRANDS:
        b = brand.split(".")[0]
        if len(b) < 4:
            continue
        for tok in tokens:
            if tok == b or _skeleton(tok) == b or (len(tok) >= 5 and _distance(tok, b) == 1):
                return brand
        if uni != domain:
            folded = [_skeleton(t.translate(_HOMOGLYPHS)) for t in re.split(r"[.\-_]", uni)[:-1]]
            if b in folded or any(len(t) >= 5 and _distance(t, b) == 1 for t in folded):
                return brand
    return None


# ---------------------------------------------------------------------------
# Received chain
# ---------------------------------------------------------------------------

_IP_IN = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3}|(?:IPv6:)?[0-9a-fA-F:]{3,}:[0-9a-fA-F.]+)\]?")


def parse_received(value: str) -> Dict[str, Any]:
    v = " ".join(value.split())
    date_part = v.rsplit(";", 1)[1].strip() if ";" in v else ""
    head = v.rsplit(";", 1)[0] if ";" in v else v

    def grab(keyword: str, stops: str) -> Optional[str]:
        m = re.search(rf"\b{keyword}\s+(.+?)(?=\s+\b(?:{stops})\b|$)", head, re.I)
        return m.group(1).strip() if m else None

    frm = grab("from", "by|via|with|id|for")
    by = grab("by", "via|with|id|for")
    with_ = grab("with", "id|for")
    ident = grab("id", "for")
    for_ = grab("for", "$^")
    ips = []
    for m in _IP_IN.finditer(frm or ""):
        cand = m.group(1).replace("IPv6:", "")
        try:
            ips.append(ipaddress.ip_address(cand).compressed)
        except ValueError:
            continue
    helo = (frm or "").split(" ", 1)[0] if frm else None
    rdns = None
    m = re.search(r"\(([^\s()\[\]]+)\s*\[", frm or "")
    if m:
        rdns = m.group(1)
    ts = None
    if date_part:
        try:
            ts = parsedate_to_datetime(date_part).timestamp()
        except (TypeError, ValueError, IndexError):
            ts = None
    return {"from": frm, "helo": helo, "rdns": rdns, "ip": ips[0] if ips else None, "by": by, "with": with_,
            "id": ident, "for": for_, "date": date_part or None, "ts": ts}


def _is_private(ip: Optional[str]) -> bool:
    try:
        return not ipaddress.ip_address(ip).is_global
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def parse_auth_results(value: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"authserv": value.split(";", 1)[0].strip()}
    for method in ("spf", "dkim", "dmarc", "arc", "compauth", "bimi"):
        results = re.findall(rf"\b{method}=([a-z]+)([^;]*)", value, re.I)
        if results:
            out[method] = [{"result": r.lower(), "detail": " ".join(d.split())[:300]} for r, d in results]
    return out


def parse_dkim_signature(value: str) -> Dict[str, str]:
    tags = {}
    for item in value.split(";"):
        if "=" in item:
            k, _, v = item.partition("=")
            tags[k.strip()] = "".join(v.split()) if k.strip() in ("b", "bh") else " ".join(v.split())
    return {k: tags.get(k, "") for k in ("v", "a", "d", "s", "c", "h", "i", "t", "x", "bh", "b") if k in tags}


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

class _Html(HTMLParser):
    URL_ATTRS = {"href", "src", "action", "formaction", "background", "data", "poster", "cite", "longdesc", "srcset",
                 "xlink:href", "lowsrc", "dynsrc", "ping"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: List[Dict[str, Any]] = []
        self.forms: List[Dict[str, Any]] = []
        self.scripts = 0
        self.iframes = 0
        self.hidden = 0
        self.pixels = 0
        self.meta_refresh: List[str] = []
        self.inputs: List[str] = []
        self._a: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        style = a.get("style", "").replace(" ", "").lower()
        if any(s in style for s in ("display:none", "visibility:hidden", "font-size:0", "max-height:0", "opacity:0")) \
                or "hidden" in a:
            self.hidden += 1
        if tag == "script":
            self.scripts += 1
        if tag in ("iframe", "frame", "embed", "object"):
            self.iframes += 1
        if tag == "form":
            self.forms.append({"action": a.get("action", ""), "method": a.get("method", "get")})
        if tag == "input":
            self.inputs.append(a.get("type", "text").lower())
        if tag == "img" and a.get("width") in ("0", "1") and a.get("height") in ("0", "1"):
            self.pixels += 1
        if tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh.append(a.get("content", ""))
            m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", a.get("content", ""), re.I)
            if m:
                self.links.append({"url": m.group(1).strip(), "context": "meta refresh"})
        for k, v in a.items():
            if k in self.URL_ATTRS and v.strip():
                values = [s.strip().split(" ")[0] for s in v.split(",")] if k == "srcset" else [v.strip()]
                for u in values:
                    item = {"url": u, "context": f"{tag} {k}"}
                    self.links.append(item)
                    if tag == "a" and k == "href":
                        self._a = item
                        item["text"] = ""
            if k == "style":
                for u in re.findall(r"url\(\s*['\"]?([^'\")]+)", v, re.I):
                    self.links.append({"url": u, "context": f"{tag} style"})

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            self._a = None

    def handle_data(self, data: str) -> None:
        if self._a is not None:
            self._a["text"] = (self._a.get("text", "") + data)[:500]


_WRAPPERS = [
    (re.compile(r"safelinks\.protection\.outlook\.com$"), "url", "Microsoft Safe Links"),
    (re.compile(r"(^|\.)google\.[a-z.]+$"), "q", "Google redirect"),
    (re.compile(r"^l\.facebook\.com$|^lm\.facebook\.com$"), "u", "Facebook redirect"),
    (re.compile(r"^l\.instagram\.com$"), "u", "Instagram redirect"),
    (re.compile(r"^(www\.)?linkedin\.com$"), "url", "LinkedIn redirect"),
]


def unwrap(url: str) -> Tuple[str, Optional[str]]:
    """Undo link-protection / redirect wrappers.  Returns (url, wrapper name)."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    q = parse_qs(parts.query)
    for pattern, param, name in _WRAPPERS:
        if pattern.search(host) and q.get(param):
            target = q[param][0]
            if target.startswith(("http://", "https://")):
                return target, name
    if host == "urldefense.proofpoint.com" and "/v2/" in parts.path and q.get("u"):
        return unquote(q["u"][0].replace("-", "%").replace("_", "/")), "Proofpoint URL Defense v2"
    if host == "urldefense.com" and parts.path.startswith("/v3/__"):
        inner = url.split("/v3/__", 1)[1].split("__;", 1)[0]
        return inner, "Proofpoint URL Defense v3"
    return url, None


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze(data: bytes, name: Optional[str] = None) -> Dict[str, Any]:
    lines = LineIndex(data)
    root = parse(data)
    findings: List[Dict[str, Any]] = []
    msg = root
    hdr = lambda n: msg.header(n)  # noqa: E731

    def hlines(n: str) -> Optional[List[int]]:
        h = hdr(n)
        return lines.span(h.start, h.end) if h else None

    def val(n: str) -> str:
        h = hdr(n)
        return h.decoded if h else ""

    # --- identity -------------------------------------------------------
    from_name, from_addr, from_dom = _addr(val("From"))
    _, reply_addr, reply_dom = _addr(val("Reply-To"))
    _, rp_addr, rp_dom = _addr(val("Return-Path"))
    _, sender_addr, sender_dom = _addr(val("Sender"))
    summary = {
        "from": val("From"), "from_addr": from_addr, "from_name": from_name, "from_domain": from_dom,
        "to": val("To"), "cc": val("Cc"), "subject": val("Subject"), "date": val("Date"),
        "reply_to": val("Reply-To"), "return_path": val("Return-Path"), "sender": val("Sender"),
        "message_id": val("Message-ID"), "x_mailer": val("X-Mailer") or val("User-Agent"),
        "x_originating_ip": val("X-Originating-IP") or val("X-Sender-IP"),
    }
    if not msg.headers:
        findings.append(_f("high", "structure", "No headers found", "this doesn't look like a raw email — "
                           "export the message source (.eml) rather than copying the visible text"))

    if len(msg.headers_named("From")) > 1:
        findings.append(_f("high", "sender", "More than one From header",
                           "different mail clients display different senders", hlines("From")))
    if from_name:
        m = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", from_name)
        if m and m.group(1).lower() != from_dom:
            findings.append(_f("high", "sender", "Display name contains a different email address",
                               f"shows “{from_name}” but the real sender is {from_addr}", hlines("From")))
        brand = next((b for b in BRANDS if b.split(".")[0] in from_name.lower().replace(" ", "")), None)
        if brand and registered_domain(from_dom) != brand and len(brand.split(".")[0]) >= 4 \
                and not from_dom.endswith(brand.split(".")[0] + ".com"):
            findings.append(_f("medium", "sender", "Display name names a brand the sending domain doesn't belong to",
                               f"“{from_name}” sent from {from_dom or 'no domain'}", hlines("From")))
    if from_dom:
        if "xn--" in from_dom or not from_dom.isascii():
            findings.append(_f("high", "sender", "Internationalised (punycode) sender domain",
                               f"{from_dom} — can imitate another domain with look-alike letters", hlines("From")))
        imitated = lookalike(from_dom)
        if imitated:
            findings.append(_f("high", "sender", "Sender domain imitates a well-known brand",
                               f"{from_dom} looks like {imitated}", hlines("From")))
    if reply_dom and from_dom and registered_domain(reply_dom) != registered_domain(from_dom):
        findings.append(_f("medium", "sender", "Replies go to a different domain",
                           f"Reply-To {reply_addr} vs From {from_addr} — normal for some newsletters and ticketing "
                           "systems, typical for invoice fraud", hlines("Reply-To")))
    if rp_dom and from_dom and registered_domain(rp_dom) != registered_domain(from_dom):
        findings.append(_f("info", "sender", "Envelope sender (Return-Path) differs from From",
                           f"{rp_addr} — usual when a mailing service sends on someone's behalf", hlines("Return-Path")))
    for field_name in ("Subject", "From"):
        inv = invisible_chars(val(field_name))
        if inv:
            findings.append(_f("medium", "content", f"Invisible characters in {field_name}",
                               ", ".join(f"{k}×{v}" for k, v in inv.items()), hlines(field_name)))
    if not hdr("Message-ID"):
        findings.append(_f("low", "structure", "No Message-ID", "legitimate mail servers almost always add one"))

    # --- received chain --------------------------------------------------
    hops = []
    for h in msg.headers_named("Received"):
        hop = parse_received(h.decoded)
        hop["lines"] = lines.span(h.start, h.end)
        hop["raw"] = visible(h.value)
        hops.append(hop)
    hops.reverse()  # chronological: first hop (sender side) first
    prev = None
    for i, hop in enumerate(hops):
        hop["n"] = i + 1
        hop["private"] = _is_private(hop["ip"])
        if hop["ts"] and prev:
            hop["delay"] = round(hop["ts"] - prev)
            if hop["delay"] < -300:
                findings.append(_f("low", "routing", f"Hop {i + 1} is timestamped before the previous one",
                                   f"{hop['delay']} s — clock skew, or forged Received headers", hop["lines"]))
        if hop["ts"]:
            prev = hop["ts"]
    origin = next((h for h in hops if h.get("ip") and not h["private"]), None)
    date_ts = None
    try:
        date_ts = parsedate_to_datetime(val("Date")).timestamp() if val("Date") else None
    except (TypeError, ValueError, IndexError):
        findings.append(_f("low", "structure", "Date header can't be parsed", val("Date")[:80], hlines("Date")))
    if date_ts and date_ts - time.time() > 86400:
        findings.append(_f("medium", "structure", "Date is in the future", val("Date"), hlines("Date")))
    if date_ts and hops and hops[-1].get("ts") and hops[-1]["ts"] - date_ts > 7 * 86400:
        findings.append(_f("low", "routing", "Delivered more than a week after its Date",
                           "old message re-sent, or a forged Date", hlines("Date")))

    # --- authentication --------------------------------------------------
    auth_results = []
    for h in msg.headers_named("Authentication-Results") + msg.headers_named("ARC-Authentication-Results"):
        r = parse_auth_results(h.decoded)
        r["header"] = h.name
        r["lines"] = lines.span(h.start, h.end)
        auth_results.append(r)
    dkim_sigs = []
    for h in msg.headers_named("DKIM-Signature"):
        sig = parse_dkim_signature(h.value)
        sig["lines"] = lines.span(h.start, h.end)
        sig["aligned"] = bool(from_dom) and registered_domain(sig.get("d", "").lower()) == registered_domain(from_dom)
        dkim_sigs.append(sig)
    received_spf = [{"value": visible(h.decoded), "lines": lines.span(h.start, h.end)}
                    for h in msg.headers_named("Received-SPF")]
    verdicts: Dict[str, str] = {}
    top = next((r for r in auth_results if r["header"] == "Authentication-Results"), None)
    if top:
        for method in ("spf", "dkim", "dmarc"):
            if top.get(method):
                results = [x["result"] for x in top[method]]
                verdicts[method] = "pass" if "pass" in results else results[0]
        for method, sev in (("dmarc", "high"), ("spf", "medium"), ("dkim", "medium")):
            res = verdicts.get(method)
            if res in ("fail", "softfail", "permerror", "temperror"):
                findings.append(_f(sev if res in ("fail",) else "low", "auth", f"{method.upper()} {res}",
                                   f"reported by {top['authserv'][:60]}", top["lines"]))
        if verdicts.get("dmarc") == "none" or not verdicts.get("dmarc"):
            findings.append(_f("low", "auth", "No DMARC verdict",
                               "the sender's domain may not publish a DMARC policy", top["lines"]))
    else:
        findings.append(_f("info", "auth", "No Authentication-Results header",
                           "the receiving server's SPF/DKIM/DMARC checks aren't in this copy — export it from the "
                           "recipient's mailbox to get them"))
    if dkim_sigs and from_dom and not any(s["aligned"] for s in dkim_sigs) and verdicts.get("dmarc") != "pass":
        findings.append(_f("medium", "auth", "DKIM signature isn't from the sender's domain",
                           "signed by " + ", ".join(sorted({s.get('d', '?') for s in dkim_sigs})) + f", From is {from_dom}",
                           dkim_sigs[0]["lines"]))

    # --- parts, bodies, links ------------------------------------------
    links: List[Dict[str, Any]] = []
    bodies: List[Dict[str, Any]] = []
    attachments: List[Dict[str, Any]] = []
    seen_urls: Dict[str, Dict[str, Any]] = {}

    def add_link(url: str, part: Part, context: str, text: Optional[str] = None) -> None:
        url = url.strip()
        if url.lower().startswith("data:") and not url.lower().startswith("data:image/"):
            findings.append(_f("medium", "links", "Embedded data: URI (content hidden inside the link)", url[:80],
                               lines.span(part.body_start, part.end), part.id))
            return
        if not url or url.lower().startswith(("#", "mailto:", "cid:", "tel:", "data:")) or len(url) > 4000:
            return
        if url.startswith("//"):
            url = "https:" + url
        if not re.match(r"^[a-z][a-z0-9+.-]*:", url, re.I):
            return  # relative link: meaningless in an email
        final, wrapper = unwrap(url)
        key = final
        item = seen_urls.get(key)
        if item is None:
            host = (urlsplit(final).hostname or "").lower()
            item = {"url": final, "defanged": defang(final, "url"), "host": host, "wrapped": url if wrapper else None,
                    "wrapper": wrapper, "contexts": [], "parts": [], "texts": [], "flags": []}
            seen_urls[key] = item
            links.append(item)
        if context not in item["contexts"]:
            item["contexts"].append(context)
        if part.id not in item["parts"]:
            item["parts"].append(part.id)
        if text and text.strip() and text.strip() not in item["texts"]:
            item["texts"].append(visible(text.strip())[:200])

    part_lines = {p.id: lines.span(p.body_start, p.end) for p in root.walk()}
    for part in root.walk():
        if part.is_multipart:
            continue
        span = lines.span(part.body_start, part.end)
        for w in part.warnings:
            sev = "medium" if ("preamble" in w or "epilogue" in w or "appended" in w) else "low"
            findings.append(_f(sev, "structure", w[0].upper() + w[1:], f"part {part.id} ({part.content_type})",
                               lines.span(part.start, part.end), part.id))
        if part.content_type == "message/rfc822":
            continue
        if part.is_attachment:
            tri = filetype.analyze_file(part.decoded, part.filename, part.content_type)
            att = {"part": part.id, "filename": visible(part.filename) if part.filename else None,
                   "content_type": part.content_type, "size": len(part.decoded), "hashes": part.hashes(),
                   "lines": span, "triage": tri}
            attachments.append(att)
            for f in tri["findings"]:
                findings.append(_f(f["severity"], "attachment", f"{f['title']}" + (f" — {att['filename']}" if att["filename"] else ""),
                                   f["detail"], lines.span(part.start, part.body_start), part.id))
            for u in tri.get("pdf_uris") or []:
                add_link(u, part, "inside PDF")
            if tri.get("detected", "") and tri["detected"].startswith(("HTML", "SVG")):
                p = _Html()
                try:
                    p.feed(part.decoded.decode("utf-8", "replace"))
                except Exception:  # noqa: BLE001
                    pass
                for ln in p.links:
                    add_link(ln["url"], part, "attachment " + ln["context"])
            continue
        if part.text is None:
            continue
        text = part.text
        body = {"part": part.id, "content_type": part.content_type, "charset": part.charset, "lines": span,
                "length": len(text), "invisible": invisible_chars(text)}
        bodies.append(body)
        if body["invisible"]:
            findings.append(_f("medium", "content", "Invisible characters in the body",
                               ", ".join(f"{k}×{v}" for k, v in body["invisible"].items()) +
                               " — often used to break up words so filters miss them", span, part.id))
        if part.content_type == "text/html":
            p = _Html()
            try:
                p.feed(text)
                p.close()
            except Exception as exc:  # noqa: BLE001 — broken HTML is still evidence
                findings.append(_f("low", "content", "HTML couldn't be fully parsed", str(exc)[:120], span, part.id))
            for ln in p.links:
                add_link(ln["url"], part, ln["context"], ln.get("text"))
            body.update({"scripts": p.scripts, "forms": p.forms, "iframes": p.iframes, "hidden_elements": p.hidden,
                         "tracking_pixels": p.pixels, "meta_refresh": p.meta_refresh})
            if p.forms:
                pw = "password" in p.inputs
                findings.append(_f("high" if pw else "medium", "content",
                                   "Form inside the email" + (" asking for a password" if pw else ""),
                                   ", ".join(f["action"] or "(no action)" for f in p.forms)[:200], span, part.id))
            if p.scripts:
                findings.append(_f("medium", "content", "JavaScript in the email body",
                                   f"{p.scripts} script element(s) — mail clients don't run them, but a saved copy would",
                                   span, part.id))
            if p.hidden:
                findings.append(_f("low", "content", "Hidden HTML elements",
                                   f"{p.hidden} element(s) invisible to the reader — can carry text meant only for filters",
                                   span, part.id))
            if p.pixels:
                findings.append(_f("info", "content", "Tracking pixel",
                                   f"{p.pixels} 1×1 image(s) — loading images tells the sender you opened it", span, part.id))
            if p.meta_refresh:
                findings.append(_f("medium", "content", "Automatic redirect (meta refresh)",
                                   "; ".join(p.meta_refresh)[:200], span, part.id))
        for ioc in extract(text):
            if ioc.type == "url":
                add_link(ioc.value, part, "text")
        cues = sorted({m.group(0).lower() for m in URGENCY.finditer(val("Subject") + " " + text[:200_000])})
        if cues:
            body["cues"] = cues

    # link checks
    for item in links:
        host = item["host"]
        if not host:
            continue
        is_ip = classify(host) is not None and classify(host).type in ("ipv4", "ipv6")
        if is_ip:
            item["flags"].append("ip-literal")
        if "@" in (urlsplit(item["url"]).netloc or ""):
            item["flags"].append("userinfo")
        if registered_domain(host) in SHORTENERS or host in SHORTENERS:
            item["flags"].append("shortener")
        if any(host == d or host.endswith("." + d) for d in ABUSED_HOSTING):
            item["flags"].append("free-hosting")
        if "xn--" in host:
            item["flags"].append("punycode")
        imitated = lookalike(host)
        if imitated:
            item["flags"].append("lookalike:" + imitated)
        for t in item["texts"]:
            shown = re.search(r"((?:https?://)?(?:[\w-]+\.)+[a-z]{2,})(?:[/\s]|$)", t, re.I)
            if shown:
                shown_host = (urlsplit(shown.group(1) if "://" in shown.group(1) else "http://" + shown.group(1)).hostname or "").lower()
                if shown_host and registered_domain(shown_host) != registered_domain(host):
                    item["flags"].append("text-mismatch")
                    item["mismatch"] = {"shown": shown_host, "actual": host}
        if item["wrapper"]:
            item["flags"].append("unwrapped")
    flagged = {
        "text-mismatch": ("high", "Link text shows a different site than the real target"),
        "userinfo": ("high", "Link uses the user@host trick"),
        "ip-literal": ("high", "Link goes to a bare IP address"),
        "punycode": ("high", "Link to a punycode (look-alike letters) domain"),
        "shortener": ("medium", "Shortened link hides the destination"),
        "free-hosting": ("medium", "Link to a free hosting service often abused for phishing"),
    }
    for flag, (sev, title) in flagged.items():
        hits = [l for l in links if flag in l["flags"]]
        if hits:
            detail = "; ".join(
                (f"shows {l['mismatch']['shown']} → goes to {l['host']}" if flag == "text-mismatch" else l["defanged"])
                for l in hits[:5])
            pid = hits[0]["parts"][0] if hits[0]["parts"] else None
            findings.append(_f(sev, "links", title, detail, part_lines.get(pid), pid))
    look = [l for l in links if any(f.startswith("lookalike:") for f in l["flags"])]
    if look:
        pid = look[0]["parts"][0] if look[0]["parts"] else None
        findings.append(_f("high", "links", "Link to a domain imitating a brand",
                           "; ".join(f"{l['host']} ≈ {next(f for f in l['flags'] if f.startswith('lookalike:'))[10:]}"
                                     for l in look[:5]), part_lines.get(pid), pid))

    # language cues (weak signal: only reported, never high)
    cues = sorted({c for b in bodies for c in b.get("cues", [])})
    if cues:
        findings.append(_f("info", "content", "Pressure / phishing wording", ", ".join(cues[:12])))

    # --- indicators -----------------------------------------------------
    iocs: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def add_ioc(raw: str, where: str) -> None:
        ioc = classify(raw)
        if not ioc:
            return
        key = (ioc.type, ioc.value.lower())
        item = iocs.setdefault(key, {"type": ioc.type, "value": ioc.value, "defanged": ioc.defanged, "where": []})
        if where not in item["where"]:
            item["where"].append(where)

    for hop in hops:
        if hop.get("ip") and not hop["private"]:
            add_ioc(hop["ip"], f"Received hop {hop['n']}")
        for key in ("rdns", "helo"):
            if hop.get(key) and "." in (hop.get(key) or ""):
                add_ioc(hop[key].strip("[]()"), f"Received hop {hop['n']} ({key})")
    if summary["x_originating_ip"]:
        add_ioc(summary["x_originating_ip"].strip("[] "), "X-Originating-IP")
    for label, addr in (("From", from_addr), ("Reply-To", reply_addr), ("Return-Path", rp_addr), ("Sender", sender_addr)):
        if addr:
            add_ioc(addr, label)
            add_ioc(addr.rpartition("@")[2], f"{label} domain")
    for _, addr in getaddresses([val("To"), val("Cc")]):
        if addr:
            add_ioc(addr, "recipient")
    for s in dkim_sigs:
        if s.get("d"):
            add_ioc(s["d"], "DKIM d=")
    for l in links:
        add_ioc(l["url"], "link")
        if l["host"]:
            add_ioc(l["host"], "link host")
    for a in attachments:
        add_ioc(a["hashes"]["sha256"], f"attachment {a['filename'] or a['part']}")

    findings.sort(key=lambda f: -SEV_ORDER[f["severity"]])
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    risk = "high" if counts["high"] else "medium" if counts["medium"] else "low" if counts["low"] else "none"
    return {
        "sha256": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "size": len(data), "name": name, "line_count": len(lines), "eol": eol_stats(data),
        "summary": {k: visible(v) if isinstance(v, str) else v for k, v in summary.items()},
        "header_lines": lines.span(0, root.body_start),
        "hops": hops, "origin": origin,
        "auth": {"verdicts": verdicts, "results": auth_results, "dkim": dkim_sigs, "received_spf": received_spf},
        "structure": root.to_dict(lines),
        "bodies": bodies, "links": links, "attachments": attachments,
        "iocs": list(iocs.values()), "findings": findings, "counts": counts, "risk": risk,
    }
