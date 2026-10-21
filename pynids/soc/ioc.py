"""
Indicators of compromise: recognise, normalise, defang and extract them.

Analysts paste indicators in every shape: defanged (``hxxp://evil[.]com``),
wrapped in quotes or brackets, with trailing punctuation, or buried in a
ticket or report.  :func:`classify` turns one value into an :class:`Ioc`;
:func:`extract` pulls every indicator out of free text.

Types
-----
``ipv4`` ``ipv6`` ``domain`` ``url`` ``email`` ``md5`` ``sha1`` ``sha256``
``sha512`` ``asn`` ``cve``
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional
from urllib.parse import urlsplit

HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
TYPES = ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "sha512", "asn", "cve")

# Defanging conventions seen in the wild, most specific first.
_REFANG = [
    (re.compile(r"\bhxxp(s?)", re.I), r"http\1"),
    (re.compile(r"\bfxp\b", re.I), "ftp"),
    (re.compile(r"\[\s*:\s*\]|\(\s*:\s*\)"), ":"),
    (re.compile(r"\[\s*/\s*\]"), "/"),
    (re.compile(r"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}", re.I), "."),
    (re.compile(r"\s+\[?dot\]?\s+", re.I), "."),
    (re.compile(r"\\\."), "."),
    (re.compile(r"\[\s*(?:@|at)\s*\]|\(\s*(?:@|at)\s*\)", re.I), "@"),
]

_LABEL = r"(?:[a-z0-9](?:[a-z0-9\-_]{0,61}[a-z0-9])?)"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+(?:[a-z]{{2,63}}|xn--[a-z0-9\-]{{2,59}})$", re.I)
_EMAIL_RE = re.compile(rf"^[a-z0-9.!#$%&'*+/=?^_`{{|}}~\-]+@((?:{_LABEL}\.)+[a-z][a-z0-9\-]{{1,62}})$", re.I)
_HEX_RE = re.compile(r"^[a-f0-9]+$", re.I)
_ASN_RE = re.compile(r"^AS\s?(\d{1,10})$", re.I)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)

# Free-text extraction patterns (run on refanged text).
_X_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`\]\[(){}|\\^]+", re.I)
_X_EMAIL = re.compile(rf"\b[a-z0-9._%+\-]+@(?:{_LABEL}\.)+[a-z]{{2,63}}\b", re.I)
_X_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d|\.\d)")
# Loose candidate; classify() validates with the ipaddress module.
_X_IPV6 = re.compile(r"(?<![\w:])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![\w:])", re.I)
_X_HASH = re.compile(r"(?<![a-f0-9])(?:[a-f0-9]{128}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})(?![a-f0-9])", re.I)
_X_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_X_DOMAIN = re.compile(rf"(?<![@\w.\-])(?:{_LABEL}\.)+[a-z]{{2,63}}\b(?![@\-])", re.I)

# Words that look like domains in prose but are almost always file names.
_FILE_EXTS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jse", "hta", "lnk", "msi", "scr", "jar",
    "py", "sh", "rb", "pl", "php", "asp", "aspx", "jsp", "html", "htm", "css", "json", "xml", "yaml",
    "yml", "txt", "log", "csv", "md", "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt",
    "pptx", "rtf", "zip", "rar", "7z", "gz", "tar", "iso", "img", "png", "jpg", "jpeg", "gif", "svg",
    "eml", "msg", "tmp", "dat", "bin", "cfg", "conf", "ini", "plist", "dmg", "pkg", "app",
}


@dataclass(frozen=True)
class Ioc:
    type: str
    value: str       # normalised value used for lookups
    original: str    # exactly what the analyst supplied

    @property
    def defanged(self) -> str:
        return defang(self.value, self.type)

    def to_dict(self) -> Dict[str, str]:
        return {**asdict(self), "defanged": self.defanged}


def refang(text: str) -> str:
    """Undo common defanging (``hxxp``, ``[.]``, ``(dot)``, ``[@]`` …)."""
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return text


def defang(value: str, kind: str) -> str:
    """Make an indicator safe to paste into chat or a ticket (not clickable)."""
    if kind == "url":
        out = re.sub(r"^(?:http|ftp)", lambda m: "hxxp" if m.group(0).lower() == "http" else "fxp",
                     value, flags=re.I)
        host = urlsplit(value).hostname or ""
        idx = out.lower().find(host) if host else -1
        if idx >= 0:
            out = out[:idx] + out[idx:idx + len(host)].replace(".", "[.]") + out[idx + len(host):]
        return out
    if kind == "email":
        local, _, dom = value.rpartition("@")
        return f"{local}[@]{dom.replace('.', '[.]')}"
    if kind in ("domain", "ipv4"):
        return value.replace(".", "[.]")
    if kind == "ipv6":
        return value.replace(":", "[:]")
    return value


def _strip(text: str) -> str:
    prev = None
    while text != prev:
        prev = text
        text = text.strip().strip("\"'`<>()[]{}").rstrip(".,;!?")
    return text


def classify(raw: str) -> Optional[Ioc]:
    """Recognise a single indicator.  Returns ``None`` if it isn't one."""
    original = raw.strip()
    text = _strip(refang(original))
    if not text or len(text) > 4096 or any(c in text for c in "\r\n"):
        return None

    if re.match(r"^(?:https?|ftp)://", text, re.I):
        parts = urlsplit(text)
        if parts.hostname:
            return Ioc("url", text, original)
        return None
    try:
        ip = ipaddress.ip_address(text.split("%")[0])
        return Ioc("ipv4" if ip.version == 4 else "ipv6", ip.compressed, original)
    except ValueError:
        pass
    if _HEX_RE.match(text) and len(text) in HASH_TYPES:
        return Ioc(HASH_TYPES[len(text)], text.lower(), original)
    m = _ASN_RE.match(text)
    if m:
        return Ioc("asn", f"AS{int(m.group(1))}", original)
    if _CVE_RE.match(text):
        return Ioc("cve", text.upper(), original)
    m = _EMAIL_RE.match(text)
    if m:
        local, _, dom = text.rpartition("@")
        return Ioc("email", f"{local}@{dom.lower()}", original)
    host = text.lower().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii") if not host.isascii() else host
    except UnicodeError:
        return None
    if _DOMAIN_RE.match(host):
        return Ioc("domain", host, original)
    # A bare host with a path ("evil.com/login") is a URL without a scheme.
    if "/" in text and _DOMAIN_RE.match(text.split("/", 1)[0].lower()):
        return Ioc("url", "http://" + text, original)
    return None


def extract(text: str, limit: int = 500) -> List[Ioc]:
    """Every indicator in free text, in order of first appearance, de-duplicated."""
    clean = refang(text)
    found: List[tuple] = []  # (position, Ioc)
    taken: List[tuple] = []  # spans already claimed by a more specific match

    def claim(m: re.Match) -> bool:
        s, e = m.span()
        if any(s < te and e > ts for ts, te in taken):
            return False
        taken.append((s, e))
        return True

    for m in _X_URL.finditer(clean):
        url = m.group(0).rstrip(".,;:!?'\"")
        if claim(m):
            ioc = classify(url)
            if ioc:
                found.append((m.start(), ioc))
    for m in _X_EMAIL.finditer(clean):
        if claim(m):
            ioc = classify(m.group(0))
            if ioc:
                found.append((m.start(), ioc))
    for pattern in (_X_HASH, _X_CVE, _X_IPV4, _X_IPV6):
        for m in pattern.finditer(clean):
            if not claim(m):
                continue
            ioc = classify(m.group(0))
            if ioc:
                found.append((m.start(), ioc))
    for m in _X_DOMAIN.finditer(clean):
        value = m.group(0)
        if value.rsplit(".", 1)[-1].lower() in _FILE_EXTS or not claim(m):
            continue
        ioc = classify(value)
        if ioc and ioc.type == "domain":
            found.append((m.start(), ioc))

    out, seen = [], set()
    for _, ioc in sorted(found, key=lambda t: t[0]):
        key = (ioc.type, ioc.value.lower())
        if key not in seen:
            seen.add(key)
            out.append(ioc)
        if len(out) >= limit:
            break
    return out


def parse(text: str) -> List[Ioc]:
    """One indicator if the whole input is one, else everything extracted from it."""
    single = classify(text)
    return [single] if single else extract(text)


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value.split("%")[0]).is_global
    except ValueError:
        return False
