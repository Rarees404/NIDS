"""
Indicators of compromise: recognise, normalise, defang and extract them.

Analysts paste indicators in every shape: defanged (``hxxp://evil[.]com``),
wrapped in quotes or brackets, with trailing punctuation, or buried in a
ticket or report.  :func:`classify` turns one value into an :class:`Ioc`;
:func:`extract` pulls every indicator out of free text.

Types
-----
``ipv4`` ``ipv6`` ``domain`` ``url`` ``email`` ``md5`` ``sha1`` ``sha256``
``sha512`` ``asn`` ``cve`` ``cidr`` ``wallet`` ``filepath`` ``regkey``

The last four are host and context indicators: they are extracted and
listed, but there is nothing to look up for them at a reputation source.
An address written with a port (``45.9.1.2:8443``, ``[2001:db8::1]:443``)
is an ``ipv4`` / ``ipv6`` indicator whose ``original`` keeps the port.
"""
from __future__ import annotations

import bisect
import hashlib
import ipaddress
import re
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional
from urllib.parse import urlsplit

HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
TYPES = ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "sha512", "asn", "cve",
         "cidr", "wallet", "filepath", "regkey")

# Defanging conventions seen in the wild, most specific first.
_REFANG = [
    (re.compile(r"\bhxxp(s?)", re.I), r"http\1"),
    (re.compile(r"\bfxp\b", re.I), "ftp"),
    (re.compile(r"\[\s*:\s*\]|\(\s*:\s*\)"), ":"),
    (re.compile(r"\[\s*/\s*\]"), "/"),
    (re.compile(r"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}", re.I), "."),
    (re.compile(r"(?<!\s)\s+\[?dot\]?\s+", re.I), "."),
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
# Lookbehinds (not \b) so a run like "a.a.a…" has one starting point, not one per dot.
_X_EMAIL = re.compile(rf"(?<![a-z0-9._%+\-])[a-z0-9._%+\-]+@(?:{_LABEL}\.)+[a-z]{{2,63}}\b", re.I)
_X_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d|\.\d)")
# Loose candidate; classify() validates with the ipaddress module.
_X_IPV6 = re.compile(r"(?<![\w:])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![\w:])", re.I)
_X_HASH = re.compile(r"(?<![a-f0-9])(?:[a-f0-9]{128}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})(?![a-f0-9])", re.I)
_X_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_X_DOMAIN = re.compile(rf"(?<![@\w.\-])(?:{_LABEL}\.)+[a-z]{{2,63}}\b(?![@\-])", re.I)

_OCTET = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
_X_CIDR = re.compile(rf"(?<![\d.])(?:{_OCTET}\.){{3}}{_OCTET}/(?:3[0-2]|[12]?\d)(?!\d|\.\d)")
_IP_PORT_RE = re.compile(rf"^((?:{_OCTET}\.){{3}}{_OCTET}):(\d{{1,5}})$")
_IP6_PORT_RE = re.compile(r"^\[([0-9a-f:.]+)\]:(\d{1,5})$", re.I)

# Cryptocurrency addresses: Bitcoin (bech32 and base58check) and Ethereum.
_BECH32 = r"bc1[ac-hj-np-z02-9]{39}(?:[ac-hj-np-z02-9]{20})?"
_BASE58 = r"[13][1-9A-HJ-NP-Za-km-z]{25,34}"
_ETH = r"0x[0-9a-fA-F]{40}"
_WALLET_RE = re.compile(rf"^(?:{_BECH32}|{_BASE58}|{_ETH})$")
_X_WALLET = re.compile(rf"(?<![0-9A-Za-z])(?:{_BECH32}|{_BASE58}|{_ETH})(?![0-9A-Za-z])")

# Registry keys: spaces are allowed inside a key name, but only when another
# key follows, so prose after the path is not swallowed.
_REG_SEG = r"[\w.\-{}()$]+"
_REGKEY = (r"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_USERS|HKEY_CLASSES_ROOT|HKEY_CURRENT_CONFIG"
           r"|HKLM|HKCU|HKU|HKCR)"
           rf"(?:\\{_REG_SEG}(?: {_REG_SEG})*(?=\\))*\\{_REG_SEG}")
_REGKEY_RE = re.compile(rf"^{_REGKEY}$", re.I)
_X_REGKEY = re.compile(rf"(?<![A-Za-z_]){_REGKEY}", re.I)

# File paths: Windows drive / UNC / %VAR% paths, and Unix paths under the
# directories that matter on a compromised host.
_WIN_SEG = r"[^\\/:*?\"<>|\r\n\t ]+"
_WIN_PATH = (rf"(?:[A-Za-z]:|%[A-Za-z_()0-9]+%|\\\\[\w.\-$]+)"
             rf"(?:\\{_WIN_SEG}(?: {_WIN_SEG})*(?=\\))*\\{_WIN_SEG}")
_UNIX_PATH = (r"(?:/(?:tmp|var|etc|usr|opt|home|root|Users|Library|private|Applications|System|dev/shm"
              r"|bin|sbin|mnt|srv|proc)|~)(?:/[^\s\"'<>|;,)(\]\[]+)+")
_FILEPATH_RE = re.compile(rf"^(?:{_WIN_PATH}|{_UNIX_PATH})$")
_X_FILEPATH = re.compile(rf"(?<![\w/\\.:%~-])(?:{_WIN_PATH}|{_UNIX_PATH})")

# "v1.2.3.4", "version: 10.0.0.1" are versions, not addresses.
_VERSION_BEFORE = re.compile(r"(?:\bv|\bver|\bversion|\brelease|\bbuild)[\s.:=#-]{0,3}$", re.I)

# TLDs accepted for a bare domain found in free text, so "object.method" and
# "self.config" aren't reported.  classify() of a single value doesn't use it.
_TLDS = frozenset((
    # every ccTLD
    "ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo bq br bs bt bv bw "
    "by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi "
    "fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in "
    "io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me "
    "mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg "
    "ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sj sk sl sm sn so sr ss st su sv "
    "sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye "
    "yt za zm zw "
    # legacy and common generic TLDs
    "com net org edu gov mil int arpa info biz name pro aero coop museum mobi asia tel travel jobs cat post "
    "app dev xyz top online site store tech shop club live cloud vip icu work space website fun life world "
    "today news blog email link click page digital agency solutions services support company network systems "
    "group zone one host press media design studio art academy center global social expert guru ninja rocks "
    "lol buzz bid win loan date download review racing party stream science trade webcam men cricket "
    "accountant faculty bar rest cyou cfd sbs bond monster quest beauty hair skin makeup lat best uno ltd inc "
    "llc moe kim ink red blue pink black green gold money cash finance financial bank credit loans tax capital "
    "fund ventures holdings enterprises industries partners business consulting management marketing events "
    "energy school university college education training courses careers health care clinic dental "
    "law legal realty properties house homes land estate rentals city country africa nyc london berlin paris "
    "tokyo moscow wiki help chat game games casino bet poker pizza cafe coffee restaurant shopping sale deals "
    "market tools software codes computer technology foundation charity church love sex porn adult xxx dating "
    "tube video photo photos pics gallery camera film movie music audio radio fm tv show "
    "fashion clothing shoes watch jewelry luxury auto car cars bike taxi flights travel tours holiday "
    "hosting server domains report reviews insure insurance mortgage exchange trading investments "
    "promo gift gifts coupons express delivery systems contact directory guide team community "
    "google goog youtube apple microsoft windows azure office amazon aws play android chrome gmail "
    "onion local localhost internal lan corp home"
).split())

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
    if kind == "cidr":
        return value.replace(".", "[.]") if "." in value else value.replace(":", "[:]")
    return value


_STRIP_BOTH = frozenset("\"'`<>()[]{}")
_STRIP_TAIL = _STRIP_BOTH | frozenset(".,;!?")


def _strip(text: str) -> str:
    """Peel whitespace, quotes and brackets (and trailing punctuation) off both ends, in one pass."""
    i, j = 0, len(text)
    while i < j and (text[i] in _STRIP_BOTH or text[i].isspace()):
        i += 1
    while j > i and (text[j - 1] in _STRIP_TAIL or text[j - 1].isspace()):
        j -= 1
    return text[i:j]


def classify(raw: str) -> Optional[Ioc]:
    """Recognise a single indicator.  Returns ``None`` if it isn't one."""
    original = raw.strip()
    bracketed = _IP6_PORT_RE.match(refang(original))
    if bracketed and int(bracketed.group(2)) <= 65535:
        try:  # "[2001:db8::1]:443" — before the brackets are peeled off as punctuation
            return Ioc("ipv6", ipaddress.IPv6Address(bracketed.group(1)).compressed, original)
        except ValueError:
            pass
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
    # An address with a port: the address is the indicator, `original` keeps the port.
    m = _IP_PORT_RE.match(text)
    if m and int(m.group(2)) <= 65535:
        return Ioc("ipv4", ipaddress.IPv4Address(m.group(1)).compressed, text)
    if "/" in text and "://" not in text:
        try:
            net = ipaddress.ip_network(text, strict=False)
            if net.prefixlen < net.max_prefixlen:
                return Ioc("cidr", net.compressed, original)
        except ValueError:
            pass
    if _WALLET_RE.match(text) and _wallet_valid(text):
        return Ioc("wallet", text, original)
    if _REGKEY_RE.match(text):
        return Ioc("regkey", text, original)
    if _FILEPATH_RE.match(text):
        return Ioc("filepath", text, original)
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


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _wallet_valid(value: str) -> bool:
    """Base58 Bitcoin addresses carry a checksum; random 30-character IDs fail it."""
    if value.startswith(("bc1", "0x")):
        return True
    n = 0
    for ch in value:
        n = n * 58 + _B58.index(ch)
    raw = n.to_bytes(25, "big") if n < (1 << 200) else b""
    return bool(raw) and hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] == raw[21:]


def _ipv6_plausible(value: str) -> bool:
    """At least two hex groups: rules out slice syntax like ``x[::5]``."""
    return sum(1 for g in value.split(":") if g) >= 2


def extract(text: str, limit: int = 500) -> List[Ioc]:
    """Every indicator in free text, in order of first appearance, de-duplicated."""
    clean = refang(text)
    found: List[tuple] = []  # (position, Ioc)
    # Spans claimed by earlier (more specific) patterns: sorted, non-overlapping.
    starts: List[int] = []
    ends: List[int] = []
    memo: Dict[str, Optional[Ioc]] = {}

    def free(s: int, e: int) -> bool:
        i = bisect.bisect_right(starts, s)
        return not ((i > 0 and ends[i - 1] > s) or (i < len(starts) and starts[i] < e))

    def ioc_of(value: str) -> Optional[Ioc]:
        if value not in memo:
            memo[value] = classify(value)
        return memo[value]

    def scan(pattern: re.Pattern, check) -> None:
        # One pattern's matches never overlap each other, so they are checked
        # against earlier patterns only and merged in afterwards.  A pattern
        # stops after `limit` distinct indicators: any later match of it would
        # sort after all of them and can't make the cut.
        new: List[tuple] = []
        keys = set()
        for m in pattern.finditer(clean):
            s, e = m.span()
            if not free(s, e):
                continue
            value, claim = check(m)
            if not claim:
                continue
            new.append((s, e))
            ioc = ioc_of(value) if value is not None else None
            if ioc and (pattern is not _X_DOMAIN or ioc.type == "domain"):
                found.append((s, ioc))
                keys.add((ioc.type, ioc.value.lower()))
                if len(keys) >= limit:
                    break
        if new:
            merged = sorted(list(zip(starts, ends)) + new)
            starts[:] = [a for a, _ in merged]
            ends[:] = [b for _, b in merged]

    scan(_X_URL, lambda m: (m.group(0).rstrip(".,;:!?'\""), True))
    scan(_X_EMAIL, lambda m: (m.group(0), True))
    scan(_X_HASH, lambda m: (m.group(0), True))
    scan(_X_CVE, lambda m: (m.group(0), True))
    scan(_X_REGKEY, lambda m: (m.group(0), True))
    scan(_X_FILEPATH, lambda m: (m.group(0).rstrip(".,;:!?'\""), True))
    scan(_X_WALLET, lambda m: (m.group(0), _wallet_valid(m.group(0))))
    scan(_X_CIDR, lambda m: (m.group(0), True))

    def ipv4(m: re.Match):
        if _VERSION_BEFORE.search(clean, max(0, m.start() - 12), m.start()):
            return None, True
        port = re.match(r":(\d{1,5})(?![\d.:])", clean[m.end():m.end() + 7])
        return m.group(0) + (port.group(0) if port and int(port.group(1)) <= 65535 else ""), True
    scan(_X_IPV4, ipv4)
    scan(_X_IPV6, lambda m: (m.group(0) if _ipv6_plausible(m.group(0)) else None, True))

    def domain(m: re.Match):
        tld = m.group(0).rsplit(".", 1)[-1].lower()
        if tld in _FILE_EXTS:
            return None, False
        return (m.group(0) if tld in _TLDS or tld.startswith("xn--") else None), True
    scan(_X_DOMAIN, domain)

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


# Names that only mean something inside a network: never sent to third parties.
_INTERNAL_SUFFIXES = ("local", "localhost", "localdomain", "internal", "intranet", "lan", "home", "home.arpa",
                      "corp", "private")


def is_internal_host(host: str) -> bool:
    """A private/reserved IP, a single-label name, or a name under an internal-only suffix."""
    host = (host or "").lower().strip("[]").rstrip(".")
    if not host:
        return True
    try:
        return not ipaddress.ip_address(host.split("%")[0]).is_global
    except ValueError:
        pass
    if "." not in host or any(host == s or host.endswith("." + s) for s in _INTERNAL_SUFFIXES):
        return True
    if host.endswith(".arpa"):
        return _arpa_ip(host) is None or not ipaddress.ip_address(_arpa_ip(host)).is_global
    return False


def _arpa_ip(name: str) -> Optional[str]:
    """``4.3.2.1.in-addr.arpa`` → ``1.2.3.4`` (None if it isn't a full reverse pointer)."""
    labels = name.split(".")
    try:
        if name.endswith(".in-addr.arpa") and len(labels) == 6:
            return str(ipaddress.IPv4Address(".".join(reversed(labels[:4]))))
        if name.endswith(".ip6.arpa") and len(labels) == 34:
            nibbles = "".join(reversed(labels[:32]))
            return str(ipaddress.IPv6Address(":".join(nibbles[i:i + 4] for i in range(0, 32, 4))))
    except ValueError:
        return None
    return None


def private_reason(ioc: Ioc) -> Optional[str]:
    """Why *ioc* must stay on this machine, or None if it may be looked up externally."""
    if ioc.type in ("ipv4", "ipv6"):
        return None if is_public_ip(ioc.value) else "private or reserved address"
    if ioc.type == "domain":
        return "internal host name" if is_internal_host(ioc.value) else None
    if ioc.type == "url":
        host = urlsplit(ioc.value).hostname or ""
        return "URL of a private address or internal host" if is_internal_host(host) else None
    if ioc.type == "email":
        return "address at an internal domain" if is_internal_host(ioc.value.rpartition("@")[2]) else None
    return None
