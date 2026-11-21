"""
Static attachment triage: what a file *really* is, and what's risky about it.

Nothing is executed, opened by another program, or written to disk.  Only
the bytes in memory are inspected.

Looking inside
--------------
* **PDF** — compressed object streams are inflated, so links and active
  content hidden inside them are found, not just what sits in plain view.
* **Archives** — ZIP, gzip and tar members are listed and the interesting
  ones triaged in turn (an archive in an archive, a document in an
  archive), to a fixed depth and size.
* **Indicators** — URLs, email addresses and public IP addresses found in
  the content (document relationships, PDF streams, strings of a binary or
  shortcut) are returned as ``urls`` / ``iocs``.
"""
from __future__ import annotations

import hashlib
import io
import math
import re
import tarfile
import zipfile
import zlib
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from ..ioc import extract, is_public_ip

MAX_DEPTH = 3                      # archive-in-archive levels followed
MAX_INNER_FILES = 20               # members triaged per archive
MAX_INNER_SIZE = 20 * 1024 * 1024  # largest member read
MAX_IOC_TEXT = 2 * 1024 * 1024     # content scanned for indicators per file

# (offset, magic, label, canonical extensions)
_MAGIC: List[Tuple[int, bytes, str, Tuple[str, ...]]] = [
    (0, b"%PDF-", "PDF document", ("pdf",)),
    (0, b"PK\x03\x04", "ZIP archive", ("zip",)),
    (0, b"PK\x05\x06", "ZIP archive (empty)", ("zip",)),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 compound file (legacy Office / MSI / MSG)", ("doc", "xls", "ppt", "msi", "msg")),
    (0, b"Rar!\x1a\x07", "RAR archive", ("rar",)),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip archive", ("7z",)),
    (0, b"\x1f\x8b", "gzip", ("gz", "tgz")),
    (0, b"BZh", "bzip2", ("bz2",)),
    (0, b"\xfd7zXZ\x00", "xz", ("xz",)),
    (0, b"MSCF", "Microsoft Cabinet", ("cab",)),
    (0, b"MZ", "Windows executable (PE)", ("exe", "dll", "scr", "sys", "cpl", "ocx", "com")),
    (0, b"\x7fELF", "Linux executable (ELF)", ("elf", "so", "bin")),
    (0, b"\xcf\xfa\xed\xfe", "macOS executable (Mach-O 64-bit)", ("dylib", "bin")),
    (0, b"\xce\xfa\xed\xfe", "macOS executable (Mach-O)", ("dylib", "bin")),
    (0, b"\xca\xfe\xba\xbe", "macOS universal binary / Java class", ("class", "bin")),
    (0, b"L\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut (LNK)", ("lnk",)),
    (0, b"{\\rt", "RTF document", ("rtf", "doc")),
    (0, b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d", "OneNote section", ("one",)),
    (0, b"conectix", "Virtual hard disk (VHD)", ("vhd",)),
    (0, b"vhdxfile", "Virtual hard disk (VHDX)", ("vhdx",)),
    (0, b"koly", "Apple disk image (DMG)", ("dmg",)),
    (0, b"\x89PNG\r\n\x1a\n", "PNG image", ("png",)),
    (0, b"\xff\xd8\xff", "JPEG image", ("jpg", "jpeg")),
    (0, b"GIF8", "GIF image", ("gif",)),
    (0, b"BM", "BMP image", ("bmp",)),
    (0, b"RIFF", "RIFF (WebP / WAV / AVI)", ("webp", "wav", "avi")),
    (0, b"II*\x00", "TIFF image", ("tif", "tiff")),
    (0, b"MM\x00*", "TIFF image", ("tif", "tiff")),
    (0, b"BEGIN:VCALENDAR", "Calendar invite (ICS)", ("ics",)),
    (0, b"\x78\x9f\x3e\x22", "TNEF (winmail.dat)", ("dat",)),
    (0x8001, b"CD001", "ISO disk image", ("iso", "img")),
]

DANGEROUS_EXT = {
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "ps1", "psm1",
    "msi", "msp", "cpl", "dll", "jar", "lnk", "iso", "img", "vhd", "vhdx", "one", "reg", "inf", "scf",
    "chm", "appx", "msix", "application", "gadget", "url", "website", "xll", "library-ms", "settingcontent-ms",
    "app", "command", "pkg", "dmg", "sh", "apk", "html", "htm", "svg", "xhtml", "shtml",
}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam", "potm", "xlsb"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tgz", "bz2", "xz", "cab", "ace", "arj", "lzh", "tar", "z"}
_DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "png", "odt", "csv"}


def sniff(data: bytes) -> Optional[Tuple[str, Tuple[str, ...]]]:
    for off, magic, label, exts in _MAGIC:
        if data[off:off + len(magic)] == magic:
            if label.startswith("ZIP"):
                return _zip_flavour(data) or (label, exts)
            return label, exts
    if data[257:262] == b"ustar":
        return "tar archive", ("tar",)
    head = data[:2048].lstrip().lower()
    if head.startswith((b"<!doctype html", b"<html")) or b"<script" in head[:512]:
        return "HTML document", ("html", "htm")
    if head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in head):
        return "SVG image (can contain scripts)", ("svg",)
    if head.startswith(b"<?xml"):
        return "XML document", ("xml",)
    return None


def _zip_flavour(data: bytes) -> Optional[Tuple[str, Tuple[str, ...]]]:
    try:
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()
    except (zipfile.BadZipFile, ValueError, RuntimeError, NotImplementedError, OSError):
        return None
    s = set(names)
    if "word/document.xml" in s:
        return "Word document (OOXML)", ("docx", "docm", "dotx", "dotm")
    if "xl/workbook.xml" in s or "xl/workbook.bin" in s:
        return "Excel workbook (OOXML)", ("xlsx", "xlsm", "xlsb", "xltx", "xltm", "xlam")
    if "ppt/presentation.xml" in s:
        return "PowerPoint presentation (OOXML)", ("pptx", "pptm", "potx", "ppsx")
    if "mimetype" in s and any(n.startswith("META-INF") for n in names):
        return "OpenDocument / EPUB / JAR", ("odt", "ods", "odp", "epub", "jar")
    if "AndroidManifest.xml" in s:
        return "Android app (APK)", ("apk",)
    if "META-INF/MANIFEST.MF" in s:
        return "Java archive (JAR)", ("jar",)
    return None


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data[:4 * 1024 * 1024])
    n = sum(counts.values())
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _strings(data: bytes, limit: int = 300) -> List[str]:
    out = [m.group(0).decode("ascii") for m in re.finditer(rb"[\x20-\x7e]{6,}", data[:8 * 1024 * 1024])]
    out += [m.group(0).decode("utf-16-le", "ignore") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){6,}", data[:8 * 1024 * 1024])]
    return out[:limit]


_PDF_KEYS = ["/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile", "/RichMedia", "/XFA",
             "/AcroForm", "/URI", "/SubmitForm", "/GoToR", "/ObjStm", "/Encrypt"]
_PDF_RISKY = {"/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile", "/RichMedia", "/XFA", "/GoToR"}


_PDF_STREAM = re.compile(rb"stream\r?\n(.*?)endstream", re.DOTALL)


def _pdf_inflate(data: bytes, max_streams: int = 400, max_total: int = 16 * 1024 * 1024) -> bytes:
    """
    The contents of the PDF's Flate-compressed streams, concatenated.

    Modern PDFs keep most objects — link annotations and JavaScript actions
    included — inside compressed object streams, where a scan of the raw
    file finds nothing.
    """
    out: List[bytes] = []
    total = 0
    for i, m in enumerate(_PDF_STREAM.finditer(data)):
        if i >= max_streams or total >= max_total:
            break
        try:
            chunk = zlib.decompressobj().decompress(m.group(1), 2 * 1024 * 1024)
        except zlib.error:
            continue
        if chunk:
            out.append(chunk)
            total += len(chunk)
    return b"\n".join(out)


def _pdf(data: bytes, findings: List[Dict[str, Any]], info: Dict[str, Any]) -> bytes:
    inflated = _pdf_inflate(data)
    if inflated:
        info["pdf_streams_inflated"] = len(inflated)
    # Everything below looks at the file as stored *and* at what its streams hold.
    data = data + b"\n" + inflated
    counts = {k: len(re.findall(re.escape(k.encode()) + rb"(?![A-Za-z])", data)) for k in _PDF_KEYS}
    # Names can be hex-escaped to dodge keyword scans (/J#61vaScript).
    obfuscated = len(re.findall(rb"/[A-Za-z]*#[0-9A-Fa-f]{2}", data))
    info["pdf_keywords"] = {k: v for k, v in counts.items() if v}
    if obfuscated:
        info["pdf_keywords"]["hex-escaped names"] = obfuscated
        findings.append(_f("high", "PDF hides keywords with hex escapes", "a common trick to evade scanners"))
    risky = [k for k in _PDF_RISKY if counts.get(k)]
    if risky:
        sev = "high" if {"/JavaScript", "/JS", "/Launch", "/EmbeddedFile"} & set(risky) else "medium"
        findings.append(_f(sev, "PDF contains active content", ", ".join(sorted(risky))))
    uris = {u.decode("latin-1") for u in re.findall(rb"/URI\s*\(([^)]{1,2000})\)", data)}
    for hexed in re.findall(rb"/URI\s*<([0-9A-Fa-f\s]{8,4000})>", data):  # /URI <68747470…>
        try:
            uris.add(bytes.fromhex(hexed.decode("ascii")).decode("latin-1"))
        except ValueError:
            pass
    info["pdf_uris"] = sorted(uris)[:100]
    return inflated


def _ole_macros(data: bytes) -> bool:
    return b"V\x00B\x00A\x00" in data or b"_VBA_PROJECT" in data or b"Macros" in data and b"VBA" in data


# Text-like members of a document or archive worth scanning for indicators.
_TEXT_MEMBER_EXT = {"rels", "xml", "txt", "htm", "html", "js", "jse", "vbs", "vbe", "wsf", "hta", "ps1", "bat",
                    "cmd", "sh", "url", "json", "csv", "svg", "iqy", "slk"}
_OFFICE_FLAVOURS = ("OOXML", "OpenDocument")


def _nested(inner: bytes, name: str, depth: int, findings: List[Dict[str, Any]],
            info: Dict[str, Any]) -> None:
    """Triage one member of an archive and fold the result into the parent's."""
    tri = analyze_file(inner, name.rsplit("/", 1)[-1], None, _depth=depth + 1)
    info.setdefault("nested", []).append({
        "name": name, "size": len(inner), "detected": tri.get("detected"),
        "sha256": hashlib.sha256(inner).hexdigest(),
        "findings": tri["findings"], "nested": tri.get("nested"),
    })
    for f in tri["findings"]:
        findings.append(_f(f["severity"], f"Inside the archive — {f['title']}",
                           f"{name}" + (f": {f['detail']}" if f["detail"] else "")))
    for key in ("urls", "iocs"):
        for item in tri.get(key) or []:
            if item not in info.setdefault("_" + key, []):
                info["_" + key].append(item)
    for u in tri.get("pdf_uris") or []:
        if u not in info.setdefault("_urls", []):
            info["_urls"].append(u)


def _gzip(data: bytes, name: Optional[str], depth: int, findings: List[Dict[str, Any]],
          info: Dict[str, Any]) -> None:
    try:
        inner = zlib.decompressobj(zlib.MAX_WBITS | 16).decompress(data, MAX_INNER_SIZE)
    except zlib.error as exc:
        info["gzip_error"] = str(exc)
        return
    if not inner or depth >= MAX_DEPTH:
        return
    stem = (name or "content.gz")
    stem = stem[:-3] if stem.lower().endswith(".gz") else stem[:-4] + ".tar" if stem.lower().endswith(".tgz") else stem
    _nested(inner, stem, depth, findings, info)


def _tar(data: bytes, depth: int, findings: List[Dict[str, Any]], info: Dict[str, Any]) -> None:
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
        members = [m for m in tf.getmembers()[:500]]
    except (tarfile.TarError, EOFError, OSError, ValueError) as exc:
        info["tar_error"] = str(exc)
        return
    info["archive"] = [{"name": m.name, "size": m.size, "compressed": m.size, "encrypted": False}
                       for m in members]
    inner_names = [m.name for m in members if _ext(m.name) in DANGEROUS_EXT]
    if inner_names:
        findings.append(_f("high", "Archive contains executable / script files", ", ".join(inner_names[:10])))
    if depth >= MAX_DEPTH:
        return
    done = 0
    for m in members:
        if done >= MAX_INNER_FILES or not m.isfile() or not 0 < m.size <= MAX_INNER_SIZE:
            continue
        try:
            fh = tf.extractfile(m)
            inner = fh.read(MAX_INNER_SIZE) if fh else b""
        except (tarfile.TarError, OSError, KeyError):
            continue
        done += 1
        _nested(inner, m.name, depth, findings, info)


def _zip(data: bytes, findings: List[Dict[str, Any]], info: Dict[str, Any], depth: int = 0,
         office: bool = False) -> str:
    """List a ZIP container; returns the text of its text-like members (for indicators)."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        entries = zf.infolist()
    except (zipfile.BadZipFile, ValueError, RuntimeError, NotImplementedError, OSError) as exc:
        info["zip_error"] = str(exc)
        return ""
    listing = []
    for e in entries[:500]:
        enc = bool(e.flag_bits & 0x1)
        listing.append({"name": e.filename, "size": e.file_size, "compressed": e.compress_size, "encrypted": enc})
    info["archive"] = listing
    names = [e.filename for e in entries]
    if any(e["encrypted"] for e in listing):
        findings.append(_f("high", "Password-protected archive",
                           "encryption stops mail scanners from looking inside; the password is usually in the email body"))
    inner = [n for n in names if _ext(n) in DANGEROUS_EXT]
    if inner:
        findings.append(_f("high", "Archive contains executable / script files", ", ".join(inner[:10])))
    if any(n.lower() == "word/vbaproject.bin" or n.lower().endswith("vbaproject.bin") for n in names):
        findings.append(_f("high", "Office document contains VBA macros", "vbaProject.bin present"))
    if any("externalLink" in n or n.endswith(".rels") and b"TargetMode=\"External\"" in _read(zf, n) for n in names[:200]):
        info["external_relationships"] = True
        findings.append(_f("medium", "Office document references external content",
                           "remote templates / OLE links can fetch payloads when opened"))
    ratio = sum(e.file_size for e in entries) / max(1, len(data))
    if ratio > 100:
        findings.append(_f("medium", "Very high compression ratio", f"{ratio:.0f}× — possible zip bomb or padded payload"))

    # Look inside: text members for indicators, the rest triaged as files of
    # their own.  An Office document is itself a ZIP, so only its embedded
    # objects are opened, not every XML part.
    text: List[str] = []
    budget = MAX_IOC_TEXT
    triaged = 0
    for e in entries[:500]:
        if e.is_dir() or e.flag_bits & 0x1 or not 0 < e.file_size <= MAX_INNER_SIZE:
            continue
        ext = _ext(e.filename)
        if ext in _TEXT_MEMBER_EXT and budget > 0:
            chunk = _read(zf, e.filename)[:budget]
            budget -= len(chunk)
            text.append(chunk.decode("utf-8", "replace"))
            if office or ext in ("rels", "xml"):
                continue
        if office and "embeddings/" not in e.filename.lower() and ext not in ("bin", "ole"):
            continue
        if ext in ("png", "jpg", "jpeg", "gif", "bmp", "emf", "wmf", "ttf", "otf", "woff", "woff2", "css"):
            continue
        if depth >= MAX_DEPTH or triaged >= MAX_INNER_FILES:
            continue
        try:
            with zf.open(e.filename) as fh:
                inner = fh.read(MAX_INNER_SIZE)
        except Exception:  # noqa: BLE001 — unsupported compression, bad CRC …
            continue
        triaged += 1
        _nested(inner, e.filename, depth, findings, info)
    return "\n".join(text)


def _read(zf: zipfile.ZipFile, name: str) -> bytes:
    try:
        with zf.open(name) as fh:
            return fh.read(256 * 1024)
    except Exception:  # noqa: BLE001
        return b""


def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _f(severity: str, title: str, detail: str = "") -> Dict[str, Any]:
    return {"severity": severity, "title": title, "detail": detail}


def analyze_name(name: Optional[str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not name:
        return findings
    if any(ord(c) in (0x202E, 0x202D, 0x2066, 0x2067, 0x2068) for c in name):
        findings.append(_f("high", "File name uses right-to-left override",
                           "the name is displayed reversed to disguise the real extension"))
    parts = name.lower().rsplit(".", 2)
    ext = _ext(name)
    if len(parts) == 3 and parts[1] in _DOC_EXT and ext in DANGEROUS_EXT:
        findings.append(_f("high", "Double extension", f"looks like .{parts[1]} but is .{ext}"))
    elif ext in DANGEROUS_EXT:
        findings.append(_f("high" if ext not in ("html", "htm", "svg", "dmg", "pkg") else "medium",
                           f"Risky file type .{ext}", "can run code or open an attacker's page when double-clicked"))
    if ext in MACRO_EXT:
        findings.append(_f("high", f"Macro-enabled Office file .{ext}"))
    if re.search(r"\s{5,}", name):
        findings.append(_f("medium", "File name padded with spaces", "pushes the real extension out of view"))
    return findings


# Hosts that appear in every document's boilerplate (XML namespaces, colour
# profiles, code-signing infrastructure) and say nothing about its author.
_BOILERPLATE_HOSTS = (
    "schemas.openxmlformats.org", "schemas.microsoft.com", "www.w3.org", "purl.org", "ns.adobe.com",
    "schemas.xmlsoap.org", "www.iec.ch", "iptc.org", "www.aiim.org", "www.npes.org", "www.color.org",
    "ns.useplus.org", "xmlns.com", "www.adobe.com", "openoffice.org", "relaxng.org", "dublincore.org",
    "www.pdfa.org", "cipa.jp", "java.sun.com", "xml.apache.org", "www.oasis-open.org",
)
_SHELL_IN_SHORTCUT = re.compile(
    r"(?i)\b(?:powershell|pwsh|cmd(?:\.exe)?\s*/[ck]|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin"
    r"|curl|msiexec|forfiles|conhost)\b.{0,200}")


def _boilerplate(host: str) -> bool:
    host = host.lower()
    return (any(host == h or host.endswith("." + h) for h in _BOILERPLATE_HOSTS)
            or host.startswith(("ocsp.", "crl.", "crl3.", "crl4.", "cacerts.", "crt.")))


def _content_iocs(text: str, info: Dict[str, Any]) -> None:
    """URLs, email addresses and public IPs found in a file's content."""
    urls: List[str] = list(info.pop("_urls", []))
    iocs: List[Dict[str, str]] = list(info.pop("_iocs", []))
    for u in info.get("pdf_uris") or []:
        if u not in urls:
            urls.append(u)
    for ioc in extract(text[:MAX_IOC_TEXT], limit=200) if text else ():
        if ioc.type == "url":
            host = urlsplit(ioc.value).hostname or ""
            if host and not _boilerplate(host) and not urlsplit(ioc.value).path.lower().endswith((".crl", ".crt", ".cer")) \
                    and ioc.value not in urls:
                urls.append(ioc.value)
        elif ioc.type == "email" or (ioc.type in ("ipv4", "ipv6") and is_public_ip(ioc.value)):
            item = {"type": ioc.type, "value": ioc.value}
            if item not in iocs:
                iocs.append(item)
    if urls:
        info["urls"] = urls[:200]
    if iocs:
        info["iocs"] = iocs[:200]


def analyze_file(data: bytes, name: Optional[str], declared_type: Optional[str],
                 _depth: int = 0) -> Dict[str, Any]:
    findings = analyze_name(name)
    info: Dict[str, Any] = {"size": len(data), "entropy": round(entropy(data), 3)}
    sniffed = sniff(data)
    info["detected"] = sniffed[0] if sniffed else None
    content = ""   # text in which indicators are looked for
    ext = _ext(name or "")
    if sniffed and ext and ext not in sniffed[1] and not (ext in ("txt", "csv", "log") and "text" in sniffed[0].lower()):
        sev = "high" if any(k in sniffed[0] for k in ("executable", "LNK", "ISO", "HTML", "OneNote", "disk")) else "medium"
        findings.append(_f(sev, "Extension doesn't match content", f".{ext} file is really: {sniffed[0]}"))
    label = sniffed[0] if sniffed else ""
    if label.startswith("PDF"):
        inflated = _pdf(data, findings, info)
        content = (data[:MAX_IOC_TEXT] + b"\n" + inflated[:MAX_IOC_TEXT]).decode("latin-1")
    elif "ZIP" in label or "OOXML" in label or "OpenDocument" in label or "JAR" in label or "APK" in label:
        content = _zip(data, findings, info, _depth, office=any(k in label for k in _OFFICE_FLAVOURS))
    elif label == "gzip":
        _gzip(data, name, _depth, findings, info)
    elif label == "tar archive":
        _tar(data, _depth, findings, info)
    elif label in ("RAR archive", "7-Zip archive", "Microsoft Cabinet", "bzip2", "xz"):
        info["note"] = "this archive format can't be opened here — its contents were not examined"
        findings.append(_f("info", f"{label}: contents not examined",
                           "only ZIP, gzip and tar archives are looked into"))
    elif label.startswith("OLE2"):
        if _ole_macros(data):
            findings.append(_f("high", "Legacy Office file contains VBA macros"))
        if b"Equation.3" in data or b"EQUATION" in data.upper()[:2_000_000]:
            findings.append(_f("high", "Equation Editor object", "exploited by CVE-2017-11882"))
    elif label.startswith("RTF"):
        if re.search(rb"\\objdata|\\objupdate|\\objemb", data):
            findings.append(_f("high", "RTF embeds OLE objects", "classic exploit delivery (\\objdata)"))
    elif label.startswith(("HTML", "SVG")):
        content = data[:MAX_IOC_TEXT].decode("utf-8", "replace")
        low = data.lower()
        hits = [k for k in (b"atob(", b"blob(", b"mssaveoropenblob", b"createobjecturl", b"download=", b"eval(",
                            b"document.write", b"window.location", b"fromcharcode") if k in low]
        if hits:
            findings.append(_f("high", "Script that builds or redirects content (HTML smuggling)",
                               ", ".join(h.decode() for h in hits)))
        if b"<form" in low and (b"password" in low or b"passwd" in low):
            findings.append(_f("high", "Local credential-harvesting form", "an HTML file with a password field"))
    elif "executable" in label or "LNK" in label or "ISO" in label or "disk" in label.lower():
        findings.append(_f("high", f"{label}", "runs code (or mounts a disk with code) when opened"))
    if info["entropy"] > 7.5 and label not in ("ZIP archive", "JPEG image", "PNG image", "gzip", "7-Zip archive",
                                                "RAR archive") and "OOXML" not in label and len(data) > 4096:
        info["note"] = "high entropy — compressed or encrypted content"
    strings = _strings(data, 2000)
    info["strings_sample"] = strings[:200]
    if "LNK" in label:
        cmd = next((m.group(0) for s in strings for m in [_SHELL_IN_SHORTCUT.search(s)] if m), None)
        if cmd:
            findings.append(_f("high", "Shortcut launches a command interpreter", cmd[:200]))
    if not content and not label.startswith(("PNG", "JPEG", "GIF", "BMP", "TIFF", "RIFF")):
        # Binaries, legacy Office files, shortcuts, plain text: their readable strings.
        content = "\n".join(strings) if sniffed else data[:MAX_IOC_TEXT].decode("utf-8", "replace")
    _content_iocs(content, info)
    return {"findings": findings, **info}
