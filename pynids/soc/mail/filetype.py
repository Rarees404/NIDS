"""
Static attachment triage: what a file *really* is, and what's risky about it.

Nothing is executed, opened by another program, or written to disk.  Only
the bytes in memory are inspected.
"""
from __future__ import annotations

import io
import math
import re
import zipfile
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

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


def _pdf(data: bytes, findings: List[Dict[str, Any]], info: Dict[str, Any]) -> None:
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
    info["pdf_uris"] = sorted({u.decode("latin-1") for u in re.findall(rb"/URI\s*\(([^)]{1,2000})\)", data)})[:100]


def _ole_macros(data: bytes) -> bool:
    return b"V\x00B\x00A\x00" in data or b"_VBA_PROJECT" in data or b"Macros" in data and b"VBA" in data


def _zip(data: bytes, findings: List[Dict[str, Any]], info: Dict[str, Any]) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        entries = zf.infolist()
    except (zipfile.BadZipFile, ValueError, RuntimeError, NotImplementedError, OSError) as exc:
        info["zip_error"] = str(exc)
        return
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


def analyze_file(data: bytes, name: Optional[str], declared_type: Optional[str]) -> Dict[str, Any]:
    findings = analyze_name(name)
    info: Dict[str, Any] = {"size": len(data), "entropy": round(entropy(data), 3)}
    sniffed = sniff(data)
    info["detected"] = sniffed[0] if sniffed else None
    ext = _ext(name or "")
    if sniffed and ext and ext not in sniffed[1] and not (ext in ("txt", "csv", "log") and "text" in sniffed[0].lower()):
        sev = "high" if any(k in sniffed[0] for k in ("executable", "LNK", "ISO", "HTML", "OneNote", "disk")) else "medium"
        findings.append(_f(sev, "Extension doesn't match content", f".{ext} file is really: {sniffed[0]}"))
    label = sniffed[0] if sniffed else ""
    if label.startswith("PDF"):
        _pdf(data, findings, info)
    elif "ZIP" in label or "OOXML" in label or "OpenDocument" in label or "JAR" in label or "APK" in label:
        _zip(data, findings, info)
    elif label.startswith("OLE2"):
        if _ole_macros(data):
            findings.append(_f("high", "Legacy Office file contains VBA macros"))
        if b"Equation.3" in data or b"EQUATION" in data.upper()[:2_000_000]:
            findings.append(_f("high", "Equation Editor object", "exploited by CVE-2017-11882"))
    elif label.startswith("RTF"):
        if re.search(rb"\\objdata|\\objupdate|\\objemb", data):
            findings.append(_f("high", "RTF embeds OLE objects", "classic exploit delivery (\\objdata)"))
    elif label.startswith(("HTML", "SVG")):
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
    info["strings_sample"] = _strings(data, 200)
    return {"findings": findings, **info}
