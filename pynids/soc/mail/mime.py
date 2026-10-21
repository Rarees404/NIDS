"""
Lossless MIME parser.

Python's :mod:`email` package normalises what it parses (unfolds, re-encodes,
repairs defects) and forgets where each piece came from.  For forensics we
need the opposite: every header and every part is located by **byte offsets
into the original message**, and every decoding step is recorded, so any
claim in the analysis can be checked against the exact raw lines.

The original bytes are never modified.  Defects (missing boundaries, bad
base64, undecodable charsets, junk in a preamble) are recorded as warnings
rather than silently repaired.

The stdlib is used only for the fiddly but well-tested bits: RFC 2047
encoded words, RFC 2231 parameters, quoted-printable.
"""
from __future__ import annotations

import base64
import binascii
import bisect
import codecs
import hashlib
import quopri
import re
from dataclasses import dataclass, field
from email.header import decode_header
from email.message import Message
from typing import Any, Dict, Iterator, List, Optional, Tuple

MAX_DEPTH = 30
MAX_PARTS = 2000

# Characters that change how text *looks* without being visible: shown as
# ⟨U+XXXX⟩ markers in every view so nothing can hide in plain sight.
INVISIBLE = {
    0x200B: "ZWSP", 0x200C: "ZWNJ", 0x200D: "ZWJ", 0x2060: "WJ", 0xFEFF: "BOM", 0x00AD: "SHY",
    0x202A: "LRE", 0x202B: "RLE", 0x202C: "PDF", 0x202D: "LRO", 0x202E: "RLO",
    0x2066: "LRI", 0x2067: "RLI", 0x2068: "FSI", 0x2069: "PDI", 0x200E: "LRM", 0x200F: "RLM",
    0x061C: "ALM", 0x180E: "MVS", 0x2061: "FA", 0x2062: "IT", 0x2063: "IS", 0x2064: "IP",
}
BIDI = {0x202A, 0x202B, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068}


def visible(text: str) -> str:
    """Make control, zero-width and bidi characters visible (tabs stay tabs)."""
    out = []
    for ch in text:
        o = ord(ch)
        if o in INVISIBLE:
            out.append(f"⟨{INVISIBLE[o]}⟩")
        elif (o < 0x20 and ch != "\t") or o == 0x7F:
            out.append("\\r" if ch == "\r" else f"\\x{o:02x}")
        else:
            out.append(ch)
    return "".join(out)


def invisible_chars(text: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for ch in text:
        name = INVISIBLE.get(ord(ch))
        if name:
            counts[name] = counts.get(name, 0) + 1
    return counts


def bytes_to_text(data: bytes) -> str:
    """UTF-8 where valid; anything else shown as \\xNN — never dropped, never guessed."""
    return data.decode("utf-8", errors="backslashreplace")


def decode_words(value: str) -> Tuple[str, List[str]]:
    """RFC 2047 encoded words → text.  Returns (text, encodings seen)."""
    if "=?" not in value:
        return value, []
    encodings = sorted({m.group(1).lower() + "?" + m.group(2).upper()
                        for m in re.finditer(r"=\?([^?\s]+)\?([bBqQ])\?", value)})
    try:
        chunks = decode_header(value)
    except Exception:  # noqa: BLE001 — malformed encoded words: keep the raw value
        return value, encodings
    out = []
    for chunk, charset in chunks:
        if isinstance(chunk, bytes):
            try:
                out.append(chunk.decode(charset or "ascii", errors="replace"))
            except LookupError:
                out.append(chunk.decode("utf-8", errors="replace"))
        else:
            out.append(chunk)
    return "".join(out), encodings


@dataclass
class Header:
    name: str
    raw: bytes                      # exactly as in the message, folding included, no final EOL
    start: int
    end: int
    value: str = ""                 # unfolded raw value (no RFC 2047 decoding)
    decoded: str = ""               # RFC 2047 decoded
    encodings: List[str] = field(default_factory=list)

    def to_dict(self, lines: "LineIndex") -> Dict[str, Any]:
        return {"name": self.name, "value": visible(self.value), "decoded": visible(self.decoded),
                "encodings": self.encodings, "lines": lines.span(self.start, self.end),
                "start": self.start, "end": self.end}


@dataclass
class Part:
    id: str
    start: int
    end: int
    body_start: int
    headers: List[Header] = field(default_factory=list)
    content_type: str = "text/plain"
    params: Dict[str, str] = field(default_factory=dict)
    disposition: Optional[str] = None
    filename: Optional[str] = None
    filename_raw: Optional[str] = None
    cte: str = "7bit"
    charset: Optional[str] = None
    children: List["Part"] = field(default_factory=list)
    embedded: Optional["Part"] = None    # message/rfc822 body, parsed
    preamble: Optional[Tuple[int, int]] = None
    epilogue: Optional[Tuple[int, int]] = None
    warnings: List[str] = field(default_factory=list)
    decoded: bytes = b""
    text: Optional[str] = None
    envelope: Optional[str] = None       # mbox "From " line

    @property
    def is_multipart(self) -> bool:
        return self.content_type.startswith("multipart/")

    @property
    def is_attachment(self) -> bool:
        if self.is_multipart or self.content_type == "message/rfc822":
            return False
        if self.disposition == "attachment" or self.filename:
            return True
        return not self.content_type.startswith("text/")

    def header(self, name: str) -> Optional[Header]:
        name = name.lower()
        return next((h for h in self.headers if h.name.lower() == name), None)

    def headers_named(self, name: str) -> List[Header]:
        name = name.lower()
        return [h for h in self.headers if h.name.lower() == name]

    def walk(self) -> Iterator["Part"]:
        yield self
        for c in self.children:
            yield from c.walk()
        if self.embedded:
            yield from self.embedded.walk()

    def hashes(self) -> Dict[str, str]:
        return {"md5": hashlib.md5(self.decoded, usedforsecurity=False).hexdigest(),
                "sha1": hashlib.sha1(self.decoded, usedforsecurity=False).hexdigest(),
                "sha256": hashlib.sha256(self.decoded).hexdigest()}

    def to_dict(self, lines: "LineIndex") -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "id": self.id, "content_type": self.content_type, "params": {k: visible(v) for k, v in self.params.items()},
            "disposition": self.disposition, "filename": visible(self.filename) if self.filename else None,
            "filename_raw": self.filename_raw, "cte": self.cte, "charset": self.charset,
            "lines": lines.span(self.start, self.end), "header_lines": lines.span(self.start, self.body_start),
            "body_lines": lines.span(self.body_start, self.end),
            "raw_size": self.end - self.start, "body_size": self.end - self.body_start,
            "decoded_size": len(self.decoded), "warnings": self.warnings,
            "headers": [h.to_dict(lines) for h in self.headers],
            "children": [c.to_dict(lines) for c in self.children],
            "embedded": self.embedded.to_dict(lines) if self.embedded else None,
            "attachment": self.is_attachment, "multipart": self.is_multipart,
        }
        if self.preamble:
            d["preamble_lines"] = lines.span(*self.preamble)
        if self.epilogue:
            d["epilogue_lines"] = lines.span(*self.epilogue)
        if not self.is_multipart and self.content_type != "message/rfc822":
            d["hashes"] = self.hashes()
        if self.envelope:
            d["envelope"] = visible(self.envelope)
        return d


class LineIndex:
    """Byte offset ↔ 1-based line number."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.starts = [0] + [m.end() for m in re.finditer(b"\n", data)]
        if self.starts[-1] == len(data) and len(self.starts) > 1:
            self.starts.pop()  # no empty phantom line after a final newline

    def line_of(self, offset: int) -> int:
        return bisect.bisect_right(self.starts, offset)

    def span(self, start: int, end: int) -> List[int]:
        """[first_line, last_line] covering bytes [start, end)."""
        if end <= start:
            line = self.line_of(start)
            return [line, line - 1]  # empty
        return [self.line_of(start), self.line_of(end - 1)]

    def __len__(self) -> int:
        return len(self.starts)

    def line(self, n: int) -> bytes:
        start = self.starts[n - 1]
        end = self.starts[n] if n < len(self.starts) else len(self.data)
        return self.data[start:end]


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _lines(data: bytes, start: int, end: int) -> Iterator[Tuple[int, int, bytes]]:
    """(line_start, line_end_incl_eol, line_bytes_without_eol) over data[start:end]."""
    pos = start
    while pos < end:
        nl = data.find(b"\n", pos, end)
        stop = end if nl < 0 else nl + 1
        line = data[pos:stop]
        yield pos, stop, line.rstrip(b"\r\n")
        pos = stop


def _parse_headers(data: bytes, start: int, end: int, part: Part) -> int:
    """Fill part.headers; return the offset where the body starts."""
    pos = start
    current: Optional[List[int]] = None  # [start, end] of the header being built
    spans: List[Tuple[int, int]] = []
    body_start = end
    first = True
    for ls, le, line in _lines(data, start, end):
        if first and line.startswith(b"From ") and start == 0:
            part.envelope = bytes_to_text(line)
            first = False
            pos = le
            continue
        first = False
        if line == b"":
            body_start = le
            break
        if line[:1] in (b" ", b"\t") and current is not None:
            current[1] = le
        elif b":" in line and re.match(rb"^[\x21-\x39\x3b-\x7e]+[ \t]*:", line):
            if current is not None:
                spans.append((current[0], current[1]))
            current = [ls, le]
        else:
            # Not a header and no blank line: RFC 5322 says the body started
            # without a separator.  Record it; don't swallow the line.
            part.warnings.append(f"header block ended without a blank line (line content: "
                                 f"{visible(bytes_to_text(line))[:60]!r})")
            body_start = ls
            break
        pos = le
    else:
        body_start = end
    if current is not None:
        spans.append((current[0], current[1]))
    for hs, he in spans:
        raw = data[hs:he].rstrip(b"\r\n")
        name, _, value = raw.partition(b":")
        unfolded = re.sub(rb"\r?\n(?=[ \t])", b"", value).strip()
        text = bytes_to_text(unfolded)
        decoded, encodings = decode_words(text)
        part.headers.append(Header(name=bytes_to_text(name.strip()), raw=raw, start=hs, end=hs + len(raw),
                                   value=text, decoded=decoded, encodings=encodings))
    return body_start


def _content_info(part: Part) -> None:
    msg = Message()
    ct = part.header("content-type")
    cd = part.header("content-disposition")
    if ct:
        msg["Content-Type"] = ct.value
    if cd:
        msg["Content-Disposition"] = cd.value
    if ct:
        part.content_type = msg.get_content_type()
        if ct and "/" not in ct.value.split(";")[0]:
            part.warnings.append(f"malformed Content-Type {ct.value[:60]!r} — treated as text/plain")
        for k, v in msg.get_params(failobj=[])[1:]:
            from email.utils import collapse_rfc2231_value
            part.params[k.lower()] = collapse_rfc2231_value(v) if isinstance(v, tuple) else str(v)
    if len(part.headers_named("content-type")) > 1:
        part.warnings.append("more than one Content-Type header — mail clients disagree on which wins")
    part.charset = part.params.get("charset")
    if cd:
        part.disposition = cd.value.split(";")[0].strip().lower() or None
    raw_name = msg.get_filename()
    if raw_name:
        part.filename_raw = raw_name
        part.filename, _ = decode_words(raw_name)
    cte = part.header("content-transfer-encoding")
    part.cte = (cte.value.strip().lower() if cte else "7bit") or "7bit"


def _decode_body(part: Part, body: bytes) -> None:
    cte = part.cte
    if cte == "base64":
        cleaned = re.sub(rb"[\r\n\t ]", b"", body)
        junk = re.findall(rb"[^A-Za-z0-9+/=]", cleaned)
        if junk:
            part.warnings.append(f"{len(junk)} characters that aren't base64 were skipped while decoding")
            cleaned = re.sub(rb"[^A-Za-z0-9+/=]", b"", cleaned)
        data_part = cleaned.split(b"=", 1)[0]
        tail = cleaned[len(data_part):]
        if tail.strip(b"=") or len(tail) > 2:
            part.warnings.append("data after base64 padding (possible appended content)")
        pad = (-len(data_part)) % 4
        if pad == 3:
            part.warnings.append("truncated base64 (one stray character dropped)")
            data_part = data_part[:-1]
            pad = 0
        elif pad and not tail:
            part.warnings.append("base64 without padding")
        try:
            part.decoded = base64.b64decode(data_part + b"=" * pad)
        except (binascii.Error, ValueError) as exc:
            part.warnings.append(f"base64 could not be decoded: {exc}")
            part.decoded = body
    elif cte == "quoted-printable":
        part.decoded = quopri.decodestring(body)
        if re.search(rb"=(?![0-9A-Fa-f]{2}|\r?\n)", body):
            part.warnings.append("malformed quoted-printable escapes (kept literally)")
    elif cte in ("7bit", "8bit", "binary", ""):
        part.decoded = body
        if cte == "7bit" and re.search(rb"[\x80-\xff]", body):
            part.warnings.append("8-bit bytes in a part declared 7bit")
    elif cte in ("x-uuencode", "uuencode", "x-uue"):
        part.decoded = _uudecode(body, part)
    else:
        part.warnings.append(f"unknown Content-Transfer-Encoding {cte!r} — shown undecoded")
        part.decoded = body

    if part.content_type.startswith("text/") or (part.content_type == "application/octet-stream" and not part.filename
                                                 and part.decoded[:1] in (b"<", b"{")):
        charset = (part.charset or "us-ascii").strip().strip('"').lower()
        if charset in ("us-ascii", "ascii", ""):
            charset = "utf-8"  # mislabelled 8-bit text is common; utf-8 is a superset of ascii
        try:
            codecs.lookup(charset)
        except LookupError:
            part.warnings.append(f"unknown charset {part.charset!r} — decoded as UTF-8")
            charset = "utf-8"
        text = part.decoded.decode(charset, errors="replace")
        bad = text.count("�") - part.decoded.decode(charset, errors="ignore").count("�")
        if bad > 0:
            part.warnings.append(f"{bad} byte sequence(s) invalid in {charset} (shown as �)")
        part.text = text


def _uudecode(body: bytes, part: Part) -> bytes:
    out = bytearray()
    inside = False
    for line in body.splitlines():
        if line.startswith(b"begin "):
            inside = True
            continue
        if line.strip() == b"end":
            break
        if inside and line:
            try:
                out += binascii.a2b_uu(line)
            except binascii.Error:
                part.warnings.append("damaged uuencoded line skipped")
    return bytes(out)


def _parse_part(data: bytes, start: int, end: int, pid: str, depth: int, counter: List[int]) -> Part:
    counter[0] += 1
    part = Part(id=pid, start=start, end=end, body_start=start)
    part.body_start = _parse_headers(data, start, end, part)
    _content_info(part)
    if depth >= MAX_DEPTH or counter[0] >= MAX_PARTS:
        part.warnings.append("nesting too deep / too many parts — not parsed further")
        part.decoded = data[part.body_start:end]
        return part

    if part.is_multipart:
        boundary = part.params.get("boundary")
        if not boundary:
            part.warnings.append("multipart without a boundary — treated as a single part")
        else:
            _split_multipart(data, part, boundary.encode("utf-8", "replace"), depth, counter)
            return part
    body = data[part.body_start:end]
    if part.content_type in ("message/rfc822", "message/global") and part.cte not in ("base64", "quoted-printable"):
        part.embedded = _parse_part(data, part.body_start, end, pid + ".m", depth + 1, counter)
        part.decoded = body
        return part
    _decode_body(part, body)
    return part


def _split_multipart(data: bytes, part: Part, boundary: bytes, depth: int, counter: List[int]) -> None:
    dash = b"--" + boundary
    delimiters: List[Tuple[int, int, bool]] = []  # (line_start, line_end, is_close)
    for ls, le, line in _lines(data, part.body_start, part.end):
        if not line.startswith(dash):
            continue
        rest = line[len(dash):].rstrip(b" \t")
        if rest == b"":
            delimiters.append((ls, le, False))
        elif rest == b"--":
            delimiters.append((ls, le, True))
            break
    if not delimiters:
        part.warnings.append("boundary never appears — the body couldn't be split into parts")
        _decode_body(part, data[part.body_start:part.end])
        return

    def before_eol(pos: int) -> int:
        """The CRLF preceding a delimiter belongs to the delimiter."""
        if pos >= 2 and data[pos - 2:pos] == b"\r\n":
            return pos - 2
        if pos >= 1 and data[pos - 1:pos] == b"\n":
            return pos - 1
        return pos

    first_ls = delimiters[0][0]
    if data[part.body_start:first_ls].strip():
        part.preamble = (part.body_start, before_eol(first_ls))
        part.warnings.append("text before the first part (preamble) — not shown by mail clients")
    n = 0
    for i, (ls, le, close) in enumerate(delimiters):
        if close:
            if data[le:part.end].strip():
                part.epilogue = (le, part.end)
                part.warnings.append("text after the closing boundary (epilogue) — not shown by mail clients")
            break
        nxt = delimiters[i + 1][0] if i + 1 < len(delimiters) else part.end
        child_end = before_eol(nxt) if i + 1 < len(delimiters) else part.end
        n += 1
        part.children.append(_parse_part(data, le, max(le, child_end), f"{part.id}.{n}", depth + 1, counter))
    if not delimiters[-1][2]:
        part.warnings.append("closing boundary missing (message may be truncated)")


def parse(data: bytes) -> Part:
    """Parse a whole message.  The root part has id ``1``."""
    return _parse_part(data, 0, len(data), "1", 0, [0])


def eol_stats(data: bytes) -> Dict[str, int]:
    crlf = data.count(b"\r\n")
    return {"crlf": crlf, "lf": data.count(b"\n") - crlf, "bare_cr": data.count(b"\r") - crlf,
            "nul": data.count(b"\x00")}
