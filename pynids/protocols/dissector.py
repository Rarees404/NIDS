"""
Application-layer protocol dissection for PyNIDS.

The ``dissect()`` function inspects raw packet metadata and returns a
supplementary ``layer7`` dictionary containing parsed application-layer
fields.  Downstream detectors and rule engines can reference these
fields for rich, protocol-aware matching.

Supported protocols
-------------------
HTTP/1.x  — request line, headers, SQLi/XSS heuristics
DNS       — query/response, answer records, entropy of the query name
TLS       — ClientHello SNI / ALPN / ECH / offered versions and JA3, recognised on
            any TCP port and reassembled across segments; ServerHello (negotiated
            version, cipher, JA3S) and, up to TLS 1.2, the server certificate
QUIC      — Initial-packet decryption to recover the ClientHello SNI
SSH       — banner / version string
SMTP      — EHLO, MAIL FROM, RCPT TO commands
DHCP      — message type, server, router, DNS servers, client host name

HTTP requests whose headers (or short body) span several TCP segments are
buffered and parsed whole, like the TLS handshakes.
"""
from __future__ import annotations

import hashlib
import math
import re
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, unquote_plus

from .quic_crypto import QuicClientHelloAssembler, decrypt_client_initial
from .stealth import (
    is_quic,
    is_stun,
    is_websocket_upgrade,
    is_beacon_request,
    parse_quic,
    parse_stun,
)


# ---------------------------------------------------------------------------
# Handshake reassembly state
# ---------------------------------------------------------------------------

class _TlsRecordAssembler:
    """
    Buffer a TLS ClientHello record that spans several TCP segments.

    Post-quantum key shares push modern ClientHellos past one MSS, and
    Chrome randomises extension order, so the SNI is often in the second
    segment.  Segments are assumed to arrive in order (true for the
    client→server first flight in practice).
    """

    def __init__(self, max_entries: int = 4096, ttl: float = 10.0) -> None:
        self._max = max_entries
        self._ttl = ttl
        self._buffers: "OrderedDict[tuple, Tuple[float, int, bytearray]]" = OrderedDict()

    def feed(self, key: tuple, payload: bytes) -> Optional[bytes]:
        """Return a complete ClientHello record, or None while still buffering."""
        now = time.monotonic()
        while self._buffers:
            k, (ts, _, _) = next(iter(self._buffers.items()))
            if now - ts <= self._ttl:
                break
            self._buffers.popitem(last=False)

        if key in self._buffers:
            _, needed, buf = self._buffers.pop(key)
            buf += payload
            if len(buf) >= needed:
                return bytes(buf[:needed])
            self._buffers[key] = (now, needed, buf)
            return None

        if len(payload) >= 6 and payload[0] == 0x16 and payload[5] == 0x01:
            needed = 5 + int.from_bytes(payload[3:5], "big")
            if len(payload) >= needed:
                return payload
            if needed <= 16389:
                self._buffers[key] = (now, needed, bytearray(payload))
                while len(self._buffers) > self._max:
                    self._buffers.popitem(last=False)
            return None
        return payload

    def pending(self, key: tuple) -> bool:
        return key in self._buffers


class _TlsServerFlight:
    """
    Buffer the server's first flight (ServerHello … Certificate) across TCP
    segments and parse it once enough has arrived.

    The flight is finished when the certificate has been read, when the
    server moves on without one (resumed session, TLS 1.3 — where the
    certificate is encrypted), or when ``max_bytes`` have been buffered.
    Segments are assumed to arrive in order, as for the ClientHello.
    """

    def __init__(self, max_entries: int = 4096, ttl: float = 10.0, max_bytes: int = 32768) -> None:
        self._max = max_entries
        self._ttl = ttl
        self._max_bytes = max_bytes
        self._buffers: "OrderedDict[tuple, Tuple[float, bytearray]]" = OrderedDict()

    def pending(self, key: tuple) -> bool:
        return key in self._buffers

    def feed(self, key: tuple, payload: bytes, now_epoch: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Parsed server-side fields once the flight is complete, None while buffering."""
        now = time.monotonic()
        while self._buffers:
            k, (ts, _) = next(iter(self._buffers.items()))
            if now - ts <= self._ttl:
                break
            self._buffers.popitem(last=False)

        entry = self._buffers.pop(key, None)
        buf = entry[1] if entry else bytearray()
        buf += payload
        info, done = _parse_tls_server_flight(bytes(buf), now_epoch)
        if done or len(buf) >= self._max_bytes:
            return info
        self._buffers[key] = (entry[0] if entry else now, buf)
        while len(self._buffers) > self._max:
            self._buffers.popitem(last=False)
        return None


class _HttpRequestAssembler:
    """
    Buffer an HTTP request until its header block (and a short body) is whole.

    A request line or header split across TCP segments would otherwise never
    be parsed: neither half is a valid request on its own, which is exactly
    what an attacker splitting ``UNION SELECT`` across two packets relies on.

    With TCP sequence numbers (live capture, PCAP replay) retransmitted
    segments are ignored and a gap abandons the buffer; without them segments
    are taken in arrival order.
    """

    _START = re.compile(rb"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) \S")
    _CONTENT_LENGTH = re.compile(rb"\r\ncontent-length:[ \t]*(\d{1,12})", re.IGNORECASE)

    def __init__(self, max_entries: int = 2048, ttl: float = 10.0, max_head: int = 16384) -> None:
        self._max = max_entries
        self._ttl = ttl
        self._max_head = max_head
        # key -> [started, buffer, next expected seq or None]
        self._buffers: "OrderedDict[tuple, list]" = OrderedDict()

    def pending(self, key: tuple) -> bool:
        return key in self._buffers

    def starts_request(self, payload: bytes) -> bool:
        return self._START.match(payload) is not None

    def _complete(self, buf: bytes) -> bool:
        end = buf.find(b"\r\n\r\n")
        if end < 0:
            return len(buf) >= self._max_head
        m = self._CONTENT_LENGTH.search(buf, 0, end + 2)
        if not m:
            return True
        wanted = min(int(m.group(1)), _HTTP_BODY_SCAN_LIMIT)
        return len(buf) - (end + 4) >= wanted

    def feed(self, key: tuple, payload: bytes, seq: Optional[int] = None) -> Optional[bytes]:
        """The whole request head once it has arrived, None while still buffering."""
        now = time.monotonic()
        while self._buffers:
            k, entry = next(iter(self._buffers.items()))
            if now - entry[0] <= self._ttl:
                break
            self._buffers.popitem(last=False)

        entry = self._buffers.pop(key, None)
        if entry is not None:
            started, buf, expected = entry
            if seq is not None and expected is not None:
                delta = (seq - expected) & 0xFFFFFFFF
                if delta >= 0x80000000:          # retransmission of bytes already buffered
                    self._buffers[key] = entry
                    return None
                if delta:                        # a hole: the rest cannot be trusted
                    entry = None
            if entry is not None:
                buf += payload
                if self._complete(bytes(buf)):
                    return bytes(buf)
                entry[2] = None if seq is None else (seq + len(payload)) & 0xFFFFFFFF
                self._buffers[key] = entry
                return None

        if self._complete(payload):
            return payload
        self._buffers[key] = [now, bytearray(payload),
                              None if seq is None else (seq + len(payload)) & 0xFFFFFFFF]
        while len(self._buffers) > self._max:
            self._buffers.popitem(last=False)
        return None


_TLS_ASSEMBLER = _TlsRecordAssembler()
_TLS_SERVER_FLIGHT = _TlsServerFlight()
_HTTP_ASSEMBLER = _HttpRequestAssembler()
_QUIC_ASSEMBLER = QuicClientHelloAssembler()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def dissect(meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich *meta* with application-layer information.

    Args:
        meta: Packet metadata produced by the sniffer (src/dst IPs, ports,
              payload_bytes, protocol, etc.).

    Returns:
        A ``layer7`` dict which may contain keys such as ``app_proto``,
        ``http``, ``dns``, ``tls``, ``ssh``, ``smtp``, ``stun``, or ``quic``.
    """
    dst_port: int = meta.get("dst_port") or 0
    src_port: int = meta.get("src_port") or 0
    payload: bytes = meta.get("payload_bytes") or b""
    proto: str = meta.get("protocol") or ""

    if not payload:
        return {}

    layer7: Dict[str, Any] = {}

    # --- Port-independent stealth-protocol probes ---------------------------
    # WebRTC's STUN/TURN and HTTP/3's QUIC routinely fly over any UDP port
    # (3478, 19302, 50000+, 443 for QUIC).  We probe by magic-cookie /
    # header bits before falling back to port-based routing.
    if proto == "udp":
        if is_stun(payload):
            stun = parse_stun(payload)
            if stun:
                layer7["app_proto"] = "stun"
                layer7["stun"] = stun
                return layer7
        if is_quic(payload):
            quic = parse_quic(payload)
            if quic:
                if quic.get("packet_type") == "Initial":
                    _decrypt_quic_sni(meta, payload, quic)
                layer7["app_proto"] = "quic"
                layer7["quic"] = quic
                return layer7

    # Plaintext HTTP requests are recognised by their request line on any
    # TCP port (dev servers, proxies, malware on 443); responses still rely
    # on the well-known ports below.
    http_request = False
    if proto == "tcp":
        http_key = (meta.get("src_ip"), src_port, meta.get("dst_ip"), dst_port)
        if _HTTP_ASSEMBLER.pending(http_key) or _HTTP_ASSEMBLER.starts_request(payload):
            head = _HTTP_ASSEMBLER.feed(http_key, payload, meta.get("tcp_seq"))
            if head is None:
                # More of the request is on its way: parsed when it is whole.
                return {"app_proto": "http", "http": {"partial": True}}
            if _HTTP_REQUEST_LINE_RE.match(head):
                http_request = True
                if head is not payload:
                    layer7["reassembled"] = True
                payload = head

    # TLS is recognised by its handshake bytes, whatever the port: command
    # servers and tunnels favour 8080, 4443, 9001 … as much as 443.
    tls_key = (meta.get("src_ip"), src_port, meta.get("dst_ip"), dst_port)
    tls_handshake = proto == "tcp" and not http_request and (
        _is_tls_hello(payload, 0x01) or _is_tls_hello(payload, 0x02)
        or _TLS_ASSEMBLER.pending(tls_key) or _TLS_SERVER_FLIGHT.pending(tls_key))

    if tls_handshake:
        layer7["app_proto"] = "tls"
        layer7["tls"] = _dissect_tls(tls_key, payload, proto, meta.get("timestamp"))

    elif (dst_port == 53 or src_port == 53) and not http_request:
        layer7["app_proto"] = "dns"
        layer7["dns"] = _parse_dns(payload, proto)

    elif http_request or dst_port in _HTTP_PORTS or src_port in _HTTP_PORTS:
        layer7["app_proto"] = "http"
        http_info = _parse_http(payload)
        layer7["http"] = http_info
        if is_websocket_upgrade(http_info):
            http_info["websocket_upgrade"] = True
        if is_beacon_request(http_info):
            http_info["beacon_suspect"] = True

    elif dst_port in (443, 8443, 853) or src_port in (443, 8443, 853):
        layer7["app_proto"] = "tls"
        layer7["tls"] = _dissect_tls(tls_key, payload, proto, meta.get("timestamp"))

    elif dst_port == 22 or src_port == 22:
        layer7["app_proto"] = "ssh"
        layer7["ssh"] = _parse_ssh_banner(payload)

    elif dst_port in (25, 465, 587) or src_port in (25, 465, 587):
        layer7["app_proto"] = "smtp"
        layer7["smtp"] = _parse_smtp(payload)

    elif proto == "udp" and {src_port, dst_port} <= {67, 68}:
        dhcp = _parse_dhcp(payload)
        if dhcp:
            layer7["app_proto"] = "dhcp"
            layer7["dhcp"] = dhcp

    return layer7


def _is_tls_hello(payload: bytes, handshake_type: int) -> bool:
    """A TLS handshake record opening with a ClientHello (1) or ServerHello (2)."""
    return (len(payload) >= 11 and payload[0] == 0x16 and payload[1] == 0x03 and payload[2] <= 0x04
            and payload[5] == handshake_type
            # record and handshake lengths must agree with each other
            and 4 <= int.from_bytes(payload[3:5], "big") <= 16384 + 256
            and payload[6] == 0 and payload[9] == 0x03)


def _dissect_tls(key: tuple, payload: bytes, proto: str, ts: Optional[float]) -> Dict[str, Any]:
    if proto != "tcp":
        return _parse_tls_client_hello(payload)
    if _TLS_SERVER_FLIGHT.pending(key) or _is_tls_hello(payload, 0x02):
        info = _TLS_SERVER_FLIGHT.feed(key, payload, ts)
        return info if info is not None else {"partial": True}
    record = _TLS_ASSEMBLER.feed(key, payload)
    return _parse_tls_client_hello(record) if record else {"partial": True}


def _decrypt_quic_sni(meta: Dict[str, Any], payload: bytes, quic: Dict[str, Any]) -> None:
    """Decrypt a client Initial and, once the ClientHello is whole, add SNI/ALPN."""
    initial = decrypt_client_initial(payload)
    if initial is None:
        return
    quic["decrypted"] = True
    key = (meta.get("src_ip"), meta.get("src_port"), initial.dcid)
    hello = _QUIC_ASSEMBLER.add(repr(key).encode(), initial.crypto_frames)
    if hello is None:
        return
    record = b"\x16\x03\x01" + len(hello).to_bytes(2, "big") + hello
    tls = _parse_tls_client_hello(record)
    for field in ("sni", "alpn", "ech", "ja3", "tls_version"):
        if tls.get(field) is not None:
            quic[field] = tls[field]
    quic["client_hello_complete"] = True


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

_HTTP_PORTS = (80, 8080, 8000, 8008)
_HTTP_REQUEST_LINE_RE = re.compile(
    rb"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) \S+ HTTP/1\.[01]\r\n"
)
# Only this much of a request body is searched for attack patterns.
_HTTP_BODY_SCAN_LIMIT = 4096

# Tautologies need SQL context (a closing quote/paren or OR/AND) so query
# strings such as ``utm_v1=1`` or ``?1=1`` cache-busters do not match.
_SQLI_RE = re.compile(
    r"(union(?:\s+all)?\s+select\b|select\s+\*\s+from\b|drop\s+table\b|['\")]\s*--|"
    r"'[;\s]+or\s+|(?:['\")]|\b(?:or|and))\s*\(?\s*['\"]?1['\"]?\s*=\s*['\"]?1\b|"
    r"\bbenchmark\s*\(|\bsleep\s*\(\s*\d|\bload_file\s*\(|"
    r"information_schema|\bpg_sleep\b|waitfor\s+delay)",
    re.IGNORECASE,
)
# Event-handler attributes only count inside a tag (``?onload=1`` is a
# harmless parameter name).
_XSS_RE = re.compile(
    r"(<\s*script|javascript\s*:|<[^>\n]*\bon(?:error|load|click|mouse\w*)\s*=|"
    r"\beval\s*\(|\balert\s*\(|document\.cookie|fromCharCode)",
    re.IGNORECASE,
)
_PATH_TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\|%2e%2e", re.IGNORECASE)
_SCANNER_UA_RE = re.compile(
    r"(nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wfuzz|nuclei|"
    r"burpsuite|zgrab|metasploit|hydra|medusa|acunetix|nessus|openvas)",
    re.IGNORECASE,
)


def _parse_http(payload: bytes) -> Dict[str, Any]:
    if not payload:
        return {}
    info: Dict[str, Any] = {}
    try:
        text = payload.decode("utf-8", errors="replace")
        lines = text.split("\r\n")
        if not lines or not lines[0]:
            return info

        first = lines[0]

        req_m = re.match(
            r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)\s+(HTTP/\S+)",
            first,
        )
        if req_m:
            info["direction"] = "request"
            info["method"] = req_m.group(1)
            info["uri"] = req_m.group(2)
            info["version"] = req_m.group(3)

        resp_m = re.match(r"^(HTTP/\S+)\s+(\d+)\s+(.*)", first)
        if resp_m:
            info["direction"] = "response"
            info["version"] = resp_m.group(1)
            info["status_code"] = int(resp_m.group(2))
            info["reason"] = resp_m.group(3)

        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                break
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        info["host"] = headers.get("host")
        info["user_agent"] = headers.get("user-agent")
        info["content_type"] = headers.get("content-type")
        info["content_length"] = headers.get("content-length")
        info["referer"] = headers.get("referer")
        if info.get("direction") == "response":
            info["server"] = headers.get("server")
            info["location"] = headers.get("location")
        info["headers"] = headers

        # Security heuristics look at what a client sends — the request line,
        # headers and the start of the body — never at server responses.
        info["sqli_suspect"] = info["xss_suspect"] = False
        info["path_traversal_suspect"] = info["scanner_ua"] = False
        if info.get("direction") == "request":
            uri = info.get("uri", "")
            head, _, body = text.partition("\r\n\r\n")
            header_block = head.partition("\r\n")[2]
            search_target = "\n".join((
                unquote_plus(uri), header_block, unquote_plus(body[:_HTTP_BODY_SCAN_LIMIT]),
            ))
            info["sqli_suspect"] = bool(_SQLI_RE.search(search_target))
            info["xss_suspect"] = bool(_XSS_RE.search(search_target))
            info["path_traversal_suspect"] = bool(
                _PATH_TRAVERSAL_RE.search(uri) or _PATH_TRAVERSAL_RE.search(unquote(uri)))
            info["scanner_ua"] = bool(_SCANNER_UA_RE.search(info.get("user_agent") or ""))

    except Exception:
        pass
    return info


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def _parse_dns(payload: bytes, proto: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        # TCP DNS has a 2-byte length prefix
        data = payload[2:] if proto == "tcp" else payload
        if len(data) < 12:
            return info

        info["txid"] = int.from_bytes(data[0:2], "big")
        flags = int.from_bytes(data[2:4], "big")
        info["is_response"] = bool(flags & 0x8000)
        info["opcode"] = (flags >> 11) & 0x0F
        info["rcode"] = flags & 0x000F
        if info["is_response"]:
            info["rcode_name"] = _DNS_RCODES.get(info["rcode"], str(info["rcode"]))
        qdcount = int.from_bytes(data[4:6], "big")
        ancount = int.from_bytes(data[6:8], "big")
        info["answer_count"] = ancount

        if qdcount > 0:
            name, pos = _dns_decode_name(data, 12)
            if name is not None and pos + 4 <= len(data):
                qtype_num = int.from_bytes(data[pos : pos + 2], "big")
                info["query_name"] = name
                info["query_type"] = _DNS_QTYPES.get(qtype_num, str(qtype_num))
                info["name_length"] = len(name)
                info["name_entropy"] = _entropy(name.lower().encode())
                # Subdomain depth hints at tunneling
                info["subdomain_depth"] = name.count(".")
                pos += 4
                if info["is_response"] and ancount:
                    info["answers"] = _dns_answers(data, pos, ancount)

    except Exception:
        pass
    return info


def _dns_answers(data: bytes, pos: int, count: int) -> List[Dict[str, Any]]:
    """Decode A / AAAA / CNAME answer records (used to map IPs back to names)."""
    answers: List[Dict[str, Any]] = []
    for _ in range(min(count, 32)):
        name, pos = _dns_decode_name(data, pos)
        if pos + 10 > len(data):
            break
        rtype = int.from_bytes(data[pos:pos + 2], "big")
        ttl = int.from_bytes(data[pos + 4:pos + 8], "big")
        rdlen = int.from_bytes(data[pos + 8:pos + 10], "big")
        pos += 10
        rdata = data[pos:pos + rdlen]
        if len(rdata) != rdlen:
            break
        value: Optional[str] = None
        if rtype == 1 and rdlen == 4:
            value = ".".join(str(b) for b in rdata)
        elif rtype == 28 and rdlen == 16:
            import ipaddress
            value = str(ipaddress.IPv6Address(rdata))
        elif rtype == 5:
            value, _ = _dns_decode_name(data, pos)
        if value is not None:
            answers.append({
                "name": name,
                "type": _DNS_QTYPES.get(rtype, str(rtype)),
                "data": value,
                "ttl": ttl,
            })
        pos += rdlen
    return answers


_DNS_QTYPES: Dict[int, str] = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 13: "HINFO",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 41: "OPT", 43: "DS",
    46: "RRSIG", 48: "DNSKEY", 52: "TLSA", 64: "SVCB", 65: "HTTPS", 99: "SPF",
    251: "IXFR", 252: "AXFR", 255: "ANY", 257: "CAA",
}
_DNS_RCODES: Dict[int, str] = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
}


_DNS_MAX_NAME = 255
_DNS_MAX_JUMPS = 32


def _dns_decode_name(data: bytes, offset: int) -> Tuple[Optional[str], int]:
    """
    Decode a DNS name starting at *offset*, returning (name, end_offset).

    *end_offset* is where the record continues: just past the terminating
    zero label, or past the first compression pointer.  Pointers must
    point strictly backwards (RFC 1035 §4.1.4) and the number of jumps and
    the name length are capped, so crafted loops cannot recurse or spin.
    A malformed name returns what was decoded so far (or None).
    """
    labels: List[str] = []
    pos = offset
    end_offset: Optional[int] = None   # set at the first pointer
    lowest = offset                    # every pointer must go below this
    jumps = 0
    total = 0

    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if (length & 0xC0) == 0xC0:  # pointer
            if pos + 1 >= len(data):
                pos = len(data)
                break
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            if end_offset is None:
                end_offset = pos + 2
            jumps += 1
            if ptr >= lowest or jumps > _DNS_MAX_JUMPS:
                break  # forward / self pointer or a loop
            lowest = ptr
            pos = ptr
            continue
        if length & 0xC0:
            break  # reserved label types (0x40 / 0x80)
        pos += 1
        end = pos + length
        total += length + 1
        if end > len(data) or total > _DNS_MAX_NAME:
            pos = min(end, len(data))
            break
        labels.append(data[pos:end].decode("ascii", errors="replace"))
        pos = end

    if end_offset is not None:
        pos = end_offset
    return (".".join(labels) if labels else None), pos


# ---------------------------------------------------------------------------
# TLS ClientHello / JA3
# ---------------------------------------------------------------------------

def _parse_tls_client_hello(payload: bytes) -> Dict[str, Any]:
    """
    Extract SNI and compute a JA3-compatible fingerprint from a TLS
    ClientHello record.  Silently returns {} for non-ClientHello records.
    """
    info: Dict[str, Any] = {}
    try:
        # TLS record: type(1) version(2) length(2)
        if len(payload) < 5 or payload[0] != 0x16:
            return info

        # Handshake record
        if len(payload) < 9 or payload[5] != 0x01:  # Not ClientHello
            return info

        # Handshake header: type(1) length(3); never read past the handshake.
        hs_len = int.from_bytes(payload[6:9], "big")
        payload = payload[:9 + hs_len]
        pos = 9

        # Client version
        if pos + 2 > len(payload):
            return info
        client_version = int.from_bytes(payload[pos : pos + 2], "big")
        info["tls_version"] = _tls_version_name(client_version)
        pos += 2

        # Random (32 bytes)
        pos += 32

        # Session ID
        if pos >= len(payload):
            return info
        sid_len = payload[pos]
        pos += 1 + sid_len

        # Cipher suites
        if pos + 2 > len(payload):
            return info
        cs_len = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2
        cipher_suites = []
        for i in range(cs_len // 2):
            o = pos + i * 2
            if o + 2 <= len(payload):
                cs = int.from_bytes(payload[o : o + 2], "big")
                if not _is_grease(cs):
                    cipher_suites.append(cs)
        pos += cs_len

        # Compression methods
        if pos >= len(payload):
            return info
        comp_len = payload[pos]
        pos += 1 + comp_len

        # Extensions
        if pos + 2 > len(payload):
            return info
        ext_total = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2
        ext_end = pos + ext_total

        extensions: List[int] = []
        elliptic_curves: List[int] = []
        ec_point_formats: List[int] = []

        while pos + 4 <= ext_end and pos + 4 <= len(payload):
            ext_type = int.from_bytes(payload[pos : pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2 : pos + 4], "big")
            data_start = pos + 4

            if not _is_grease(ext_type):
                extensions.append(ext_type)

            # ALPN (type 16) — e.g. ["h2", "http/1.1"] or ["h3"]
            if ext_type == 0x0010 and data_start + 2 <= len(payload):
                alpn: List[str] = []
                apos = data_start + 2
                aend = min(data_start + ext_len, len(payload))
                while apos < aend:
                    alen = payload[apos]
                    alpn.append(payload[apos + 1:apos + 1 + alen].decode("ascii", errors="replace"))
                    apos += 1 + alen
                info["alpn"] = alpn

            # supported_versions (type 43): since TLS 1.3 the real offer lives
            # here; the legacy version field above stays at 1.2 forever.
            if ext_type == 0x002B and data_start + 1 <= len(payload):
                vend = min(data_start + 1 + payload[data_start], data_start + ext_len, len(payload))
                offered = [int.from_bytes(payload[v:v + 2], "big") for v in range(data_start + 1, vend - 1, 2)]
                offered = [v for v in offered if not _is_grease(v)]
                if offered:
                    info["supported_versions"] = [_tls_version_name(v) for v in offered]
                    info["legacy_version"] = info["tls_version"]
                    # Highest version the client offers (drafts and unknowns sort last).
                    info["tls_version"] = _tls_version_name(
                        max(offered, key=lambda v: v if 0x0300 <= v <= 0x0304 else 0))

            # Encrypted Client Hello — the visible SNI is only the outer, public name
            if ext_type == 0xFE0D:
                info["ech"] = True

            # SNI (type 0)
            if ext_type == 0x0000 and data_start + 5 <= len(payload):
                sni_pos = data_start + 2  # skip list_length
                if sni_pos + 3 <= len(payload) and payload[sni_pos] == 0:
                    name_len = int.from_bytes(payload[sni_pos + 1 : sni_pos + 3], "big")
                    sni_end = sni_pos + 3 + name_len
                    if sni_end <= len(payload):
                        info["sni"] = payload[sni_pos + 3 : sni_end].decode(
                            "ascii", errors="replace"
                        )

            # Supported groups / elliptic curves (type 10)
            if ext_type == 0x000A and data_start + 2 <= len(payload):
                gc_len = int.from_bytes(payload[data_start : data_start + 2], "big")
                for gi in range(gc_len // 2):
                    go = data_start + 2 + gi * 2
                    if go + 2 <= len(payload):
                        g = int.from_bytes(payload[go : go + 2], "big")
                        if not _is_grease(g):
                            elliptic_curves.append(g)

            # EC point formats (type 11)
            if ext_type == 0x000B and data_start + 1 <= len(payload):
                pf_len = payload[data_start]
                for pfi in range(pf_len):
                    if data_start + 1 + pfi < len(payload):
                        ec_point_formats.append(payload[data_start + 1 + pfi])

            pos = data_start + ext_len

        info["cipher_suites"] = cipher_suites
        info["extensions"] = extensions

        # JA3 fingerprint: version,ciphers,extensions,elliptic_curves,ec_point_formats
        ja3_str = (
            f"{client_version},"
            f"{'-'.join(str(c) for c in cipher_suites)},"
            f"{'-'.join(str(e) for e in extensions)},"
            f"{'-'.join(str(g) for g in elliptic_curves)},"
            f"{'-'.join(str(p) for p in ec_point_formats)}"
        )
        info["ja3"] = hashlib.md5(ja3_str.encode(), usedforsecurity=False).hexdigest()
        info["ja3_string"] = ja3_str

    except Exception:
        pass
    return info


# ---------------------------------------------------------------------------
# TLS server flight: ServerHello / JA3S / certificate
# ---------------------------------------------------------------------------

def _parse_tls_server_flight(data: bytes, now: Optional[float] = None) -> Tuple[Dict[str, Any], bool]:
    """
    Parse what has arrived of a server's first flight.

    Returns ``(info, done)``; *done* is False while more segments are needed.
    """
    info: Dict[str, Any] = {}
    try:
        # 1. Strip the record layer: handshake messages may span records.
        handshake = bytearray()
        pos, ended = 0, False
        while pos + 5 <= len(data):
            rtype = data[pos]
            rlen = int.from_bytes(data[pos + 3:pos + 5], "big")
            if rtype != 0x16:          # ChangeCipherSpec / application data: plaintext is over
                ended = True
                break
            if pos + 5 + rlen > len(data):
                handshake += data[pos + 5:]   # partial record: still useful below
                break
            handshake += data[pos + 5:pos + 5 + rlen]
            pos += 5 + rlen

        # 2. Walk the handshake messages.
        hp = 0
        while hp + 4 <= len(handshake):
            mtype = handshake[hp]
            mlen = int.from_bytes(handshake[hp + 1:hp + 4], "big")
            body = bytes(handshake[hp + 4:hp + 4 + mlen])
            if len(body) < mlen:
                if mtype == 0x02 or info:
                    return info, False  # this message continues in the next segment
                break
            hp += 4 + mlen
            if mtype == 0x02:
                _parse_server_hello(body, info)
                if info.get("negotiated_version") == "TLS 1.3":
                    return info, True   # everything after this is encrypted
            elif mtype == 0x0B:
                cert = _parse_certificate_message(body, now)
                if cert:
                    info["cert"] = cert
                return info, True
            elif mtype in (0x0C, 0x0D, 0x0E):
                return info, True       # key exchange / done without a certificate
        if not info:
            return info, True           # not a ServerHello after all
        return info, ended
    except Exception:
        return info, True


def _parse_server_hello(body: bytes, info: Dict[str, Any]) -> None:
    if len(body) < 38:
        return
    version = int.from_bytes(body[0:2], "big")
    pos = 34
    pos += 1 + body[pos]                          # session id
    if pos + 3 > len(body):
        return
    cipher = int.from_bytes(body[pos:pos + 2], "big")
    pos += 3                                      # cipher suite + compression method
    extensions: List[int] = []
    negotiated = version
    if pos + 2 <= len(body):
        ext_end = min(len(body), pos + 2 + int.from_bytes(body[pos:pos + 2], "big"))
        pos += 2
        while pos + 4 <= ext_end:
            etype = int.from_bytes(body[pos:pos + 2], "big")
            elen = int.from_bytes(body[pos + 2:pos + 4], "big")
            edata = body[pos + 4:pos + 4 + elen]
            extensions.append(etype)
            if etype == 0x002B and len(edata) >= 2:
                negotiated = int.from_bytes(edata[0:2], "big")
            elif etype == 0x0010 and len(edata) >= 4:
                info["alpn_selected"] = edata[3:3 + edata[2]].decode("ascii", errors="replace")
            pos += 4 + elen
    info["direction"] = "server"
    info["negotiated_version"] = _tls_version_name(negotiated)
    info["cipher_suite"] = f"0x{cipher:04X}"
    # JA3S: version,cipher,extensions (as sent, legacy version field)
    ja3s = f"{version},{cipher},{'-'.join(str(e) for e in extensions)}"
    info["ja3s"] = hashlib.md5(ja3s.encode(), usedforsecurity=False).hexdigest()
    info["ja3s_string"] = ja3s


def _parse_certificate_message(body: bytes, now: Optional[float] = None) -> Dict[str, Any]:
    """The leaf certificate of a TLS ≤ 1.2 Certificate message, as plain fields."""
    if len(body) < 6:
        return {}
    total = int.from_bytes(body[0:3], "big")
    end = min(len(body), 3 + total)
    pos, chain = 3, []
    while pos + 3 <= end and len(chain) < 8:
        clen = int.from_bytes(body[pos:pos + 3], "big")
        chain.append(body[pos + 3:pos + 3 + clen])
        pos += 3 + clen
    if not chain or not chain[0]:
        return {}
    der = chain[0]
    out: Dict[str, Any] = {
        "sha256": hashlib.sha256(der).hexdigest(),
        "sha1": hashlib.sha1(der, usedforsecurity=False).hexdigest(),
        "chain_length": len(chain),
    }
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID, NameOID

        cert = x509.load_der_x509_certificate(der)

        def _cn(name: Any) -> Optional[str]:
            attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
            return str(attrs[0].value) if attrs else None

        def _epoch(attr: str) -> float:
            aware = getattr(cert, attr + "_utc", None)
            if aware is not None:
                return aware.timestamp()
            import calendar
            return float(calendar.timegm(getattr(cert, attr).timetuple()))

        not_before, not_after = _epoch("not_valid_before"), _epoch("not_valid_after")
        out.update({
            "subject": cert.subject.rfc4514_string()[:300],
            "issuer": cert.issuer.rfc4514_string()[:300],
            "subject_cn": _cn(cert.subject),
            "issuer_cn": _cn(cert.issuer),
            "serial": format(cert.serial_number, "x"),
            "not_before": not_before,
            "not_after": not_after,
            "validity_days": round((not_after - not_before) / 86400.0, 1),
            "self_signed": cert.subject == cert.issuer,
        })
        when = now if now else time.time()
        out["expired"] = when > not_after
        out["not_yet_valid"] = when < not_before
        try:
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            names = [str(n) for n in san.get_values_for_type(x509.DNSName)]
            names += [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
            out["san"] = names[:50]
        except x509.ExtensionNotFound:
            out["san"] = []
    except Exception:
        out["unparsed"] = True
    return out


def cert_matches_name(cert: Dict[str, Any], name: Optional[str]) -> Optional[bool]:
    """
    Does *cert* cover the host *name* (SAN first, then CN; ``*.`` wildcards)?

    None when it cannot be judged (no name, or the certificate did not parse).
    """
    if not name or not cert or cert.get("unparsed"):
        return None
    host = name.lower().rstrip(".")
    candidates = [c.lower().rstrip(".") for c in (cert.get("san") or []) if c]
    if not candidates and cert.get("subject_cn"):
        candidates = [str(cert["subject_cn"]).lower().rstrip(".")]
    if not candidates:
        return None
    for pattern in candidates:
        if pattern == host:
            return True
        if pattern.startswith("*.") and "." in host and host.split(".", 1)[1] == pattern[2:]:
            return True
    return False


def _is_grease(value: int) -> bool:
    """RFC 8701 GREASE values: 0x0A0A, 0x1A1A, … 0xFAFA."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def _tls_version_name(version: int) -> str:
    return {
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3",
    }.get(version, f"0x{version:04X}")


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------

_SSH_BANNER_RE = re.compile(r"^SSH-(\S+)-(\S+)(?:\s+(.*))?", re.ASCII)


def _parse_ssh_banner(payload: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        text = payload.decode("utf-8", errors="replace").strip()
        m = _SSH_BANNER_RE.match(text)
        if m:
            info["proto_version"] = m.group(1)
            info["software"] = m.group(2)
            info["comments"] = m.group(3) or ""
    except Exception:
        pass
    return info


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------

def _parse_smtp(payload: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        text = payload.decode("utf-8", errors="replace")
        for line in text.splitlines():
            upper = line.upper().lstrip()
            if upper.startswith("EHLO ") or upper.startswith("HELO "):
                info["helo"] = line.split(None, 1)[1] if " " in line else ""
            elif upper.startswith("MAIL FROM:"):
                info["mail_from"] = line[10:].strip(" <>\r\n")
            elif upper.startswith("RCPT TO:"):
                info["rcpt_to"] = line[8:].strip(" <>\r\n")
            elif upper.startswith("AUTH "):
                info["auth_mechanism"] = line.split()[1] if len(line.split()) > 1 else ""
    except Exception:
        pass
    return info


# ---------------------------------------------------------------------------
# DHCP
# ---------------------------------------------------------------------------

_DHCP_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK",
               7: "RELEASE", 8: "INFORM"}


def _parse_dhcp(payload: bytes) -> Dict[str, Any]:
    """BOOTP header plus the options that say who is handing out what."""
    info: Dict[str, Any] = {}
    try:
        if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
            return info
        info["op"] = "reply" if payload[0] == 2 else "request"
        hlen = min(payload[2], 16)
        info["client_mac"] = payload[28:28 + hlen].hex(":")
        your_ip = ".".join(str(b) for b in payload[16:20])
        if your_ip != "0.0.0.0":
            info["your_ip"] = your_ip

        def _ips(data: bytes) -> List[str]:
            return [".".join(str(b) for b in data[i:i + 4]) for i in range(0, len(data) - 3, 4)]

        pos = 240
        while pos < len(payload):
            code = payload[pos]
            if code == 255:
                break
            if code == 0:
                pos += 1
                continue
            if pos + 2 > len(payload):
                break
            length = payload[pos + 1]
            data = payload[pos + 2:pos + 2 + length]
            pos += 2 + length
            if code == 53 and data:
                info["msg_type"] = _DHCP_TYPES.get(data[0], str(data[0]))
            elif code == 54 and len(data) == 4:
                info["server_id"] = _ips(data)[0]
            elif code == 3:
                info["routers"] = _ips(data)
            elif code == 6:
                info["dns_servers"] = _ips(data)
            elif code == 1 and len(data) == 4:
                info["subnet_mask"] = _ips(data)[0]
            elif code == 12:
                info["hostname"] = data.decode("utf-8", errors="replace").strip("\x00")[:64]
            elif code == 15:
                info["domain"] = data.decode("utf-8", errors="replace").strip("\x00")[:128]
            elif code == 50 and len(data) == 4:
                info["requested_ip"] = _ips(data)[0]
            elif code == 51 and len(data) == 4:
                info["lease_seconds"] = int.from_bytes(data, "big")
            elif code == 60:
                info["vendor_class"] = data.decode("ascii", errors="replace")[:64]
            elif code == 252:
                info["wpad"] = data.decode("ascii", errors="replace").strip("\x00")[:200]
    except Exception:
        pass
    return info


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _entropy(data: bytes) -> float:
    """Shannon entropy (bits per byte) of *data*."""
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())
