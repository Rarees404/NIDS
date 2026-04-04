"""
Application-layer protocol dissection for PyNIDS.

The ``dissect()`` function inspects raw packet metadata and returns a
supplementary ``layer7`` dictionary containing parsed application-layer
fields.  Downstream detectors and rule engines can reference these
fields for rich, protocol-aware matching.

Supported protocols
-------------------
HTTP/1.x  — request line, headers, SQLi/XSS heuristics
DNS       — query/response, entropy of the query name (tunneling hint)
TLS       — ClientHello SNI extraction and JA3 fingerprint
SSH       — banner / version string
SMTP      — EHLO, MAIL FROM, RCPT TO commands
"""
from __future__ import annotations

import hashlib
import math
import re
from typing import Any, Dict, List, Optional, Tuple


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
        ``http``, ``dns``, ``tls``, ``ssh``, and ``smtp``.
    """
    dst_port: int = meta.get("dst_port") or 0
    src_port: int = meta.get("src_port") or 0
    payload: bytes = meta.get("payload_bytes") or b""
    proto: str = meta.get("protocol") or ""

    if not payload:
        return {}

    layer7: Dict[str, Any] = {}

    if dst_port == 53 or src_port == 53:
        layer7["app_proto"] = "dns"
        layer7["dns"] = _parse_dns(payload, proto)

    elif dst_port in (80, 8080, 8000, 8008) or src_port in (80, 8080, 8000, 8008):
        layer7["app_proto"] = "http"
        layer7["http"] = _parse_http(payload)

    elif dst_port in (443, 8443) or src_port in (443, 8443):
        layer7["app_proto"] = "tls"
        layer7["tls"] = _parse_tls_client_hello(payload)

    elif dst_port == 22 or src_port == 22:
        layer7["app_proto"] = "ssh"
        layer7["ssh"] = _parse_ssh_banner(payload)

    elif dst_port in (25, 465, 587) or src_port in (25, 465, 587):
        layer7["app_proto"] = "smtp"
        layer7["smtp"] = _parse_smtp(payload)

    return layer7


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

_SQLI_RE = re.compile(
    r"(union\s+select|select\s+\*\s+from|drop\s+table|--\s*$|'[;\s]+or\s+|"
    r"1\s*=\s*1|or\s+1\s*=\s*1|benchmark\s*\(|sleep\s*\(|load_file\s*\(|"
    r"information_schema|pg_sleep|waitfor\s+delay)",
    re.IGNORECASE,
)
_XSS_RE = re.compile(
    r"(<\s*script|javascript\s*:|on(?:error|load|click|mouse)\s*=|"
    r"eval\s*\(|alert\s*\(|document\.cookie|fromCharCode)",
    re.IGNORECASE,
)
_PATH_TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\|%2e%2e", re.IGNORECASE)
_SCANNER_UA_RE = re.compile(
    r"(nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wfuzz|nuclei|"
    r"burpsuite|zgrab|metasploit|hydra|medusa|acunetix|nessus|openvas)",
    re.IGNORECASE,
)


def _parse_http(payload: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        text = payload.decode("utf-8", errors="replace")
        lines = text.split("\r\n")
        if not lines:
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
        info["headers"] = headers

        # Security heuristics
        search_target = info.get("uri", "") + text
        info["sqli_suspect"] = bool(_SQLI_RE.search(search_target))
        info["xss_suspect"] = bool(_XSS_RE.search(search_target))
        info["path_traversal_suspect"] = bool(_PATH_TRAVERSAL_RE.search(info.get("uri", "")))
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

    except Exception:
        pass
    return info


_DNS_QTYPES: Dict[int, str] = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}


def _dns_decode_name(data: bytes, offset: int) -> Tuple[Optional[str], int]:
    """Decode a DNS name starting at *offset*, returning (name, end_offset)."""
    labels: List[str] = []
    pos = offset
    visited: set = set()

    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if (length & 0xC0) == 0xC0:  # pointer
            if pos + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            if ptr in visited or ptr >= len(data):
                break
            visited.add(ptr)
            pointed_name, _ = _dns_decode_name(data, ptr)
            if pointed_name:
                labels.append(pointed_name)
            pos += 2
            break
        else:
            pos += 1
            end = pos + length
            if end > len(data):
                break
            labels.append(data[pos:end].decode("ascii", errors="replace"))
            pos = end

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

        rec_version = int.from_bytes(payload[1:3], "big")
        # Handshake record
        if payload[5] != 0x01:  # Not ClientHello
            return info

        # Handshake header: type(1) length(3)
        hs_len = int.from_bytes(payload[6:9], "big")
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
                if cs != 0x0000:  # skip GREASE
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

            if ext_type != 0x0A0A:  # skip GREASE extensions
                extensions.append(ext_type)

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
                        if g != 0x0A0A:
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
