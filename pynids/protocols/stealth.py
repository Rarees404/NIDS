"""
Stealth-protocol parsers for activity that browsers hide from DevTools.

The Chrome/Firefox/Safari Network tab shows only *renderer-initiated*
``fetch``/``XHR`` traffic.  A surprising amount of network activity is
intentionally — or by spec — invisible there:

* **WebRTC** peer connections speak STUN/TURN (RFC 5389/8489) over UDP
  to learn their public IP and to traverse NAT.  STUN binding responses
  contain ``XOR-MAPPED-ADDRESS`` attributes that reveal both the public
  IP **and** the private/loopback addresses of the host — a long-known
  privacy leak.
* **HTTP/3** rides on **QUIC** (RFC 9000) UDP datagrams.  DevTools shows
  the resulting ``fetch`` calls but not the underlying QUIC handshake.
* **WebSocket** sessions live in the browser's "WS" sub-tab; the
  underlying ``Upgrade`` handshake on TCP/80/443 is otherwise hidden.
* **navigator.sendBeacon** requests are fire-and-forget HTTP POSTs that
  fly out on page-unload and routinely escape the user's attention.
* **Localhost port-scans** — a well-documented fingerprinting technique
  in which a webpage probes 127.0.0.1 ports to detect locally-running
  developer tools, malware-analysis tools, etc.  These never appear in
  DevTools because the requests are typically ``no-cors`` images.

This module provides byte-level parsers for STUN and QUIC plus a small
helper for detecting WebSocket upgrades and beacon-style HTTP POSTs.

The parsers are deliberately defensive — every malformed input simply
returns an empty dict and the caller treats that as "not a match".
"""
from __future__ import annotations

import socket
import struct
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# STUN / TURN — RFC 5389 / RFC 8489
# ---------------------------------------------------------------------------

# Every STUN message starts with these four bytes at offset 4.
_STUN_MAGIC_COOKIE = 0x2112A442

# Selected STUN/TURN message types.  The high bits encode method+class.
_STUN_MESSAGE_TYPES: Dict[int, str] = {
    0x0001: "Binding Request",
    0x0011: "Binding Indication",
    0x0101: "Binding Success Response",
    0x0111: "Binding Error Response",
    0x0003: "Allocate Request (TURN)",
    0x0103: "Allocate Success Response (TURN)",
    0x0113: "Allocate Error Response (TURN)",
    0x0004: "Refresh Request (TURN)",
    0x0006: "Send Indication (TURN)",
    0x0007: "Data Indication (TURN)",
    0x0008: "CreatePermission Request (TURN)",
    0x0009: "ChannelBind Request (TURN)",
}

# STUN attribute types we care about.
_ATTR_MAPPED_ADDRESS = 0x0001
_ATTR_USERNAME = 0x0006
_ATTR_XOR_MAPPED_ADDRESS = 0x0020
_ATTR_SOFTWARE = 0x8022
_ATTR_XOR_RELAYED_ADDRESS = 0x0016  # TURN allocation


def is_stun(payload: bytes) -> bool:
    """Quick port-independent classifier: True if *payload* looks like STUN."""
    if len(payload) < 20:
        return False
    # First two bits of byte 0 are always zero in STUN.
    if payload[0] & 0xC0:
        return False
    cookie = int.from_bytes(payload[4:8], "big")
    return cookie == _STUN_MAGIC_COOKIE


def parse_stun(payload: bytes) -> Dict[str, Any]:
    """
    Decode a STUN/TURN message.

    Returns a dict with at least ``message_type`` and ``txid``.  When the
    response carries an ``XOR-MAPPED-ADDRESS`` (or relayed address) the
    extracted ``ip`` and ``port`` are placed under ``mapped_address``.

    Returns an empty dict for non-STUN payloads.
    """
    if not is_stun(payload):
        return {}

    info: Dict[str, Any] = {}
    try:
        msg_type = int.from_bytes(payload[0:2], "big")
        msg_len = int.from_bytes(payload[2:4], "big")
        txid = payload[8:20]

        info["message_type_code"] = msg_type
        info["message_type"] = _STUN_MESSAGE_TYPES.get(msg_type, f"Unknown(0x{msg_type:04X})")
        info["message_length"] = msg_len
        info["txid"] = txid.hex()

        # STUN class is bits 8 and 4 of msg_type.
        is_response = bool(msg_type & 0x0100)
        is_error = bool(msg_type & 0x0010 and is_response)
        info["is_response"] = is_response
        info["is_error"] = is_error
        info["is_turn"] = msg_type in (0x0003, 0x0103, 0x0113, 0x0004, 0x0006,
                                       0x0007, 0x0008, 0x0009)

        # Walk the TLV attributes.
        addresses: List[Dict[str, Any]] = []
        pos = 20
        end = min(20 + msg_len, len(payload))
        while pos + 4 <= end:
            atype = int.from_bytes(payload[pos:pos + 2], "big")
            alen = int.from_bytes(payload[pos + 2:pos + 4], "big")
            value = payload[pos + 4:pos + 4 + alen]
            if len(value) != alen:
                break

            if atype == _ATTR_XOR_MAPPED_ADDRESS or atype == _ATTR_XOR_RELAYED_ADDRESS:
                addr = _decode_xor_address(value, payload[4:20])
                if addr:
                    addr["attribute"] = (
                        "XOR-MAPPED-ADDRESS"
                        if atype == _ATTR_XOR_MAPPED_ADDRESS
                        else "XOR-RELAYED-ADDRESS"
                    )
                    addresses.append(addr)

            elif atype == _ATTR_MAPPED_ADDRESS:
                addr = _decode_address(value)
                if addr:
                    addr["attribute"] = "MAPPED-ADDRESS"
                    addresses.append(addr)

            elif atype == _ATTR_SOFTWARE:
                try:
                    info["software"] = value.decode("utf-8", errors="replace").rstrip("\x00")
                except Exception:
                    pass

            elif atype == _ATTR_USERNAME:
                try:
                    info["username"] = value.decode("utf-8", errors="replace")
                except Exception:
                    pass

            # Attributes are 4-byte aligned.
            pos += 4 + ((alen + 3) & ~3)

        if addresses:
            info["addresses"] = addresses
            info["mapped_address"] = addresses[0]

    except Exception:
        return {}

    return info


def _decode_address(value: bytes) -> Optional[Dict[str, Any]]:
    """Decode a plain MAPPED-ADDRESS attribute (family/port/ip)."""
    if len(value) < 4:
        return None
    family = value[1]
    port = int.from_bytes(value[2:4], "big")
    if family == 0x01 and len(value) >= 8:
        ip = socket.inet_ntop(socket.AF_INET, value[4:8])
        return {"family": "IPv4", "ip": ip, "port": port}
    if family == 0x02 and len(value) >= 20:
        ip = socket.inet_ntop(socket.AF_INET6, value[4:20])
        return {"family": "IPv6", "ip": ip, "port": port}
    return None


def _decode_xor_address(value: bytes, magic_and_txid: bytes) -> Optional[Dict[str, Any]]:
    """
    Decode an XOR-MAPPED-ADDRESS attribute (RFC 5389 §15.2).

    The IPv4 address is XORed with the magic cookie, the IPv6 address
    with magic cookie || transaction ID.  The port is XORed with the
    upper 16 bits of the magic cookie.
    """
    if len(value) < 4:
        return None
    family = value[1]
    xport = int.from_bytes(value[2:4], "big")
    port = xport ^ ((_STUN_MAGIC_COOKIE >> 16) & 0xFFFF)
    if family == 0x01 and len(value) >= 8:
        xip = value[4:8]
        magic = magic_and_txid[0:4]
        ip_bytes = bytes(a ^ b for a, b in zip(xip, magic))
        ip = socket.inet_ntop(socket.AF_INET, ip_bytes)
        return {"family": "IPv4", "ip": ip, "port": port}
    if family == 0x02 and len(value) >= 20:
        xip = value[4:20]
        mask = magic_and_txid[0:16]  # magic cookie || txid
        ip_bytes = bytes(a ^ b for a, b in zip(xip, mask))
        ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
        return {"family": "IPv6", "ip": ip, "port": port}
    return None


# ---------------------------------------------------------------------------
# QUIC — RFC 9000 long-header packet probe
# ---------------------------------------------------------------------------

# Long-header bit + fixed bit pattern: 0b11xxxxxx.
_QUIC_LONG_HEADER_MASK = 0xC0
_QUIC_LONG_HEADER_VALUE = 0xC0

_QUIC_LONG_PACKET_TYPES = {
    0x00: "Initial",
    0x01: "0-RTT",
    0x02: "Handshake",
    0x03: "Retry",
}

_KNOWN_QUIC_VERSIONS = {
    0x00000000: "Version Negotiation",
    0x00000001: "QUIC v1 (RFC 9000)",
    0x709A50C4: "Quicly draft",
    0xFF00001D: "QUIC draft-29",
    0x6B3343CF: "QUIC v2 (RFC 9369)",
}


def is_quic(payload: bytes) -> bool:
    """Heuristic: True if *payload* starts with a QUIC long-header packet."""
    if len(payload) < 7:
        return False
    if (payload[0] & _QUIC_LONG_HEADER_MASK) != _QUIC_LONG_HEADER_VALUE:
        return False
    version = int.from_bytes(payload[1:5], "big")
    # Anything with a high-byte of 0x00 or one of the well-known values
    # we consider plausible QUIC.  Excludes random UDP traffic on :443.
    return version in _KNOWN_QUIC_VERSIONS or (version & 0xFFFF0000) == 0


def parse_quic(payload: bytes) -> Dict[str, Any]:
    """Extract version, packet type, and connection IDs from a QUIC datagram."""
    if not is_quic(payload):
        return {}

    info: Dict[str, Any] = {}
    try:
        first_byte = payload[0]
        version = int.from_bytes(payload[1:5], "big")
        packet_type_code = (first_byte & 0x30) >> 4

        info["version_code"] = version
        info["version"] = _KNOWN_QUIC_VERSIONS.get(
            version, f"Unknown 0x{version:08X}"
        )
        info["packet_type"] = _QUIC_LONG_PACKET_TYPES.get(
            packet_type_code, f"Unknown(0x{packet_type_code:02X})"
        )

        pos = 5
        if pos >= len(payload):
            return info
        dcid_len = payload[pos]
        pos += 1
        info["dcid"] = payload[pos:pos + dcid_len].hex()
        pos += dcid_len

        if pos < len(payload):
            scid_len = payload[pos]
            pos += 1
            info["scid"] = payload[pos:pos + scid_len].hex()

    except Exception:
        return {}

    return info


# ---------------------------------------------------------------------------
# WebSocket / Beacon helpers (HTTP-layer)
# ---------------------------------------------------------------------------

_BEACON_HINT_PATHS = (
    "/beacon", "/collect", "/track", "/event", "/log", "/p.gif",
    "/__utm.gif", "/pixel", "/b/ss/", "/_/log", "/cdn-cgi/rum",
)


def is_websocket_upgrade(http_info: Dict[str, Any]) -> bool:
    """True if the HTTP request is a WebSocket Upgrade handshake."""
    if not http_info or http_info.get("direction") != "request":
        return False
    headers = http_info.get("headers") or {}
    upgrade = (headers.get("upgrade") or "").lower()
    connection = (headers.get("connection") or "").lower()
    return "websocket" in upgrade and "upgrade" in connection


def is_beacon_request(http_info: Dict[str, Any]) -> bool:
    """
    Heuristic: True if the request looks like ``navigator.sendBeacon``
    or a 1×1 tracking pixel.

    Markers we look at:
      * very small POST (≤ 1500 bytes) with ``Content-Type:`` of the
        beacon family (``text/plain``, ``application/x-www-form-...``,
        ``application/json``) and **no** ``Accept`` header — the
        browser does not request a body back from sendBeacon.
      * GET to a path that strongly resembles a tracking endpoint
        (``/collect``, ``/__utm.gif``, ``/pixel``, etc.).
    """
    if not http_info or http_info.get("direction") != "request":
        return False

    method = http_info.get("method", "")
    headers = http_info.get("headers") or {}
    uri = (http_info.get("uri") or "").lower()
    ctype = (headers.get("content-type") or "").lower()

    if method == "POST":
        try:
            content_length = int(headers.get("content-length") or 0)
        except ValueError:
            content_length = 0
        accept = headers.get("accept", "")
        beaconish_ct = (
            "text/plain" in ctype
            or "application/json" in ctype
            or "application/x-www-form-urlencoded" in ctype
            or ctype == ""
        )
        if (
            content_length and content_length <= 1500
            and beaconish_ct
            and (not accept or accept == "*/*")
        ):
            return True

    if method == "GET":
        if any(hint in uri for hint in _BEACON_HINT_PATHS):
            return True
        if uri.endswith(".gif") and ("?" in uri or "tr=" in uri or "id=" in uri):
            return True

    return False


# ---------------------------------------------------------------------------
# Convenience: address classification
# ---------------------------------------------------------------------------

def classify_ip(ip: Optional[str]) -> str:
    """
    Classify an IP into a coarse category that the X-Ray UI uses to
    decide what to highlight: 'loopback', 'private', 'link_local',
    'multicast', 'public', or 'unknown'.
    """
    if not ip:
        return "unknown"
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            return "loopback"
        if addr.is_link_local:
            return "link_local"
        if addr.is_multicast:
            return "multicast"
        if addr.is_private:
            return "private"
        return "public"
    except ValueError:
        return "unknown"
