"""
Packet capture layer for PyNIDS.

Provides two capture modes:

- **Live capture** straight from Scapy's link-layer listen socket (BPF on
  macOS, ``AF_PACKET`` on Linux).  Frames are read as raw bytes and decoded
  by :func:`decode_frame`, a small ``struct``-based Ethernet/IP/TCP/UDP
  parser, so no Scapy packet objects are built on the hot path.

- **PCAP replay** via Scapy's :class:`~scapy.utils.PcapReader`, reading
  packets sequentially from a PCAP/PCAPNG file.

Both modes produce the same normalised *meta* dictionary consumed by the
engine.

Why not let Scapy dissect?  Besides being ~5× slower, Scapy decodes the
protocols it knows (DNS, mDNS, NTP, NetBIOS/SMB …) into its own layers and
leaves no ``Raw`` payload behind, so the engine's own dissector — DNS
tunnelling, malicious-domain intel, DNS trackers, hostname learning — would
never see those payloads.

Meta dictionary keys
--------------------
``timestamp``      float  — Unix epoch of packet capture time
``protocol``       str    — 'tcp', 'udp', 'icmp', 'icmpv6', 'other'
``src_ip``         str    — Source IP (v4 or v6)
``dst_ip``         str    — Destination IP (v4 or v6)
``src_port``       int    — Source TCP/UDP port (None for ICMP)
``dst_port``       int    — Destination TCP/UDP port (None for ICMP)
``tcp_flags``      int    — Bitmask of TCP flags (0 for non-TCP)
``payload_bytes``  bytes  — Application-layer payload (may be empty)
``ip_ttl``         int    — IP TTL / Hop Limit
``ip_tos``         int    — IP TOS / DSCP byte
``packet_len``     int    — Total captured packet length in bytes
"""
from __future__ import annotations

import logging
import queue
import socket
import struct
import threading
from typing import Any, Callable, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

_U16 = struct.Struct("!H")
_PORTS = struct.Struct("!HH")
_inet_ntoa = socket.inet_ntoa


def _ntop6(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, raw)


# ---------------------------------------------------------------------------
# Frame decoding
# ---------------------------------------------------------------------------

# Link layers by the Scapy class name a listen socket reports, mapped to the
# fixed header length in front of the IP header (None = Ethernet, parsed).
_LINK_OFFSETS = {
    "Ether": None,
    "Loopback": 4,      # DLT_NULL: 4-byte address family (lo0, utun on macOS)
    "LoopbackOpenBSD": 4,
    "CookedLinux": 16,  # Linux "any" pseudo-interface
    "CookedLinuxV2": 20,
    "IP": 0,
    "IPv6": 0,
    "Raw": 0,           # DLT_RAW
}

_IPV6_EXT_HEADERS = frozenset({0, 43, 60})  # hop-by-hop, routing, destination options


def _empty_meta(ts: float, length: int) -> Dict[str, Any]:
    return {
        "timestamp": ts,
        "protocol": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "tcp_flags": 0,
        "payload_bytes": b"",
        "ip_ttl": None,
        "ip_tos": None,
        "packet_len": length,
    }


def decode_frame(frame: bytes, link: str = "Ether", ts: float = 0.0) -> Dict[str, Any]:
    """
    Decode one captured frame into a *meta* dict.

    Args:
        frame: The raw bytes as captured, starting at the link-layer header.
        link:  Scapy class name of the link layer (``Ether``, ``Loopback`` …).
        ts:    Capture timestamp.

    Non-IP frames (ARP, LLDP …) and truncated packets come back with the
    fields that could not be read left as ``None``.
    """
    meta = _empty_meta(ts, len(frame))
    try:
        offset = _LINK_OFFSETS.get(link, 0)
        if offset is None:  # Ethernet, possibly VLAN-tagged
            offset = 14
            ethertype = _U16.unpack_from(frame, 12)[0]
            while ethertype in (0x8100, 0x88A8, 0x9100):
                ethertype = _U16.unpack_from(frame, offset + 2)[0]
                offset += 4
            if ethertype not in (0x0800, 0x86DD):
                return meta
        _decode_ip(frame, offset, meta)
    except (struct.error, IndexError, ValueError, OSError):
        pass  # truncated / malformed: keep whatever was decoded
    return meta


def _decode_ip(frame: bytes, o: int, meta: Dict[str, Any]) -> None:
    version = frame[o] >> 4
    if version == 4:
        ihl = (frame[o] & 0x0F) * 4
        total = _U16.unpack_from(frame, o + 2)[0]
        fragment_offset = _U16.unpack_from(frame, o + 6)[0] & 0x1FFF
        meta["ip_tos"] = frame[o + 1]
        meta["ip_ttl"] = frame[o + 8]
        proto = frame[o + 9]
        meta["src_ip"] = _inet_ntoa(frame[o + 12:o + 16])
        meta["dst_ip"] = _inet_ntoa(frame[o + 16:o + 20])
        # The IP total length excludes Ethernet padding; TSO-offloaded
        # outbound packets can report 0, so fall back to the capture.
        end = o + total if total >= ihl else len(frame)
        l4 = o + ihl
        if fragment_offset:
            meta["protocol"] = "other"
            meta["payload_bytes"] = frame[l4:end]
            return
    elif version == 6:
        meta["ip_tos"] = ((frame[o] & 0x0F) << 4) | (frame[o + 1] >> 4)
        payload_len = _U16.unpack_from(frame, o + 4)[0]
        proto = frame[o + 6]
        meta["ip_ttl"] = frame[o + 7]
        meta["src_ip"] = _ntop6(frame[o + 8:o + 24])
        meta["dst_ip"] = _ntop6(frame[o + 24:o + 40])
        l4 = o + 40
        end = l4 + payload_len if payload_len else len(frame)
        while proto in _IPV6_EXT_HEADERS:
            proto, hdr_len = frame[l4], (frame[l4 + 1] + 1) * 8
            l4 += hdr_len
        if proto == 44:  # fragment header
            proto = frame[l4]
            fragment_offset = _U16.unpack_from(frame, l4 + 2)[0] >> 3
            l4 += 8
            if fragment_offset:
                meta["protocol"] = "other"
                meta["payload_bytes"] = frame[l4:end]
                return
    else:
        return

    if proto == 6:
        meta["protocol"] = "tcp"
        meta["src_port"], meta["dst_port"] = _PORTS.unpack_from(frame, l4)
        data_offset = (frame[l4 + 12] >> 4) * 4
        meta["tcp_flags"] = ((frame[l4 + 12] & 0x01) << 8) | frame[l4 + 13]
        meta["payload_bytes"] = frame[l4 + data_offset:end]
    elif proto == 17:
        meta["protocol"] = "udp"
        meta["src_port"], meta["dst_port"] = _PORTS.unpack_from(frame, l4)
        meta["payload_bytes"] = frame[l4 + 8:end]
    elif proto == 1:
        meta["protocol"] = "icmp"
        if frame[l4] in (0, 8):  # echo reply / request carry data
            meta["payload_bytes"] = frame[l4 + 8:end]
    elif proto == 58 and frame[l4] == 128:
        meta["protocol"] = "icmpv6"
        meta["payload_bytes"] = frame[l4 + 8:end]
    else:
        meta["protocol"] = "other"


def packet_to_meta(pkt) -> Dict[str, Any]:
    """
    Build a *meta* dict from a Scapy packet (PCAP replay, tests).

    The packet is re-read from its raw bytes so replay sees exactly what
    live capture sees, including payloads Scapy decoded into its own layers.
    """
    return decode_frame(bytes(pkt), type(pkt).__name__, float(getattr(pkt, "time", 0.0)))


# ---------------------------------------------------------------------------
# Live capture
# ---------------------------------------------------------------------------

RawCallback = Callable[[bytes, float, int], None]


def _linktype(cls: Any) -> int:
    from scapy.config import conf
    return conf.l2types.layer2num.get(cls, 1)


def sniff_live(
    iface: str,
    engine_callback: Callable[[Dict[str, Any]], None],
    bpf_filter: Optional[str] = None,
    packet_queue_size: int = 10_000,
    raw_callback: Optional[RawCallback] = None,
    stop_event: Optional[threading.Event] = None,
) -> None:
    """
    Capture packets from *iface* and call *engine_callback* for each.

    Blocks until *stop_event* is set (or :class:`KeyboardInterrupt`).  A
    reader thread drains the capture socket into a bounded queue so bursts
    never stall the kernel buffer while the engine is busy; this thread
    decodes frames and runs the engine.

    Args:
        iface:            Network interface name (e.g. ``en0``, ``eth0``).
        engine_callback:  Function called with each packet's meta dict.
        bpf_filter:       Optional BPF capture filter string.
        packet_queue_size: Capacity of the internal packet queue.
        raw_callback:     Optional ``(frame, timestamp, linktype)`` hook
                          (used to record PCAPs for later decryption).
        stop_event:       Optional event that ends the capture when set.

    Raises:
        OSError: if the interface cannot be opened or disappears.
    """
    import scapy.all  # noqa: F401 — registers the platform capture sockets on conf
    from scapy.config import conf

    stop = stop_event or threading.Event()
    done = threading.Event()  # ends the reader even if the engine raised
    sock = conf.L2listen(iface=iface, filter=bpf_filter or None)
    pkt_queue: "queue.Queue[Tuple[str, bytes, float]]" = queue.Queue(maxsize=packet_queue_size)
    reader_error: list = []
    dropped = 0
    link_names: Dict[Any, str] = {}

    def _reader() -> None:
        nonlocal dropped
        select = type(sock).select
        buffered = getattr(sock, "buffered_frames", None)
        try:
            while not (stop.is_set() or done.is_set()):
                if not select([sock], 0.5):
                    continue
                while True:
                    cls, frame, ts = sock.recv_raw()
                    if frame is None:
                        break
                    if raw_callback is not None:
                        try:
                            raw_callback(frame, ts, _linktype(cls))
                        except Exception as exc:  # noqa: BLE001 — recording must never stop capture
                            logger.debug("raw_callback failed: %s", exc)
                    link = link_names.get(cls)
                    if link is None:
                        link = link_names[cls] = cls.__name__ if cls else "Raw"
                    try:
                        pkt_queue.put_nowait((link, frame, ts or 0.0))
                    except queue.Full:
                        dropped += 1
                        if dropped % 1000 == 0:
                            logger.warning("Packet queue full — %d packets dropped so far", dropped)
                    if buffered is None or not buffered():
                        break
        except Exception as exc:  # noqa: BLE001 — surfaced to the caller below
            reader_error.append(exc)

    reader = threading.Thread(target=_reader, name=f"bpf-{iface}", daemon=True)
    reader.start()
    logger.info("Live capture started on %s (filter: %r)", iface, bpf_filter or "none")

    try:
        while not stop.is_set():
            try:
                link, frame, ts = pkt_queue.get(timeout=0.2)
            except queue.Empty:
                if not reader.is_alive():
                    err = reader_error[0] if reader_error else None
                    raise OSError(f"capture on {iface} stopped unexpectedly: {err}")
                continue
            engine_callback(decode_frame(frame, link, ts))
    except KeyboardInterrupt:
        logger.info("Capture interrupted — stopping sniffer")
    finally:
        done.set()
        reader.join(timeout=2)
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass
        if dropped:
            logger.warning("Total packets dropped due to full queue: %d", dropped)


# ---------------------------------------------------------------------------
# PCAP replay
# ---------------------------------------------------------------------------

def replay_pcap(
    pcap_path: str,
    engine_callback: Callable[[Dict[str, Any]], None],
) -> int:
    """
    Replay packets from *pcap_path*, calling *engine_callback* for each.

    Args:
        pcap_path:        Path to a PCAP or PCAPNG file.
        engine_callback:  Function called with each packet's meta dict.

    Returns:
        The total number of packets processed.
    """
    from scapy.utils import PcapReader

    count = 0
    reader = PcapReader(pcap_path)
    try:
        for pkt in reader:
            engine_callback(packet_to_meta(pkt))
            count += 1
    finally:
        reader.close()
    logger.info("PCAP replay complete: %d packets from %s", count, pcap_path)
    return count
