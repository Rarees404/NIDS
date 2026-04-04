"""
Packet capture layer for PyNIDS.

Provides two capture modes:

- **Live capture** via Scapy's :class:`~scapy.sendrecv.AsyncSniffer`,
  reading from a network interface in a background thread and feeding
  packets to the engine via a thread-safe queue.

- **PCAP replay** via Scapy's :class:`~scapy.utils.PcapReader`,
  reading packets sequentially from a PCAP/PCAPNG file.

Both modes produce a normalised *meta* dictionary consumed by the engine.

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

import queue
import logging
from typing import Any, Callable, Dict, Generator, Optional

from scapy.all import (
    AsyncSniffer,
    PcapReader,
    IP, IPv6,
    TCP, UDP, ICMP, ICMPv6EchoRequest,
    Raw,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Packet normalisation
# ---------------------------------------------------------------------------

def packet_to_meta(pkt) -> Dict[str, Any]:
    """
    Extract a normalised metadata dictionary from a Scapy packet.

    Non-IP packets (e.g. ARP, pure Ethernet frames) are returned with
    most fields set to None; the engine handles None gracefully.
    """
    meta: Dict[str, Any] = {
        "timestamp": float(getattr(pkt, "time", 0.0)),
        "protocol": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "tcp_flags": 0,
        "payload_bytes": b"",
        "ip_ttl": None,
        "ip_tos": None,
        "packet_len": len(pkt),
    }

    # IPv4
    if IP in pkt:
        meta["src_ip"] = pkt[IP].src
        meta["dst_ip"] = pkt[IP].dst
        meta["ip_ttl"] = pkt[IP].ttl
        meta["ip_tos"] = pkt[IP].tos

    # IPv6
    elif IPv6 in pkt:
        meta["src_ip"] = pkt[IPv6].src
        meta["dst_ip"] = pkt[IPv6].dst
        meta["ip_ttl"] = pkt[IPv6].hlim
        meta["ip_tos"] = pkt[IPv6].tc

    # Transport layer
    if TCP in pkt:
        meta["protocol"] = "tcp"
        meta["src_port"] = int(pkt[TCP].sport)
        meta["dst_port"] = int(pkt[TCP].dport)
        meta["tcp_flags"] = int(pkt[TCP].flags)
    elif UDP in pkt:
        meta["protocol"] = "udp"
        meta["src_port"] = int(pkt[UDP].sport)
        meta["dst_port"] = int(pkt[UDP].dport)
    elif ICMP in pkt:
        meta["protocol"] = "icmp"
    elif ICMPv6EchoRequest in pkt:
        meta["protocol"] = "icmpv6"
    elif meta["src_ip"] is not None:
        meta["protocol"] = "other"

    # Payload
    if Raw in pkt:
        meta["payload_bytes"] = bytes(pkt[Raw].load or b"")

    return meta


# ---------------------------------------------------------------------------
# Live capture
# ---------------------------------------------------------------------------

def sniff_live(
    iface: str,
    engine_callback: Callable[[Dict[str, Any]], None],
    bpf_filter: Optional[str] = None,
    packet_queue_size: int = 10_000,
) -> None:
    """
    Capture packets from *iface* and call *engine_callback* for each.

    This function blocks until a :class:`KeyboardInterrupt` is received.
    Packets are handed off to a background thread via a bounded queue to
    prevent the capture callback from blocking the sniffer thread.

    Args:
        iface:            Network interface name (e.g. ``en0``, ``eth0``).
        engine_callback:  Function called with each packet's meta dict.
        bpf_filter:       Optional BPF capture filter string.
        packet_queue_size: Capacity of the internal packet queue.
    """
    pkt_queue: queue.Queue = queue.Queue(maxsize=packet_queue_size)
    dropped = 0

    def _on_packet(pkt) -> None:
        nonlocal dropped
        meta = packet_to_meta(pkt)
        try:
            pkt_queue.put_nowait(meta)
        except queue.Full:
            dropped += 1
            if dropped % 1000 == 0:
                logger.warning("Packet queue full — %d packets dropped so far", dropped)

    sniffer = AsyncSniffer(
        iface=iface,
        store=False,
        prn=_on_packet,
        filter=bpf_filter or "",
    )
    sniffer.start()
    logger.info("Live capture started on %s (filter: %r)", iface, bpf_filter or "none")

    try:
        while True:
            try:
                meta = pkt_queue.get(timeout=0.2)
                engine_callback(meta)
            except queue.Empty:
                continue
    except KeyboardInterrupt:
        logger.info("Capture interrupted — stopping sniffer")
    finally:
        sniffer.stop()
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
    count = 0
    reader = PcapReader(pcap_path)
    try:
        for pkt in reader:
            meta = packet_to_meta(pkt)
            engine_callback(meta)
            count += 1
    finally:
        reader.close()
    logger.info("PCAP replay complete: %d packets from %s", count, pcap_path)
    return count
