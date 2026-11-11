"""
Stateful TCP/UDP flow tracking for PyNIDS.

FlowTracker maintains a connection table keyed on the canonical 5-tuple
(proto, lower-endpoint, higher-endpoint), enabling stateful analysis
across multiple packets in the same stream.

Features:
  - Bidirectional flow identification via canonical key ordering
  - Initiator inference: a flow first seen through its SYN-ACK, or through a
    reply from a well-known port, is still attributed to the real client
  - TCP state machine (NEW → ESTABLISHED → CLOSING → CLOSED) and a compact
    per-side flag history ("ShADdFf", Zeek style)
  - A reused 5-tuple (new SYN after a close, or a UDP exchange after a long
    silence) starts a fresh flow instead of inflating the old one
  - Idle timeout and periodic GC to bound memory usage
  - Per-direction byte and packet counters for exfiltration detection
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class FlowState(str, Enum):
    NEW = "new"
    ESTABLISHED = "established"
    CLOSING = "closing"
    CLOSED = "closed"


@dataclass
class Flow:
    """
    Represents a single bidirectional network flow.

    Attributes:
        flow_id:          MD5 of the canonical 5-tuple (stable across packet direction).
        protocol:         'tcp' | 'udp' | 'icmp'
        src_ip:           IP that initiated the flow (the client).
        src_port:         Initiating port.
        dst_ip:           Responder IP.
        dst_port:         Responder port / service.
        state:            Current TCP state-machine state.
        start_time:       Unix epoch of the first packet in this flow.
        last_seen:        Unix epoch of the most recent packet.
        packet_count:     Total packets observed (both directions).
        byte_count:       Total payload bytes (both directions).
        bytes_from_src:   Payload bytes sent by the initiator.
        packets_from_src: Packets sent by the initiator.
        tcp_flags_seen:   Bitmask union of all TCP flags encountered.
        history:          Flag/data history, upper case = initiator, lower = responder:
                          S syn, H syn-ack, A ack, D data, F fin, R reset.
        initiator_inferred: True when the first packet seen was not the client's opening
                          packet and the client was worked out from flags / ports.
        app_proto:        Application protocol the dissector recognised (http, tls, dns …).
        server_name:      TLS SNI / HTTP Host / DNS name seen on the flow.
        app:              Local program that owns the flow, when attributed.
    """

    flow_id: str
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    state: FlowState = FlowState.NEW
    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packet_count: int = 0
    byte_count: int = 0
    bytes_from_src: int = 0  # payload bytes sent by the initiator (outbound for local clients)
    tcp_flags_seen: int = 0
    packets_from_src: int = 0
    history: str = ""
    initiator_inferred: bool = False
    app_proto: Optional[str] = None
    server_name: Optional[str] = None
    app: Optional[str] = None
    _fin_sides: int = 0  # bit 0: initiator sent FIN, bit 1: responder sent FIN

    @property
    def duration(self) -> float:
        """Elapsed seconds from the first to the last observed packet."""
        return self.last_seen - self.start_time

    @property
    def avg_packet_size(self) -> float:
        if self.packet_count == 0:
            return 0.0
        return self.byte_count / self.packet_count

    @property
    def bytes_to_src(self) -> int:
        """Payload bytes sent by the responder."""
        return self.byte_count - self.bytes_from_src

    @property
    def packets_to_src(self) -> int:
        return self.packet_count - self.packets_from_src

    @property
    def outcome(self) -> str:
        """
        What became of the connection, in one word:

        ``attempt``      SYN sent, nothing came back (filtered port, dead host)
        ``rejected``     the responder answered the SYN with a reset (closed port)
        ``established``  handshake completed, still open
        ``reset``        torn down by a reset after data flowed
        ``closed``       both sides finished normally
        ``closing``      one side has finished
        ``active``       non-TCP traffic, or TCP picked up mid-stream
        """
        if self.protocol != "tcp" or not self.tcp_flags_seen:
            return "active"
        h = self.history
        if "R" in h or "r" in h:
            if "S" in h and "h" not in h and "d" not in h and "D" not in h:
                return "rejected" if "r" in h else "reset"
            return "reset"
        if self.state == FlowState.CLOSED:
            return "closed"
        if self.state == FlowState.CLOSING:
            return "closing"
        if "S" in h and "h" not in h and self.packets_to_src == 0:
            return "attempt"
        if self.state == FlowState.ESTABLISHED:
            return "established"
        return "active"

    def is_idle(self, idle_timeout: float) -> bool:
        return (time.time() - self.last_seen) > idle_timeout

    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe snapshot for the API."""
        return {
            "flow_id": self.flow_id,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "state": self.state.value,
            "outcome": self.outcome,
            "history": self.history,
            "start_time": self.start_time,
            "last_seen": self.last_seen,
            "duration": round(self.duration, 3),
            "packets": self.packet_count,
            "packets_out": self.packets_from_src,
            "packets_in": self.packets_to_src,
            "bytes": self.byte_count,
            "bytes_out": self.bytes_from_src,
            "bytes_in": self.bytes_to_src,
            "app_proto": self.app_proto,
            "server_name": self.server_name,
            "app": self.app,
            "initiator_inferred": self.initiator_inferred,
        }


_Key = Tuple[str, Tuple[str, int], Tuple[str, int]]


class FlowTracker:
    """
    Maintains an in-memory connection table.

    The table is keyed on the canonical 5-tuple so that both directions of
    a conversation share the same entry.

    Args:
        max_flows:       Upper bound on tracked flows (oldest pruned when hit).
        idle_timeout:    Seconds of inactivity before a flow is considered expired.
        udp_session_gap: A non-TCP 5-tuple silent for longer than this starts a
                         new flow, so periodic check-ins count as separate
                         connections (0 disables).
        closed_linger:   Seconds a closed TCP flow stays in the table.
    """

    # TCP flag bit positions
    _FLAG_FIN = 0x01
    _FLAG_SYN = 0x02
    _FLAG_RST = 0x04
    _FLAG_ACK = 0x10

    _HISTORY_MAX = 12

    def __init__(
        self,
        max_flows: int = 100_000,
        idle_timeout: float = 300.0,
        udp_session_gap: float = 60.0,
        closed_linger: float = 60.0,
    ) -> None:
        self.max_flows = max_flows
        self.idle_timeout = idle_timeout
        self.udp_session_gap = udp_session_gap
        self.closed_linger = closed_linger
        self._flows: Dict[_Key, Flow] = {}
        self._last_gc: float = time.time()
        self._newest: float = 0.0  # latest packet timestamp seen (packet clock)
        self.total_flows: int = 0  # flows ever created

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update(self, meta: dict) -> Optional[Flow]:
        """
        Process one packet's metadata and return the updated Flow object.

        Returns None if the packet lacks enough network-layer information.
        """
        proto = meta.get("protocol")
        src_ip = meta.get("src_ip")
        dst_ip = meta.get("dst_ip")
        if not (proto and src_ip and dst_ip):
            return None

        src_port = meta.get("src_port") or 0
        dst_port = meta.get("dst_port") or 0
        ts = meta.get("timestamp")
        if ts is None:
            ts = time.time()
        tcp_flags = meta.get("tcp_flags") or 0
        key = self._tuple_key(proto, src_ip, src_port, dst_ip, dst_port)

        flow = self._flows.get(key)
        if flow is not None and self._is_new_session(flow, proto, tcp_flags, ts):
            flow = None  # same 5-tuple, new conversation: replaced below
        if flow is None:
            # A flood of new flows (SYN flood, scan) must not outgrow the
            # table between the periodic GC passes.
            if key not in self._flows and len(self._flows) >= self.max_flows:
                self._gc(force_evict=True)
            flow = self._new_flow(proto, src_ip, src_port, dst_ip, dst_port, tcp_flags, ts)
            self._flows[key] = flow
            self.total_flows += 1

        flow.last_seen = ts
        if ts > self._newest:
            self._newest = ts
        from_src = src_ip == flow.src_ip and src_port == flow.src_port
        flow.packet_count += 1
        payload_len = len(meta.get("payload_bytes") or b"")
        flow.byte_count += payload_len
        if from_src:
            flow.packets_from_src += 1
            flow.bytes_from_src += payload_len

        if proto == "tcp":
            self._advance_tcp(flow, tcp_flags, from_src, payload_len)

        self._maybe_gc()
        return flow

    def get(self, flow_id: str) -> Optional[Flow]:
        """Return the Flow for *flow_id*, or None if not tracked."""
        for flow in self._flows.values():
            if flow.flow_id == flow_id:
                return flow
        return None

    @property
    def active_count(self) -> int:
        """Number of flows currently in the connection table."""
        return len(self._flows)

    def snapshot(self, limit: int = 200, sort: str = "recent") -> List[Dict[str, Any]]:
        """
        The connection table as dicts, for the API.

        *sort*: ``recent`` (last packet), ``bytes``, ``duration`` or ``packets``.
        The table is copied first, so this is safe to call from another
        thread while packets are being processed.
        """
        keys = {
            "recent": lambda f: f.last_seen,
            "bytes": lambda f: f.byte_count,
            "duration": lambda f: f.duration,
            "packets": lambda f: f.packet_count,
        }
        for _ in range(3):
            try:
                flows = list(self._flows.values())
                break
            except RuntimeError:  # table resized by the capture thread mid-copy
                continue
        else:
            flows = []
        flows.sort(key=keys.get(sort, keys["recent"]), reverse=True)
        return [f.to_dict() for f in flows[:max(0, limit)]]

    def counts(self) -> Dict[str, int]:
        """Flows by state and protocol (cheap summary for dashboards)."""
        out: Dict[str, int] = {"total": self.total_flows}
        try:
            flows = list(self._flows.values())
        except RuntimeError:
            return out
        out["active"] = len(flows)
        for f in flows:
            out[f.protocol] = out.get(f.protocol, 0) + 1
            out[f.state.value] = out.get(f.state.value, 0) + 1
        return out

    def make_key(
        self,
        proto: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> str:
        """Public wrapper around the canonical key builder."""
        return self._make_key(proto, src_ip, src_port, dst_ip, dst_port)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _tuple_key(proto: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> _Key:
        ep1 = (src_ip, src_port)
        ep2 = (dst_ip, dst_port)
        return (proto, ep1, ep2) if ep1 < ep2 else (proto, ep2, ep1)

    @staticmethod
    def _make_key(
        proto: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> str:
        """
        Build a canonical, direction-independent MD5 key for the flow.

        Sorting the two endpoints ensures that the packet from A→B and
        the reply from B→A map to the same table entry.
        """
        ep1 = (src_ip, src_port)
        ep2 = (dst_ip, dst_port)
        low, high = (ep1, ep2) if ep1 < ep2 else (ep2, ep1)
        raw = f"{proto}:{low[0]}:{low[1]}:{high[0]}:{high[1]}"
        return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()

    def _is_new_session(self, flow: Flow, proto: str, tcp_flags: int, ts: float) -> bool:
        """Does this packet start a new conversation on an already-known 5-tuple?"""
        if proto == "tcp":
            # A fresh SYN after the old connection ended: the port pair was reused.
            pure_syn = tcp_flags & self._FLAG_SYN and not tcp_flags & self._FLAG_ACK
            return bool(pure_syn) and flow.state in (FlowState.CLOSING, FlowState.CLOSED)
        return bool(self.udp_session_gap) and ts - flow.last_seen > self.udp_session_gap

    def _new_flow(self, proto: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                  tcp_flags: int, ts: float) -> Flow:
        # Who opened the conversation?  Normally the sender of the first
        # packet.  But capture can start mid-stream, and the first packet we
        # see may be the server's: a SYN-ACK, or a reply from a well-known port.
        reverse = False
        if proto == "tcp" and tcp_flags & self._FLAG_SYN:
            reverse = bool(tcp_flags & self._FLAG_ACK)
        elif 0 < src_port < 1024 <= dst_port:
            reverse = True
        flow_id = self._make_key(proto, src_ip, src_port, dst_ip, dst_port)
        if reverse:
            return Flow(flow_id=flow_id, protocol=proto, src_ip=dst_ip, src_port=dst_port,
                        dst_ip=src_ip, dst_port=src_port, start_time=ts, last_seen=ts,
                        initiator_inferred=True)
        return Flow(flow_id=flow_id, protocol=proto, src_ip=src_ip, src_port=src_port,
                    dst_ip=dst_ip, dst_port=dst_port, start_time=ts, last_seen=ts)

    def _advance_tcp(self, flow: Flow, tcp_flags: int, from_src: bool, payload_len: int) -> None:
        if not tcp_flags:
            return
        flow.tcp_flags_seen |= tcp_flags
        syn = tcp_flags & self._FLAG_SYN
        ack = tcp_flags & self._FLAG_ACK
        fin = tcp_flags & self._FLAG_FIN
        rst = tcp_flags & self._FLAG_RST

        letters = ""
        if syn:
            letters += "H" if ack else "S"
        elif ack and not (fin or rst or payload_len):
            letters += "A"
        if payload_len:
            letters += "D"
        if fin:
            letters += "F"
        if rst:
            letters += "R"
        if letters and len(flow.history) < self._HISTORY_MAX:
            for letter in letters if from_src else letters.lower():
                if letter not in flow.history:
                    flow.history += letter

        if rst:
            flow.state = FlowState.CLOSED
        elif fin:
            flow._fin_sides |= 1 if from_src else 2
            flow.state = FlowState.CLOSED if flow._fin_sides == 3 else FlowState.CLOSING
        elif syn and not ack:
            flow.state = FlowState.NEW
        elif ack and flow.state == FlowState.NEW:
            flow.state = FlowState.ESTABLISHED

    def _maybe_gc(self) -> None:
        """Periodically remove idle flows to bound memory."""
        if time.time() - self._last_gc < 30.0:
            return
        self._gc()

    def _gc(self, force_evict: bool = False) -> None:
        self._last_gc = time.time()
        # Idle is measured on the packet clock, so a PCAP replay of old
        # traffic doesn't expire every flow as soon as it is created.
        now = self._newest or time.time()
        linger = min(self.closed_linger, self.idle_timeout)
        expired = [
            key
            for key, f in self._flows.items()
            if now - f.last_seen > (linger if f.state == FlowState.CLOSED else self.idle_timeout)
        ]
        for key in expired:
            del self._flows[key]

        # Still at capacity: evict the least recently seen, down to 90% so
        # the next new flow doesn't immediately trigger another sort.
        limit = int(self.max_flows * 0.9) if force_evict else self.max_flows
        if len(self._flows) > limit:
            oldest = sorted(self._flows.items(), key=lambda kv: kv[1].last_seen)
            for key, _ in oldest[: len(self._flows) - limit]:
                del self._flows[key]
