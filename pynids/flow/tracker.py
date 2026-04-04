"""
Stateful TCP/UDP flow tracking for PyNIDS.

FlowTracker maintains a connection table keyed on the canonical 5-tuple
(proto, lower-endpoint, higher-endpoint), enabling stateful analysis
across multiple packets in the same stream.

Features:
  - Bidirectional flow identification via canonical key ordering
  - TCP state machine (NEW → ESTABLISHED → CLOSING)
  - Idle timeout and periodic GC to bound memory usage
  - Per-flow byte and packet counters for exfiltration detection
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional


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
        src_ip:           IP that initiated the flow (first packet seen).
        src_port:         Initiating port.
        dst_ip:           Responder IP.
        dst_port:         Responder port / service.
        state:            Current TCP state-machine state.
        start_time:       Unix epoch of the first packet in this flow.
        last_seen:        Unix epoch of the most recent packet.
        packet_count:     Total packets observed (both directions).
        byte_count:       Total payload bytes (both directions).
        tcp_flags_seen:   Bitmask union of all TCP flags encountered.
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
    tcp_flags_seen: int = 0

    @property
    def duration(self) -> float:
        """Elapsed seconds from the first to the last observed packet."""
        return self.last_seen - self.start_time

    @property
    def avg_packet_size(self) -> float:
        if self.packet_count == 0:
            return 0.0
        return self.byte_count / self.packet_count

    def is_idle(self, idle_timeout: float) -> bool:
        return (time.time() - self.last_seen) > idle_timeout


class FlowTracker:
    """
    Maintains an in-memory connection table.

    The table is keyed on a canonical flow ID derived from the 5-tuple
    so that both directions of a conversation share the same entry.

    Args:
        max_flows:    Upper bound on tracked flows (oldest pruned when hit).
        idle_timeout: Seconds of inactivity before a flow is considered expired.
    """

    # TCP flag bit positions
    _FLAG_FIN = 0x01
    _FLAG_SYN = 0x02
    _FLAG_RST = 0x04
    _FLAG_ACK = 0x10

    def __init__(self, max_flows: int = 100_000, idle_timeout: float = 300.0) -> None:
        self.max_flows = max_flows
        self.idle_timeout = idle_timeout
        self._flows: Dict[str, Flow] = {}
        self._last_gc: float = time.time()

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
        flow_id = self._make_key(proto, src_ip, src_port, dst_ip, dst_port)

        if flow_id not in self._flows:
            flow = Flow(
                flow_id=flow_id,
                protocol=proto,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                start_time=meta.get("timestamp", time.time()),
            )
            self._flows[flow_id] = flow
        else:
            flow = self._flows[flow_id]

        flow.last_seen = meta.get("timestamp", time.time())
        flow.packet_count += 1
        flow.byte_count += len(meta.get("payload_bytes", b""))

        # Advance TCP state machine
        tcp_flags = meta.get("tcp_flags", 0)
        if tcp_flags:
            flow.tcp_flags_seen |= tcp_flags
            if tcp_flags & self._FLAG_SYN and not (tcp_flags & self._FLAG_ACK):
                flow.state = FlowState.NEW
            elif tcp_flags & self._FLAG_ACK and flow.state == FlowState.NEW:
                flow.state = FlowState.ESTABLISHED
            elif tcp_flags & (self._FLAG_FIN | self._FLAG_RST):
                flow.state = FlowState.CLOSING

        self._maybe_gc()
        return flow

    def get(self, flow_id: str) -> Optional[Flow]:
        """Return the Flow for *flow_id*, or None if not tracked."""
        return self._flows.get(flow_id)

    @property
    def active_count(self) -> int:
        """Number of flows currently in the connection table."""
        return len(self._flows)

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

    def _maybe_gc(self) -> None:
        """Periodically remove idle flows to bound memory."""
        now = time.time()
        if now - self._last_gc < 30.0:
            return
        expired = [
            fid
            for fid, f in self._flows.items()
            if f.is_idle(self.idle_timeout)
        ]
        for fid in expired:
            del self._flows[fid]

        # If still over capacity, evict oldest-seen entries
        if len(self._flows) > self.max_flows:
            oldest = sorted(self._flows.items(), key=lambda kv: kv[1].last_seen)
            for fid, _ in oldest[: len(self._flows) - self.max_flows]:
                del self._flows[fid]

        self._last_gc = now
