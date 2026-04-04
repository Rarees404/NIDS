"""Tests for the stateful flow tracker."""
from __future__ import annotations

import time
import pytest
from pynids.flow.tracker import FlowTracker, FlowState
from tests.conftest import make_meta


class TestFlowTracker:
    def test_new_flow_created(self):
        tracker = FlowTracker()
        meta = make_meta(src_ip="1.2.3.4", dst_ip="5.6.7.8", src_port=100, dst_port=80)
        flow = tracker.update(meta)
        assert flow is not None
        assert tracker.active_count == 1

    def test_same_flow_accumulates(self):
        tracker = FlowTracker()
        meta = make_meta(
            src_ip="1.2.3.4", dst_ip="5.6.7.8", src_port=1234, dst_port=80, payload=b"abc"
        )
        for _ in range(5):
            flow = tracker.update(meta)
        assert flow.packet_count == 5
        assert flow.byte_count == 15  # 5 × 3 bytes

    def test_bidirectional_key(self):
        """Reply packet (src/dst swapped) should map to the same flow."""
        tracker = FlowTracker()
        fwd = make_meta(src_ip="A", dst_ip="B", src_port=1234, dst_port=80, protocol="tcp")
        rev = make_meta(src_ip="B", dst_ip="A", src_port=80, dst_port=1234, protocol="tcp")

        f1 = tracker.update(fwd)
        f2 = tracker.update(rev)
        assert f1.flow_id == f2.flow_id
        assert tracker.active_count == 1

    def test_different_protocols_different_flows(self):
        tracker = FlowTracker()
        tcp = make_meta(src_ip="A", dst_ip="B", src_port=1, dst_port=80, protocol="tcp")
        udp = make_meta(src_ip="A", dst_ip="B", src_port=1, dst_port=80, protocol="udp")
        tracker.update(tcp)
        tracker.update(udp)
        assert tracker.active_count == 2

    def test_tcp_state_machine_new_to_established(self):
        tracker = FlowTracker()
        # SYN
        syn = make_meta(src_ip="C", dst_ip="D", dst_port=443, tcp_flags=0x02)
        flow = tracker.update(syn)
        assert flow.state == FlowState.NEW

        # SYN+ACK then ACK
        ack = make_meta(src_ip="D", dst_ip="C", dst_port=syn["src_port"], tcp_flags=0x10)
        flow = tracker.update(ack)
        assert flow.state == FlowState.ESTABLISHED

    def test_tcp_fin_moves_to_closing(self):
        tracker = FlowTracker()
        syn = make_meta(src_ip="E", dst_ip="F", dst_port=80, tcp_flags=0x02)
        tracker.update(syn)
        ack = make_meta(src_ip="E", dst_ip="F", dst_port=80, tcp_flags=0x10)
        tracker.update(ack)
        fin = make_meta(src_ip="E", dst_ip="F", dst_port=80, tcp_flags=0x01)
        flow = tracker.update(fin)
        assert flow.state == FlowState.CLOSING

    def test_missing_ips_returns_none(self):
        tracker = FlowTracker()
        meta = {"protocol": "tcp", "src_port": 1234, "dst_port": 80}
        result = tracker.update(meta)
        assert result is None
        assert tracker.active_count == 0

    def test_flow_duration(self):
        tracker = FlowTracker()
        t0 = 1000.0
        meta = make_meta(src_ip="G", dst_ip="H", dst_port=443, timestamp=t0)
        tracker.update(meta)
        meta2 = make_meta(src_ip="G", dst_ip="H", dst_port=443, timestamp=t0 + 5.0)
        flow = tracker.update(meta2)
        assert abs(flow.duration - 5.0) < 0.1

    def test_make_key_is_deterministic_and_symmetric(self):
        k1 = FlowTracker._make_key("tcp", "1.2.3.4", 1234, "5.6.7.8", 80)
        k2 = FlowTracker._make_key("tcp", "5.6.7.8", 80, "1.2.3.4", 1234)
        assert k1 == k2
        assert len(k1) == 32  # MD5 hex
