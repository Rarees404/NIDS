"""Raw frame decoding: must match Scapy field-for-field and keep payloads Scapy swallows."""
from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Dot1Q, Ether, IPv6, Loopback, Raw

from pynids.engine import DetectionEngine
from pynids.enrich import Enricher
from pynids.sniffer import decode_frame, packet_to_meta

E = dict(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def test_ipv4_tcp_fields():
    f = bytes(Ether(**E) / IP(src="10.0.0.2", dst="1.2.3.4", ttl=63, tos=8)
              / TCP(sport=50000, dport=443, flags="SEC"))
    m = decode_frame(f, "Ether", 1.5)
    assert (m["src_ip"], m["dst_ip"], m["src_port"], m["dst_port"]) == ("10.0.0.2", "1.2.3.4", 50000, 443)
    assert m["protocol"] == "tcp" and m["tcp_flags"] == 0xC2 and m["ip_ttl"] == 63 and m["ip_tos"] == 8
    assert m["timestamp"] == 1.5 and m["packet_len"] == len(f)


def test_dns_payload_survives():
    # Scapy decodes this into a DNS layer and leaves no Raw payload.
    f = bytes(Ether(**E) / IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=5555, dport=53)
              / DNS(rd=1, qd=DNSQR(qname="evil.example.com")))
    m = decode_frame(f, "Ether", 0)
    assert m["payload_bytes"] and b"evil" in m["payload_bytes"]


def test_vlan_ipv6_loopback_and_padding():
    v = decode_frame(bytes(Ether(**E) / Dot1Q(vlan=5) / IP(src="10.0.0.2", dst="10.0.0.1")
                           / UDP(sport=1, dport=2) / Raw(b"hi")), "Ether", 0)
    assert v["payload_bytes"] == b"hi"
    six = decode_frame(bytes(Ether(**E) / IPv6(src="fe80::1", dst="2001:db8::5", hlim=9)
                             / TCP(sport=3, dport=443, flags="S")), "Ether", 0)
    assert six["src_ip"] == "fe80::1" and six["dst_ip"] == "2001:db8::5" and six["ip_ttl"] == 9
    lo = decode_frame(bytes(Loopback(type=2) / IP(src="127.0.0.1", dst="127.0.0.1")
                            / TCP(sport=50336, dport=1337, flags="S")), "Loopback", 0)
    assert lo["dst_port"] == 1337 and lo["tcp_flags"] == 0x02
    # Ethernet pads short frames to 60 bytes; the padding is not payload.
    small = bytes(Ether(**E) / IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=1, dport=2) / Raw(b"x"))
    assert decode_frame(small + b"\x00" * 20, "Ether", 0)["payload_bytes"] == b"x"


def test_truncated_and_non_ip_frames_do_not_raise():
    f = bytes(Ether(**E) / IP(src="10.0.0.2", dst="1.2.3.4") / TCP(sport=1, dport=2))
    assert decode_frame(f[:30], "Ether", 0)["src_port"] is None
    assert decode_frame(b"\x00" * 10, "Ether", 0)["protocol"] is None


def test_packet_to_meta_uses_raw_bytes():
    pkt = Ether(bytes(Ether(**E) / IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=5555, dport=53)
                      / DNS(rd=1, qd=DNSQR(qname="a.example"))))
    assert packet_to_meta(pkt)["payload_bytes"]


def test_dns_answer_names_later_connections():
    """End to end: a live DNS answer lets later traffic to that IP carry its hostname."""
    enricher = Enricher(local_ips=frozenset({"10.0.0.2", "127.0.0.1", "::1"}))
    engine = DetectionEngine(config={}, enricher=enricher)
    answer = bytes(Ether(**E) / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=53, dport=5555)
                   / DNS(id=1, qr=1, qd=DNSQR(qname="api.example.org"),
                         an=DNSRR(rrname="api.example.org", type="A", rdata="93.184.216.34")))
    engine.process_packet(decode_frame(answer, "Ether", 1.0))
    assert enricher.hostnames.lookup("93.184.216.34") == "api.example.org"


def test_sniff_live_drains_buffered_frames_and_stops(monkeypatch):
    import threading
    import scapy.all  # noqa: F401
    from scapy.config import conf
    from pynids import sniffer

    frames = [bytes(Ether(**E) / IP(src="10.0.0.2", dst="1.2.3.4") / TCP(sport=40000 + i, dport=443, flags="S"))
              for i in range(5)]

    class FakeBpf:
        def __init__(self, iface=None, filter=None):
            self.pending = [(Ether, f, 100.0 + i) for i, f in enumerate(frames)]
            self.closed = False

        @staticmethod
        def select(socks, remain=None):
            return [s for s in socks if s.pending]

        def recv_raw(self):
            return self.pending.pop(0) if self.pending else (None, None, None)

        def buffered_frames(self):
            return len(self.pending)

        def close(self):
            self.closed = True

    monkeypatch.setattr(conf, "L2listen", FakeBpf)
    stop = threading.Event()
    seen, recorded = [], []

    def on_packet(meta):
        seen.append(meta)
        if len(seen) == len(frames):
            stop.set()

    sniffer.sniff_live("en0", on_packet, raw_callback=lambda f, ts, lt: recorded.append((ts, lt)),
                       stop_event=stop)
    assert [m["src_port"] for m in seen] == [40000 + i for i in range(5)]
    assert seen[0]["timestamp"] == 100.0
    assert recorded[0] == (100.0, 1)  # Ethernet link type for the PCAP recorder


def test_pcap_ring_writes_raw_frames(tmp_path):
    from scapy.utils import rdpcap
    from pynids.service.recorder import PcapRing
    ring = PcapRing(tmp_path, max_mb=1, max_files=3)
    f = bytes(Ether(**E) / IP(src="10.0.0.2", dst="1.2.3.4") / TCP(sport=1, dport=443, flags="S"))
    ring.write(f, 1234.5, 1)
    lo = bytes(Loopback(type=2) / IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=2, dport=3))
    ring.write(lo, 1235.0, 0)  # link type change → new file
    ring.close()
    files = sorted(tmp_path.glob("*.pcap"))
    assert len(files) == 2
    eth = rdpcap(str(files[0]))
    assert len(eth) == 1 and eth[0][TCP].dport == 443 and float(eth[0].time) == 1234.5
    assert rdpcap(str(files[1]))[0][TCP].dport == 3
