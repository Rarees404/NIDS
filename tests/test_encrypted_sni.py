"""QUIC Initial decryption, TLS reassembly, and DNS answer parsing."""
from __future__ import annotations

import struct

import pytest

from pynids.protocols import dissector
from pynids.protocols.dissector import _parse_tls_client_hello, dissect
from pynids.protocols.quic_crypto import (
    QUIC_V1,
    QUIC_V2,
    QuicClientHelloAssembler,
    build_client_initial,
    decrypt_client_initial,
    derive_client_initial_keys,
    encode_varint,
    read_varint,
)
from tests.conftest import make_meta


def client_hello(sni: str, alpn=("h2",), key_share_len: int = 1216, ech: bool = False) -> bytes:
    """A TLS 1.3 ClientHello handshake message with GREASE and a PQ-sized key share."""
    def ext(t: int, body: bytes) -> bytes:
        return struct.pack("!HH", t, len(body)) + body

    name = sni.encode()
    alpn_list = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
    exts = b"".join([
        ext(0x3A3A, b""),
        ext(0x0033, struct.pack("!HHH", key_share_len + 4, 0x11EC, key_share_len) + b"\x00" * key_share_len),
        ext(0x0000, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name),
        ext(0x0010, struct.pack("!H", len(alpn_list)) + alpn_list),
        ext(0x000A, struct.pack("!HHH", 4, 0x2A2A, 0x001D)),
    ] + ([ext(0xFE0D, b"\x00")] if ech else []))
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack("!HHH", 4, 0x0A0A, 0x1301)
            + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    return b"\x01" + len(body).to_bytes(3, "big") + body


class TestQuicCrypto:
    def test_rfc9001_initial_key_vectors(self):
        # RFC 9001 Appendix A.1
        keys = derive_client_initial_keys(bytes.fromhex("8394c8f03e515708"))
        assert keys.key.hex() == "1f369613dd76d5467730efcbe3b1a22d"
        assert keys.iv.hex() == "fa044b2f42a3fd3b46fb255c"
        assert keys.hp.hex() == "9f50449e04a0e810283a1e9933adedd2"

    @pytest.mark.parametrize("value", [0, 63, 64, 16383, 16384, 1073741823, 1073741824])
    def test_varint_roundtrip(self, value):
        assert read_varint(encode_varint(value), 0) == (value, len(encode_varint(value)))

    @pytest.mark.parametrize("version", [QUIC_V1, QUIC_V2])
    def test_initial_roundtrip(self, version):
        frames = [(0, b"\x01\x00\x00\x02hi")]
        pkt = build_client_initial(b"\x01" * 8, b"\x02" * 4, frames, packet_number=7, version=version)
        assert len(pkt) >= 1200
        out = decrypt_client_initial(pkt)
        assert out is not None
        assert out.version == version and out.packet_number == 7
        assert out.crypto_frames == frames

    def test_tampered_packet_is_rejected(self):
        pkt = bytearray(build_client_initial(b"\x01" * 8, b"", [(0, b"abc")]))
        pkt[-1] ^= 0xFF
        assert decrypt_client_initial(bytes(pkt)) is None

    def test_non_quic_is_rejected(self):
        assert decrypt_client_initial(b"\x17\x03\x03" + b"\x00" * 100) is None

    def test_assembler_out_of_order(self):
        asm = QuicClientHelloAssembler()
        hello = client_hello("example.org")
        half = len(hello) // 2
        assert asm.add(b"k", [(half, hello[half:])]) is None
        assert asm.add(b"k", [(0, hello[:half])]) == hello
        # Reported once only.
        assert asm.add(b"k", [(0, hello)]) is None


class TestQuicSniThroughDissector:
    def test_sni_from_two_initial_packets(self):
        hello = client_hello("www.youtube.com", alpn=("h3",))
        half = len(hello) // 2
        dcid, scid = b"\x09" * 8, b"\x07" * 8
        p1 = build_client_initial(dcid, scid, [(0, hello[:half])], packet_number=0)
        p2 = build_client_initial(dcid, scid, [(half, hello[half:])], packet_number=1)
        meta1 = make_meta(src_ip="10.0.0.9", dst_ip="142.250.74.46", src_port=61000,
                          dst_port=443, protocol="udp", payload=p1)
        meta2 = dict(meta1, payload_bytes=p2)
        first = dissect(meta1)["quic"]
        assert first["decrypted"] and "sni" not in first
        second = dissect(meta2)["quic"]
        assert second["sni"] == "www.youtube.com"
        assert second["alpn"] == ["h3"]
        assert second["client_hello_complete"]


class TestTls:
    def test_split_client_hello_is_reassembled(self):
        hello = client_hello("static.hotjar.com")
        record = b"\x16\x03\x01" + len(hello).to_bytes(2, "big") + hello
        meta = make_meta(src_ip="10.0.0.9", dst_ip="18.155.68.92", src_port=61001,
                         dst_port=443, payload=record[:500])
        assert dissect(meta)["tls"] == {"partial": True}
        tls = dissect(dict(meta, payload_bytes=record[500:]))["tls"]
        assert tls["sni"] == "static.hotjar.com"
        assert tls["alpn"] == ["h2"]

    def test_grease_is_excluded_from_ja3(self):
        hello = client_hello("a.example")
        tls = _parse_tls_client_hello(b"\x16\x03\x01" + len(hello).to_bytes(2, "big") + hello)
        assert 0x0A0A not in tls["cipher_suites"]
        assert 0x3A3A not in tls["extensions"]
        assert "10794" not in tls["ja3_string"].split(",")[3].split("-")  # 0x2A2A group

    def test_ech_flag(self):
        hello = client_hello("cloudflare-ech.com", ech=True)
        tls = _parse_tls_client_hello(b"\x16\x03\x01" + len(hello).to_bytes(2, "big") + hello)
        assert tls["ech"] is True


class TestDnsAnswers:
    def test_a_and_cname_answers(self):
        from scapy.all import DNS, DNSQR, DNSRR
        pkt = DNS(id=1, qr=1, rd=1, ra=1, qd=DNSQR(qname="www.example.com"),
                  an=[DNSRR(rrname="www.example.com", type="CNAME", rdata="edge.example.net"),
                      DNSRR(rrname="edge.example.net", type="A", rdata="93.184.215.14")])
        info = dissector._parse_dns(bytes(pkt), "udp")
        assert info["is_response"]
        types = {(a["type"], a["data"]) for a in info["answers"]}
        assert ("A", "93.184.215.14") in types
        assert ("CNAME", "edge.example.net") in types
