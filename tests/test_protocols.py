"""Tests for the application-layer protocol dissector."""
from __future__ import annotations

import pytest
from pynids.protocols.dissector import (
    dissect,
    _parse_http,
    _parse_dns,
    _parse_ssh_banner,
    _parse_smtp,
    _parse_tls_client_hello,
    _entropy,
)
from tests.conftest import make_meta


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

class TestHttpParser:
    def test_get_request(self):
        payload = b"GET /search?q=hello HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.0\r\n\r\n"
        result = _parse_http(payload)
        assert result["method"] == "GET"
        assert result["uri"] == "/search?q=hello"
        assert result["version"] == "HTTP/1.1"
        assert result["host"] == "example.com"
        assert result["user_agent"] == "curl/7.0"
        assert result["direction"] == "request"

    def test_post_request(self):
        payload = b"POST /login HTTP/1.1\r\nHost: site.com\r\nContent-Length: 20\r\n\r\nuser=admin&pass=x"
        result = _parse_http(payload)
        assert result["method"] == "POST"
        assert result["uri"] == "/login"

    def test_response(self):
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html/>"
        result = _parse_http(payload)
        assert result["direction"] == "response"
        assert result["status_code"] == 200
        assert result["reason"] == "OK"

    def test_sqli_detection(self):
        payload = b"GET /products?id=1+UNION+SELECT+*+FROM+users HTTP/1.1\r\n\r\n"
        result = _parse_http(payload)
        assert result["sqli_suspect"] is True

    def test_xss_detection(self):
        payload = b"GET /search?q=<script>alert(1)</script> HTTP/1.1\r\n\r\n"
        result = _parse_http(payload)
        assert result["xss_suspect"] is True

    def test_path_traversal_detection(self):
        payload = b"GET /../../etc/passwd HTTP/1.1\r\n\r\n"
        result = _parse_http(payload)
        assert result["path_traversal_suspect"] is True

    def test_scanner_ua_detection(self):
        payload = b"GET / HTTP/1.1\r\nUser-Agent: nikto/2.1.6\r\n\r\n"
        result = _parse_http(payload)
        assert result["scanner_ua"] is True

    def test_clean_request_no_flags(self):
        payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result = _parse_http(payload)
        assert result["sqli_suspect"] is False
        assert result["xss_suspect"] is False
        assert result["path_traversal_suspect"] is False
        assert result["scanner_ua"] is False

    def test_empty_payload(self):
        result = _parse_http(b"")
        assert result == {}


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

class TestDnsParser:
    def _make_dns_query(self, name: str, qtype: int = 1) -> bytes:
        """Build a minimal valid DNS query packet for *name*."""
        header = b"\x12\x34"   # txid
        header += b"\x01\x00"  # flags: standard query
        header += b"\x00\x01"  # qdcount = 1
        header += b"\x00\x00"  # ancount = 0
        header += b"\x00\x00"  # nscount = 0
        header += b"\x00\x00"  # arcount = 0

        # Encode QNAME
        qname = b""
        for label in name.rstrip(".").split("."):
            encoded = label.encode()
            qname += bytes([len(encoded)]) + encoded
        qname += b"\x00"

        header += qname
        header += qtype.to_bytes(2, "big")  # QTYPE
        header += b"\x00\x01"              # QCLASS IN
        return header

    def test_query_parsing(self):
        payload = self._make_dns_query("www.google.com")
        result = _parse_dns(payload, "udp")
        assert result["query_name"] == "www.google.com"
        assert result["query_type"] == "A"
        assert result["is_response"] is False

    def test_name_entropy_computed(self):
        payload = self._make_dns_query("abc.example.com")
        result = _parse_dns(payload, "udp")
        assert "name_entropy" in result
        assert result["name_entropy"] > 0

    def test_subdomain_depth(self):
        payload = self._make_dns_query("a.b.c.d.example.com")
        result = _parse_dns(payload, "udp")
        assert result["subdomain_depth"] >= 4

    def test_empty_payload(self):
        result = _parse_dns(b"", "udp")
        assert result == {}


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------

class TestSshBannerParser:
    def test_openssh_banner(self):
        payload = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
        result = _parse_ssh_banner(payload)
        assert result["proto_version"] == "2.0"
        assert "OpenSSH" in result["software"]

    def test_empty_payload(self):
        result = _parse_ssh_banner(b"")
        assert result == {}

    def test_non_ssh_payload(self):
        result = _parse_ssh_banner(b"HTTP/1.1 200 OK")
        assert "proto_version" not in result


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------

class TestSmtpParser:
    def test_ehlo_and_mail_from(self):
        payload = b"EHLO attacker.example\r\nMAIL FROM: <spam@evil.example>\r\nRCPT TO: <victim@target.com>\r\n"
        result = _parse_smtp(payload)
        assert result.get("helo") == "attacker.example"
        assert "spam@evil.example" in result.get("mail_from", "")
        assert "victim@target.com" in result.get("rcpt_to", "")

    def test_empty_payload(self):
        result = _parse_smtp(b"")
        assert result == {}


# ---------------------------------------------------------------------------
# Dissect routing
# ---------------------------------------------------------------------------

class TestDissect:
    def test_routes_http(self):
        meta = make_meta(dst_port=80, payload=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        result = dissect(meta)
        assert result.get("app_proto") == "http"
        assert "http" in result

    def test_routes_dns(self):
        # Minimal 12-byte DNS header
        dns_payload = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        meta = make_meta(dst_port=53, protocol="udp", payload=dns_payload)
        result = dissect(meta)
        assert result.get("app_proto") == "dns"

    def test_routes_ssh(self):
        meta = make_meta(dst_port=22, payload=b"SSH-2.0-OpenSSH_8.9\r\n")
        result = dissect(meta)
        assert result.get("app_proto") == "ssh"

    def test_empty_payload_returns_empty(self):
        meta = make_meta(dst_port=80, payload=b"")
        result = dissect(meta)
        assert result == {}


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

class TestEntropy:
    def test_uniform_entropy(self):
        # All same bytes → entropy = 0
        assert _entropy(b"aaaa") == 0.0

    def test_random_high_entropy(self):
        import os
        data = os.urandom(256)
        e = _entropy(data)
        assert e > 6.0  # Expect near 8 bits for random data

    def test_empty_data(self):
        assert _entropy(b"") == 0.0
