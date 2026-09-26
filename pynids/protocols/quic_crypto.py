"""
QUIC Initial packet decryption (RFC 9001 §5, RFC 9369).

QUIC encrypts even its first packet, but the keys for Initial packets are
derived from the client's Destination Connection ID, which travels in the
clear.  Any on-path observer can therefore recover the TLS ClientHello
inside the first flight and read the Server Name Indication — exactly
what we need to turn "UDP to 142.250.74.46:443" into "www.youtube.com".

Only client→server Initials are decrypted (with the ``client in`` secret).
Server Initials fail AEAD authentication and are ignored.

Chrome's post-quantum ClientHello (X25519MLKEM768) is larger than one
datagram, so the ClientHello is spread over several CRYPTO frames in two
or more Initial packets.  :class:`QuicClientHelloAssembler` stitches them
back together, keyed by the client's original DCID.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

QUIC_V1 = 0x00000001
QUIC_V2 = 0x6B3343CF
QUIC_DRAFT29 = 0xFF00001D

_SALTS: Dict[int, bytes] = {
    QUIC_V1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    QUIC_V2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
    QUIC_DRAFT29: bytes.fromhex("afbfec289993d24c9e9786f19c6111e04390a899"),
}

# Long-header packet-type bits that mean "Initial" per version.
_INITIAL_TYPE_BITS = {QUIC_V1: 0x00, QUIC_V2: 0x01, QUIC_DRAFT29: 0x00}


def is_supported_version(version: int) -> bool:
    return version in _SALTS


def long_packet_type_name(version: int, type_bits: int) -> str:
    """Map the two long-header type bits to a name, honouring QUIC v2's remap."""
    if version == QUIC_V2:
        names = {0x01: "Initial", 0x02: "0-RTT", 0x03: "Handshake", 0x00: "Retry"}
    else:
        names = {0x00: "Initial", 0x01: "0-RTT", 0x02: "Handshake", 0x03: "Retry"}
    return names.get(type_bits, f"Unknown(0x{type_bits:02X})")


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def hkdf_expand_label(secret: bytes, label: str, length: int, context: bytes = b"") -> bytes:
    full = b"tls13 " + label.encode("ascii")
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(context)]) + context
    return _hkdf_expand(secret, info, length)


@dataclass(frozen=True)
class InitialKeys:
    key: bytes
    iv: bytes
    hp: bytes


def derive_client_initial_keys(dcid: bytes, version: int = QUIC_V1) -> InitialKeys:
    """Derive the client Initial AEAD key, IV, and header-protection key."""
    salt = _SALTS[version]
    initial_secret = _hkdf_extract(salt, dcid)
    client_secret = hkdf_expand_label(initial_secret, "client in", 32)
    prefix = "quicv2 " if version == QUIC_V2 else "quic "
    return InitialKeys(
        key=hkdf_expand_label(client_secret, prefix + "key", 16),
        iv=hkdf_expand_label(client_secret, prefix + "iv", 12),
        hp=hkdf_expand_label(client_secret, prefix + "hp", 16),
    )


def _hp_mask(hp_key: bytes, sample: bytes) -> bytes:
    enc = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor()
    return enc.update(sample) + enc.finalize()


# ---------------------------------------------------------------------------
# Variable-length integers (RFC 9000 §16)
# ---------------------------------------------------------------------------

def read_varint(data: bytes, pos: int) -> Tuple[int, int]:
    """Return (value, new_pos).  Raises IndexError on truncated input."""
    first = data[pos]
    length = 1 << (first >> 6)
    if pos + length > len(data):
        raise IndexError("truncated varint")
    value = first & 0x3F
    for i in range(1, length):
        value = (value << 8) | data[pos + i]
    return value, pos + length


def encode_varint(value: int) -> bytes:
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return (value | 0x4000).to_bytes(2, "big")
    if value < 0x40000000:
        return (value | 0x80000000).to_bytes(4, "big")
    return (value | 0xC000000000000000).to_bytes(8, "big")


# ---------------------------------------------------------------------------
# Initial packet decryption
# ---------------------------------------------------------------------------

@dataclass
class DecryptedInitial:
    version: int
    dcid: bytes
    scid: bytes
    packet_number: int
    crypto_frames: List[Tuple[int, bytes]] = field(default_factory=list)


def decrypt_client_initial(datagram: bytes) -> Optional[DecryptedInitial]:
    """
    Decrypt the first (Initial) packet in *datagram*.

    Returns ``None`` if the datagram is not a client Initial for a supported
    version, is truncated, or fails authentication.
    """
    try:
        if len(datagram) < 7 or (datagram[0] & 0xC0) != 0xC0:
            return None
        version = int.from_bytes(datagram[1:5], "big")
        if not is_supported_version(version):
            return None
        if ((datagram[0] & 0x30) >> 4) != _INITIAL_TYPE_BITS[version]:
            return None

        pos = 5
        dcid_len = datagram[pos]
        pos += 1
        dcid = datagram[pos:pos + dcid_len]
        pos += dcid_len
        scid_len = datagram[pos]
        pos += 1
        scid = datagram[pos:pos + scid_len]
        pos += scid_len
        token_len, pos = read_varint(datagram, pos)
        pos += token_len
        length, pos = read_varint(datagram, pos)
        pn_offset = pos
        if pn_offset + length > len(datagram) or pn_offset + 20 > len(datagram):
            return None

        keys = derive_client_initial_keys(dcid, version)
        mask = _hp_mask(keys.hp, datagram[pn_offset + 4:pn_offset + 20])
        first = datagram[0] ^ (mask[0] & 0x0F)
        pn_len = (first & 0x03) + 1
        pn_bytes = bytes(
            b ^ m for b, m in zip(datagram[pn_offset:pn_offset + pn_len], mask[1:1 + pn_len])
        )
        packet_number = int.from_bytes(pn_bytes, "big")
        header = bytes([first]) + datagram[1:pn_offset] + pn_bytes
        nonce = bytes(
            a ^ b for a, b in zip(keys.iv, packet_number.to_bytes(12, "big"))
        )
        ciphertext = datagram[pn_offset + pn_len:pn_offset + length]
        plaintext = AESGCM(keys.key).decrypt(nonce, ciphertext, header)
    except (IndexError, ValueError, InvalidTag):
        return None

    result = DecryptedInitial(
        version=version, dcid=dcid, scid=scid, packet_number=packet_number
    )
    try:
        result.crypto_frames = _parse_crypto_frames(plaintext)
    except IndexError:
        pass
    return result


def _parse_crypto_frames(payload: bytes) -> List[Tuple[int, bytes]]:
    """Walk Initial-packet frames and return [(offset, data)] of CRYPTO frames."""
    frames: List[Tuple[int, bytes]] = []
    pos = 0
    while pos < len(payload):
        ftype, pos = read_varint(payload, pos)
        if ftype == 0x00:  # PADDING
            continue
        if ftype == 0x01:  # PING
            continue
        if ftype in (0x02, 0x03):  # ACK
            _, pos = read_varint(payload, pos)  # largest acknowledged
            _, pos = read_varint(payload, pos)  # ack delay
            count, pos = read_varint(payload, pos)
            _, pos = read_varint(payload, pos)  # first range
            for _ in range(count):
                _, pos = read_varint(payload, pos)
                _, pos = read_varint(payload, pos)
            if ftype == 0x03:
                for _ in range(3):
                    _, pos = read_varint(payload, pos)
            continue
        if ftype == 0x06:  # CRYPTO
            offset, pos = read_varint(payload, pos)
            length, pos = read_varint(payload, pos)
            frames.append((offset, payload[pos:pos + length]))
            pos += length
            continue
        if ftype in (0x1C, 0x1D):  # CONNECTION_CLOSE
            break
        break  # anything else is not allowed in Initial packets
    return frames


# ---------------------------------------------------------------------------
# Encryption — used by tests and the demo PCAP generator
# ---------------------------------------------------------------------------

def build_client_initial(
    dcid: bytes,
    scid: bytes,
    crypto_frames: List[Tuple[int, bytes]],
    packet_number: int = 0,
    version: int = QUIC_V1,
    pad_to: int = 1200,
) -> bytes:
    """Build a protected client Initial carrying the given CRYPTO frames."""
    payload = b"".join(
        b"\x06" + encode_varint(off) + encode_varint(len(data)) + data
        for off, data in crypto_frames
    )
    pn_len = 4
    type_bits = _INITIAL_TYPE_BITS[version]
    first = 0xC0 | (type_bits << 4) | (pn_len - 1)
    base = (
        bytes([first]) + version.to_bytes(4, "big")
        + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
        + encode_varint(0)  # empty token
    )
    # Pad so the datagram reaches pad_to bytes (clients must send >= 1200).
    overhead = len(base) + 2 + pn_len + 16
    if overhead + len(payload) < pad_to:
        payload += b"\x00" * (pad_to - overhead - len(payload))
    length = pn_len + len(payload) + 16
    length_bytes = (length | 0x4000).to_bytes(2, "big")
    pn_bytes = packet_number.to_bytes(pn_len, "big")
    header = base + length_bytes + pn_bytes

    keys = derive_client_initial_keys(dcid, version)
    nonce = bytes(a ^ b for a, b in zip(keys.iv, packet_number.to_bytes(12, "big")))
    ciphertext = AESGCM(keys.key).encrypt(nonce, payload, header)

    pn_offset = len(base) + 2
    sample = ciphertext[4 - pn_len:4 - pn_len + 16]
    mask = _hp_mask(keys.hp, sample)
    protected = bytearray(header + ciphertext)
    protected[0] ^= mask[0] & 0x0F
    for i in range(pn_len):
        protected[pn_offset + i] ^= mask[1 + i]
    return bytes(protected)


# ---------------------------------------------------------------------------
# Multi-packet ClientHello reassembly
# ---------------------------------------------------------------------------

class QuicClientHelloAssembler:
    """
    Collect CRYPTO-frame fragments per connection until the full TLS
    ClientHello handshake message is available.

    Bounded LRU so a flood of junk Initials cannot grow memory.
    """

    def __init__(self, max_entries: int = 2048, ttl: float = 10.0) -> None:
        self._max = max_entries
        self._ttl = ttl
        self._buffers: "OrderedDict[bytes, Tuple[float, Dict[int, bytes]]]" = OrderedDict()
        self._done: "OrderedDict[bytes, float]" = OrderedDict()

    def add(self, key: bytes, frames: List[Tuple[int, bytes]]) -> Optional[bytes]:
        """
        Add *frames* for connection *key*.  Returns the complete ClientHello
        handshake message (type + length + body) once, when it is complete.
        """
        if not frames or key in self._done:
            return None
        now = time.monotonic()
        self._expire(now)
        _, pieces = self._buffers.pop(key, (now, {}))
        for offset, data in frames:
            if offset < 65536 and data:
                pieces[offset] = data
        self._buffers[key] = (now, pieces)
        while len(self._buffers) > self._max:
            self._buffers.popitem(last=False)

        stream = _contiguous(pieces)
        if len(stream) < 4 or stream[0] != 0x01:
            return None
        needed = 4 + int.from_bytes(stream[1:4], "big")
        if len(stream) < needed:
            return None
        del self._buffers[key]
        self._done[key] = now
        while len(self._done) > self._max:
            self._done.popitem(last=False)
        return stream[:needed]

    def _expire(self, now: float) -> None:
        while self._buffers:
            key, (ts, _) = next(iter(self._buffers.items()))
            if now - ts <= self._ttl:
                break
            self._buffers.popitem(last=False)
        while self._done:
            key, ts = next(iter(self._done.items()))
            if now - ts <= 60:
                break
            self._done.popitem(last=False)


def _contiguous(pieces: Dict[int, bytes]) -> bytes:
    """Concatenate fragments starting at offset 0 until the first gap."""
    out = bytearray()
    for offset in sorted(pieces):
        data = pieces[offset]
        if offset > len(out):
            break
        end = offset + len(data)
        if end > len(out):
            out += data[len(out) - offset:]
    return bytes(out)
