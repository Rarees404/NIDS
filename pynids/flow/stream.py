"""
A sliding window over each TCP direction's byte stream.

Signature rules look at one packet at a time, so a pattern cut in two by a
segment boundary (``…UNION SEL`` | ``ECT…``) matches neither half.  For
every in-order data segment this tracker hands back the bytes that came
just before it on the same direction of the same connection; the signature
engine then also evaluates its payload rules on ``previous + current``.

It is deliberately small: it follows sequence numbers, keeps the last
``tail_bytes`` of plaintext per direction, and flags retransmissions.  It
does not buffer out-of-order segments — a hole simply restarts the window.
Encrypted streams (TLS records, SSH) keep no bytes at all.
"""
from __future__ import annotations

from collections import OrderedDict
from typing import Any, Dict, Optional, Tuple

_Key = Tuple[Any, Any, Any, Any]
_SEQ_MASK = 0xFFFFFFFF


class StreamWindow:
    """
    Args:
        tail_bytes:  Plaintext kept per direction (the widest gap a split
                     pattern can straddle).
        max_streams: Directions tracked; the least recently used are dropped.
    """

    def __init__(self, tail_bytes: int = 1024, max_streams: int = 8192) -> None:
        self.tail_bytes = tail_bytes
        self.max_streams = max_streams
        # key -> [next expected seq, tail bytes, opaque (encrypted)]
        self._streams: "OrderedDict[_Key, list]" = OrderedDict()

    def __len__(self) -> int:
        return len(self._streams)

    def update(self, meta: Dict[str, Any], opaque: bool = False) -> Optional[bytes]:
        """
        Account for one TCP packet.

        Returns the bytes preceding this segment when it continues the
        stream in order (else None), and sets ``meta['tcp_retransmit']`` on a
        segment whose bytes were all seen before.
        """
        seq = meta.get("tcp_seq")
        if seq is None or meta.get("protocol") != "tcp":
            return None
        flags = meta.get("tcp_flags") or 0
        key = (meta.get("src_ip"), meta.get("src_port"), meta.get("dst_ip"), meta.get("dst_port"))
        payload: bytes = meta.get("payload_bytes") or b""

        if flags & 0x02:  # SYN: a new stream starts one past the initial sequence number
            self._streams.pop(key, None)
            self._store(key, [(seq + 1 + len(payload)) & _SEQ_MASK, b"", False])
            return None
        if flags & 0x05:  # FIN / RST: this direction is finished
            self._streams.pop(key, None)
            return None
        if not payload:
            return None

        entry = self._streams.get(key)
        end = (seq + len(payload)) & _SEQ_MASK
        if entry is None:  # picked up mid-stream
            self._store(key, [end, b"" if opaque else payload[-self.tail_bytes:], opaque])
            return None
        self._streams.move_to_end(key)

        delta = (seq - entry[0]) & _SEQ_MASK
        if delta >= 0x80000000:
            # Starts before what we expect.  Entirely old bytes: a retransmission.
            if ((end - entry[0]) & _SEQ_MASK) >= 0x80000000 or end == entry[0]:
                meta["tcp_retransmit"] = True
            return None
        prefix = entry[1] if delta == 0 and not entry[2] and not opaque else None
        if opaque:
            entry[2] = True
        entry[0] = end
        if entry[2]:
            entry[1] = b""
        elif delta == 0:
            entry[1] = (entry[1] + payload)[-self.tail_bytes:]
        else:  # a hole: older bytes no longer adjoin this segment
            entry[1] = payload[-self.tail_bytes:]
        return prefix or None

    def _store(self, key: _Key, entry: list) -> None:
        self._streams[key] = entry
        while len(self._streams) > self.max_streams:
            self._streams.popitem(last=False)
