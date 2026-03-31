"""
packet.py – Custom UDP packet format for the Reliable Group Notification System.

Wire format (all fields in network / big-endian byte order):
┌──────────┬──────┬────────────┬──────────┬─────────────┬──────────┬──────────────────┐
│  Magic   │ Type │  Seq No    │ Group ID │ Payload Len │ Checksum │     Payload      │
│  2 bytes │ 1 B  │  4 bytes   │  2 bytes │   2 bytes   │  4 bytes │  variable length │
└──────────┴──────┴────────────┴──────────┴─────────────┴──────────┴──────────────────┘
Total header = 15 bytes.

Checksum is CRC-32 over (type + seq + group_id + payload) — detects corruption.
"""

import struct
import time
import zlib

from config import MAGIC_BYTES, PKT_NOTIFY, PKT_ACK

# struct format: network byte-order, 2s=magic, B=type, I=seq, H=group, H=plen, I=crc32
_FMT        = "!2sBIHHI"
HEADER_SIZE = struct.calcsize(_FMT)   # 15 bytes


class Packet:
    """Immutable-ish packet object.  Build one, call .pack(); receive bytes, call .unpack()."""

    def __init__(self, pkt_type: int, seq_no: int, group_id: int,
                 payload: bytes | str = b""):
        self.pkt_type  = pkt_type
        self.seq_no    = seq_no
        self.group_id  = group_id
        self.payload   = payload.encode() if isinstance(payload, str) else payload
        self.timestamp = time.time()
        self.checksum  = self._crc()

    # ── Serialisation ──────────────────────────────────────────────────────

    def _crc(self) -> int:
        """CRC-32 over the mutable fields and payload."""
        blob = struct.pack("!BIH", self.pkt_type, self.seq_no, self.group_id) + self.payload
        return zlib.crc32(blob) & 0xFFFF_FFFF

    def pack(self) -> bytes:
        """Serialise to bytes ready for sendto()."""
        header = struct.pack(
            _FMT,
            MAGIC_BYTES,
            self.pkt_type,
            self.seq_no,
            self.group_id,
            len(self.payload),
            self.checksum,
        )
        return header + self.payload

    @classmethod
    def unpack(cls, data: bytes) -> "Packet | None":
        """
        Deserialise raw bytes.  Returns None if:
          • too short to hold a header
          • magic bytes don't match
          • CRC-32 mismatch (corruption detected)
        """
        if len(data) < HEADER_SIZE:
            return None

        magic, pkt_type, seq_no, group_id, plen, checksum = struct.unpack(
            _FMT, data[:HEADER_SIZE]
        )

        if magic != MAGIC_BYTES:
            return None

        payload = data[HEADER_SIZE : HEADER_SIZE + plen]

        pkt = cls(pkt_type, seq_no, group_id, payload)
        if pkt.checksum != checksum:          # corruption check
            return None

        return pkt

    # ── Helpers ────────────────────────────────────────────────────────────

    @property
    def text(self) -> str:
        """Decode payload as UTF-8, replacing any invalid bytes."""
        return self.payload.decode("utf-8", errors="replace")

    def make_ack(self, subscriber_id: str) -> "Packet":
        """Return an ACK packet for this notification."""
        return Packet(PKT_ACK, self.seq_no, self.group_id, subscriber_id)

    def __repr__(self) -> str:
        return (
            f"Packet(type={self.pkt_type:#04x}, seq={self.seq_no}, "
            f"group={self.group_id:#06x}, payload={len(self.payload)}B)"
        )
