"""
Red String Enterprise Binary Chunk Framing Engine
Zero-Overhead Wire Protocol (17-Byte Header, Network Byte Order)
"""

import struct
import time

# Supported Magic Headers
MAGIC_PRIMARY = b"RDSG"
MAGIC_LEGACY = b"RDST"
SUPPORTED_MAGICS = (MAGIC_PRIMARY, MAGIC_LEGACY)

# Stream Channel IDs
CHANNEL_CLIPBOARD = 0x01
CHANNEL_KEYSTROKE = 0x02
CHANNEL_FILE = 0x03

# Channel mapping human-readable
CHANNEL_NAMES = {
    CHANNEL_CLIPBOARD: "CLIPBOARD",
    CHANNEL_KEYSTROKE: "KEYSTROKE",
    CHANNEL_FILE: "FILE_CHUNK",
}

# Header struct: 4s (magic), B (channel_id), Q (timestamp uint64), I (length uint32)
# Total size: 4 + 1 + 8 + 4 = 17 bytes
HEADER_FORMAT = "!4sBQI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
assert HEADER_SIZE == 17, f"Expected header size 17 bytes, got {HEADER_SIZE}"

# Maximum allowed payload chunk (prevents buffer allocation attacks / starvation)
MAX_PAYLOAD_CEILING_BYTES = 50 * 1024 * 1024  # 50 MB per single frame


class FrameParsingError(Exception):
    """Raised when framing validation fails."""


class FrameBoundaryError(Exception):
    """Raised when frame exceeds platform security bounds."""


def encode_frame(channel_id: int, payload: bytes, timestamp_ms: int | None = None, magic: bytes = MAGIC_PRIMARY) -> bytes:
    """
    Encodes an opaque payload into a deterministic 17-byte framed binary packet.
    
    Format:
        [Magic: 4B ('RDSG')]
        [Channel ID: 1B]
        [Timestamp: 8B (uint64 Big-Endian ms)]
        [Payload Length: 4B (uint32 Big-Endian)]
        [Payload: N Bytes]
    """
    if channel_id not in (CHANNEL_CLIPBOARD, CHANNEL_KEYSTROKE, CHANNEL_FILE):
        raise ValueError(f"Invalid channel ID: {channel_id}")

    payload_len = len(payload)
    if payload_len > MAX_PAYLOAD_CEILING_BYTES:
        raise FrameBoundaryError(
            f"Payload size {payload_len} exceeds max platform ceiling of {MAX_PAYLOAD_CEILING_BYTES} bytes."
        )

    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)

    header = struct.pack(HEADER_FORMAT, magic, channel_id, timestamp_ms, payload_len)
    return header + payload


def decode_header(header_bytes: bytes) -> tuple[bytes, int, int, int]:
    """
    Decodes and validates the 17-byte wire header.
    
    Returns:
        (magic, channel_id, timestamp_ms, payload_length)
    """
    if len(header_bytes) < HEADER_SIZE:
        raise FrameParsingError(f"Header buffer too short: expected {HEADER_SIZE} bytes, got {len(header_bytes)}")

    magic, channel_id, timestamp_ms, payload_len = struct.unpack(HEADER_FORMAT, header_bytes[:HEADER_SIZE])

    if magic not in SUPPORTED_MAGICS:
        raise FrameParsingError(f"Invalid magic header: {magic!r}. Expected {SUPPORTED_MAGICS}")

    if channel_id not in (CHANNEL_CLIPBOARD, CHANNEL_KEYSTROKE, CHANNEL_FILE):
        raise FrameParsingError(f"Unrecognized channel identifier: {channel_id}")

    if payload_len > MAX_PAYLOAD_CEILING_BYTES:
        raise FrameBoundaryError(f"Unpacked payload length {payload_len} exceeds max safety ceiling.")

    return magic, channel_id, timestamp_ms, payload_len
