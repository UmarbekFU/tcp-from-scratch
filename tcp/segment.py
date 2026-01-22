"""
TCP Segment - Parsing and construction of TCP segments.

The TCP segment is the fundamental unit of data in TCP. Each segment contains
a header with control information and optionally a payload of data.

TCP Header Format (20 bytes minimum, up to 60 with options):

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |       |C|E|U|A|P|R|S|F|                               |
    | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
    |       |       |R|E|G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Key design insight: The header is self-describing. The Data Offset field tells
you where the data begins, allowing for variable-length options while maintaining
backward compatibility.
"""

import struct
from dataclasses import dataclass, field
from typing import Optional
from enum import IntFlag


class TCPFlags(IntFlag):
    """
    TCP control flags.

    These flags control the behavior of TCP connections. Understanding when
    each flag is used is crucial to understanding TCP:

    - FIN: "I'm done sending data" (graceful close)
    - SYN: "Let's synchronize sequence numbers" (connection establishment)
    - RST: "Abort this connection immediately" (error condition)
    - PSH: "Push this data to the application immediately" (don't buffer)
    - ACK: "The acknowledgment number field is valid"
    - URG: "The urgent pointer field is valid" (rarely used today)
    - ECE: "ECN-Echo - congestion was experienced" (explicit congestion notification)
    - CWR: "Congestion Window Reduced" (response to ECE)
    """
    FIN = 0x01  # Finish - no more data from sender
    SYN = 0x02  # Synchronize - initiate connection
    RST = 0x04  # Reset - abort connection
    PSH = 0x08  # Push - deliver data immediately
    ACK = 0x10  # Acknowledgment field is valid
    URG = 0x20  # Urgent pointer field is valid
    ECE = 0x40  # ECN-Echo
    CWR = 0x80  # Congestion Window Reduced

    def __str__(self) -> str:
        """Human-readable representation of flags."""
        names = []
        if self & TCPFlags.FIN: names.append("FIN")
        if self & TCPFlags.SYN: names.append("SYN")
        if self & TCPFlags.RST: names.append("RST")
        if self & TCPFlags.PSH: names.append("PSH")
        if self & TCPFlags.ACK: names.append("ACK")
        if self & TCPFlags.URG: names.append("URG")
        if self & TCPFlags.ECE: names.append("ECE")
        if self & TCPFlags.CWR: names.append("CWR")
        return "|".join(names) if names else "NONE"


@dataclass
class TCPOption:
    """
    TCP Option.

    Options allow TCP to be extended without breaking backward compatibility.
    If a receiver doesn't understand an option, it ignores it.

    Common options:
    - MSS (Maximum Segment Size): Negotiated during handshake
    - Window Scale: Allows windows larger than 64KB
    - SACK (Selective ACK): Report out-of-order segments received
    - Timestamps: For RTT measurement and PAWS
    """
    kind: int
    length: int = 0
    data: bytes = field(default_factory=bytes)

    # Option kinds (from RFC 793 and extensions)
    END_OF_OPTIONS = 0
    NOP = 1
    MSS = 2
    WINDOW_SCALE = 3
    SACK_PERMITTED = 4
    SACK = 5
    TIMESTAMPS = 8


@dataclass
class TCPSegment:
    """
    A TCP segment - the unit of transmission in TCP.

    Mental model: Think of a TCP segment as an envelope containing:
    1. Addressing info (ports)
    2. Stream position (sequence number)
    3. Acknowledgment of what's been received
    4. Control flags
    5. Flow control info (window)
    6. Optional extensions (options)
    7. The actual data (payload)

    The segment doesn't contain IP addresses - those are in the IP header.
    TCP segments are encapsulated within IP packets.
    """

    # Required fields
    src_port: int
    dst_port: int
    seq_num: int
    ack_num: int
    flags: TCPFlags
    window: int

    # Optional fields with defaults
    data: bytes = field(default_factory=bytes)
    urgent_ptr: int = 0
    options: list = field(default_factory=list)
    checksum: int = 0  # Computed during serialization

    # Minimum header size (no options)
    MIN_HEADER_SIZE = 20

    def __post_init__(self):
        """Validate segment after construction."""
        if not 0 <= self.src_port <= 65535:
            raise ValueError(f"Invalid source port: {self.src_port}")
        if not 0 <= self.dst_port <= 65535:
            raise ValueError(f"Invalid destination port: {self.dst_port}")
        if not 0 <= self.seq_num <= 0xFFFFFFFF:
            raise ValueError(f"Invalid sequence number: {self.seq_num}")
        if not 0 <= self.ack_num <= 0xFFFFFFFF:
            raise ValueError(f"Invalid acknowledgment number: {self.ack_num}")
        if not 0 <= self.window <= 65535:
            raise ValueError(f"Invalid window: {self.window}")

    @property
    def header_length(self) -> int:
        """
        Calculate header length in bytes.

        Header length is always a multiple of 4 bytes (32-bit words).
        The Data Offset field stores this as number of 32-bit words.
        """
        options_len = sum(self._option_length(opt) for opt in self.options)
        # Pad to 4-byte boundary
        padded_options = (options_len + 3) // 4 * 4
        return self.MIN_HEADER_SIZE + padded_options

    @property
    def data_offset(self) -> int:
        """Data offset in 32-bit words (for header encoding)."""
        return self.header_length // 4

    @property
    def payload_length(self) -> int:
        """Length of the data payload."""
        return len(self.data)

    @property
    def segment_length(self) -> int:
        """
        Total segment length for sequence number accounting.

        Important: SYN and FIN flags each consume one sequence number,
        even though they carry no data. This ensures they are acknowledged.
        """
        length = len(self.data)
        if self.flags & TCPFlags.SYN:
            length += 1
        if self.flags & TCPFlags.FIN:
            length += 1
        return length

    def _option_length(self, option: TCPOption) -> int:
        """Calculate the wire length of an option."""
        if option.kind == TCPOption.END_OF_OPTIONS:
            return 1
        elif option.kind == TCPOption.NOP:
            return 1
        else:
            return option.length

    def serialize(self, src_ip: str = "0.0.0.0", dst_ip: str = "0.0.0.0") -> bytes:
        """
        Serialize segment to bytes for transmission.

        The checksum is computed over a pseudo-header (containing IP addresses)
        plus the TCP segment. This provides end-to-end verification that the
        segment wasn't corrupted AND wasn't delivered to the wrong destination.

        Args:
            src_ip: Source IP address (for checksum calculation)
            dst_ip: Destination IP address (for checksum calculation)

        Returns:
            Serialized TCP segment as bytes
        """
        # Build options bytes
        options_bytes = self._serialize_options()

        # Pad options to 4-byte boundary
        padding_needed = (4 - len(options_bytes) % 4) % 4
        options_bytes += bytes(padding_needed)

        # Data offset (header length in 32-bit words)
        data_offset = (self.MIN_HEADER_SIZE + len(options_bytes)) // 4

        # Build header with checksum = 0 for initial calculation
        header = struct.pack(
            "!HHIIBBHHH",
            self.src_port,
            self.dst_port,
            self.seq_num,
            self.ack_num,
            (data_offset << 4),  # Data offset in upper 4 bits
            int(self.flags),
            self.window,
            0,  # Checksum placeholder
            self.urgent_ptr
        )

        # Combine header, options, and data
        segment = header + options_bytes + self.data

        # Calculate checksum
        checksum = self._calculate_checksum(segment, src_ip, dst_ip)

        # Rebuild with correct checksum
        header = struct.pack(
            "!HHIIBBHHH",
            self.src_port,
            self.dst_port,
            self.seq_num,
            self.ack_num,
            (data_offset << 4),
            int(self.flags),
            self.window,
            checksum,
            self.urgent_ptr
        )

        return header + options_bytes + self.data

    def _serialize_options(self) -> bytes:
        """Serialize TCP options to bytes."""
        result = bytearray()

        for option in self.options:
            if option.kind == TCPOption.END_OF_OPTIONS:
                result.append(0)
            elif option.kind == TCPOption.NOP:
                result.append(1)
            elif option.kind == TCPOption.MSS:
                # MSS is always 4 bytes: kind(1) + length(1) + value(2)
                result.append(2)
                result.append(4)
                result.extend(option.data)
            elif option.kind == TCPOption.WINDOW_SCALE:
                # Window scale: kind(1) + length(1) + shift(1)
                result.append(3)
                result.append(3)
                result.extend(option.data)
            elif option.kind == TCPOption.SACK_PERMITTED:
                # SACK permitted: kind(1) + length(1)
                result.append(4)
                result.append(2)
            elif option.kind == TCPOption.TIMESTAMPS:
                # Timestamps: kind(1) + length(1) + TSval(4) + TSecr(4)
                result.append(8)
                result.append(10)
                result.extend(option.data)
            else:
                # Generic option
                result.append(option.kind)
                result.append(option.length)
                result.extend(option.data)

        return bytes(result)

    def _calculate_checksum(self, segment: bytes, src_ip: str, dst_ip: str) -> int:
        """
        Calculate TCP checksum.

        The checksum covers:
        1. A pseudo-header containing IP addresses (provides extra verification)
        2. The entire TCP segment

        The pseudo-header prevents delivery to wrong host even if header is corrupted.

        Algorithm: One's complement sum of 16-bit words, then one's complement of result.
        """
        # Build pseudo-header
        src_ip_bytes = bytes(int(x) for x in src_ip.split("."))
        dst_ip_bytes = bytes(int(x) for x in dst_ip.split("."))

        pseudo_header = struct.pack(
            "!4s4sBBH",
            src_ip_bytes,
            dst_ip_bytes,
            0,  # Reserved
            6,  # Protocol (TCP = 6)
            len(segment)
        )

        # Combine pseudo-header and segment
        data = pseudo_header + segment

        # Pad to even length
        if len(data) % 2:
            data += b'\x00'

        # Calculate one's complement sum
        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            total += word
            # Handle carry (fold into lower 16 bits)
            total = (total & 0xFFFF) + (total >> 16)

        # One's complement
        return ~total & 0xFFFF

    @classmethod
    def parse(cls, data: bytes) -> "TCPSegment":
        """
        Parse a TCP segment from raw bytes.

        This is the inverse of serialize(). Takes raw bytes from the wire
        and reconstructs the TCPSegment object.

        Args:
            data: Raw TCP segment bytes

        Returns:
            Parsed TCPSegment object

        Raises:
            ValueError: If data is too short or malformed
        """
        if len(data) < cls.MIN_HEADER_SIZE:
            raise ValueError(f"TCP segment too short: {len(data)} bytes")

        # Parse fixed header
        (
            src_port,
            dst_port,
            seq_num,
            ack_num,
            data_offset_reserved,
            flags,
            window,
            checksum,
            urgent_ptr
        ) = struct.unpack("!HHIIBBHHH", data[:20])

        # Extract data offset (upper 4 bits)
        data_offset = (data_offset_reserved >> 4) * 4

        if len(data) < data_offset:
            raise ValueError(f"TCP segment truncated: expected {data_offset} header bytes")

        # Parse options (bytes 20 to data_offset)
        options = cls._parse_options(data[20:data_offset])

        # Extract payload
        payload = data[data_offset:]

        return cls(
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq_num,
            ack_num=ack_num,
            flags=TCPFlags(flags),
            window=window,
            urgent_ptr=urgent_ptr,
            checksum=checksum,
            options=options,
            data=payload
        )

    @classmethod
    def _parse_options(cls, data: bytes) -> list:
        """Parse TCP options from bytes."""
        options = []
        i = 0

        while i < len(data):
            kind = data[i]

            if kind == TCPOption.END_OF_OPTIONS:
                options.append(TCPOption(kind=kind))
                break
            elif kind == TCPOption.NOP:
                options.append(TCPOption(kind=kind))
                i += 1
            else:
                if i + 1 >= len(data):
                    break
                length = data[i + 1]
                if i + length > len(data):
                    break
                opt_data = data[i + 2:i + length]
                options.append(TCPOption(kind=kind, length=length, data=opt_data))
                i += length

        return options

    def __str__(self) -> str:
        """Human-readable representation of segment."""
        return (
            f"TCP {self.src_port} -> {self.dst_port} "
            f"[{self.flags}] "
            f"seq={self.seq_num} ack={self.ack_num} "
            f"win={self.window} len={len(self.data)}"
        )

    def __repr__(self) -> str:
        return (
            f"TCPSegment(src_port={self.src_port}, dst_port={self.dst_port}, "
            f"seq_num={self.seq_num}, ack_num={self.ack_num}, "
            f"flags={self.flags}, window={self.window}, "
            f"data={len(self.data)} bytes)"
        )


# Convenience functions for creating common segment types

def create_syn_segment(src_port: int, dst_port: int, seq_num: int,
                       window: int = 65535, mss: int = 1460) -> TCPSegment:
    """Create a SYN segment for connection initiation."""
    options = [
        TCPOption(kind=TCPOption.MSS, length=4, data=struct.pack("!H", mss)),
    ]
    return TCPSegment(
        src_port=src_port,
        dst_port=dst_port,
        seq_num=seq_num,
        ack_num=0,
        flags=TCPFlags.SYN,
        window=window,
        options=options
    )


def create_syn_ack_segment(src_port: int, dst_port: int, seq_num: int,
                           ack_num: int, window: int = 65535,
                           mss: int = 1460) -> TCPSegment:
    """Create a SYN-ACK segment for connection response."""
    options = [
        TCPOption(kind=TCPOption.MSS, length=4, data=struct.pack("!H", mss)),
    ]
    return TCPSegment(
        src_port=src_port,
        dst_port=dst_port,
        seq_num=seq_num,
        ack_num=ack_num,
        flags=TCPFlags.SYN | TCPFlags.ACK,
        window=window,
        options=options
    )


def create_ack_segment(src_port: int, dst_port: int, seq_num: int,
                       ack_num: int, window: int = 65535) -> TCPSegment:
    """Create an ACK segment."""
    return TCPSegment(
        src_port=src_port,
        dst_port=dst_port,
        seq_num=seq_num,
        ack_num=ack_num,
        flags=TCPFlags.ACK,
        window=window
    )


def create_data_segment(src_port: int, dst_port: int, seq_num: int,
                        ack_num: int, data: bytes, window: int = 65535,
                        push: bool = False) -> TCPSegment:
    """Create a data segment."""
    flags = TCPFlags.ACK
    if push:
        flags |= TCPFlags.PSH
    return TCPSegment(
        src_port=src_port,
        dst_port=dst_port,
        seq_num=seq_num,
        ack_num=ack_num,
        flags=flags,
        window=window,
        data=data
    )


def create_fin_segment(src_port: int, dst_port: int, seq_num: int,
                       ack_num: int, window: int = 65535) -> TCPSegment:
    """Create a FIN segment for connection termination."""
    return TCPSegment(
        src_port=src_port,
        dst_port=dst_port,
        seq_num=seq_num,
        ack_num=ack_num,
        flags=TCPFlags.FIN | TCPFlags.ACK,
        window=window
    )


def create_rst_segment(src_port: int, dst_port: int, seq_num: int) -> TCPSegment:
    """Create a RST segment for connection reset."""
    return TCPSegment(
        src_port=src_port,
        dst_port=dst_port,
        seq_num=seq_num,
        ack_num=0,
        flags=TCPFlags.RST,
        window=0
    )
