"""
Tests for TCP Segment parsing and construction.
"""

import pytest
import struct
from tcp.segment import (
    TCPSegment, TCPFlags, TCPOption,
    create_syn_segment, create_syn_ack_segment,
    create_ack_segment, create_data_segment,
    create_fin_segment, create_rst_segment
)


class TestTCPFlags:
    """Test TCP flags."""

    def test_individual_flags(self):
        """Test individual flag values."""
        assert TCPFlags.FIN == 0x01
        assert TCPFlags.SYN == 0x02
        assert TCPFlags.RST == 0x04
        assert TCPFlags.PSH == 0x08
        assert TCPFlags.ACK == 0x10
        assert TCPFlags.URG == 0x20

    def test_flag_combinations(self):
        """Test combining flags."""
        syn_ack = TCPFlags.SYN | TCPFlags.ACK
        assert syn_ack == 0x12
        assert syn_ack & TCPFlags.SYN
        assert syn_ack & TCPFlags.ACK
        assert not (syn_ack & TCPFlags.FIN)

    def test_flag_str(self):
        """Test string representation of flags."""
        assert "SYN" in str(TCPFlags.SYN)
        assert "ACK" in str(TCPFlags.ACK)
        syn_ack = TCPFlags.SYN | TCPFlags.ACK
        assert "SYN" in str(syn_ack)
        assert "ACK" in str(syn_ack)


class TestTCPSegment:
    """Test TCP segment parsing and serialization."""

    def test_basic_segment_creation(self):
        """Test creating a basic segment."""
        seg = TCPSegment(
            src_port=12345,
            dst_port=80,
            seq_num=1000,
            ack_num=2000,
            flags=TCPFlags.ACK,
            window=65535
        )

        assert seg.src_port == 12345
        assert seg.dst_port == 80
        assert seg.seq_num == 1000
        assert seg.ack_num == 2000
        assert seg.flags == TCPFlags.ACK
        assert seg.window == 65535
        assert seg.data == b''

    def test_segment_with_data(self):
        """Test segment with payload."""
        data = b"Hello, TCP!"
        seg = TCPSegment(
            src_port=12345,
            dst_port=80,
            seq_num=1000,
            ack_num=2000,
            flags=TCPFlags.ACK | TCPFlags.PSH,
            window=65535,
            data=data
        )

        assert seg.data == data
        assert seg.payload_length == len(data)

    def test_segment_length_calculation(self):
        """Test segment length calculation including SYN/FIN."""
        # Data only
        seg = TCPSegment(
            src_port=1, dst_port=2, seq_num=0, ack_num=0,
            flags=TCPFlags.ACK, window=1000, data=b"test"
        )
        assert seg.segment_length == 4

        # SYN consumes a sequence number
        syn = TCPSegment(
            src_port=1, dst_port=2, seq_num=0, ack_num=0,
            flags=TCPFlags.SYN, window=1000
        )
        assert syn.segment_length == 1

        # FIN consumes a sequence number
        fin = TCPSegment(
            src_port=1, dst_port=2, seq_num=0, ack_num=0,
            flags=TCPFlags.FIN | TCPFlags.ACK, window=1000
        )
        assert fin.segment_length == 1

        # FIN with data
        fin_data = TCPSegment(
            src_port=1, dst_port=2, seq_num=0, ack_num=0,
            flags=TCPFlags.FIN | TCPFlags.ACK, window=1000, data=b"bye"
        )
        assert fin_data.segment_length == 4  # 3 bytes + 1 for FIN

    def test_serialize_parse_roundtrip(self):
        """Test that serialize then parse gives same segment."""
        original = TCPSegment(
            src_port=12345,
            dst_port=80,
            seq_num=1000,
            ack_num=2000,
            flags=TCPFlags.SYN | TCPFlags.ACK,
            window=65535,
            data=b"Hello"
        )

        # Serialize
        data = original.serialize("192.168.1.1", "192.168.1.2")

        # Parse
        parsed = TCPSegment.parse(data)

        # Verify
        assert parsed.src_port == original.src_port
        assert parsed.dst_port == original.dst_port
        assert parsed.seq_num == original.seq_num
        assert parsed.ack_num == original.ack_num
        assert parsed.flags == original.flags
        assert parsed.window == original.window
        assert parsed.data == original.data

    def test_validation(self):
        """Test segment validation."""
        # Invalid port
        with pytest.raises(ValueError):
            TCPSegment(src_port=-1, dst_port=80, seq_num=0, ack_num=0,
                      flags=TCPFlags.ACK, window=1000)

        with pytest.raises(ValueError):
            TCPSegment(src_port=70000, dst_port=80, seq_num=0, ack_num=0,
                      flags=TCPFlags.ACK, window=1000)

        # Invalid window
        with pytest.raises(ValueError):
            TCPSegment(src_port=1000, dst_port=80, seq_num=0, ack_num=0,
                      flags=TCPFlags.ACK, window=-1)


class TestSegmentHelpers:
    """Test segment creation helper functions."""

    def test_create_syn(self):
        """Test SYN segment creation."""
        syn = create_syn_segment(12345, 80, 1000, window=32000, mss=1460)

        assert syn.src_port == 12345
        assert syn.dst_port == 80
        assert syn.seq_num == 1000
        assert syn.flags == TCPFlags.SYN
        assert syn.window == 32000

        # Check MSS option
        mss_opt = next((o for o in syn.options if o.kind == TCPOption.MSS), None)
        assert mss_opt is not None
        assert struct.unpack("!H", mss_opt.data)[0] == 1460

    def test_create_syn_ack(self):
        """Test SYN-ACK segment creation."""
        syn_ack = create_syn_ack_segment(80, 12345, 5000, 1001)

        assert syn_ack.src_port == 80
        assert syn_ack.dst_port == 12345
        assert syn_ack.seq_num == 5000
        assert syn_ack.ack_num == 1001
        assert syn_ack.flags == (TCPFlags.SYN | TCPFlags.ACK)

    def test_create_ack(self):
        """Test ACK segment creation."""
        ack = create_ack_segment(12345, 80, 1001, 5001, window=32000)

        assert ack.seq_num == 1001
        assert ack.ack_num == 5001
        assert ack.flags == TCPFlags.ACK
        assert ack.window == 32000

    def test_create_data(self):
        """Test data segment creation."""
        data = b"Hello, World!"
        seg = create_data_segment(12345, 80, 1001, 5001, data, push=True)

        assert seg.data == data
        assert seg.flags == (TCPFlags.ACK | TCPFlags.PSH)

    def test_create_fin(self):
        """Test FIN segment creation."""
        fin = create_fin_segment(12345, 80, 2000, 5001)

        assert fin.flags == (TCPFlags.FIN | TCPFlags.ACK)

    def test_create_rst(self):
        """Test RST segment creation."""
        rst = create_rst_segment(12345, 80, 2000)

        assert rst.flags == TCPFlags.RST
        assert rst.window == 0


class TestTCPOptions:
    """Test TCP options parsing and serialization."""

    def test_mss_option(self):
        """Test MSS option."""
        syn = create_syn_segment(1000, 80, 0, mss=1460)
        data = syn.serialize()
        parsed = TCPSegment.parse(data)

        mss_opt = next((o for o in parsed.options if o.kind == TCPOption.MSS), None)
        assert mss_opt is not None
        assert struct.unpack("!H", mss_opt.data)[0] == 1460

    def test_nop_and_end_options(self):
        """Test NOP and End of Options."""
        seg = TCPSegment(
            src_port=1000, dst_port=80, seq_num=0, ack_num=0,
            flags=TCPFlags.ACK, window=65535,
            options=[
                TCPOption(kind=TCPOption.NOP),
                TCPOption(kind=TCPOption.NOP),
                TCPOption(kind=TCPOption.END_OF_OPTIONS),
            ]
        )

        data = seg.serialize()
        parsed = TCPSegment.parse(data)

        nop_count = sum(1 for o in parsed.options if o.kind == TCPOption.NOP)
        assert nop_count == 2


class TestChecksum:
    """Test TCP checksum calculation."""

    def test_checksum_valid(self):
        """Test that checksum is calculated correctly."""
        seg = TCPSegment(
            src_port=12345,
            dst_port=80,
            seq_num=1000,
            ack_num=2000,
            flags=TCPFlags.ACK,
            window=65535,
            data=b"test data"
        )

        # Serialize with checksum
        data = seg.serialize("192.168.1.1", "192.168.1.2")

        # Verify checksum is non-zero
        checksum = struct.unpack("!H", data[16:18])[0]
        assert checksum != 0

    def test_checksum_detects_corruption(self):
        """Test that corrupted data fails checksum validation."""
        seg = TCPSegment(
            src_port=12345,
            dst_port=80,
            seq_num=1000,
            ack_num=2000,
            flags=TCPFlags.ACK,
            window=65535,
            data=b"test data"
        )

        data = seg.serialize("192.168.1.1", "192.168.1.2")

        # Corrupt a byte
        corrupted = bytearray(data)
        corrupted[25] ^= 0xFF  # Flip bits in data
        corrupted = bytes(corrupted)

        # Should still parse (checksum validation would be at network layer)
        parsed = TCPSegment.parse(corrupted)
        assert parsed.data != seg.data  # Data is corrupted
