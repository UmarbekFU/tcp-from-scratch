"""
Tests for TCP Buffers.
"""

import pytest
from tcp.buffer import SendBuffer, ReceiveBuffer, BufferSegment


class TestSendBuffer:
    """Test send buffer operations."""

    def test_basic_write_and_send(self):
        """Test basic write and get_data_to_send."""
        buf = SendBuffer(capacity=1000, initial_seq=100)

        # Write data
        written = buf.write(b"Hello, World!")
        assert written == 13
        assert buf.bytes_unsent == 13
        assert buf.bytes_in_flight == 0

        # Get data to send
        result = buf.get_data_to_send(max_bytes=100)
        assert result is not None
        seq, data = result
        assert seq == 100
        assert data == b"Hello, World!"

    def test_partial_send(self):
        """Test sending data in chunks."""
        buf = SendBuffer(capacity=1000, initial_seq=100)
        buf.write(b"Hello, World!")

        # Send first chunk
        result = buf.get_data_to_send(max_bytes=5)
        seq, data = result
        assert seq == 100
        assert data == b"Hello"

        # Mark as sent
        buf.mark_sent(100, 5, 1000.0)
        assert buf.bytes_in_flight == 5
        assert buf.bytes_unsent == 8

        # Get next chunk
        result = buf.get_data_to_send(max_bytes=100)
        seq, data = result
        assert seq == 105
        assert data == b", World!"

    def test_acknowledgment(self):
        """Test acknowledging data."""
        buf = SendBuffer(capacity=1000, initial_seq=100)
        buf.write(b"Hello, World!")

        # Send all
        buf.get_data_to_send(100)
        buf.mark_sent(100, 13, 1000.0)

        # Acknowledge
        acked = buf.acknowledge(113)
        assert len(acked) == 1
        assert acked[0].seq_num == 100
        assert buf.bytes_in_flight == 0
        assert buf.is_empty()

    def test_partial_acknowledgment(self):
        """Test partial acknowledgment."""
        buf = SendBuffer(capacity=1000, initial_seq=100)
        buf.write(b"Hello, World!")

        # Send in chunks
        buf.get_data_to_send(5)
        buf.mark_sent(100, 5, 1000.0)
        buf.get_data_to_send(8)
        buf.mark_sent(105, 8, 1001.0)

        # Acknowledge first chunk only
        acked = buf.acknowledge(105)
        assert len(acked) == 1
        assert buf.bytes_in_flight == 8
        assert buf.snd_una == 105

    def test_buffer_full(self):
        """Test buffer capacity limit."""
        buf = SendBuffer(capacity=10, initial_seq=0)

        written = buf.write(b"Hello, World!")  # 13 bytes
        assert written == 10  # Only 10 fit
        assert buf.available_space == 0

    def test_retransmit(self):
        """Test getting segment for retransmission."""
        buf = SendBuffer(capacity=1000, initial_seq=100)
        buf.write(b"Hello")
        buf.get_data_to_send(5)
        buf.mark_sent(100, 5, 1000.0)

        # Get for retransmit
        seg = buf.get_segment_for_retransmit(100)
        assert seg is not None
        assert seg.data == b"Hello"
        assert seg.retransmit_count == 1

        # Retransmit again
        seg = buf.get_segment_for_retransmit(100)
        assert seg.retransmit_count == 2

    def test_oldest_unacked(self):
        """Test getting oldest unacknowledged segment."""
        buf = SendBuffer(capacity=1000, initial_seq=100)
        buf.write(b"Hello, World!")

        buf.get_data_to_send(5)
        buf.mark_sent(100, 5, 1000.0)
        buf.get_data_to_send(5)
        buf.mark_sent(105, 5, 1001.0)

        seg = buf.get_oldest_unacked()
        assert seg is not None
        assert seg.seq_num == 100


class TestReceiveBuffer:
    """Test receive buffer operations."""

    def test_in_order_receive(self):
        """Test receiving in-order segments."""
        buf = ReceiveBuffer(capacity=1000, initial_seq=100)

        # Receive in order
        accepted, ack = buf.receive_segment(100, b"Hello")
        assert accepted
        assert ack == 105
        assert buf.bytes_available == 5

        accepted, ack = buf.receive_segment(105, b", World!")
        assert accepted
        assert ack == 113

        # Read data
        data = buf.read(100)
        assert data == b"Hello, World!"

    def test_out_of_order_receive(self):
        """Test receiving out-of-order segments."""
        buf = ReceiveBuffer(capacity=1000, initial_seq=100)

        # Receive second segment first
        accepted, ack = buf.receive_segment(105, b", World!")
        assert accepted
        assert ack == 100  # Still waiting for 100-104
        assert buf.bytes_available == 0  # Not yet readable

        # Receive first segment
        accepted, ack = buf.receive_segment(100, b"Hello")
        assert accepted
        assert ack == 113  # Now have everything
        assert buf.bytes_available == 13

        data = buf.read(100)
        assert data == b"Hello, World!"

    def test_duplicate_segment(self):
        """Test receiving duplicate segment."""
        buf = ReceiveBuffer(capacity=1000, initial_seq=100)

        buf.receive_segment(100, b"Hello")

        # Receive same segment again
        accepted, ack = buf.receive_segment(100, b"Hello")
        assert not accepted  # Already have it
        assert ack == 105

    def test_partial_overlap(self):
        """Test segment with partial overlap."""
        buf = ReceiveBuffer(capacity=1000, initial_seq=100)

        buf.receive_segment(100, b"Hello")

        # Receive overlapping segment
        accepted, ack = buf.receive_segment(103, b"loWorld")
        assert accepted
        assert ack == 110  # Got new bytes from 105-110

    def test_receive_window(self):
        """Test receive window calculation."""
        buf = ReceiveBuffer(capacity=100, initial_seq=0)

        assert buf.receive_window == 100

        buf.receive_segment(0, b"Hello")  # 5 bytes
        assert buf.receive_window == 95

        buf.read(5)  # Application reads data
        assert buf.receive_window == 100

    def test_sack_blocks(self):
        """Test SACK block generation."""
        buf = ReceiveBuffer(capacity=1000, initial_seq=100)

        # Receive out of order
        buf.receive_segment(110, b"World")
        buf.receive_segment(120, b"!")

        blocks = buf.get_sack_blocks()
        assert len(blocks) >= 2

        # Should report the out-of-order ranges
        # (110-115) and (120-121)

    def test_segment_before_window(self):
        """Test segment entirely before receive window."""
        buf = ReceiveBuffer(capacity=1000, initial_seq=100)

        # Receive and advance window
        buf.receive_segment(100, b"Hello")
        buf.read(5)

        # Old segment
        accepted, ack = buf.receive_segment(95, b"Old")
        assert not accepted
        assert ack == 105

    def test_peek(self):
        """Test peeking without removing data."""
        buf = ReceiveBuffer(capacity=1000, initial_seq=100)
        buf.receive_segment(100, b"Hello")

        peeked = buf.peek(3)
        assert peeked == b"Hel"
        assert buf.bytes_available == 5  # Still there

        data = buf.read(5)
        assert data == b"Hello"


class TestBufferSegment:
    """Test BufferSegment dataclass."""

    def test_end_seq(self):
        """Test end sequence calculation."""
        seg = BufferSegment(seq_num=100, data=b"Hello")
        assert seg.end_seq == 105
        assert len(seg) == 5

    def test_empty_segment(self):
        """Test empty segment."""
        seg = BufferSegment(seq_num=100, data=b"")
        assert seg.end_seq == 100
        assert len(seg) == 0
