"""
TCP Buffers - Send and Receive buffer management.

TCP needs buffers on both ends:

Send Buffer:
- Holds data written by the application but not yet acknowledged
- Data remains until ACKed (for potential retransmission)
- Organized by sequence number

Receive Buffer:
- Holds data received from the network but not yet read by application
- Handles out-of-order segments (storing them until gaps are filled)
- Provides the receive window advertisement

The buffer design is crucial for TCP performance. The receive window (how much
space we advertise) directly affects throughput - a small window means the
sender must wait frequently for ACKs.
"""

from dataclasses import dataclass, field
from typing import Optional, Tuple, List, Dict
from collections import OrderedDict
import threading


@dataclass
class BufferSegment:
    """
    A segment of data in the buffer with its sequence number.

    Used for tracking sent-but-unacknowledged data and out-of-order received data.
    """
    seq_num: int
    data: bytes
    sent_time: Optional[float] = None  # For RTT calculation
    retransmit_count: int = 0

    @property
    def end_seq(self) -> int:
        """Sequence number of byte after last byte in segment."""
        return self.seq_num + len(self.data)

    def __len__(self) -> int:
        return len(self.data)


class SendBuffer:
    """
    TCP Send Buffer - manages outgoing data.

    The send buffer has three logical regions:
    1. Data sent and acknowledged (can be discarded)
    2. Data sent but not yet acknowledged (must be kept for retransmission)
    3. Data written by application but not yet sent

    Visualization:
    [    ACKed (discarded)    |  Sent, unACKed  |    Unsent    |  Empty  ]
                              ^                 ^              ^         ^
                           SND.UNA           SND.NXT       write_ptr   capacity

    SND.UNA = Send Unacknowledged - oldest unacknowledged byte
    SND.NXT = Send Next - next byte to send
    """

    def __init__(self, capacity: int = 65535, initial_seq: int = 0):
        """
        Initialize send buffer.

        Args:
            capacity: Maximum buffer size in bytes
            initial_seq: Initial sequence number (ISN)
        """
        self.capacity = capacity
        self._buffer = bytearray()

        # Sequence number tracking
        self._snd_una = initial_seq  # Oldest unacknowledged
        self._snd_nxt = initial_seq  # Next to send

        # Track sent segments for retransmission
        self._unacked_segments: Dict[int, BufferSegment] = {}

        # Thread safety
        self._lock = threading.Lock()

    @property
    def snd_una(self) -> int:
        """Oldest unacknowledged sequence number."""
        return self._snd_una

    @property
    def snd_nxt(self) -> int:
        """Next sequence number to send."""
        return self._snd_nxt

    @property
    def bytes_in_flight(self) -> int:
        """Number of bytes sent but not yet acknowledged."""
        return self._snd_nxt - self._snd_una

    @property
    def bytes_unsent(self) -> int:
        """Number of bytes in buffer not yet sent."""
        return len(self._buffer) - self.bytes_in_flight

    @property
    def available_space(self) -> int:
        """Space available for new data."""
        return self.capacity - len(self._buffer)

    def write(self, data: bytes) -> int:
        """
        Write data to the buffer.

        Returns the number of bytes actually written (may be less than
        len(data) if buffer is full).
        """
        with self._lock:
            space = self.available_space
            to_write = data[:space]
            self._buffer.extend(to_write)
            return len(to_write)

    def get_data_to_send(self, max_bytes: int) -> Optional[Tuple[int, bytes]]:
        """
        Get the next chunk of data to send.

        Args:
            max_bytes: Maximum segment size

        Returns:
            Tuple of (sequence_number, data) or None if nothing to send
        """
        with self._lock:
            # Calculate how much unsent data we have
            sent_offset = self._snd_nxt - self._snd_una
            unsent_start = sent_offset
            unsent_data = self._buffer[unsent_start:]

            if not unsent_data:
                return None

            # Take up to max_bytes
            to_send = bytes(unsent_data[:max_bytes])
            seq = self._snd_nxt

            return (seq, to_send)

    def mark_sent(self, seq_num: int, length: int, sent_time: float):
        """
        Mark data as sent (but not yet acknowledged).

        Called after successfully transmitting a segment.
        """
        with self._lock:
            # Advance SND.NXT
            if seq_num + length > self._snd_nxt:
                self._snd_nxt = seq_num + length

            # Record for potential retransmission
            offset = seq_num - self._snd_una
            data = bytes(self._buffer[offset:offset + length])
            self._unacked_segments[seq_num] = BufferSegment(
                seq_num=seq_num,
                data=data,
                sent_time=sent_time
            )

    def acknowledge(self, ack_num: int) -> List[BufferSegment]:
        """
        Process an acknowledgment.

        Removes acknowledged data from the buffer and returns the segments
        that were acknowledged (for RTT calculation).

        Args:
            ack_num: Cumulative acknowledgment number

        Returns:
            List of newly acknowledged segments
        """
        with self._lock:
            if ack_num <= self._snd_una:
                return []  # Duplicate ACK, nothing new acknowledged

            if ack_num > self._snd_nxt:
                # ACK for data we haven't sent - protocol error
                return []

            # Calculate how many bytes were acknowledged
            bytes_acked = ack_num - self._snd_una

            # Remove acknowledged data from buffer
            self._buffer = self._buffer[bytes_acked:]

            # Find and remove acknowledged segments
            acked_segments = []
            seqs_to_remove = []

            for seq, segment in self._unacked_segments.items():
                if segment.end_seq <= ack_num:
                    acked_segments.append(segment)
                    seqs_to_remove.append(seq)

            for seq in seqs_to_remove:
                del self._unacked_segments[seq]

            # Update SND.UNA
            self._snd_una = ack_num

            # Adjust SND.NXT if needed (shouldn't happen in normal operation)
            if self._snd_nxt < self._snd_una:
                self._snd_nxt = self._snd_una

            return acked_segments

    def get_segment_for_retransmit(self, seq_num: int) -> Optional[BufferSegment]:
        """
        Get a specific segment for retransmission.

        Args:
            seq_num: Sequence number of segment to retransmit

        Returns:
            The segment if found, None otherwise
        """
        with self._lock:
            if seq_num in self._unacked_segments:
                segment = self._unacked_segments[seq_num]
                segment.retransmit_count += 1
                return segment
            return None

    def get_oldest_unacked(self) -> Optional[BufferSegment]:
        """Get the oldest unacknowledged segment for timeout retransmission."""
        with self._lock:
            if not self._unacked_segments:
                return None
            oldest_seq = min(self._unacked_segments.keys())
            segment = self._unacked_segments[oldest_seq]
            segment.retransmit_count += 1
            return segment

    def is_empty(self) -> bool:
        """Check if buffer has no data (all sent and acknowledged)."""
        with self._lock:
            return len(self._buffer) == 0

    def has_data_to_send(self) -> bool:
        """Check if there's unsent data in the buffer."""
        with self._lock:
            return self.bytes_unsent > 0

    def has_unacked_data(self) -> bool:
        """Check if there's sent but unacknowledged data."""
        with self._lock:
            return self.bytes_in_flight > 0

    def __len__(self) -> int:
        """Total bytes in buffer (sent + unsent)."""
        return len(self._buffer)


class ReceiveBuffer:
    """
    TCP Receive Buffer - manages incoming data.

    The receive buffer handles:
    1. In-order data delivery to the application
    2. Out-of-order segment storage
    3. Receive window advertisement

    Visualization:
    [  Read by app  |  Received, in-order  |  [gaps]  [out-of-order]  |  Empty  ]
                    ^                      ^                          ^
                 RCV.NXT               contiguous_end               capacity

    RCV.NXT = Receive Next - next expected sequence number
    """

    def __init__(self, capacity: int = 65535, initial_seq: int = 0):
        """
        Initialize receive buffer.

        Args:
            capacity: Maximum buffer size (also the max receive window)
            initial_seq: Initial sequence number (from SYN)
        """
        self.capacity = capacity

        # The in-order buffer (ready for application to read)
        self._buffer = bytearray()

        # Out-of-order segments (seq_num -> data)
        self._out_of_order: Dict[int, bytes] = {}

        # Next expected sequence number
        self._rcv_nxt = initial_seq

        # Thread safety
        self._lock = threading.Lock()

    @property
    def rcv_nxt(self) -> int:
        """Next expected sequence number."""
        return self._rcv_nxt

    @property
    def receive_window(self) -> int:
        """
        Current receive window to advertise.

        This tells the sender how much more data we can accept.
        """
        with self._lock:
            used = len(self._buffer) + sum(len(d) for d in self._out_of_order.values())
            return max(0, self.capacity - used)

    @property
    def bytes_available(self) -> int:
        """Bytes available for application to read."""
        with self._lock:
            return len(self._buffer)

    def receive_segment(self, seq_num: int, data: bytes) -> Tuple[bool, int]:
        """
        Receive a segment and add it to the buffer.

        Handles in-order and out-of-order segments. Out-of-order segments
        are stored until the gap is filled.

        Args:
            seq_num: Sequence number of first byte
            data: Segment payload

        Returns:
            Tuple of (accepted, ack_num)
            accepted: True if segment was accepted (had new data)
            ack_num: The acknowledgment number to send back
        """
        if not data:
            return (False, self._rcv_nxt)

        with self._lock:
            end_seq = seq_num + len(data)

            # Check if segment is completely before our window (old duplicate)
            if end_seq <= self._rcv_nxt:
                return (False, self._rcv_nxt)

            # Check if segment starts after our window (future data, no space)
            if seq_num >= self._rcv_nxt + self.capacity:
                return (False, self._rcv_nxt)

            # Trim data that's before RCV.NXT (partial retransmission)
            if seq_num < self._rcv_nxt:
                trim = self._rcv_nxt - seq_num
                data = data[trim:]
                seq_num = self._rcv_nxt

            # Check if this is the next expected segment (in order)
            if seq_num == self._rcv_nxt:
                # Add to in-order buffer
                self._buffer.extend(data)
                self._rcv_nxt += len(data)

                # Check if we can now add any out-of-order segments
                self._merge_out_of_order()

                return (True, self._rcv_nxt)
            else:
                # Out of order - store for later
                # Check for overlap with existing out-of-order segments
                self._store_out_of_order(seq_num, data)
                return (True, self._rcv_nxt)  # ACK still indicates gap

    def _store_out_of_order(self, seq_num: int, data: bytes):
        """Store an out-of-order segment, handling overlaps."""
        end_seq = seq_num + len(data)

        # Remove any segments completely covered by this one
        seqs_to_remove = []
        for existing_seq, existing_data in self._out_of_order.items():
            existing_end = existing_seq + len(existing_data)
            if seq_num <= existing_seq and end_seq >= existing_end:
                seqs_to_remove.append(existing_seq)

        for seq in seqs_to_remove:
            del self._out_of_order[seq]

        # Check if this segment is covered by existing data
        for existing_seq, existing_data in self._out_of_order.items():
            existing_end = existing_seq + len(existing_data)
            if existing_seq <= seq_num and existing_end >= end_seq:
                return  # Already have this data

        # Store the segment
        self._out_of_order[seq_num] = data

    def _merge_out_of_order(self):
        """
        Merge any out-of-order segments that are now contiguous.

        Called after adding in-order data to see if we can incorporate
        previously out-of-order segments.
        """
        while True:
            merged = False
            for seq_num, data in list(self._out_of_order.items()):
                if seq_num <= self._rcv_nxt:
                    # This segment can be merged
                    if seq_num + len(data) > self._rcv_nxt:
                        # Some new data
                        overlap = self._rcv_nxt - seq_num
                        new_data = data[overlap:]
                        self._buffer.extend(new_data)
                        self._rcv_nxt += len(new_data)
                    del self._out_of_order[seq_num]
                    merged = True
                    break
            if not merged:
                break

    def read(self, max_bytes: int) -> bytes:
        """
        Read data from the buffer (for application).

        Args:
            max_bytes: Maximum bytes to read

        Returns:
            The data read (may be less than max_bytes if less available)
        """
        with self._lock:
            to_read = min(max_bytes, len(self._buffer))
            data = bytes(self._buffer[:to_read])
            self._buffer = self._buffer[to_read:]
            return data

    def peek(self, max_bytes: int) -> bytes:
        """
        Peek at data without removing it from buffer.

        Args:
            max_bytes: Maximum bytes to peek

        Returns:
            The data (without removing from buffer)
        """
        with self._lock:
            to_peek = min(max_bytes, len(self._buffer))
            return bytes(self._buffer[:to_peek])

    def get_sack_blocks(self) -> List[Tuple[int, int]]:
        """
        Get SACK blocks for out-of-order segments.

        Returns a list of (left_edge, right_edge) tuples representing
        received but non-contiguous data. This allows the sender to
        know exactly what we've received and what's missing.

        Returns:
            List of (start_seq, end_seq) tuples
        """
        with self._lock:
            if not self._out_of_order:
                return []

            blocks = []
            for seq, data in sorted(self._out_of_order.items()):
                end = seq + len(data)
                # Try to merge with previous block
                if blocks and blocks[-1][1] >= seq:
                    blocks[-1] = (blocks[-1][0], max(blocks[-1][1], end))
                else:
                    blocks.append((seq, end))

            return blocks[:4]  # SACK option has room for 4 blocks

    def is_empty(self) -> bool:
        """Check if buffer has no data to read."""
        with self._lock:
            return len(self._buffer) == 0

    def has_data(self) -> bool:
        """Check if there's data available to read."""
        with self._lock:
            return len(self._buffer) > 0

    def __len__(self) -> int:
        """Total bytes available to read."""
        return len(self._buffer)
