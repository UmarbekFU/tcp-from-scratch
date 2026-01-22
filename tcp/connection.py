"""
TCP Connection - The main TCP connection implementation.

This module brings together all the TCP components:
- Segment parsing and construction
- State machine for connection lifecycle
- Send and receive buffers for data management
- Retransmission timer for reliability
- Congestion controller for network capacity management

A TCPConnection represents one end of a TCP connection. It handles:
1. Connection establishment (3-way handshake)
2. Data transfer with reliability
3. Flow control (receive window)
4. Congestion control
5. Connection teardown (4-way handshake)

This implementation is educational - it's not meant to replace the OS TCP stack,
but to demonstrate how TCP works at a fundamental level.
"""

import time
import threading
import secrets
import logging
from dataclasses import dataclass, field
from typing import Optional, Tuple, Callable, List, Any
from queue import Queue, Empty

from .segment import (
    TCPSegment, TCPFlags, TCPOption,
    create_syn_segment, create_syn_ack_segment,
    create_ack_segment, create_data_segment,
    create_fin_segment, create_rst_segment
)
from .states import TCPState, TCPStateMachine, determine_event_from_segment
from .buffer import SendBuffer, ReceiveBuffer
from .timer import RetransmissionTimer, PersistTimer
from .congestion import CongestionController, TCPReno, CUBIC


# Set up logging
logger = logging.getLogger(__name__)


@dataclass
class ConnectionId:
    """
    Identifies a TCP connection (4-tuple).

    A TCP connection is uniquely identified by:
    - Local IP and port
    - Remote IP and port

    This allows multiple connections between the same hosts (different ports)
    and multiple connections to the same service from different clients.
    """
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int

    def __hash__(self):
        return hash((self.local_ip, self.local_port, self.remote_ip, self.remote_port))

    def reversed(self) -> "ConnectionId":
        """Return connection ID from the other endpoint's perspective."""
        return ConnectionId(
            local_ip=self.remote_ip,
            local_port=self.remote_port,
            remote_ip=self.local_ip,
            remote_port=self.local_port
        )


@dataclass
class TCPConfig:
    """Configuration options for TCP connection."""

    # Buffer sizes
    send_buffer_size: int = 65535
    receive_buffer_size: int = 65535

    # Maximum Segment Size (typically MTU - 40 for IP + TCP headers)
    mss: int = 1460

    # Initial window size in segments
    initial_window: int = 10

    # Retransmission settings
    initial_rto: float = 1.0  # seconds
    min_rto: float = 0.2      # seconds
    max_rto: float = 60.0     # seconds

    # Timeouts
    connection_timeout: float = 75.0  # seconds
    time_wait_duration: float = 120.0  # seconds (2 * MSL)
    fin_wait_2_timeout: float = 60.0  # seconds

    # Congestion control algorithm: "reno" or "cubic"
    congestion_algorithm: str = "reno"

    # Enable/disable features
    nagle_enabled: bool = True
    delayed_ack_enabled: bool = True
    sack_enabled: bool = True


class TCPConnection:
    """
    A TCP connection implementation.

    This class implements the core TCP protocol logic:
    - Connection establishment via 3-way handshake
    - Reliable data transfer using sequence numbers and ACKs
    - Flow control using the sliding window protocol
    - Congestion control to prevent network overload
    - Connection teardown via 4-way handshake

    Usage:
        # Active open (client)
        conn = TCPConnection(config)
        conn.connect(remote_ip, remote_port, local_ip, local_port)

        # Passive open (server)
        conn = TCPConnection(config)
        conn.listen(local_ip, local_port)
        new_conn = conn.accept()

        # Data transfer
        conn.send(b"Hello, World!")
        data = conn.receive()

        # Close
        conn.close()
    """

    def __init__(self, config: Optional[TCPConfig] = None,
                 send_callback: Optional[Callable[[bytes, str, int], None]] = None):
        """
        Initialize TCP connection.

        Args:
            config: TCP configuration options
            send_callback: Function to call when sending segments
                          Signature: (segment_bytes, dest_ip, dest_port)
        """
        self.config = config or TCPConfig()
        self._send_callback = send_callback

        # Connection identification
        self.conn_id: Optional[ConnectionId] = None

        # State machine
        self._state_machine = TCPStateMachine()

        # Sequence number state
        self._iss = 0  # Initial Send Sequence number
        self._irs = 0  # Initial Receive Sequence number

        # Buffers (created when connection established)
        self._send_buffer: Optional[SendBuffer] = None
        self._receive_buffer: Optional[ReceiveBuffer] = None

        # Timers
        self._retransmit_timer = RetransmissionTimer(on_timeout=self._on_timeout)
        self._persist_timer = PersistTimer(on_probe=self._send_window_probe)
        self._time_wait_timer: Optional[threading.Timer] = None
        self._fin_wait_2_timer: Optional[threading.Timer] = None

        # Congestion control
        if self.config.congestion_algorithm == "cubic":
            self._congestion = CUBIC(mss=self.config.mss,
                                     initial_cwnd=self.config.initial_window)
        else:
            self._congestion = TCPReno(mss=self.config.mss,
                                       initial_cwnd=self.config.initial_window)

        # Remote receive window
        self._remote_window = 0

        # MSS negotiated with peer
        self._peer_mss = self.config.mss

        # Tracking for duplicate ACKs
        self._last_ack_received = 0
        self._dup_ack_count = 0

        # Nagle algorithm state
        self._nagle_waiting = False

        # Delayed ACK state
        self._delayed_ack_pending = False
        self._delayed_ack_timer: Optional[threading.Timer] = None

        # Event for blocking operations
        self._established_event = threading.Event()
        self._close_event = threading.Event()
        self._data_available = threading.Event()

        # Queue for incoming segments (from network layer)
        self._incoming_segments: Queue = Queue()

        # Processing thread
        self._running = False
        self._process_thread: Optional[threading.Thread] = None

        # Callbacks for events
        self._on_established: Optional[Callable] = None
        self._on_data_received: Optional[Callable[[bytes], None]] = None
        self._on_closed: Optional[Callable] = None

        # Lock for thread safety
        self._lock = threading.RLock()

    @property
    def state(self) -> TCPState:
        """Current connection state."""
        return self._state_machine.state

    @property
    def is_established(self) -> bool:
        """Check if connection is established."""
        return self._state_machine.is_established()

    @property
    def is_closed(self) -> bool:
        """Check if connection is closed."""
        return self._state_machine.is_closed()

    def _generate_isn(self) -> int:
        """
        Generate Initial Sequence Number.

        ISN should be unpredictable to prevent:
        1. Old duplicate segments being accepted
        2. Sequence number prediction attacks

        Modern systems use cryptographically random ISNs.
        """
        return secrets.randbelow(2**32)

    # ========== Connection Establishment ==========

    def connect(self, remote_ip: str, remote_port: int,
                local_ip: str = "0.0.0.0", local_port: int = 0,
                timeout: Optional[float] = None) -> bool:
        """
        Actively open a connection (client side).

        Performs the three-way handshake:
        1. Send SYN
        2. Receive SYN-ACK
        3. Send ACK

        Args:
            remote_ip: Destination IP address
            remote_port: Destination port
            local_ip: Source IP address
            local_port: Source port (0 for auto-assign)
            timeout: Connection timeout in seconds

        Returns:
            True if connection established, False on timeout/error
        """
        if local_port == 0:
            local_port = secrets.randbelow(16384) + 49152  # Ephemeral port

        with self._lock:
            self.conn_id = ConnectionId(local_ip, local_port, remote_ip, remote_port)

            # Generate ISN
            self._iss = self._generate_isn()

            # Initialize send buffer with ISN
            self._send_buffer = SendBuffer(
                capacity=self.config.send_buffer_size,
                initial_seq=self._iss + 1  # +1 because SYN consumes a seq
            )

            # Transition state
            success, action = self._state_machine.transition("active_open")
            if not success:
                logger.error("Failed to transition to SYN_SENT state")
                return False

            # Send SYN
            self._send_syn()

            # Start processing thread
            self._start_processing()

        # Wait for established
        timeout = timeout or self.config.connection_timeout
        if self._established_event.wait(timeout=timeout):
            return True
        else:
            # Timeout - clean up
            self.abort()
            return False

    def _send_syn(self):
        """Send SYN segment."""
        syn = create_syn_segment(
            src_port=self.conn_id.local_port,
            dst_port=self.conn_id.remote_port,
            seq_num=self._iss,
            window=self.config.receive_buffer_size,
            mss=self.config.mss
        )

        # Add SACK permitted option if enabled
        if self.config.sack_enabled:
            syn.options.append(TCPOption(kind=TCPOption.SACK_PERMITTED, length=2))

        self._transmit_segment(syn)
        self._retransmit_timer.start()

        logger.debug(f"Sent SYN: seq={self._iss}")

    def listen(self, local_ip: str = "0.0.0.0", local_port: int = 0):
        """
        Passively open a connection (server side).

        Puts the connection in LISTEN state, ready to accept incoming connections.

        Args:
            local_ip: IP address to listen on
            local_port: Port to listen on
        """
        with self._lock:
            self.conn_id = ConnectionId(local_ip, local_port, "", 0)

            success, action = self._state_machine.transition("passive_open")
            if not success:
                raise RuntimeError("Failed to enter LISTEN state")

            self._start_processing()

        logger.debug(f"Listening on {local_ip}:{local_port}")

    def accept_connection(self, syn_segment: TCPSegment, remote_ip: str) -> bool:
        """
        Accept an incoming SYN and complete handshake.

        Called by the server when a SYN arrives on a listening socket.

        Args:
            syn_segment: The received SYN segment
            remote_ip: Source IP of the SYN

        Returns:
            True if handshake completed successfully
        """
        with self._lock:
            if self.state != TCPState.LISTEN:
                logger.warning("accept_connection called in non-LISTEN state")
                return False

            # Update connection ID with remote info
            self.conn_id = ConnectionId(
                self.conn_id.local_ip,
                self.conn_id.local_port,
                remote_ip,
                syn_segment.src_port
            )

            # Generate our ISN
            self._iss = self._generate_isn()

            # Record their ISN
            self._irs = syn_segment.seq_num

            # Initialize buffers
            self._send_buffer = SendBuffer(
                capacity=self.config.send_buffer_size,
                initial_seq=self._iss + 1
            )
            self._receive_buffer = ReceiveBuffer(
                capacity=self.config.receive_buffer_size,
                initial_seq=self._irs + 1  # +1 because SYN consumed a seq
            )

            # Record remote window
            self._remote_window = syn_segment.window

            # Extract MSS from options
            for opt in syn_segment.options:
                if opt.kind == TCPOption.MSS and len(opt.data) >= 2:
                    self._peer_mss = int.from_bytes(opt.data[:2], 'big')
                    logger.debug(f"Peer MSS: {self._peer_mss}")

            # Transition state
            success, action = self._state_machine.transition("recv_syn")
            if not success:
                return False

            # Send SYN-ACK
            self._send_syn_ack()

            return True

    def _send_syn_ack(self):
        """Send SYN-ACK segment."""
        syn_ack = create_syn_ack_segment(
            src_port=self.conn_id.local_port,
            dst_port=self.conn_id.remote_port,
            seq_num=self._iss,
            ack_num=self._irs + 1,
            window=self.config.receive_buffer_size,
            mss=self.config.mss
        )

        if self.config.sack_enabled:
            syn_ack.options.append(TCPOption(kind=TCPOption.SACK_PERMITTED, length=2))

        self._transmit_segment(syn_ack)
        self._retransmit_timer.start()

        logger.debug(f"Sent SYN-ACK: seq={self._iss}, ack={self._irs + 1}")

    # ========== Data Transfer ==========

    def send(self, data: bytes, push: bool = False) -> int:
        """
        Send data on the connection.

        Data is buffered and sent according to flow control and congestion
        control constraints. Returns immediately after buffering.

        Args:
            data: Data to send
            push: If True, set PSH flag to request immediate delivery

        Returns:
            Number of bytes accepted into send buffer

        Raises:
            RuntimeError: If connection is not in a state that allows sending
        """
        with self._lock:
            if not self._state_machine.can_send():
                raise RuntimeError(f"Cannot send in state {self.state}")

            if not self._send_buffer:
                raise RuntimeError("Send buffer not initialized")

            # Write to send buffer
            bytes_written = self._send_buffer.write(data)

            # Trigger sending
            self._send_data()

            return bytes_written

    def receive(self, max_bytes: int = 65535, timeout: Optional[float] = None) -> bytes:
        """
        Receive data from the connection.

        Blocks until data is available or timeout expires.

        Args:
            max_bytes: Maximum bytes to receive
            timeout: Timeout in seconds (None for no timeout)

        Returns:
            Received data (may be less than max_bytes)

        Raises:
            RuntimeError: If connection is not in a state that allows receiving
        """
        with self._lock:
            if not self._state_machine.can_receive() and not self._receive_buffer.has_data():
                if self.state == TCPState.CLOSE_WAIT:
                    # Peer closed, return remaining data then empty
                    pass
                else:
                    raise RuntimeError(f"Cannot receive in state {self.state}")

        # Wait for data
        start = time.time()
        while True:
            with self._lock:
                if self._receive_buffer and self._receive_buffer.has_data():
                    return self._receive_buffer.read(max_bytes)

                if self.state in (TCPState.CLOSE_WAIT, TCPState.TIME_WAIT, TCPState.CLOSED):
                    return b""  # Connection closed by peer

            # Check timeout
            if timeout is not None:
                elapsed = time.time() - start
                if elapsed >= timeout:
                    return b""
                remaining = timeout - elapsed
            else:
                remaining = None

            self._data_available.wait(timeout=remaining)
            self._data_available.clear()

    def _send_data(self):
        """
        Send data from the send buffer.

        Respects both flow control (receiver window) and congestion control.
        Implements Nagle's algorithm if enabled.
        """
        if not self._send_buffer:
            return

        # Calculate effective window
        send_window = self._congestion.get_send_window(self._remote_window)

        # How much can we send?
        bytes_in_flight = self._send_buffer.bytes_in_flight
        available_window = max(0, send_window - bytes_in_flight)

        if available_window == 0:
            # Window is full, start persist timer if receiver window is zero
            if self._remote_window == 0:
                self._persist_timer.start(self._retransmit_timer.rto)
            return

        # Nagle's algorithm: don't send small segments if there's unacked data
        if self.config.nagle_enabled and bytes_in_flight > 0:
            if self._send_buffer.bytes_unsent < self._peer_mss:
                # Small segment and unacked data - wait
                return

        # Get data to send
        segment_size = min(self._peer_mss, available_window)
        result = self._send_buffer.get_data_to_send(segment_size)

        if result is None:
            return

        seq_num, data = result

        # Create and send segment
        segment = create_data_segment(
            src_port=self.conn_id.local_port,
            dst_port=self.conn_id.remote_port,
            seq_num=seq_num,
            ack_num=self._receive_buffer.rcv_nxt if self._receive_buffer else 0,
            data=data,
            window=self._receive_buffer.receive_window if self._receive_buffer else 0,
            push=True  # Could be smarter about PSH flag
        )

        self._transmit_segment(segment)
        self._send_buffer.mark_sent(seq_num, len(data), time.time())

        # Start retransmission timer
        if not self._retransmit_timer.is_active():
            self._retransmit_timer.start()

        logger.debug(f"Sent data: seq={seq_num}, len={len(data)}")

        # Try to send more
        if self._send_buffer.has_data_to_send():
            self._send_data()

    def _send_window_probe(self):
        """Send a zero-window probe."""
        if not self._send_buffer or not self._send_buffer.has_data_to_send():
            return

        # Send 1 byte probe
        result = self._send_buffer.get_data_to_send(1)
        if result is None:
            return

        seq_num, data = result
        segment = create_data_segment(
            src_port=self.conn_id.local_port,
            dst_port=self.conn_id.remote_port,
            seq_num=seq_num,
            ack_num=self._receive_buffer.rcv_nxt if self._receive_buffer else 0,
            data=data,
            window=self._receive_buffer.receive_window if self._receive_buffer else 0
        )
        self._transmit_segment(segment)

    def _send_ack(self):
        """Send an ACK segment."""
        if not self._receive_buffer or not self.conn_id:
            return

        ack = create_ack_segment(
            src_port=self.conn_id.local_port,
            dst_port=self.conn_id.remote_port,
            seq_num=self._send_buffer.snd_nxt if self._send_buffer else self._iss + 1,
            ack_num=self._receive_buffer.rcv_nxt,
            window=self._receive_buffer.receive_window
        )

        # Add SACK blocks if available
        if self.config.sack_enabled:
            sack_blocks = self._receive_buffer.get_sack_blocks()
            # Would add SACK option here

        self._transmit_segment(ack)

        logger.debug(f"Sent ACK: ack={self._receive_buffer.rcv_nxt}")

    def _schedule_delayed_ack(self):
        """Schedule a delayed ACK (200ms max)."""
        if self._delayed_ack_timer:
            return  # Already scheduled

        def send_delayed():
            with self._lock:
                self._delayed_ack_timer = None
                self._send_ack()

        self._delayed_ack_timer = threading.Timer(0.2, send_delayed)
        self._delayed_ack_timer.start()

    # ========== Segment Reception ==========

    def receive_segment(self, segment: TCPSegment, remote_ip: str):
        """
        Called when a segment arrives from the network.

        This is the main entry point for incoming data. The segment is
        queued for processing by the main loop.

        Args:
            segment: The received TCP segment
            remote_ip: Source IP address
        """
        self._incoming_segments.put((segment, remote_ip))

    def _process_segment(self, segment: TCPSegment, remote_ip: str):
        """
        Process a received segment.

        This is the heart of TCP reception - it handles all incoming segments
        based on the current state.
        """
        with self._lock:
            # Verify connection
            if self.conn_id and self.conn_id.remote_ip:
                if remote_ip != self.conn_id.remote_ip or \
                   segment.src_port != self.conn_id.remote_port:
                    # Not for this connection
                    return

            # Handle RST
            if segment.flags & TCPFlags.RST:
                self._handle_rst(segment)
                return

            # State-specific processing
            if self.state == TCPState.LISTEN:
                if segment.flags & TCPFlags.SYN:
                    self.accept_connection(segment, remote_ip)
                return

            if self.state == TCPState.SYN_SENT:
                self._handle_syn_sent(segment)
                return

            if self.state == TCPState.SYN_RECEIVED:
                self._handle_syn_received(segment)
                return

            # For established and closing states
            if self.state in (TCPState.ESTABLISHED, TCPState.FIN_WAIT_1,
                             TCPState.FIN_WAIT_2, TCPState.CLOSE_WAIT):
                self._handle_established_segment(segment)
                return

            if self.state == TCPState.CLOSING:
                self._handle_closing(segment)
                return

            if self.state == TCPState.LAST_ACK:
                self._handle_last_ack(segment)
                return

            if self.state == TCPState.TIME_WAIT:
                self._handle_time_wait(segment)
                return

    def _handle_syn_sent(self, segment: TCPSegment):
        """Handle segment received in SYN_SENT state."""
        # Expecting SYN-ACK
        if (segment.flags & TCPFlags.SYN) and (segment.flags & TCPFlags.ACK):
            # Verify ACK acknowledges our SYN
            if segment.ack_num != self._iss + 1:
                logger.warning(f"SYN-ACK with wrong ACK: {segment.ack_num} != {self._iss + 1}")
                return

            # Record peer's ISN
            self._irs = segment.seq_num
            self._remote_window = segment.window

            # Initialize receive buffer
            self._receive_buffer = ReceiveBuffer(
                capacity=self.config.receive_buffer_size,
                initial_seq=self._irs + 1
            )

            # Extract options
            for opt in segment.options:
                if opt.kind == TCPOption.MSS and len(opt.data) >= 2:
                    self._peer_mss = int.from_bytes(opt.data[:2], 'big')

            # Transition to ESTABLISHED
            self._state_machine.transition("recv_syn_ack")

            # Stop retransmission timer
            self._retransmit_timer.stop()

            # Send ACK
            self._send_ack()

            # Signal connection established
            self._established_event.set()
            if self._on_established:
                self._on_established()

            logger.info(f"Connection established: {self.conn_id}")

        elif segment.flags & TCPFlags.SYN:
            # Simultaneous open
            self._irs = segment.seq_num
            self._state_machine.transition("recv_syn")
            self._send_syn_ack()

    def _handle_syn_received(self, segment: TCPSegment):
        """Handle segment received in SYN_RECEIVED state."""
        if segment.flags & TCPFlags.ACK:
            # Verify ACK
            if segment.ack_num != self._iss + 1:
                return

            # Transition to ESTABLISHED
            self._state_machine.transition("recv_ack")
            self._retransmit_timer.stop()

            self._established_event.set()
            if self._on_established:
                self._on_established()

            logger.info(f"Connection established (server): {self.conn_id}")

            # Process any data in this segment
            if segment.data:
                self._process_data(segment)

    def _handle_established_segment(self, segment: TCPSegment):
        """Handle segment in ESTABLISHED or FIN_WAIT states."""
        # Process ACK
        if segment.flags & TCPFlags.ACK:
            self._process_ack(segment)

        # Process data
        if segment.data:
            self._process_data(segment)

        # Process FIN
        if segment.flags & TCPFlags.FIN:
            self._process_fin(segment)

    def _process_ack(self, segment: TCPSegment):
        """Process acknowledgment in a segment."""
        if not self._send_buffer:
            return

        ack_num = segment.ack_num

        # Check for duplicate ACK
        if ack_num == self._last_ack_received:
            self._dup_ack_count += 1
            self._congestion.on_duplicate_ack()

            # Fast retransmit on 3 duplicate ACKs
            if self._dup_ack_count == 3:
                logger.debug("Triple duplicate ACK - fast retransmit")
                self._retransmit_oldest()
        elif ack_num > self._last_ack_received:
            # New data acknowledged
            bytes_acked = ack_num - self._last_ack_received
            self._last_ack_received = ack_num
            self._dup_ack_count = 0

            # Update congestion control
            self._congestion.on_ack(bytes_acked)

            # Update send buffer
            acked_segments = self._send_buffer.acknowledge(ack_num)

            # Update RTT estimate from acknowledged segments
            for seg in acked_segments:
                if seg.sent_time and seg.retransmit_count == 0:
                    rtt = time.time() - seg.sent_time
                    self._retransmit_timer.update_rtt(rtt)

            # Restart timer if more data outstanding
            if self._send_buffer.has_unacked_data():
                self._retransmit_timer.restart()
            else:
                self._retransmit_timer.stop()

            # Stop persist timer if window opened
            if self._remote_window > 0:
                self._persist_timer.stop()

            # Try to send more data
            self._send_data()

            # Check for FIN acknowledgment in closing states
            if self.state == TCPState.FIN_WAIT_1:
                if ack_num >= self._send_buffer.snd_nxt:
                    self._state_machine.transition("recv_ack")

        # Update remote window
        self._remote_window = segment.window

    def _process_data(self, segment: TCPSegment):
        """Process data in a segment."""
        if not self._receive_buffer:
            return

        # Add to receive buffer
        accepted, ack_num = self._receive_buffer.receive_segment(
            segment.seq_num, segment.data
        )

        if accepted:
            # Notify application
            self._data_available.set()
            if self._on_data_received:
                self._on_data_received(segment.data)

        # Send ACK (possibly delayed)
        if self.config.delayed_ack_enabled and not (segment.flags & TCPFlags.PSH):
            self._schedule_delayed_ack()
        else:
            self._send_ack()

    def _process_fin(self, segment: TCPSegment):
        """Process FIN flag in a segment."""
        logger.debug(f"Received FIN in state {self.state}")

        # FIN consumes a sequence number
        if self._receive_buffer:
            self._receive_buffer.receive_segment(segment.seq_num + len(segment.data), b'')

        if self.state == TCPState.ESTABLISHED:
            self._state_machine.transition("recv_fin")
            self._send_ack()
        elif self.state == TCPState.FIN_WAIT_1:
            if segment.flags & TCPFlags.ACK:
                self._state_machine.transition("recv_fin_ack")
            else:
                self._state_machine.transition("recv_fin")
            self._send_ack()
            self._start_time_wait()
        elif self.state == TCPState.FIN_WAIT_2:
            self._state_machine.transition("recv_fin")
            self._send_ack()
            self._start_time_wait()

    def _handle_closing(self, segment: TCPSegment):
        """Handle segment in CLOSING state."""
        if segment.flags & TCPFlags.ACK:
            self._state_machine.transition("recv_ack")
            self._start_time_wait()

    def _handle_last_ack(self, segment: TCPSegment):
        """Handle segment in LAST_ACK state."""
        if segment.flags & TCPFlags.ACK:
            self._state_machine.transition("recv_ack")
            self._connection_closed()

    def _handle_time_wait(self, segment: TCPSegment):
        """Handle segment in TIME_WAIT state."""
        if segment.flags & TCPFlags.FIN:
            # Retransmitted FIN - resend ACK
            self._send_ack()
            # Restart TIME_WAIT timer
            self._start_time_wait()

    def _handle_rst(self, segment: TCPSegment):
        """Handle RST segment."""
        logger.warning(f"Received RST in state {self.state}")
        self._state_machine.transition("recv_rst")
        self._connection_closed()

    # ========== Connection Termination ==========

    def close(self, timeout: Optional[float] = None):
        """
        Close the connection gracefully.

        Initiates the four-way handshake:
        1. Send FIN
        2. Receive ACK of FIN
        3. Receive FIN from peer
        4. Send ACK of peer's FIN

        Args:
            timeout: Time to wait for graceful close
        """
        with self._lock:
            if self.state == TCPState.ESTABLISHED:
                self._state_machine.transition("close")
                self._send_fin()
            elif self.state == TCPState.CLOSE_WAIT:
                self._state_machine.transition("close")
                self._send_fin()
            elif self.state in (TCPState.CLOSED, TCPState.LISTEN):
                self._connection_closed()
                return
            else:
                logger.warning(f"Close called in state {self.state}")
                return

        # Wait for close to complete
        timeout = timeout or self.config.time_wait_duration
        self._close_event.wait(timeout=timeout)

    def _send_fin(self):
        """Send FIN segment."""
        fin = create_fin_segment(
            src_port=self.conn_id.local_port,
            dst_port=self.conn_id.remote_port,
            seq_num=self._send_buffer.snd_nxt if self._send_buffer else self._iss + 1,
            ack_num=self._receive_buffer.rcv_nxt if self._receive_buffer else 0,
            window=self._receive_buffer.receive_window if self._receive_buffer else 0
        )
        self._transmit_segment(fin)
        self._retransmit_timer.start()

        logger.debug("Sent FIN")

    def abort(self):
        """
        Abort the connection immediately.

        Sends RST and closes without waiting for peer.
        """
        with self._lock:
            if self.state != TCPState.CLOSED and self.conn_id:
                rst = create_rst_segment(
                    src_port=self.conn_id.local_port,
                    dst_port=self.conn_id.remote_port,
                    seq_num=self._send_buffer.snd_nxt if self._send_buffer else 0
                )
                self._transmit_segment(rst)

            self._connection_closed()

    def _start_time_wait(self):
        """Start TIME_WAIT timer."""
        if self._time_wait_timer:
            self._time_wait_timer.cancel()

        self._time_wait_timer = threading.Timer(
            self.config.time_wait_duration,
            self._time_wait_expired
        )
        self._time_wait_timer.start()

    def _time_wait_expired(self):
        """Called when TIME_WAIT timer expires."""
        with self._lock:
            self._state_machine.transition("timeout")
            self._connection_closed()

    def _connection_closed(self):
        """Clean up after connection is closed."""
        self._running = False
        self._retransmit_timer.stop()
        self._persist_timer.stop()

        if self._time_wait_timer:
            self._time_wait_timer.cancel()
        if self._fin_wait_2_timer:
            self._fin_wait_2_timer.cancel()
        if self._delayed_ack_timer:
            self._delayed_ack_timer.cancel()

        self._close_event.set()
        self._data_available.set()  # Wake up any waiting receivers

        if self._on_closed:
            self._on_closed()

        logger.info(f"Connection closed: {self.conn_id}")

    # ========== Retransmission ==========

    def _on_timeout(self):
        """Called by retransmission timer on timeout."""
        with self._lock:
            logger.debug("Retransmission timeout")

            # Congestion control response
            self._congestion.on_timeout()

            # Retransmit oldest unacknowledged segment
            self._retransmit_oldest()

    def _retransmit_oldest(self):
        """Retransmit the oldest unacknowledged segment."""
        if not self._send_buffer:
            return

        segment = self._send_buffer.get_oldest_unacked()
        if segment:
            data_segment = create_data_segment(
                src_port=self.conn_id.local_port,
                dst_port=self.conn_id.remote_port,
                seq_num=segment.seq_num,
                ack_num=self._receive_buffer.rcv_nxt if self._receive_buffer else 0,
                data=segment.data,
                window=self._receive_buffer.receive_window if self._receive_buffer else 0
            )
            self._transmit_segment(data_segment)

            logger.debug(f"Retransmitted: seq={segment.seq_num}, len={len(segment.data)}")

    # ========== Transmission ==========

    def _transmit_segment(self, segment: TCPSegment):
        """
        Transmit a segment.

        Uses the send_callback to actually send the segment to the network.
        """
        if self._send_callback and self.conn_id:
            segment_bytes = segment.serialize(
                self.conn_id.local_ip,
                self.conn_id.remote_ip
            )
            self._send_callback(segment_bytes, self.conn_id.remote_ip, self.conn_id.remote_port)

    # ========== Processing Thread ==========

    def _start_processing(self):
        """Start the segment processing thread."""
        if self._running:
            return

        self._running = True
        self._process_thread = threading.Thread(target=self._process_loop, daemon=True)
        self._process_thread.start()

    def _process_loop(self):
        """Main processing loop for incoming segments."""
        while self._running:
            try:
                segment, remote_ip = self._incoming_segments.get(timeout=0.1)
                self._process_segment(segment, remote_ip)
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing segment: {e}")

    # ========== Statistics and Debugging ==========

    def get_statistics(self) -> dict:
        """Get connection statistics."""
        return {
            "state": self.state.name,
            "send_buffer_size": len(self._send_buffer) if self._send_buffer else 0,
            "receive_buffer_size": len(self._receive_buffer) if self._receive_buffer else 0,
            "bytes_in_flight": self._send_buffer.bytes_in_flight if self._send_buffer else 0,
            "cwnd": self._congestion.cwnd,
            "ssthresh": self._congestion.ssthresh,
            "congestion_state": self._congestion.state.name,
            "rto": self._retransmit_timer.rto,
            "srtt": self._retransmit_timer.srtt,
            "remote_window": self._remote_window,
        }

    def __str__(self) -> str:
        return f"TCPConnection({self.conn_id}, state={self.state.name})"
