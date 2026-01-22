"""
TCP Socket - High-level socket API.

This module provides a familiar socket-like interface for TCP connections,
similar to Python's socket module but using our custom TCP implementation.

The TCPSocket class wraps TCPConnection and provides:
- Berkeley socket-like API (bind, listen, accept, connect, send, recv, close)
- Blocking and timeout modes
- Integration with a simulated or real network layer

This is the primary interface for applications using this TCP implementation.
"""

import threading
import logging
from typing import Optional, Tuple, List, Callable
from queue import Queue, Empty
from dataclasses import dataclass

from .segment import TCPSegment
from .connection import TCPConnection, TCPConfig, ConnectionId


logger = logging.getLogger(__name__)


@dataclass
class SocketAddress:
    """Socket address (IP and port)."""
    ip: str
    port: int

    def __iter__(self):
        return iter((self.ip, self.port))


class NetworkInterface:
    """
    Abstract network interface for sending/receiving packets.

    This can be implemented to use:
    - Raw sockets (for real network testing)
    - A simulated network (for testing)
    - A tunnel/VPN (for deployment)
    """

    def send(self, data: bytes, dest_ip: str, dest_port: int,
             src_ip: str, src_port: int):
        """Send a TCP segment to the network."""
        raise NotImplementedError

    def set_receive_callback(self, callback: Callable[[bytes, str], None]):
        """Set callback for received packets."""
        raise NotImplementedError


class SimulatedNetwork(NetworkInterface):
    """
    Simulated network for testing.

    Allows connecting multiple TCPSockets in a simulated environment
    without requiring actual network access.
    """

    def __init__(self):
        self._sockets: dict[Tuple[str, int], "TCPSocket"] = {}
        self._lock = threading.Lock()

        # Network characteristics for simulation
        self.latency = 0.01  # 10ms base latency
        self.jitter = 0.005  # 5ms jitter
        self.loss_rate = 0.0  # No loss by default
        self.reorder_rate = 0.0  # No reordering by default

    def register_socket(self, socket: "TCPSocket", ip: str, port: int):
        """Register a socket to receive packets."""
        with self._lock:
            self._sockets[(ip, port)] = socket

    def unregister_socket(self, ip: str, port: int):
        """Unregister a socket."""
        with self._lock:
            self._sockets.pop((ip, port), None)

    def send(self, data: bytes, dest_ip: str, dest_port: int,
             src_ip: str, src_port: int):
        """Deliver a packet to the destination socket."""
        import random
        import time

        # Simulate loss
        if random.random() < self.loss_rate:
            logger.debug(f"Simulated packet loss: {src_ip}:{src_port} -> {dest_ip}:{dest_port}")
            return

        # Simulate latency
        delay = self.latency + random.uniform(-self.jitter, self.jitter)

        def deliver():
            time.sleep(delay)
            with self._lock:
                dest_socket = self._sockets.get((dest_ip, dest_port))
                if dest_socket:
                    dest_socket._receive_packet(data, src_ip)
                else:
                    # Try wildcard (listening socket)
                    dest_socket = self._sockets.get(("0.0.0.0", dest_port))
                    if dest_socket:
                        dest_socket._receive_packet(data, src_ip)

        # Deliver in background thread
        threading.Thread(target=deliver, daemon=True).start()


# Global simulated network for easy testing
_simulated_network = SimulatedNetwork()


class TCPSocket:
    """
    TCP Socket implementation.

    Provides a familiar socket API for TCP connections:

        # Server
        server = TCPSocket()
        server.bind(('0.0.0.0', 8080))
        server.listen(5)
        client_socket, addr = server.accept()
        data = client_socket.recv(1024)
        client_socket.send(b'Response')
        client_socket.close()

        # Client
        client = TCPSocket()
        client.connect(('localhost', 8080))
        client.send(b'Hello')
        response = client.recv(1024)
        client.close()
    """

    def __init__(self, config: Optional[TCPConfig] = None,
                 network: Optional[NetworkInterface] = None):
        """
        Create a new TCP socket.

        Args:
            config: TCP configuration options
            network: Network interface for sending/receiving
        """
        self.config = config or TCPConfig()
        self._network = network or _simulated_network

        self._local_addr: Optional[SocketAddress] = None
        self._remote_addr: Optional[SocketAddress] = None

        # The underlying TCP connection
        self._connection: Optional[TCPConnection] = None

        # For listening sockets
        self._listening = False
        self._backlog = 0
        self._pending_connections: Queue = Queue()
        self._accepted_connections: dict[ConnectionId, TCPConnection] = {}

        # Timeout for blocking operations
        self._timeout: Optional[float] = None

        # Lock for thread safety
        self._lock = threading.Lock()

    def bind(self, address: Tuple[str, int]):
        """
        Bind the socket to a local address.

        Args:
            address: Tuple of (ip, port)
        """
        ip, port = address
        with self._lock:
            self._local_addr = SocketAddress(ip, port)

            # Register with network
            if isinstance(self._network, SimulatedNetwork):
                self._network.register_socket(self, ip, port)

    def listen(self, backlog: int = 5):
        """
        Mark the socket as a listening (server) socket.

        Args:
            backlog: Maximum number of pending connections
        """
        with self._lock:
            if not self._local_addr:
                raise RuntimeError("Socket must be bound before listening")

            self._listening = True
            self._backlog = backlog

            # Create a connection for listening
            self._connection = TCPConnection(
                config=self.config,
                send_callback=self._send_callback
            )
            self._connection.listen(self._local_addr.ip, self._local_addr.port)

    def accept(self) -> Tuple["TCPSocket", Tuple[str, int]]:
        """
        Accept an incoming connection.

        Blocks until a connection is available (or timeout).

        Returns:
            Tuple of (new_socket, (remote_ip, remote_port))

        Raises:
            TimeoutError: If timeout expires before connection arrives
        """
        if not self._listening:
            raise RuntimeError("Socket is not listening")

        try:
            connection = self._pending_connections.get(timeout=self._timeout)
        except Empty:
            raise TimeoutError("Accept timed out")

        # Create new socket for this connection
        new_socket = TCPSocket(config=self.config, network=self._network)
        new_socket._connection = connection
        new_socket._local_addr = self._local_addr
        new_socket._remote_addr = SocketAddress(
            connection.conn_id.remote_ip,
            connection.conn_id.remote_port
        )

        # Register new socket for its specific connection
        if isinstance(self._network, SimulatedNetwork):
            # Use a composite key for accepted connections
            pass  # Handled by routing in _receive_packet

        return new_socket, (new_socket._remote_addr.ip, new_socket._remote_addr.port)

    def connect(self, address: Tuple[str, int]) -> bool:
        """
        Connect to a remote address.

        Performs the TCP three-way handshake.

        Args:
            address: Tuple of (remote_ip, remote_port)

        Returns:
            True if connection established

        Raises:
            TimeoutError: If connection times out
            RuntimeError: If connection fails
        """
        remote_ip, remote_port = address

        with self._lock:
            # Bind to ephemeral port if not already bound
            if not self._local_addr:
                import secrets
                port = secrets.randbelow(16384) + 49152
                self.bind(("127.0.0.1", port))

            self._remote_addr = SocketAddress(remote_ip, remote_port)

            # Create connection
            self._connection = TCPConnection(
                config=self.config,
                send_callback=self._send_callback
            )

        # Perform handshake
        success = self._connection.connect(
            remote_ip, remote_port,
            self._local_addr.ip, self._local_addr.port,
            timeout=self._timeout
        )

        if not success:
            raise RuntimeError("Connection failed")

        return True

    def send(self, data: bytes) -> int:
        """
        Send data on the connection.

        Args:
            data: Data to send

        Returns:
            Number of bytes sent

        Raises:
            RuntimeError: If socket is not connected
        """
        if not self._connection or not self._connection.is_established:
            raise RuntimeError("Socket is not connected")

        return self._connection.send(data)

    def sendall(self, data: bytes):
        """
        Send all data, blocking until complete.

        Args:
            data: Data to send

        Raises:
            RuntimeError: If socket is not connected
        """
        total_sent = 0
        while total_sent < len(data):
            sent = self.send(data[total_sent:])
            if sent == 0:
                raise RuntimeError("Connection closed")
            total_sent += sent

    def recv(self, bufsize: int) -> bytes:
        """
        Receive data from the connection.

        Blocks until data is available (or timeout).

        Args:
            bufsize: Maximum bytes to receive

        Returns:
            Received data (empty bytes if connection closed)

        Raises:
            TimeoutError: If timeout expires
        """
        if not self._connection:
            raise RuntimeError("Socket is not connected")

        return self._connection.receive(bufsize, timeout=self._timeout)

    def close(self):
        """
        Close the connection gracefully.

        Performs the TCP four-way handshake.
        """
        with self._lock:
            if self._connection:
                self._connection.close(timeout=self._timeout)
                self._connection = None

            if self._local_addr and isinstance(self._network, SimulatedNetwork):
                self._network.unregister_socket(
                    self._local_addr.ip, self._local_addr.port
                )

            self._listening = False

    def shutdown(self, how: int):
        """
        Shutdown one or both halves of the connection.

        Args:
            how: 0=SHUT_RD, 1=SHUT_WR, 2=SHUT_RDWR
        """
        # Simplified - just close
        if how in (1, 2):
            self.close()

    def settimeout(self, timeout: Optional[float]):
        """
        Set timeout for blocking operations.

        Args:
            timeout: Timeout in seconds (None for no timeout)
        """
        self._timeout = timeout

    def gettimeout(self) -> Optional[float]:
        """Get the current timeout."""
        return self._timeout

    def setblocking(self, blocking: bool):
        """
        Set blocking mode.

        Args:
            blocking: True for blocking, False for non-blocking
        """
        if blocking:
            self._timeout = None
        else:
            self._timeout = 0.0

    def getpeername(self) -> Tuple[str, int]:
        """Get the remote address."""
        if not self._remote_addr:
            raise RuntimeError("Socket is not connected")
        return (self._remote_addr.ip, self._remote_addr.port)

    def getsockname(self) -> Tuple[str, int]:
        """Get the local address."""
        if not self._local_addr:
            raise RuntimeError("Socket is not bound")
        return (self._local_addr.ip, self._local_addr.port)

    def fileno(self) -> int:
        """Return a fake file descriptor (for compatibility)."""
        return id(self)

    # ========== Internal Methods ==========

    def _send_callback(self, segment_bytes: bytes, dest_ip: str, dest_port: int):
        """Callback used by TCPConnection to send segments."""
        if self._local_addr:
            self._network.send(
                segment_bytes, dest_ip, dest_port,
                self._local_addr.ip, self._local_addr.port
            )

    def _receive_packet(self, data: bytes, src_ip: str):
        """Called by the network when a packet arrives."""
        try:
            segment = TCPSegment.parse(data)
        except Exception as e:
            logger.warning(f"Failed to parse segment: {e}")
            return

        with self._lock:
            # If listening, check for SYN
            if self._listening and (segment.flags & 0x02):  # SYN flag
                self._handle_incoming_syn(segment, src_ip)
                return

            # Check for established connection
            conn_id = ConnectionId(
                self._local_addr.ip, self._local_addr.port,
                src_ip, segment.src_port
            )

            if conn_id in self._accepted_connections:
                self._accepted_connections[conn_id].receive_segment(segment, src_ip)
            elif self._connection:
                self._connection.receive_segment(segment, src_ip)

    def _handle_incoming_syn(self, segment: TCPSegment, src_ip: str):
        """Handle incoming SYN on listening socket."""
        # Check backlog
        if self._pending_connections.qsize() >= self._backlog:
            logger.warning("Connection backlog full, dropping SYN")
            return

        # Create new connection for this client
        new_conn = TCPConnection(
            config=self.config,
            send_callback=self._send_callback
        )

        # Copy listening state
        new_conn.conn_id = ConnectionId(
            self._local_addr.ip, self._local_addr.port,
            src_ip, segment.src_port
        )

        # Accept the SYN
        if new_conn.accept_connection(segment, src_ip):
            # Track connection
            self._accepted_connections[new_conn.conn_id] = new_conn

            # Set up callback for when connection is established
            def on_established():
                self._pending_connections.put(new_conn)

            new_conn._on_established = on_established

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __repr__(self):
        state = "CLOSED"
        if self._connection:
            state = self._connection.state.name
        local = f"{self._local_addr.ip}:{self._local_addr.port}" if self._local_addr else "unbound"
        remote = f"{self._remote_addr.ip}:{self._remote_addr.port}" if self._remote_addr else "none"
        return f"TCPSocket({local} -> {remote}, {state})"


# Convenience function for creating sockets
def create_connection(address: Tuple[str, int],
                     timeout: Optional[float] = None) -> TCPSocket:
    """
    Create a TCP connection to a remote address.

    This is a convenience function similar to socket.create_connection().

    Args:
        address: (host, port) to connect to
        timeout: Connection timeout in seconds

    Returns:
        Connected TCPSocket
    """
    sock = TCPSocket()
    if timeout is not None:
        sock.settimeout(timeout)
    sock.connect(address)
    return sock
