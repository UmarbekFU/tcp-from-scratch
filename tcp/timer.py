"""
TCP Retransmission Timer - RTT estimation and timeout management.

TCP's retransmission timer is crucial for reliability. Set it too short and
you'll retransmit unnecessarily, wasting bandwidth. Set it too long and you'll
wait forever when packets are actually lost.

The challenge: network conditions vary wildly. A LAN might have 1ms RTT, while
a satellite link has 600ms. Even on a single path, RTT varies due to queuing.

Solution: Continuously estimate RTT and variance, then set timeout based on both.

Key algorithms implemented here:
1. Jacobson's RTT estimator (exponential weighted moving average)
2. Karn's algorithm (don't sample RTT on retransmissions)
3. Exponential backoff on repeated timeouts
"""

import time
import threading
from dataclasses import dataclass
from typing import Optional, Callable


@dataclass
class RTTMeasurement:
    """A single RTT measurement with metadata."""
    seq_num: int
    send_time: float
    ack_time: float
    rtt: float
    retransmitted: bool = False


class RetransmissionTimer:
    """
    TCP Retransmission Timer with RTT estimation.

    Implements RFC 6298 (Computing TCP's Retransmission Timer).

    The timer tracks:
    - SRTT: Smoothed Round-Trip Time (exponential average)
    - RTTVAR: RTT Variance
    - RTO: Retransmission Timeout

    RTO = SRTT + max(G, K*RTTVAR)
    where G = clock granularity (usually 0), K = 4

    On timeout, RTO is doubled (exponential backoff).
    """

    # RFC 6298 constants
    ALPHA = 1/8   # Weight for new RTT sample in SRTT
    BETA = 1/4    # Weight for new RTT deviation in RTTVAR
    K = 4         # Multiplier for RTTVAR in RTO calculation

    # Timer bounds (in seconds)
    MIN_RTO = 1.0     # Minimum RTO
    MAX_RTO = 60.0    # Maximum RTO
    INITIAL_RTO = 1.0 # Initial RTO before any measurements

    def __init__(self, on_timeout: Optional[Callable] = None):
        """
        Initialize the retransmission timer.

        Args:
            on_timeout: Callback function to invoke on timeout
        """
        # RTT estimates (None until first measurement)
        self._srtt: Optional[float] = None
        self._rttvar: Optional[float] = None
        self._rto: float = self.INITIAL_RTO

        # Timer state
        self._timer_active = False
        self._timer_deadline: Optional[float] = None
        self._timer_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Callback
        self._on_timeout = on_timeout

        # Statistics
        self._measurements: list[RTTMeasurement] = []
        self._timeout_count = 0
        self._backoff_count = 0

        # Thread safety
        self._lock = threading.Lock()

    @property
    def srtt(self) -> Optional[float]:
        """Smoothed RTT in seconds."""
        return self._srtt

    @property
    def rttvar(self) -> Optional[float]:
        """RTT variance in seconds."""
        return self._rttvar

    @property
    def rto(self) -> float:
        """Current retransmission timeout in seconds."""
        return self._rto

    def update_rtt(self, measured_rtt: float, retransmitted: bool = False):
        """
        Update RTT estimates with a new measurement.

        Implements RFC 6298 algorithm:
        - First measurement: SRTT = R, RTTVAR = R/2
        - Subsequent: RTTVAR = (1-β)*RTTVAR + β*|SRTT-R|
                     SRTT = (1-α)*SRTT + α*R

        IMPORTANT: Karn's algorithm - don't update RTT from retransmitted segments
        because we can't tell if the ACK is for the original or retransmission.

        Args:
            measured_rtt: Measured round-trip time in seconds
            retransmitted: True if this was a retransmitted segment
        """
        with self._lock:
            # Karn's algorithm: skip retransmitted segments
            if retransmitted:
                return

            if self._srtt is None:
                # First measurement
                self._srtt = measured_rtt
                self._rttvar = measured_rtt / 2
            else:
                # Subsequent measurements (Jacobson's algorithm)
                # RTTVAR = (1 - β) * RTTVAR + β * |SRTT - R|
                self._rttvar = (1 - self.BETA) * self._rttvar + \
                              self.BETA * abs(self._srtt - measured_rtt)
                # SRTT = (1 - α) * SRTT + α * R
                self._srtt = (1 - self.ALPHA) * self._srtt + \
                            self.ALPHA * measured_rtt

            # Update RTO
            # RTO = SRTT + max(G, K*RTTVAR)
            # G (granularity) is effectively 0 on modern systems
            self._rto = self._srtt + self.K * self._rttvar

            # Apply bounds
            self._rto = max(self.MIN_RTO, min(self.MAX_RTO, self._rto))

            # Reset backoff count on successful RTT measurement
            self._backoff_count = 0

    def start(self):
        """
        Start or restart the retransmission timer.

        Called when:
        - Sending new data
        - Receiving an ACK that acknowledges new data
        """
        with self._lock:
            self._stop_event.clear()
            self._timer_deadline = time.time() + self._rto
            self._timer_active = True

            # Start timer thread if not already running
            if self._timer_thread is None or not self._timer_thread.is_alive():
                self._timer_thread = threading.Thread(target=self._timer_loop, daemon=True)
                self._timer_thread.start()

    def stop(self):
        """
        Stop the retransmission timer.

        Called when all outstanding data has been acknowledged.
        """
        with self._lock:
            self._timer_active = False
            self._timer_deadline = None
            self._stop_event.set()

    def restart(self):
        """
        Restart the timer with current RTO.

        Called when new data is ACKed but more data is outstanding.
        """
        self.start()

    def _timer_loop(self):
        """Background thread that monitors the timer."""
        while True:
            with self._lock:
                if not self._timer_active:
                    return

                deadline = self._timer_deadline
                if deadline is None:
                    return

            # Wait until deadline or stop event
            wait_time = max(0, deadline - time.time())
            if self._stop_event.wait(timeout=wait_time):
                return  # Stopped

            # Check if we should fire
            with self._lock:
                if not self._timer_active:
                    return

                if time.time() >= self._timer_deadline:
                    self._handle_timeout()

    def _handle_timeout(self):
        """Handle a retransmission timeout."""
        self._timeout_count += 1
        self._backoff_count += 1

        # Exponential backoff (RFC 6298)
        self._rto = min(self._rto * 2, self.MAX_RTO)

        # Reset timer for potential re-retransmission
        self._timer_deadline = time.time() + self._rto

        # Invoke callback (without holding lock to avoid deadlock)
        callback = self._on_timeout
        if callback:
            # Release lock before callback
            self._lock.release()
            try:
                callback()
            finally:
                self._lock.acquire()

    def on_ack(self, acked_new_data: bool):
        """
        Called when an ACK is received.

        Args:
            acked_new_data: True if ACK acknowledged new data
        """
        with self._lock:
            if acked_new_data:
                # Reset backoff on successful ACK
                if self._backoff_count > 0:
                    self._backoff_count = 0
                    # Restore RTO from SRTT (remove backoff)
                    if self._srtt is not None:
                        self._rto = self._srtt + self.K * self._rttvar
                        self._rto = max(self.MIN_RTO, min(self.MAX_RTO, self._rto))

    def is_active(self) -> bool:
        """Check if timer is currently running."""
        with self._lock:
            return self._timer_active

    def time_remaining(self) -> Optional[float]:
        """Get time remaining until timeout, or None if not active."""
        with self._lock:
            if not self._timer_active or self._timer_deadline is None:
                return None
            return max(0, self._timer_deadline - time.time())

    def get_statistics(self) -> dict:
        """Get timer statistics for debugging."""
        with self._lock:
            return {
                "srtt": self._srtt,
                "rttvar": self._rttvar,
                "rto": self._rto,
                "timeout_count": self._timeout_count,
                "backoff_count": self._backoff_count,
                "is_active": self._timer_active
            }

    def __str__(self) -> str:
        srtt_str = f"{self._srtt*1000:.1f}ms" if self._srtt else "N/A"
        rto_str = f"{self._rto*1000:.1f}ms"
        return f"Timer(SRTT={srtt_str}, RTO={rto_str})"


class PersistTimer:
    """
    TCP Persist Timer - for zero-window probing.

    When the receiver advertises a zero window, the sender stops sending.
    But what if the receiver's window update ACK is lost? Deadlock.

    The persist timer sends periodic "window probes" - tiny segments that
    force the receiver to send an ACK with current window status.

    Uses exponential backoff similar to retransmission timer.
    """

    MIN_PERSIST = 5.0    # Minimum persist interval
    MAX_PERSIST = 60.0   # Maximum persist interval

    def __init__(self, on_probe: Optional[Callable] = None):
        """
        Initialize persist timer.

        Args:
            on_probe: Callback to invoke when probe should be sent
        """
        self._interval = self.MIN_PERSIST
        self._active = False
        self._deadline: Optional[float] = None
        self._on_probe = on_probe
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    def start(self, rto: float):
        """
        Start the persist timer.

        Args:
            rto: Current RTO (used as initial interval)
        """
        with self._lock:
            self._interval = max(self.MIN_PERSIST, min(rto, self.MAX_PERSIST))
            self._deadline = time.time() + self._interval
            self._active = True
            self._stop_event.clear()

            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._timer_loop, daemon=True)
                self._thread.start()

    def stop(self):
        """Stop the persist timer."""
        with self._lock:
            self._active = False
            self._stop_event.set()

    def _timer_loop(self):
        """Background thread for persist timer."""
        while True:
            with self._lock:
                if not self._active:
                    return
                deadline = self._deadline

            wait_time = max(0, deadline - time.time())
            if self._stop_event.wait(timeout=wait_time):
                return

            with self._lock:
                if not self._active:
                    return

                if time.time() >= self._deadline:
                    # Time to probe
                    callback = self._on_probe

                    # Exponential backoff
                    self._interval = min(self._interval * 2, self.MAX_PERSIST)
                    self._deadline = time.time() + self._interval

            if callback:
                callback()


class KeepAliveTimer:
    """
    TCP Keep-Alive Timer - for detecting dead connections.

    If a connection is idle for too long, send a keep-alive probe to verify
    the peer is still there. This is optional (off by default in TCP) but
    useful for long-lived connections.

    Default: probe after 2 hours of idle, then every 75 seconds, give up after 9 failures.
    """

    DEFAULT_IDLE = 7200      # 2 hours
    DEFAULT_INTERVAL = 75    # 75 seconds between probes
    DEFAULT_COUNT = 9        # Give up after 9 failed probes

    def __init__(self,
                 idle_time: float = DEFAULT_IDLE,
                 interval: float = DEFAULT_INTERVAL,
                 max_probes: int = DEFAULT_COUNT,
                 on_probe: Optional[Callable] = None,
                 on_dead: Optional[Callable] = None):
        """
        Initialize keep-alive timer.

        Args:
            idle_time: Time before first probe
            interval: Time between subsequent probes
            max_probes: Number of probes before declaring connection dead
            on_probe: Callback when probe should be sent
            on_dead: Callback when connection is declared dead
        """
        self._idle_time = idle_time
        self._interval = interval
        self._max_probes = max_probes
        self._probe_count = 0
        self._on_probe = on_probe
        self._on_dead = on_dead

        self._active = False
        self._last_activity = time.time()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    def start(self):
        """Start keep-alive monitoring."""
        with self._lock:
            self._active = True
            self._last_activity = time.time()
            self._probe_count = 0
            self._stop_event.clear()

            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._timer_loop, daemon=True)
                self._thread.start()

    def stop(self):
        """Stop keep-alive monitoring."""
        with self._lock:
            self._active = False
            self._stop_event.set()

    def activity(self):
        """Record activity on the connection."""
        with self._lock:
            self._last_activity = time.time()
            self._probe_count = 0

    def _timer_loop(self):
        """Background thread for keep-alive monitoring."""
        while True:
            with self._lock:
                if not self._active:
                    return

                since_activity = time.time() - self._last_activity

                if self._probe_count == 0:
                    # Waiting for idle timeout
                    if since_activity < self._idle_time:
                        wait_time = self._idle_time - since_activity
                    else:
                        # Send first probe
                        self._probe_count = 1
                        if self._on_probe:
                            self._on_probe()
                        wait_time = self._interval
                else:
                    # In probing mode
                    if since_activity >= self._interval:
                        self._probe_count += 1
                        if self._probe_count > self._max_probes:
                            # Connection is dead
                            if self._on_dead:
                                self._on_dead()
                            return
                        if self._on_probe:
                            self._on_probe()
                    wait_time = self._interval

            if self._stop_event.wait(timeout=wait_time):
                return
