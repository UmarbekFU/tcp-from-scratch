"""
TCP Congestion Control - Managing network capacity.

This is where TCP gets really clever. Unlike flow control (preventing receiver
overflow), congestion control prevents overloading the *network itself*.

The network doesn't explicitly tell TCP when it's congested. TCP must infer
congestion from indirect signals:
- Packet loss (traditional signal)
- Increased RTT (used by newer algorithms like BBR)
- Explicit congestion notification (ECN - when available)

The fundamental algorithm is AIMD (Additive Increase, Multiplicative Decrease):
- When things are going well: slowly increase sending rate (additive)
- When congestion is detected: quickly reduce sending rate (multiplicative)

This creates the characteristic TCP "sawtooth" pattern and provably converges
to fair bandwidth sharing among competing flows.

Algorithms implemented:
1. Slow Start - Exponential growth to probe capacity
2. Congestion Avoidance - Linear growth to approach capacity carefully
3. Fast Retransmit - Respond to 3 duplicate ACKs
4. Fast Recovery (Reno) - Don't reset to slow start on fast retransmit
5. CUBIC (Linux default) - More aggressive recovery, better for high BDP networks
"""

import time
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional, List
from abc import ABC, abstractmethod


class CongestionState(Enum):
    """
    Congestion control states.

    SLOW_START: Exponentially increase cwnd until loss or threshold
    CONGESTION_AVOIDANCE: Linearly increase cwnd
    FAST_RECOVERY: Maintain throughput after fast retransmit
    """
    SLOW_START = auto()
    CONGESTION_AVOIDANCE = auto()
    FAST_RECOVERY = auto()


@dataclass
class CongestionEvent:
    """Record of a congestion event for analysis."""
    timestamp: float
    event_type: str  # "timeout", "fast_retransmit", "ece"
    cwnd_before: int
    cwnd_after: int
    ssthresh_after: int


class CongestionController(ABC):
    """
    Abstract base class for congestion control algorithms.

    All TCP congestion control algorithms must implement:
    - on_ack: Called when ACK acknowledges new data
    - on_duplicate_ack: Called on duplicate ACK
    - on_timeout: Called on retransmission timeout
    - on_loss: Called when loss is detected

    The controller manages:
    - cwnd: Congestion window (bytes we can have in flight)
    - ssthresh: Slow start threshold
    """

    def __init__(self, mss: int = 1460, initial_cwnd: int = 10):
        """
        Initialize congestion controller.

        Args:
            mss: Maximum Segment Size
            initial_cwnd: Initial congestion window in segments
        """
        self.mss = mss
        self._cwnd = initial_cwnd * mss  # Initial window (RFC 6928: 10 segments)
        self._ssthresh = float('inf')    # Start with no threshold
        self._state = CongestionState.SLOW_START
        self._dup_ack_count = 0
        self._events: List[CongestionEvent] = []

    @property
    def cwnd(self) -> int:
        """Current congestion window in bytes."""
        return self._cwnd

    @property
    def ssthresh(self) -> int:
        """Slow start threshold in bytes."""
        return int(self._ssthresh) if self._ssthresh != float('inf') else 0

    @property
    def state(self) -> CongestionState:
        """Current congestion state."""
        return self._state

    @abstractmethod
    def on_ack(self, bytes_acked: int):
        """
        Called when an ACK acknowledges new data.

        Args:
            bytes_acked: Number of newly acknowledged bytes
        """
        pass

    @abstractmethod
    def on_duplicate_ack(self):
        """Called when a duplicate ACK is received."""
        pass

    @abstractmethod
    def on_timeout(self):
        """Called on retransmission timeout."""
        pass

    def get_send_window(self, receiver_window: int) -> int:
        """
        Get the effective send window.

        The actual window is min(cwnd, receiver_window).

        Args:
            receiver_window: Advertised receiver window

        Returns:
            Effective window in bytes
        """
        return min(self._cwnd, receiver_window)

    def _record_event(self, event_type: str, cwnd_before: int,
                     cwnd_after: int, ssthresh_after: int):
        """Record a congestion event for analysis."""
        self._events.append(CongestionEvent(
            timestamp=time.time(),
            event_type=event_type,
            cwnd_before=cwnd_before,
            cwnd_after=cwnd_after,
            ssthresh_after=ssthresh_after
        ))


class TCPReno(CongestionController):
    """
    TCP Reno congestion control algorithm.

    Reno was the standard for many years and is still widely understood.
    It implements:
    - Slow Start: cwnd grows exponentially
    - Congestion Avoidance: cwnd grows linearly
    - Fast Retransmit: Retransmit on 3 duplicate ACKs
    - Fast Recovery: Don't reset to slow start after fast retransmit

    The key insight of Reno (vs. Tahoe): 3 duplicate ACKs indicate a single
    loss, while timeout indicates severe congestion. Respond differently.
    """

    DUPLICATE_ACK_THRESHOLD = 3

    def on_ack(self, bytes_acked: int):
        """
        Handle new data acknowledgment.

        Slow Start: cwnd += mss for each ACK (exponential growth)
        Congestion Avoidance: cwnd += mss * mss / cwnd (linear growth)
        """
        self._dup_ack_count = 0

        if self._state == CongestionState.FAST_RECOVERY:
            # Exit fast recovery
            self._cwnd = self._ssthresh
            self._state = CongestionState.CONGESTION_AVOIDANCE
            return

        if self._state == CongestionState.SLOW_START:
            # Exponential growth: increase cwnd by amount ACKed
            # This doubles cwnd every RTT
            self._cwnd += min(bytes_acked, self.mss)

            # Check if we should transition to congestion avoidance
            if self._cwnd >= self._ssthresh:
                self._state = CongestionState.CONGESTION_AVOIDANCE

        elif self._state == CongestionState.CONGESTION_AVOIDANCE:
            # Linear growth: increase cwnd by ~mss per RTT
            # Each ACK increases cwnd by mss^2/cwnd
            # After cwnd/mss ACKs (one RTT worth), cwnd increases by mss
            increment = (self.mss * self.mss) // self._cwnd
            self._cwnd += max(1, increment)

    def on_duplicate_ack(self):
        """
        Handle duplicate ACK.

        3 duplicate ACKs trigger fast retransmit and fast recovery.
        During fast recovery, inflate cwnd for each additional dup ACK.
        """
        self._dup_ack_count += 1

        if self._state == CongestionState.FAST_RECOVERY:
            # Inflate window for each additional dup ACK
            # This allows new data to be sent while waiting for retransmit
            self._cwnd += self.mss
            return

        if self._dup_ack_count == self.DUPLICATE_ACK_THRESHOLD:
            # Enter fast retransmit / fast recovery
            cwnd_before = self._cwnd

            # Set threshold to half of current window
            self._ssthresh = max(self._cwnd // 2, 2 * self.mss)

            # Set cwnd to ssthresh plus 3 MSS (for the 3 dup ACKs)
            # The 3 dup ACKs indicate 3 segments left the network
            self._cwnd = self._ssthresh + 3 * self.mss
            self._state = CongestionState.FAST_RECOVERY

            self._record_event(
                "fast_retransmit",
                cwnd_before,
                self._cwnd,
                int(self._ssthresh)
            )

    def on_timeout(self):
        """
        Handle retransmission timeout.

        Timeout indicates severe congestion. Be aggressive:
        - ssthresh = cwnd / 2
        - cwnd = 1 MSS
        - Enter slow start
        """
        cwnd_before = self._cwnd

        self._ssthresh = max(self._cwnd // 2, 2 * self.mss)
        self._cwnd = self.mss  # Reset to 1 segment
        self._state = CongestionState.SLOW_START
        self._dup_ack_count = 0

        self._record_event(
            "timeout",
            cwnd_before,
            self._cwnd,
            int(self._ssthresh)
        )

    def __str__(self) -> str:
        return (f"Reno(cwnd={self._cwnd}, ssthresh={self._ssthresh}, "
                f"state={self._state.name})")


class TCPNewReno(TCPReno):
    """
    TCP NewReno - Improved fast recovery.

    NewReno handles multiple losses in a single window better than Reno.
    When a partial ACK arrives during fast recovery (ACKs some but not all
    data that was outstanding when recovery started), it indicates another
    loss and triggers retransmission without leaving fast recovery.

    This prevents the "multiple fast retransmit" problem where Reno would
    leave recovery prematurely.
    """

    def __init__(self, mss: int = 1460, initial_cwnd: int = 10):
        super().__init__(mss, initial_cwnd)
        self._recovery_point = 0  # Sequence number at start of recovery
        self._partial_ack = False

    def enter_fast_recovery(self, highest_seq: int):
        """
        Enter fast recovery, recording the recovery point.

        Args:
            highest_seq: Highest sequence number sent when entering recovery
        """
        cwnd_before = self._cwnd
        self._ssthresh = max(self._cwnd // 2, 2 * self.mss)
        self._cwnd = self._ssthresh + 3 * self.mss
        self._state = CongestionState.FAST_RECOVERY
        self._recovery_point = highest_seq

        self._record_event(
            "fast_retransmit",
            cwnd_before,
            self._cwnd,
            int(self._ssthresh)
        )

    def on_ack_with_seq(self, bytes_acked: int, ack_num: int):
        """
        Handle ACK with sequence number tracking.

        Args:
            bytes_acked: Bytes acknowledged
            ack_num: Acknowledgment number
        """
        if self._state == CongestionState.FAST_RECOVERY:
            if ack_num < self._recovery_point:
                # Partial ACK - indicates another loss
                # Retransmit next segment, don't leave recovery
                self._cwnd -= bytes_acked
                self._cwnd += self.mss
                self._partial_ack = True
                return "retransmit"
            else:
                # Full ACK - recovery complete
                self._cwnd = self._ssthresh
                self._state = CongestionState.CONGESTION_AVOIDANCE
                self._dup_ack_count = 0
                return None

        # Normal ACK processing
        self.on_ack(bytes_acked)
        return None


class CUBIC(CongestionController):
    """
    CUBIC congestion control algorithm (Linux default since 2.6.19).

    CUBIC uses a cubic function for window growth, making it more aggressive
    than Reno/NewReno at recovering to previous window sizes after loss.

    Key characteristics:
    - Window growth is a cubic function of time since last congestion event
    - Less aggressive near W_max (previous window size), more aggressive far from it
    - Better performance on high bandwidth-delay product networks
    - Fairer to concurrent flows with different RTTs (RTT-independence)

    The cubic function: W(t) = C * (t - K)^3 + W_max
    where:
    - C is a scaling factor (default 0.4)
    - K is the time to reach W_max without any loss
    - W_max is the window size just before the last reduction

    This creates a characteristic "cubic" shape: fast growth far from W_max,
    slow approach near W_max (to probe carefully), fast growth beyond.
    """

    # CUBIC parameters
    C = 0.4       # Scaling constant
    BETA = 0.7    # Multiplicative decrease factor (less aggressive than Reno's 0.5)

    def __init__(self, mss: int = 1460, initial_cwnd: int = 10):
        super().__init__(mss, initial_cwnd)
        self._w_max = 0           # Window size before last reduction
        self._k = 0               # Time to reach W_max
        self._epoch_start = 0     # Time of last window reduction
        self._tcp_cwnd = 0        # TCP Reno-equivalent cwnd for TCP-friendliness
        self._ack_cnt = 0         # ACK counter for cwnd increase
        self._last_cwnd = 0       # cwnd at last adjustment

    def on_ack(self, bytes_acked: int):
        """
        Handle new data acknowledgment with CUBIC growth.
        """
        self._dup_ack_count = 0

        if self._state == CongestionState.FAST_RECOVERY:
            self._cwnd = int(self._w_max * self.BETA)
            self._state = CongestionState.CONGESTION_AVOIDANCE
            return

        if self._state == CongestionState.SLOW_START:
            self._cwnd += min(bytes_acked, self.mss)
            if self._cwnd >= self._ssthresh:
                self._state = CongestionState.CONGESTION_AVOIDANCE
                self._epoch_start = time.time()
            return

        # Congestion avoidance - CUBIC growth
        self._ack_cnt += bytes_acked

        # Calculate cubic window
        t = time.time() - self._epoch_start
        target = self._cubic_window(t)

        # Calculate TCP-friendly window (for fairness with Reno flows)
        rtt_estimate = 0.1  # Would normally use measured RTT
        self._tcp_cwnd = self._tcp_friendly_window(t, rtt_estimate)

        # Use maximum of CUBIC and TCP-friendly
        target = max(target, self._tcp_cwnd)

        # Increase cwnd
        if self._cwnd < target:
            # How much to increase
            cnt = self._cwnd / (target - self._cwnd)
            if self._ack_cnt > cnt:
                self._cwnd += self.mss
                self._ack_cnt = 0

    def _cubic_window(self, t: float) -> int:
        """
        Calculate CUBIC window size at time t.

        W(t) = C * (t - K)^3 + W_max

        where K = (W_max * beta / C)^(1/3)
        """
        if self._epoch_start == 0:
            self._epoch_start = time.time()
            self._w_max = self._cwnd
            self._k = ((self._w_max * (1 - self.BETA)) / self.C) ** (1/3)

        # Calculate cubic window
        w_cubic = self.C * (t - self._k) ** 3 + self._w_max

        return int(w_cubic)

    def _tcp_friendly_window(self, t: float, rtt: float) -> int:
        """
        Calculate TCP-friendly window for fairness.

        This ensures CUBIC doesn't take more than its fair share
        when competing with standard TCP Reno flows.
        """
        # TCP Reno would grow by approximately mss / cwnd per ACK
        # Over time t with RTT, that's t/RTT RTTs
        # Each RTT adds mss to cwnd
        rtt = max(rtt, 0.001)  # Avoid division by zero
        rtts = t / rtt
        return int(self._w_max * self.BETA + 3 * self.BETA / (2 - self.BETA) * rtts)

    def on_duplicate_ack(self):
        """Handle duplicate ACK."""
        self._dup_ack_count += 1

        if self._dup_ack_count == 3 and self._state != CongestionState.FAST_RECOVERY:
            cwnd_before = self._cwnd

            # Record W_max
            self._w_max = self._cwnd

            # CUBIC uses beta = 0.7 (less aggressive than Reno's 0.5)
            self._ssthresh = max(int(self._cwnd * self.BETA), 2 * self.mss)
            self._cwnd = self._ssthresh + 3 * self.mss
            self._state = CongestionState.FAST_RECOVERY

            # Reset epoch
            self._epoch_start = time.time()
            self._k = ((self._w_max * (1 - self.BETA)) / self.C) ** (1/3)

            self._record_event(
                "fast_retransmit",
                cwnd_before,
                self._cwnd,
                self._ssthresh
            )
        elif self._state == CongestionState.FAST_RECOVERY:
            self._cwnd += self.mss

    def on_timeout(self):
        """Handle retransmission timeout."""
        cwnd_before = self._cwnd

        self._w_max = self._cwnd
        self._ssthresh = max(int(self._cwnd * self.BETA), 2 * self.mss)
        self._cwnd = self.mss
        self._state = CongestionState.SLOW_START
        self._dup_ack_count = 0

        # Reset epoch
        self._epoch_start = 0

        self._record_event(
            "timeout",
            cwnd_before,
            self._cwnd,
            self._ssthresh
        )

    def __str__(self) -> str:
        return (f"CUBIC(cwnd={self._cwnd}, w_max={self._w_max}, "
                f"state={self._state.name})")


class BBR:
    """
    BBR (Bottleneck Bandwidth and Round-trip propagation time) congestion control.

    BBR is fundamentally different from loss-based algorithms. Instead of
    reacting to loss, it actively probes for:
    - Bottleneck Bandwidth (BtlBw): Maximum throughput
    - Round-trip propagation time (RTprop): Minimum RTT

    The sending rate is then: rate = BtlBw * RTprop / RTT

    BBR cycles through phases:
    1. STARTUP: Like slow start, but exits at BtlBw
    2. DRAIN: Reduce inflight to BDP
    3. PROBE_BW: Steady state, periodic probing for more bandwidth
    4. PROBE_RTT: Periodic RTT probing by reducing inflight

    This is a simplified implementation for educational purposes.
    Full BBR is significantly more complex.
    """

    class State(Enum):
        STARTUP = auto()
        DRAIN = auto()
        PROBE_BW = auto()
        PROBE_RTT = auto()

    # BBR constants
    STARTUP_GAIN = 2.885     # ~2/ln(2), for doubling each RTT
    DRAIN_GAIN = 0.35        # 1/STARTUP_GAIN
    PROBE_BW_GAINS = [1.25, 0.75, 1, 1, 1, 1, 1, 1]  # 8-phase cycle
    PROBE_RTT_CWND = 4       # Min packets during RTT probe

    def __init__(self, mss: int = 1460):
        self.mss = mss
        self._state = self.State.STARTUP

        # Bandwidth and RTT estimates
        self._btl_bw = 0                    # Estimated bottleneck bandwidth (bytes/sec)
        self._rt_prop = float('inf')        # Estimated min RTT (seconds)
        self._rt_prop_stamp = time.time()   # When rt_prop was last updated

        # Delivery tracking
        self._delivered = 0                 # Total bytes delivered
        self._delivered_time = time.time()  # Time of last delivery update

        # Pacing
        self._pacing_rate = 0
        self._cwnd = 10 * mss

        # Probe state
        self._probe_bw_phase = 0
        self._probe_rtt_time = 0

    @property
    def cwnd(self) -> int:
        return self._cwnd

    @property
    def pacing_rate(self) -> float:
        """Bytes per second to send."""
        return self._pacing_rate

    def on_ack(self, bytes_acked: int, rtt: float, delivered: int):
        """
        Handle ACK with delivery and RTT information.

        Args:
            bytes_acked: Bytes acknowledged
            rtt: Measured RTT
            delivered: Total bytes delivered so far
        """
        # Update RTT estimate
        if rtt < self._rt_prop or time.time() - self._rt_prop_stamp > 10:
            self._rt_prop = rtt
            self._rt_prop_stamp = time.time()

        # Update bandwidth estimate
        interval = time.time() - self._delivered_time
        if interval > 0:
            delivery_rate = (delivered - self._delivered) / interval
            self._btl_bw = max(self._btl_bw, delivery_rate)

        self._delivered = delivered
        self._delivered_time = time.time()

        # State machine
        if self._state == self.State.STARTUP:
            self._update_startup()
        elif self._state == self.State.DRAIN:
            self._update_drain()
        elif self._state == self.State.PROBE_BW:
            self._update_probe_bw()
        elif self._state == self.State.PROBE_RTT:
            self._update_probe_rtt()

        # Calculate cwnd and pacing rate
        self._update_cwnd_and_rate()

    def _update_startup(self):
        """Update in STARTUP state."""
        # Stay in startup until bandwidth stops increasing
        # (simplified: transition after initial growth)
        if self._btl_bw > 0 and self._cwnd > 10 * self._bdp():
            self._state = self.State.DRAIN

    def _update_drain(self):
        """Update in DRAIN state."""
        # Drain until inflight <= BDP
        if self._cwnd <= self._bdp():
            self._state = self.State.PROBE_BW
            self._probe_bw_phase = 0

    def _update_probe_bw(self):
        """Update in PROBE_BW state."""
        # Cycle through gain phases
        self._probe_bw_phase = (self._probe_bw_phase + 1) % 8

        # Periodically enter PROBE_RTT
        if time.time() - self._rt_prop_stamp > 10:
            self._state = self.State.PROBE_RTT
            self._probe_rtt_time = time.time()

    def _update_probe_rtt(self):
        """Update in PROBE_RTT state."""
        # Stay for at least 200ms
        if time.time() - self._probe_rtt_time > 0.2:
            self._state = self.State.PROBE_BW
            self._probe_bw_phase = 0

    def _update_cwnd_and_rate(self):
        """Calculate cwnd and pacing rate based on state."""
        bdp = self._bdp()

        if self._state == self.State.STARTUP:
            self._cwnd = int(bdp * self.STARTUP_GAIN)
            self._pacing_rate = self._btl_bw * self.STARTUP_GAIN
        elif self._state == self.State.DRAIN:
            self._cwnd = int(bdp * self.DRAIN_GAIN)
            self._pacing_rate = self._btl_bw * self.DRAIN_GAIN
        elif self._state == self.State.PROBE_BW:
            gain = self.PROBE_BW_GAINS[self._probe_bw_phase]
            self._cwnd = int(bdp * gain)
            self._pacing_rate = self._btl_bw * gain
        elif self._state == self.State.PROBE_RTT:
            self._cwnd = self.PROBE_RTT_CWND * self.mss
            self._pacing_rate = self._btl_bw

        # Ensure minimum cwnd
        self._cwnd = max(self._cwnd, 4 * self.mss)

    def _bdp(self) -> int:
        """Calculate bandwidth-delay product."""
        if self._rt_prop == float('inf') or self._btl_bw == 0:
            return 10 * self.mss
        return int(self._btl_bw * self._rt_prop)

    def on_timeout(self):
        """Handle timeout - BBR doesn't react strongly to loss."""
        pass  # BBR ignores loss, relies on rate estimation

    def __str__(self) -> str:
        return (f"BBR(btl_bw={self._btl_bw:.0f}B/s, "
                f"rt_prop={self._rt_prop*1000:.1f}ms, "
                f"state={self._state.name})")
