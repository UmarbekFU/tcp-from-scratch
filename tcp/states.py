"""
TCP State Machine - The 11 states of a TCP connection.

The TCP state machine is the heart of TCP's connection management. Every TCP
connection moves through these states based on events (segment arrivals, user
commands, timeouts).

Understanding this state machine is essential to understanding TCP:
- Why connections sometimes hang in CLOSE_WAIT (application didn't close)
- Why TIME_WAIT exists and lasts so long (2*MSL)
- How simultaneous open/close works
- What causes RST packets

The state machine ensures both endpoints agree on connection status despite
unreliable communication. It's a distributed consensus protocol for two parties.
"""

from enum import Enum, auto
from dataclasses import dataclass
from typing import Optional, Tuple, Callable
from .segment import TCPSegment, TCPFlags


class TCPState(Enum):
    """
    The 11 TCP states from RFC 793.

    State transitions are triggered by:
    1. User commands (OPEN, SEND, RECEIVE, CLOSE)
    2. Arriving segments (SYN, ACK, FIN, RST, data)
    3. Timeouts

    The states can be grouped:
    - Connection establishment: CLOSED, LISTEN, SYN_SENT, SYN_RECEIVED, ESTABLISHED
    - Connection termination: FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT, CLOSING, LAST_ACK, TIME_WAIT
    """

    # The connection does not exist
    CLOSED = auto()

    # Waiting for a connection request (server passive open)
    LISTEN = auto()

    # Sent SYN, waiting for SYN-ACK (client active open)
    SYN_SENT = auto()

    # Received SYN, sent SYN-ACK, waiting for ACK
    SYN_RECEIVED = auto()

    # Connection is open - data can flow both directions
    ESTABLISHED = auto()

    # Sent FIN, waiting for ACK of FIN
    FIN_WAIT_1 = auto()

    # FIN acknowledged, waiting for peer's FIN
    FIN_WAIT_2 = auto()

    # Received FIN, waiting for application to close
    CLOSE_WAIT = auto()

    # Both sides sent FIN, waiting for ACK of our FIN
    CLOSING = auto()

    # Received FIN, sent FIN, waiting for ACK
    LAST_ACK = auto()

    # Waiting for enough time to pass to be sure remote received ACK
    # Duration: 2 * MSL (Maximum Segment Lifetime)
    TIME_WAIT = auto()

    def is_established(self) -> bool:
        """Check if connection is fully established."""
        return self == TCPState.ESTABLISHED

    def can_send_data(self) -> bool:
        """Check if we can send data in this state."""
        return self in (
            TCPState.ESTABLISHED,
            TCPState.CLOSE_WAIT  # Can still send after receiving FIN
        )

    def can_receive_data(self) -> bool:
        """Check if we can receive data in this state."""
        return self in (
            TCPState.ESTABLISHED,
            TCPState.FIN_WAIT_1,
            TCPState.FIN_WAIT_2
        )

    def is_closing(self) -> bool:
        """Check if connection is in a closing state."""
        return self in (
            TCPState.FIN_WAIT_1,
            TCPState.FIN_WAIT_2,
            TCPState.CLOSE_WAIT,
            TCPState.CLOSING,
            TCPState.LAST_ACK,
            TCPState.TIME_WAIT
        )


@dataclass
class StateTransition:
    """
    Represents a state transition with its action.

    Each transition has:
    - from_state: Current state
    - event: What triggered the transition
    - to_state: New state after transition
    - action: What to do during transition (send segment, etc.)
    """
    from_state: TCPState
    event: str
    to_state: TCPState
    action: Optional[str] = None

    def __str__(self) -> str:
        action_str = f" / {self.action}" if self.action else ""
        return f"{self.from_state.name} --[{self.event}]--> {self.to_state.name}{action_str}"


class TCPStateMachine:
    """
    TCP State Machine implementation.

    This class manages state transitions for a TCP connection. It validates
    that transitions are legal and executes associated actions.

    Design insight: The state machine is deterministic given the same inputs.
    This makes TCP behavior predictable and debuggable, even across different
    implementations.
    """

    # Maximum Segment Lifetime - how long a segment can exist in the network
    # RFC 793 suggests 2 minutes, but implementations often use 30-60 seconds
    MSL = 60  # seconds

    # TIME_WAIT duration
    TIME_WAIT_DURATION = 2 * MSL

    def __init__(self, initial_state: TCPState = TCPState.CLOSED):
        self.state = initial_state
        self._transition_callbacks: list[Callable] = []

    def on_transition(self, callback: Callable[[TCPState, TCPState, str], None]):
        """Register a callback for state transitions."""
        self._transition_callbacks.append(callback)

    def _notify_transition(self, from_state: TCPState, to_state: TCPState, event: str):
        """Notify registered callbacks of state transition."""
        for callback in self._transition_callbacks:
            callback(from_state, to_state, event)

    def transition(self, event: str) -> Tuple[bool, Optional[str]]:
        """
        Attempt a state transition based on an event.

        Args:
            event: The event triggering the transition

        Returns:
            Tuple of (success, action_to_take)
            If success is False, the transition was invalid.
        """
        old_state = self.state
        result = self._process_event(event)

        if result[0] and self.state != old_state:
            self._notify_transition(old_state, self.state, event)

        return result

    def _process_event(self, event: str) -> Tuple[bool, Optional[str]]:
        """
        Process an event and update state.

        This implements the TCP state machine from RFC 793.
        The state machine is complex because it must handle:
        - Normal operation
        - Error conditions
        - Simultaneous open/close by both ends
        - Retransmissions and duplicates
        """

        # CLOSED state transitions
        if self.state == TCPState.CLOSED:
            if event == "passive_open":
                self.state = TCPState.LISTEN
                return (True, "create_tcb")
            elif event == "active_open":
                self.state = TCPState.SYN_SENT
                return (True, "send_syn")

        # LISTEN state transitions
        elif self.state == TCPState.LISTEN:
            if event == "recv_syn":
                self.state = TCPState.SYN_RECEIVED
                return (True, "send_syn_ack")
            elif event == "send":
                self.state = TCPState.SYN_SENT
                return (True, "send_syn")
            elif event == "close":
                self.state = TCPState.CLOSED
                return (True, "delete_tcb")

        # SYN_SENT state transitions
        elif self.state == TCPState.SYN_SENT:
            if event == "recv_syn_ack":
                self.state = TCPState.ESTABLISHED
                return (True, "send_ack")
            elif event == "recv_syn":
                # Simultaneous open - both sides sent SYN
                self.state = TCPState.SYN_RECEIVED
                return (True, "send_syn_ack")
            elif event == "close":
                self.state = TCPState.CLOSED
                return (True, "delete_tcb")
            elif event == "timeout":
                self.state = TCPState.CLOSED
                return (True, "delete_tcb")

        # SYN_RECEIVED state transitions
        elif self.state == TCPState.SYN_RECEIVED:
            if event == "recv_ack":
                self.state = TCPState.ESTABLISHED
                return (True, None)
            elif event == "close":
                self.state = TCPState.FIN_WAIT_1
                return (True, "send_fin")
            elif event == "recv_rst":
                self.state = TCPState.LISTEN
                return (True, None)
            elif event == "timeout":
                self.state = TCPState.CLOSED
                return (True, "delete_tcb")

        # ESTABLISHED state transitions
        elif self.state == TCPState.ESTABLISHED:
            if event == "close":
                self.state = TCPState.FIN_WAIT_1
                return (True, "send_fin")
            elif event == "recv_fin":
                self.state = TCPState.CLOSE_WAIT
                return (True, "send_ack")
            elif event == "recv_rst":
                self.state = TCPState.CLOSED
                return (True, "delete_tcb")

        # FIN_WAIT_1 state transitions
        elif self.state == TCPState.FIN_WAIT_1:
            if event == "recv_ack":
                # ACK of our FIN
                self.state = TCPState.FIN_WAIT_2
                return (True, None)
            elif event == "recv_fin":
                # Simultaneous close
                self.state = TCPState.CLOSING
                return (True, "send_ack")
            elif event == "recv_fin_ack":
                # FIN + ACK of our FIN
                self.state = TCPState.TIME_WAIT
                return (True, "send_ack")
            elif event == "recv_rst":
                self.state = TCPState.CLOSED
                return (True, "delete_tcb")

        # FIN_WAIT_2 state transitions
        elif self.state == TCPState.FIN_WAIT_2:
            if event == "recv_fin":
                self.state = TCPState.TIME_WAIT
                return (True, "send_ack")
            elif event == "recv_rst":
                self.state = TCPState.CLOSED
                return (True, "delete_tcb")
            elif event == "timeout":
                # FIN_WAIT_2 timeout (to handle peer that never sends FIN)
                self.state = TCPState.CLOSED
                return (True, "delete_tcb")

        # CLOSE_WAIT state transitions
        elif self.state == TCPState.CLOSE_WAIT:
            if event == "close":
                self.state = TCPState.LAST_ACK
                return (True, "send_fin")
            elif event == "recv_rst":
                self.state = TCPState.CLOSED
                return (True, "delete_tcb")

        # CLOSING state transitions
        elif self.state == TCPState.CLOSING:
            if event == "recv_ack":
                self.state = TCPState.TIME_WAIT
                return (True, None)
            elif event == "recv_rst":
                self.state = TCPState.CLOSED
                return (True, "delete_tcb")

        # LAST_ACK state transitions
        elif self.state == TCPState.LAST_ACK:
            if event == "recv_ack":
                self.state = TCPState.CLOSED
                return (True, "delete_tcb")
            elif event == "recv_rst":
                self.state = TCPState.CLOSED
                return (True, "delete_tcb")
            elif event == "timeout":
                self.state = TCPState.CLOSED
                return (True, "delete_tcb")

        # TIME_WAIT state transitions
        elif self.state == TCPState.TIME_WAIT:
            if event == "timeout":
                # 2*MSL timer expired
                self.state = TCPState.CLOSED
                return (True, "delete_tcb")
            elif event == "recv_fin":
                # Retransmitted FIN - resend ACK and restart timer
                return (True, "send_ack_restart_timer")

        # Invalid transition
        return (False, None)

    def can_send(self) -> bool:
        """Check if sending data is allowed in current state."""
        return self.state.can_send_data()

    def can_receive(self) -> bool:
        """Check if receiving data is allowed in current state."""
        return self.state.can_receive_data()

    def is_established(self) -> bool:
        """Check if connection is fully established."""
        return self.state.is_established()

    def is_closed(self) -> bool:
        """Check if connection is closed."""
        return self.state == TCPState.CLOSED

    def __str__(self) -> str:
        return f"TCPStateMachine(state={self.state.name})"


def determine_event_from_segment(segment: TCPSegment, current_state: TCPState) -> str:
    """
    Determine the state machine event from a received segment.

    This maps the low-level segment flags to high-level state machine events.
    """
    flags = segment.flags

    # RST always generates recv_rst
    if flags & TCPFlags.RST:
        return "recv_rst"

    # SYN-ACK
    if (flags & TCPFlags.SYN) and (flags & TCPFlags.ACK):
        return "recv_syn_ack"

    # SYN only
    if flags & TCPFlags.SYN:
        return "recv_syn"

    # FIN with ACK
    if (flags & TCPFlags.FIN) and (flags & TCPFlags.ACK):
        if current_state == TCPState.FIN_WAIT_1:
            return "recv_fin_ack"
        return "recv_fin"

    # FIN only
    if flags & TCPFlags.FIN:
        return "recv_fin"

    # ACK only (or with data)
    if flags & TCPFlags.ACK:
        return "recv_ack"

    return "unknown"


# Pretty print state machine transitions
def print_state_diagram():
    """Print the TCP state diagram in ASCII art."""
    diagram = """
TCP State Diagram
=================

                              +---------+
                              |  CLOSED |
                              +---------+
                         passive |     | active
                           OPEN  |     | OPEN
                                 v     v
                +--------+     +---------+
      rcv SYN   |        |<----|         |
     -------    |  SYN   |     | LISTEN  |
     snd SYN,   | RCVD   |     |         |
         ACK    |        |     +---------+
                +--------+          |
                    |               | rcv SYN
              rcv ACK of SYN        | -------
                    |               | snd SYN, ACK
                    v               v
                +---------+    +---------+
                |  ESTAB  |<---|   SYN   |
                |  LISHED |    |   SENT  |
                +---------+    +---------+
                    |               ^
              CLOSE |               | rcv SYN,ACK
             ------  |               | ---------
             snd FIN |               | snd ACK
                    v               |
                +---------+         |
                |   FIN   |<--------+
                | WAIT-1  |
                +---------+
                    |
          +---------+---------+
    rcv ACK of FIN  |         | rcv FIN
    -------------   |         | -------
          x         v         | snd ACK
                +---------+   v
                |   FIN   | +---------+
                | WAIT-2  | | CLOSING |
                +---------+ +---------+
                    |           |
              rcv FIN|     rcv ACK of FIN
              -------           |
              snd ACK           v
                    |      +---------+
                    +----->|  TIME   |
                           |  WAIT   |
                           +---------+
                                |
                         Timeout=2MSL
                                |
                                v
                           +---------+
                           | CLOSED  |
                           +---------+

CLOSE_WAIT and LAST_ACK states (server-side close):

+---------+  rcv FIN   +---------+  CLOSE     +---------+  rcv ACK   +---------+
|  ESTAB  | -------->  | CLOSE   | -------->  |  LAST   | ---------> | CLOSED  |
|  LISHED | snd ACK    |  WAIT   | snd FIN    |   ACK   |            |         |
+---------+            +---------+            +---------+            +---------+
"""
    print(diagram)
