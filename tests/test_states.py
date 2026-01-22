"""
Tests for TCP State Machine.
"""

import pytest
from tcp.states import TCPState, TCPStateMachine, determine_event_from_segment
from tcp.segment import TCPSegment, TCPFlags


class TestTCPState:
    """Test TCP state enum and helpers."""

    def test_state_properties(self):
        """Test state property methods."""
        assert TCPState.ESTABLISHED.is_established()
        assert not TCPState.SYN_SENT.is_established()

        assert TCPState.ESTABLISHED.can_send_data()
        assert TCPState.CLOSE_WAIT.can_send_data()
        assert not TCPState.FIN_WAIT_1.can_send_data()

        assert TCPState.ESTABLISHED.can_receive_data()
        assert TCPState.FIN_WAIT_1.can_receive_data()
        assert not TCPState.CLOSE_WAIT.can_receive_data()

    def test_closing_states(self):
        """Test is_closing property."""
        closing_states = [
            TCPState.FIN_WAIT_1,
            TCPState.FIN_WAIT_2,
            TCPState.CLOSE_WAIT,
            TCPState.CLOSING,
            TCPState.LAST_ACK,
            TCPState.TIME_WAIT
        ]

        for state in closing_states:
            assert state.is_closing(), f"{state} should be closing"

        non_closing = [
            TCPState.CLOSED,
            TCPState.LISTEN,
            TCPState.SYN_SENT,
            TCPState.SYN_RECEIVED,
            TCPState.ESTABLISHED
        ]

        for state in non_closing:
            assert not state.is_closing(), f"{state} should not be closing"


class TestTCPStateMachine:
    """Test TCP state machine transitions."""

    def test_initial_state(self):
        """Test initial state is CLOSED."""
        sm = TCPStateMachine()
        assert sm.state == TCPState.CLOSED

    def test_passive_open(self):
        """Test passive open (server)."""
        sm = TCPStateMachine()

        success, action = sm.transition("passive_open")
        assert success
        assert action == "create_tcb"
        assert sm.state == TCPState.LISTEN

    def test_active_open(self):
        """Test active open (client)."""
        sm = TCPStateMachine()

        success, action = sm.transition("active_open")
        assert success
        assert action == "send_syn"
        assert sm.state == TCPState.SYN_SENT

    def test_three_way_handshake_client(self):
        """Test client-side three-way handshake."""
        sm = TCPStateMachine()

        # CLOSED -> SYN_SENT
        sm.transition("active_open")
        assert sm.state == TCPState.SYN_SENT

        # SYN_SENT -> ESTABLISHED (on SYN-ACK)
        success, action = sm.transition("recv_syn_ack")
        assert success
        assert action == "send_ack"
        assert sm.state == TCPState.ESTABLISHED

    def test_three_way_handshake_server(self):
        """Test server-side three-way handshake."""
        sm = TCPStateMachine()

        # CLOSED -> LISTEN
        sm.transition("passive_open")
        assert sm.state == TCPState.LISTEN

        # LISTEN -> SYN_RECEIVED
        success, action = sm.transition("recv_syn")
        assert success
        assert action == "send_syn_ack"
        assert sm.state == TCPState.SYN_RECEIVED

        # SYN_RECEIVED -> ESTABLISHED
        success, action = sm.transition("recv_ack")
        assert success
        assert sm.state == TCPState.ESTABLISHED

    def test_simultaneous_open(self):
        """Test simultaneous open (both send SYN)."""
        sm = TCPStateMachine()

        # Active open
        sm.transition("active_open")
        assert sm.state == TCPState.SYN_SENT

        # Receive SYN (not SYN-ACK) - simultaneous open
        success, action = sm.transition("recv_syn")
        assert success
        assert action == "send_syn_ack"
        assert sm.state == TCPState.SYN_RECEIVED

        # Receive ACK
        sm.transition("recv_ack")
        assert sm.state == TCPState.ESTABLISHED

    def test_close_initiator(self):
        """Test connection close by initiator."""
        sm = TCPStateMachine(initial_state=TCPState.ESTABLISHED)

        # ESTABLISHED -> FIN_WAIT_1
        success, action = sm.transition("close")
        assert success
        assert action == "send_fin"
        assert sm.state == TCPState.FIN_WAIT_1

        # FIN_WAIT_1 -> FIN_WAIT_2
        success, action = sm.transition("recv_ack")
        assert success
        assert sm.state == TCPState.FIN_WAIT_2

        # FIN_WAIT_2 -> TIME_WAIT
        success, action = sm.transition("recv_fin")
        assert success
        assert action == "send_ack"
        assert sm.state == TCPState.TIME_WAIT

        # TIME_WAIT -> CLOSED
        success, action = sm.transition("timeout")
        assert success
        assert action == "delete_tcb"
        assert sm.state == TCPState.CLOSED

    def test_close_responder(self):
        """Test connection close by responder."""
        sm = TCPStateMachine(initial_state=TCPState.ESTABLISHED)

        # Receive FIN
        success, action = sm.transition("recv_fin")
        assert success
        assert action == "send_ack"
        assert sm.state == TCPState.CLOSE_WAIT

        # Application closes
        success, action = sm.transition("close")
        assert success
        assert action == "send_fin"
        assert sm.state == TCPState.LAST_ACK

        # Receive ACK of our FIN
        success, action = sm.transition("recv_ack")
        assert success
        assert action == "delete_tcb"
        assert sm.state == TCPState.CLOSED

    def test_simultaneous_close(self):
        """Test simultaneous close (both send FIN)."""
        sm = TCPStateMachine(initial_state=TCPState.ESTABLISHED)

        # Both send FIN
        sm.transition("close")
        assert sm.state == TCPState.FIN_WAIT_1

        # Receive FIN (before our FIN is ACKed)
        success, action = sm.transition("recv_fin")
        assert success
        assert action == "send_ack"
        assert sm.state == TCPState.CLOSING

        # Receive ACK of our FIN
        sm.transition("recv_ack")
        assert sm.state == TCPState.TIME_WAIT

    def test_fin_ack_optimization(self):
        """Test receiving FIN+ACK in one segment."""
        sm = TCPStateMachine(initial_state=TCPState.FIN_WAIT_1)

        # Receive FIN that also ACKs our FIN
        success, action = sm.transition("recv_fin_ack")
        assert success
        assert action == "send_ack"
        assert sm.state == TCPState.TIME_WAIT

    def test_rst_handling(self):
        """Test RST handling in various states."""
        # RST in ESTABLISHED
        sm = TCPStateMachine(initial_state=TCPState.ESTABLISHED)
        success, action = sm.transition("recv_rst")
        assert success
        assert action == "delete_tcb"
        assert sm.state == TCPState.CLOSED

        # RST in SYN_RECEIVED returns to LISTEN
        sm = TCPStateMachine(initial_state=TCPState.SYN_RECEIVED)
        success, action = sm.transition("recv_rst")
        assert success
        assert sm.state == TCPState.LISTEN

    def test_timeout_handling(self):
        """Test timeout in various states."""
        # Timeout in SYN_SENT
        sm = TCPStateMachine(initial_state=TCPState.SYN_SENT)
        success, action = sm.transition("timeout")
        assert success
        assert sm.state == TCPState.CLOSED

        # Timeout in TIME_WAIT
        sm = TCPStateMachine(initial_state=TCPState.TIME_WAIT)
        success, action = sm.transition("timeout")
        assert success
        assert action == "delete_tcb"
        assert sm.state == TCPState.CLOSED

    def test_invalid_transitions(self):
        """Test invalid state transitions."""
        sm = TCPStateMachine()

        # Can't receive SYN-ACK in CLOSED
        success, action = sm.transition("recv_syn_ack")
        assert not success
        assert sm.state == TCPState.CLOSED

        # Can't send data in CLOSED
        success, action = sm.transition("send")
        assert not success

    def test_transition_callback(self):
        """Test state transition callbacks."""
        sm = TCPStateMachine()
        transitions = []

        def on_transition(from_state, to_state, event):
            transitions.append((from_state, to_state, event))

        sm.on_transition(on_transition)

        sm.transition("active_open")
        sm.transition("recv_syn_ack")

        assert len(transitions) == 2
        assert transitions[0] == (TCPState.CLOSED, TCPState.SYN_SENT, "active_open")
        assert transitions[1] == (TCPState.SYN_SENT, TCPState.ESTABLISHED, "recv_syn_ack")


class TestEventDetermination:
    """Test determining events from segments."""

    def test_syn_detection(self):
        """Test SYN segment detection."""
        syn = TCPSegment(
            src_port=1000, dst_port=80, seq_num=100, ack_num=0,
            flags=TCPFlags.SYN, window=65535
        )
        event = determine_event_from_segment(syn, TCPState.LISTEN)
        assert event == "recv_syn"

    def test_syn_ack_detection(self):
        """Test SYN-ACK segment detection."""
        syn_ack = TCPSegment(
            src_port=80, dst_port=1000, seq_num=200, ack_num=101,
            flags=TCPFlags.SYN | TCPFlags.ACK, window=65535
        )
        event = determine_event_from_segment(syn_ack, TCPState.SYN_SENT)
        assert event == "recv_syn_ack"

    def test_fin_detection(self):
        """Test FIN segment detection."""
        fin = TCPSegment(
            src_port=80, dst_port=1000, seq_num=300, ack_num=200,
            flags=TCPFlags.FIN | TCPFlags.ACK, window=65535
        )
        event = determine_event_from_segment(fin, TCPState.ESTABLISHED)
        assert event == "recv_fin"

    def test_rst_detection(self):
        """Test RST segment detection."""
        rst = TCPSegment(
            src_port=80, dst_port=1000, seq_num=0, ack_num=0,
            flags=TCPFlags.RST, window=0
        )
        event = determine_event_from_segment(rst, TCPState.ESTABLISHED)
        assert event == "recv_rst"

    def test_ack_detection(self):
        """Test ACK segment detection."""
        ack = TCPSegment(
            src_port=80, dst_port=1000, seq_num=200, ack_num=101,
            flags=TCPFlags.ACK, window=65535
        )
        event = determine_event_from_segment(ack, TCPState.SYN_RECEIVED)
        assert event == "recv_ack"
