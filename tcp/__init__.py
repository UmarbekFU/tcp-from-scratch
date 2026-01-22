"""
TCP From Scratch - A complete TCP implementation for learning.

This package implements TCP (Transmission Control Protocol) from first principles,
including connection establishment, reliable data transfer, flow control,
congestion control, and connection teardown.
"""

from .segment import TCPSegment, TCPFlags
from .states import TCPState
from .buffer import SendBuffer, ReceiveBuffer
from .timer import RetransmissionTimer
from .congestion import CongestionController
from .connection import TCPConnection
from .socket import TCPSocket

__version__ = "1.0.0"
__author__ = "Umarbek"

__all__ = [
    "TCPSegment",
    "TCPFlags",
    "TCPState",
    "SendBuffer",
    "ReceiveBuffer",
    "RetransmissionTimer",
    "CongestionController",
    "TCPConnection",
    "TCPSocket",
]
