# TCP From Scratch

A complete implementation of TCP (Transmission Control Protocol) built from first principles for deep understanding.

This is not a toy implementation. It includes:
- **Full state machine** (11 states from RFC 793)
- **Three-way handshake** with proper ISN generation
- **Reliable data transfer** with sequence numbers and acknowledgments
- **Flow control** with sliding window and receive window
- **Congestion control** (Slow Start, Congestion Avoidance, Fast Retransmit, Fast Recovery)
- **Retransmission** with RTT estimation and exponential backoff
- **Connection teardown** with TIME_WAIT handling

## Why Build TCP From Scratch?

TCP is the backbone of the internet. Understanding it deeply means understanding:
- How reliability is built on unreliable networks
- How distributed systems coordinate without central control
- How feedback loops can be stable or catastrophic
- Why certain design decisions were made (and their tradeoffs)

## Project Structure

```
tcp-from-scratch/
├── tcp/
│   ├── __init__.py
│   ├── segment.py      # TCP segment parsing and construction
│   ├── states.py       # TCP state machine (11 states)
│   ├── buffer.py       # Send and receive buffers
│   ├── timer.py        # Retransmission timer with RTT estimation
│   ├── congestion.py   # Congestion control algorithms
│   ├── connection.py   # Main TCPConnection class
│   └── socket.py       # High-level socket API
├── examples/
│   ├── echo_server.py  # Simple echo server
│   ├── echo_client.py  # Simple echo client
│   └── file_transfer.py # File transfer example
├── tests/
│   ├── test_segment.py
│   ├── test_states.py
│   ├── test_buffer.py
│   └── test_connection.py
├── docs/
│   └── DEEP_DIVE.md    # In-depth explanation of TCP internals
├── simulator/
│   └── network.py      # Network simulator for testing
└── README.md
```

## Quick Start

```python
from tcp import TCPSocket

# Server
server = TCPSocket()
server.bind(('0.0.0.0', 8080))
server.listen()
conn, addr = server.accept()
data = conn.recv(1024)
conn.send(b'Hello back!')
conn.close()

# Client
client = TCPSocket()
client.connect(('localhost', 8080))
client.send(b'Hello!')
response = client.recv(1024)
client.close()
```

## Running the Examples

```bash
# Terminal 1: Start the echo server
python -m examples.echo_server

# Terminal 2: Run the echo client
python -m examples.echo_client
```

## Running Tests

```bash
python -m pytest tests/ -v
```

## Implementation Details

### TCP Segment Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### State Machine

```
                              +---------+ ---------\      active OPEN
                              |  CLOSED |            \    -----------
                              +---------+<---------\   \   create TCB
                                |     ^              \   \  snd SYN
                   passive OPEN |     |   CLOSE        \   \
                   ------------ |     | ----------       \   \
                    create TCB  |     | delete TCB         \   \
                                V     |                      \   \
                              +---------+            CLOSE    |    \
                              |  LISTEN |          ---------- |     |
                              +---------+          delete TCB |     |
                   rcv SYN      |     |     SEND              |     |
                   -------      |     |    -------            |     V
  +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
  |         |<-----------------           ------------------>|         |
  |   SYN   |                    rcv SYN                     |   SYN   |
  |   RCVD  |<-----------------------------------------------|   SENT  |
  |         |                    snd ACK                     |         |
  |         |------------------           -------------------|         |
  +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
      |           ----------      |     |   ----------
      |               x           |     |   snd ACK
      |                           V     V
      |  CLOSE                   +---------+
      | -------                  |  ESTAB  |
      | snd FIN                  +---------+
      |                   CLOSE    |     |    rcv FIN
      V                  -------   |     |    -------
  +---------+            snd FIN  /       \   snd ACK          +---------+
  |  FIN    |<-----------------           ------------------>|  CLOSE  |
  | WAIT-1  |------------------                              |   WAIT  |
  +---------+          rcv FIN  \                            +---------+
    | rcv ACK of FIN   -------   |                            CLOSE  |
    | --------------   snd ACK   |                           ------- |
    V        x                   V                           snd FIN V
  +---------+                  +---------+                   +---------+
  |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
  +---------+                  +---------+                   +---------+
    |                rcv ACK of FIN |                 rcv ACK of FIN |
    |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
    |  -------              x       V    ------------        x       V
     \ snd ACK                 +---------+delete TCB         +---------+
      ------------------------>|TIME WAIT|------------------>| CLOSED  |
                               +---------+                   +---------+
```

## Key Concepts Implemented

### 1. Sequence Numbers
Every byte in the stream has a unique 32-bit sequence number. This enables:
- Detection of lost packets
- Reordering of out-of-order packets
- Detection of duplicates

### 2. Cumulative Acknowledgments
ACK number N means "I have received all bytes up to N-1". This is stateless and handles loss gracefully.

### 3. Flow Control (Receive Window)
The receiver advertises available buffer space. The sender limits bytes-in-flight to this window, preventing receiver buffer overflow.

### 4. Congestion Control
- **Slow Start**: Exponential growth from initial small window
- **Congestion Avoidance**: Linear growth after threshold
- **Fast Retransmit**: Retransmit on 3 duplicate ACKs
- **Fast Recovery**: Don't reset to slow start on fast retransmit

### 5. RTT Estimation
Uses exponential weighted moving average (EWMA) with variance tracking:
```
SRTT = (1 - α) * SRTT + α * RTT_sample
RTTVAR = (1 - β) * RTTVAR + β * |RTT_sample - SRTT|
RTO = SRTT + 4 * RTTVAR
```

## References

- [RFC 793](https://tools.ietf.org/html/rfc793) - Transmission Control Protocol (original spec)
- [RFC 5681](https://tools.ietf.org/html/rfc5681) - TCP Congestion Control
- [RFC 6298](https://tools.ietf.org/html/rfc6298) - Computing TCP's Retransmission Timer
- [RFC 7323](https://tools.ietf.org/html/rfc7323) - TCP Extensions for High Performance

## License

MIT License - Use this code to learn, experiment, and build.

## Author

Built by [Umarbek](https://um.ar) as part of the [101 Projects](https://um.ar/101/) series.
