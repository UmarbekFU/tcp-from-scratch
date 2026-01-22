#!/usr/bin/env python3
"""
TCP Echo Client Example

A simple echo client that demonstrates:
- Connecting to a server
- Sending data
- Receiving response
- Graceful connection close

Run the echo server first, then run this client.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tcp import TCPSocket, TCPConfig
import logging
import time

# Enable logging to see TCP internals
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


def echo_client(host: str = "127.0.0.1", port: int = 8080, message: str = "Hello, TCP!"):
    """
    Run a TCP echo client.

    The client:
    1. Connects to the server
    2. Sends a message
    3. Receives the echo
    4. Prints the response
    5. Closes the connection
    """
    print(f"Connecting to {host}:{port}...")

    # Create client socket
    client = TCPSocket()

    # Set a timeout (optional)
    client.settimeout(30.0)

    try:
        # Connect to server
        client.connect((host, port))
        print(f"Connected to {host}:{port}")

        # Send message
        data = message.encode('utf-8')
        print(f"Sending: {message}")
        client.sendall(data)
        print(f"Sent {len(data)} bytes")

        # Receive response
        response = client.recv(4096)
        print(f"Received {len(response)} bytes: {response.decode('utf-8')}")

        # Verify echo
        if response == data:
            print("Echo verified!")
        else:
            print("WARNING: Response doesn't match sent data!")

    except TimeoutError:
        print("Connection timed out")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()
        print("Connection closed")


def interactive_client(host: str = "127.0.0.1", port: int = 8080):
    """
    Interactive echo client - send multiple messages.
    """
    print(f"Connecting to {host}:{port}...")

    client = TCPSocket()
    client.settimeout(30.0)

    try:
        client.connect((host, port))
        print(f"Connected! Type messages to send (Ctrl+C to quit)")

        while True:
            try:
                message = input("> ")
                if not message:
                    continue

                # Send
                client.sendall(message.encode('utf-8'))

                # Receive
                response = client.recv(4096)
                print(f"< {response.decode('utf-8')}")

            except KeyboardInterrupt:
                print("\nDisconnecting...")
                break

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()
        print("Disconnected")


def benchmark_client(host: str = "127.0.0.1", port: int = 8080,
                    message_size: int = 1024, count: int = 100):
    """
    Benchmark the echo server with multiple messages.
    """
    print(f"Benchmarking {host}:{port}")
    print(f"Message size: {message_size} bytes, Count: {count}")

    client = TCPSocket()
    client.settimeout(30.0)

    try:
        client.connect((host, port))
        print("Connected, starting benchmark...")

        # Create test data
        test_data = b'X' * message_size

        start_time = time.time()
        bytes_sent = 0
        bytes_received = 0

        for i in range(count):
            client.sendall(test_data)
            bytes_sent += len(test_data)

            response = b''
            while len(response) < message_size:
                chunk = client.recv(message_size - len(response))
                if not chunk:
                    raise RuntimeError("Connection closed")
                response += chunk
            bytes_received += len(response)

            if (i + 1) % 10 == 0:
                print(f"  Completed {i + 1}/{count} iterations")

        end_time = time.time()
        elapsed = end_time - start_time

        print(f"\nResults:")
        print(f"  Total time: {elapsed:.2f} seconds")
        print(f"  Messages: {count}")
        print(f"  Bytes sent: {bytes_sent}")
        print(f"  Bytes received: {bytes_received}")
        print(f"  Throughput: {bytes_sent / elapsed / 1024:.2f} KB/s")
        print(f"  Messages/sec: {count / elapsed:.2f}")
        print(f"  Avg latency: {elapsed / count * 1000:.2f} ms")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="TCP Echo Client")
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=8080, help="Server port")
    parser.add_argument("--message", "-m", default="Hello, TCP!", help="Message to send")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive mode")
    parser.add_argument("--benchmark", "-b", action="store_true", help="Benchmark mode")
    parser.add_argument("--size", type=int, default=1024, help="Message size for benchmark")
    parser.add_argument("--count", type=int, default=100, help="Message count for benchmark")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if not args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    if args.interactive:
        interactive_client(args.host, args.port)
    elif args.benchmark:
        benchmark_client(args.host, args.port, args.size, args.count)
    else:
        echo_client(args.host, args.port, args.message)
