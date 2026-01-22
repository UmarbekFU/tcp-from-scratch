#!/usr/bin/env python3
"""
TCP Echo Server Example

A simple echo server that demonstrates:
- Binding to a port
- Listening for connections
- Accepting connections
- Receiving and sending data
- Graceful connection close

Run this server, then connect with the echo client.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tcp import TCPSocket, TCPConfig
import logging

# Enable logging to see TCP internals
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


def echo_server(host: str = "127.0.0.1", port: int = 8080):
    """
    Run a TCP echo server.

    The server:
    1. Listens on the specified port
    2. Accepts one connection at a time
    3. Echoes back any received data
    4. Closes when client disconnects
    """
    print(f"Starting echo server on {host}:{port}")

    # Create server socket
    server = TCPSocket()

    # Bind to address
    server.bind((host, port))
    print(f"Bound to {host}:{port}")

    # Start listening (backlog of 5 pending connections)
    server.listen(5)
    print("Listening for connections...")

    try:
        while True:
            # Accept a connection
            print("Waiting for client...")
            client_socket, client_addr = server.accept()
            print(f"Accepted connection from {client_addr[0]}:{client_addr[1]}")

            # Handle the client
            handle_client(client_socket)

    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        server.close()
        print("Server closed")


def handle_client(client_socket: TCPSocket):
    """
    Handle a single client connection.

    Receives data and echoes it back until the client closes the connection.
    """
    try:
        while True:
            # Receive data (blocking, up to 4KB)
            data = client_socket.recv(4096)

            if not data:
                # Client closed connection
                print("Client disconnected")
                break

            print(f"Received {len(data)} bytes: {data[:50]}...")

            # Echo the data back
            client_socket.sendall(data)
            print(f"Echoed {len(data)} bytes back")

    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="TCP Echo Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if not args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    echo_server(args.host, args.port)
