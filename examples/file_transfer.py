#!/usr/bin/env python3
"""
TCP File Transfer Example

Demonstrates reliable file transfer using our TCP implementation.
Shows how TCP handles large data transfers with:
- Segmentation of large files
- Flow control (don't overwhelm receiver)
- Congestion control (don't overwhelm network)
- Reliable delivery (retransmit lost segments)
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tcp import TCPSocket, TCPConfig
import logging
import hashlib
import struct
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def send_file(host: str, port: int, filepath: str):
    """
    Send a file to the server.

    Protocol:
    1. Send filename length (4 bytes)
    2. Send filename
    3. Send file size (8 bytes)
    4. Send file content
    5. Send MD5 hash (16 bytes)
    """
    # Read file
    filename = os.path.basename(filepath)
    with open(filepath, 'rb') as f:
        content = f.read()

    file_size = len(content)
    file_hash = hashlib.md5(content).digest()

    print(f"Sending file: {filename}")
    print(f"Size: {file_size} bytes")
    print(f"MD5: {file_hash.hex()}")

    # Connect
    client = TCPSocket()
    client.settimeout(60.0)

    try:
        client.connect((host, port))
        print(f"Connected to {host}:{port}")

        start_time = time.time()

        # Send filename
        filename_bytes = filename.encode('utf-8')
        client.sendall(struct.pack('!I', len(filename_bytes)))
        client.sendall(filename_bytes)

        # Send file size
        client.sendall(struct.pack('!Q', file_size))

        # Send content
        bytes_sent = 0
        chunk_size = 8192

        while bytes_sent < file_size:
            chunk = content[bytes_sent:bytes_sent + chunk_size]
            client.sendall(chunk)
            bytes_sent += len(chunk)

            # Progress
            progress = bytes_sent / file_size * 100
            print(f"\rProgress: {progress:.1f}% ({bytes_sent}/{file_size})", end='')

        print()  # Newline after progress

        # Send hash
        client.sendall(file_hash)

        # Wait for confirmation
        response = client.recv(2)
        if response == b'OK':
            elapsed = time.time() - start_time
            throughput = file_size / elapsed / 1024 / 1024
            print(f"Transfer complete!")
            print(f"Time: {elapsed:.2f}s, Throughput: {throughput:.2f} MB/s")
        else:
            print(f"Transfer failed: {response}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()


def receive_file(port: int, output_dir: str = "."):
    """
    Receive files from clients.

    Listens on the specified port and saves received files.
    """
    server = TCPSocket()
    server.bind(("0.0.0.0", port))
    server.listen(5)

    print(f"File server listening on port {port}")
    print(f"Output directory: {output_dir}")

    try:
        while True:
            print("\nWaiting for connection...")
            client, addr = server.accept()
            print(f"Connection from {addr[0]}:{addr[1]}")

            try:
                receive_one_file(client, output_dir)
            except Exception as e:
                print(f"Error receiving file: {e}")
            finally:
                client.close()

    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.close()


def receive_one_file(client: TCPSocket, output_dir: str):
    """Receive a single file from a client."""
    start_time = time.time()

    # Receive filename length
    data = recv_exact(client, 4)
    filename_len = struct.unpack('!I', data)[0]

    # Receive filename
    filename = recv_exact(client, filename_len).decode('utf-8')
    print(f"Receiving: {filename}")

    # Receive file size
    data = recv_exact(client, 8)
    file_size = struct.unpack('!Q', data)[0]
    print(f"Size: {file_size} bytes")

    # Receive content
    content = bytearray()
    bytes_received = 0

    while bytes_received < file_size:
        chunk = client.recv(min(8192, file_size - bytes_received))
        if not chunk:
            raise RuntimeError("Connection closed during transfer")
        content.extend(chunk)
        bytes_received += len(chunk)

        progress = bytes_received / file_size * 100
        print(f"\rProgress: {progress:.1f}% ({bytes_received}/{file_size})", end='')

    print()

    # Receive hash
    expected_hash = recv_exact(client, 16)
    actual_hash = hashlib.md5(content).digest()

    if actual_hash == expected_hash:
        # Save file
        output_path = os.path.join(output_dir, filename)
        with open(output_path, 'wb') as f:
            f.write(content)

        elapsed = time.time() - start_time
        throughput = file_size / elapsed / 1024 / 1024

        print(f"File saved to: {output_path}")
        print(f"Hash verified: {actual_hash.hex()}")
        print(f"Time: {elapsed:.2f}s, Throughput: {throughput:.2f} MB/s")

        client.sendall(b'OK')
    else:
        print(f"Hash mismatch!")
        print(f"Expected: {expected_hash.hex()}")
        print(f"Actual:   {actual_hash.hex()}")
        client.sendall(b'ER')


def recv_exact(sock: TCPSocket, size: int) -> bytes:
    """Receive exactly `size` bytes."""
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("Connection closed")
        data.extend(chunk)
    return bytes(data)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="TCP File Transfer")
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Send command
    send_parser = subparsers.add_parser('send', help='Send a file')
    send_parser.add_argument('file', help='File to send')
    send_parser.add_argument('--host', default='127.0.0.1', help='Server host')
    send_parser.add_argument('--port', type=int, default=9000, help='Server port')

    # Receive command
    recv_parser = subparsers.add_parser('receive', help='Receive files (server mode)')
    recv_parser.add_argument('--port', type=int, default=9000, help='Port to listen on')
    recv_parser.add_argument('--output', default='.', help='Output directory')

    args = parser.parse_args()

    if args.command == 'send':
        send_file(args.host, args.port, args.file)
    elif args.command == 'receive':
        receive_file(args.port, args.output)
    else:
        parser.print_help()
