#!/usr/bin/env python3
"""
Network Simulator for TCP Testing

This module provides a simulated network environment for testing TCP
without requiring actual network access. It allows you to:

1. Create virtual networks with configurable characteristics
2. Simulate packet loss, delay, reordering, and duplication
3. Visualize TCP behavior under different conditions
4. Test edge cases that are hard to reproduce on real networks

This is invaluable for understanding TCP behavior and debugging.
"""

import random
import time
import threading
import heapq
from dataclasses import dataclass, field
from typing import Optional, Callable, Dict, Tuple, List
from queue import Queue
import logging

logger = logging.getLogger(__name__)


@dataclass(order=True)
class ScheduledPacket:
    """A packet scheduled for future delivery."""
    delivery_time: float
    packet: bytes = field(compare=False)
    src_ip: str = field(compare=False)
    src_port: int = field(compare=False)
    dst_ip: str = field(compare=False)
    dst_port: int = field(compare=False)


@dataclass
class NetworkStats:
    """Statistics about network behavior."""
    packets_sent: int = 0
    packets_delivered: int = 0
    packets_dropped: int = 0
    packets_delayed: int = 0
    packets_reordered: int = 0
    packets_duplicated: int = 0
    bytes_sent: int = 0
    bytes_delivered: int = 0

    def __str__(self) -> str:
        loss_rate = self.packets_dropped / max(1, self.packets_sent) * 100
        return (
            f"Network Stats:\n"
            f"  Packets sent: {self.packets_sent}\n"
            f"  Packets delivered: {self.packets_delivered}\n"
            f"  Packets dropped: {self.packets_dropped} ({loss_rate:.1f}%)\n"
            f"  Packets reordered: {self.packets_reordered}\n"
            f"  Packets duplicated: {self.packets_duplicated}\n"
            f"  Bytes sent: {self.bytes_sent}\n"
            f"  Bytes delivered: {self.bytes_delivered}"
        )


class NetworkSimulator:
    """
    A network simulator that models real network behavior.

    Features:
    - Configurable latency (base + jitter)
    - Packet loss (random or burst)
    - Packet reordering
    - Packet duplication
    - Bandwidth limiting
    - Multiple endpoints
    """

    def __init__(self):
        self._endpoints: Dict[Tuple[str, int], Callable] = {}
        self._scheduled: List[ScheduledPacket] = []  # heap
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stats = NetworkStats()

        # Network characteristics
        self.latency = 0.050  # 50ms base latency
        self.jitter = 0.010   # 10ms jitter
        self.loss_rate = 0.0  # 0% packet loss
        self.reorder_rate = 0.0  # 0% reordering
        self.duplicate_rate = 0.0  # 0% duplication
        self.bandwidth = float('inf')  # Unlimited bandwidth (bytes/sec)

        # Burst loss simulation
        self.burst_loss_enabled = False
        self.burst_loss_probability = 0.01  # Probability of entering burst
        self.burst_loss_length = 3  # Average packets lost in burst
        self._in_burst = False
        self._burst_remaining = 0

    def register_endpoint(self, ip: str, port: int,
                         callback: Callable[[bytes, str, int], None]):
        """
        Register an endpoint to receive packets.

        Args:
            ip: IP address of the endpoint
            port: Port number
            callback: Function to call when packet arrives
                     Signature: (packet_data, src_ip, src_port)
        """
        with self._lock:
            self._endpoints[(ip, port)] = callback

    def unregister_endpoint(self, ip: str, port: int):
        """Unregister an endpoint."""
        with self._lock:
            self._endpoints.pop((ip, port), None)

    def send(self, packet: bytes, src_ip: str, src_port: int,
             dst_ip: str, dst_port: int):
        """
        Send a packet through the simulated network.

        The packet may be delayed, dropped, reordered, or duplicated
        based on the network characteristics.
        """
        with self._lock:
            self._stats.packets_sent += 1
            self._stats.bytes_sent += len(packet)

            # Check for loss
            if self._should_drop():
                self._stats.packets_dropped += 1
                logger.debug(f"Dropped: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                return

            # Calculate delivery time
            delay = self._calculate_delay()

            # Check for duplication
            if random.random() < self.duplicate_rate:
                self._stats.packets_duplicated += 1
                # Schedule duplicate with different delay
                dup_delay = self._calculate_delay()
                self._schedule_packet(packet, src_ip, src_port, dst_ip, dst_port,
                                     time.time() + dup_delay)

            # Check for reordering (add extra delay)
            if random.random() < self.reorder_rate:
                self._stats.packets_reordered += 1
                delay += random.uniform(0.01, 0.05)  # Extra 10-50ms

            # Schedule delivery
            self._schedule_packet(packet, src_ip, src_port, dst_ip, dst_port,
                                 time.time() + delay)

    def _should_drop(self) -> bool:
        """Determine if packet should be dropped."""
        # Burst loss
        if self.burst_loss_enabled:
            if self._in_burst:
                self._burst_remaining -= 1
                if self._burst_remaining <= 0:
                    self._in_burst = False
                return True
            elif random.random() < self.burst_loss_probability:
                self._in_burst = True
                self._burst_remaining = random.randint(1, self.burst_loss_length * 2)
                return True

        # Random loss
        return random.random() < self.loss_rate

    def _calculate_delay(self) -> float:
        """Calculate packet delay."""
        base_delay = self.latency + random.uniform(-self.jitter, self.jitter)
        return max(0.001, base_delay)  # Minimum 1ms

    def _schedule_packet(self, packet: bytes, src_ip: str, src_port: int,
                        dst_ip: str, dst_port: int, delivery_time: float):
        """Schedule a packet for delivery."""
        scheduled = ScheduledPacket(
            delivery_time=delivery_time,
            packet=packet,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port
        )
        heapq.heappush(self._scheduled, scheduled)

    def start(self):
        """Start the network simulator."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._delivery_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the network simulator."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.0)

    def _delivery_loop(self):
        """Background thread that delivers packets at scheduled times."""
        while self._running:
            with self._lock:
                if not self._scheduled:
                    continue

                # Check if next packet is ready
                if self._scheduled[0].delivery_time <= time.time():
                    packet = heapq.heappop(self._scheduled)
                    self._deliver_packet(packet)
                else:
                    # Wait for next packet
                    wait_time = self._scheduled[0].delivery_time - time.time()

            time.sleep(min(0.001, wait_time) if 'wait_time' in dir() else 0.001)

    def _deliver_packet(self, packet: ScheduledPacket):
        """Deliver a packet to its destination."""
        # Try exact match first
        callback = self._endpoints.get((packet.dst_ip, packet.dst_port))

        # Try wildcard
        if not callback:
            callback = self._endpoints.get(("0.0.0.0", packet.dst_port))

        if callback:
            self._stats.packets_delivered += 1
            self._stats.bytes_delivered += len(packet.packet)

            # Deliver in separate thread to avoid blocking
            threading.Thread(
                target=callback,
                args=(packet.packet, packet.src_ip, packet.src_port),
                daemon=True
            ).start()
        else:
            logger.debug(f"No endpoint for {packet.dst_ip}:{packet.dst_port}")

    def get_stats(self) -> NetworkStats:
        """Get network statistics."""
        return self._stats

    def reset_stats(self):
        """Reset network statistics."""
        self._stats = NetworkStats()

    def configure_lossy(self, loss_rate: float = 0.05):
        """Configure for a lossy network (e.g., wireless)."""
        self.loss_rate = loss_rate
        self.reorder_rate = 0.02
        self.jitter = 0.020
        print(f"Configured lossy network: {loss_rate*100}% loss")

    def configure_satellite(self):
        """Configure for satellite-like characteristics."""
        self.latency = 0.300  # 300ms
        self.jitter = 0.050
        self.loss_rate = 0.01
        print("Configured satellite network: 300ms latency")

    def configure_wan(self):
        """Configure for typical WAN characteristics."""
        self.latency = 0.050
        self.jitter = 0.020
        self.loss_rate = 0.001
        print("Configured WAN: 50ms latency")

    def configure_lan(self):
        """Configure for LAN characteristics."""
        self.latency = 0.001
        self.jitter = 0.0005
        self.loss_rate = 0.0
        print("Configured LAN: 1ms latency")

    def configure_congested(self):
        """Configure for a congested network."""
        self.latency = 0.100
        self.jitter = 0.100  # High jitter
        self.loss_rate = 0.05
        self.burst_loss_enabled = True
        self.burst_loss_probability = 0.02
        print("Configured congested network")


class PacketCapture:
    """
    Capture and analyze packets in the simulated network.

    Useful for debugging TCP behavior and understanding protocol dynamics.
    """

    def __init__(self):
        self._packets: List[dict] = []
        self._lock = threading.Lock()

    def capture(self, packet: bytes, src_ip: str, src_port: int,
                dst_ip: str, dst_port: int, direction: str = "->"):
        """Capture a packet."""
        with self._lock:
            self._packets.append({
                'timestamp': time.time(),
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'direction': direction,
                'size': len(packet),
                'raw': packet
            })

    def get_packets(self) -> List[dict]:
        """Get all captured packets."""
        with self._lock:
            return list(self._packets)

    def clear(self):
        """Clear captured packets."""
        with self._lock:
            self._packets.clear()

    def summary(self) -> str:
        """Generate a summary of captured packets."""
        with self._lock:
            if not self._packets:
                return "No packets captured"

            lines = [f"Captured {len(self._packets)} packets:"]
            start_time = self._packets[0]['timestamp']

            for i, pkt in enumerate(self._packets[:50]):  # Limit to 50
                rel_time = (pkt['timestamp'] - start_time) * 1000
                lines.append(
                    f"  {i:4d} [{rel_time:8.1f}ms] "
                    f"{pkt['src_ip']}:{pkt['src_port']} {pkt['direction']} "
                    f"{pkt['dst_ip']}:{pkt['dst_port']} "
                    f"({pkt['size']} bytes)"
                )

            if len(self._packets) > 50:
                lines.append(f"  ... and {len(self._packets) - 50} more")

            return '\n'.join(lines)


def demo_network_conditions():
    """
    Demonstrate how TCP behaves under different network conditions.

    This is a visual demo showing TCP's response to:
    1. Normal conditions
    2. Packet loss
    3. High latency
    4. Congestion
    """
    print("=" * 60)
    print("TCP Behavior Under Different Network Conditions")
    print("=" * 60)

    # This would integrate with our TCP implementation
    print("\n1. Normal Network (LAN)")
    print("   - Low latency, no loss")
    print("   - TCP operates efficiently, cwnd grows quickly")

    print("\n2. Lossy Network (Wireless)")
    print("   - 5% random packet loss")
    print("   - TCP detects loss via timeout or triple dup ACK")
    print("   - cwnd reduced, recovery begins")

    print("\n3. High Latency (Satellite)")
    print("   - 300ms RTT")
    print("   - Slow cwnd growth (once per RTT)")
    print("   - Need large windows to fill the pipe")

    print("\n4. Congested Network")
    print("   - Variable latency, burst losses")
    print("   - TCP backs off during congestion")
    print("   - AIMD finds fair share of bandwidth")

    print("\nTo run interactive tests, use the simulator with TCPSocket:")
    print("  from simulator.network import NetworkSimulator")
    print("  sim = NetworkSimulator()")
    print("  sim.configure_lossy(loss_rate=0.05)")
    print("  sim.start()")


if __name__ == "__main__":
    demo_network_conditions()
