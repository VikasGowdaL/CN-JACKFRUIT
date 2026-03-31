"""
performance_test.py – Automated Performance Comparison
=======================================================

Runs two back-to-back experiments without the full interactive server:
  1. Best-effort UDP  — fire-and-forget, no ACK
  2. Reliable UDP     — custom ACK + retransmission on top of raw UDP

Metrics collected
─────────────────
  • Delivery rate      (%)
  • Average latency    (ms) — time from sendto() to receipt
  • Throughput         (packets / second)
  • Total retransmissions (reliable only)
  • Overhead ratio     (bytes sent / bytes of useful payload)

Usage
─────
  python performance_test.py [--msgs 100] [--subs 5] [--loss 0.3]

The test sends packets directly via raw UDP sockets (bypassing the server)
so it runs standalone — you do NOT need to start server.py first.
"""

import argparse
import random
import socket
import statistics
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List

from config import (
    MAX_RETRANSMISSIONS, RETRANSMIT_INTERVAL,
    GROUP_ALL, PKT_NOTIFY, PKT_BEST_EFFORT, PKT_ACK,
)
from packet import Packet, HEADER_SIZE

SEQ_BASE_BE  = 10_000   # best-effort sequence numbers start here
SEQ_BASE_REL = 20_000   # reliable sequence numbers start here
PAYLOAD_SIZE = 64        # bytes of application payload per notification


# ── Passive subscriber (no TLS — test only) ──────────────────────────────

@dataclass
class TestSubscriber:
    sub_id:    str
    loss_rate: float          # 0–1 artificial loss

    received_be:  Dict[int, float] = field(default_factory=dict)   # seq→recv_time
    received_rel: Dict[int, float] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)
    running: bool = False

    udp: socket.socket = field(init=False)
    port: int          = field(init=False)

    def __post_init__(self):
        self.udp  = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.port = self.udp.getsockname()[1]

    def listen(self, sender_port: int):
        """Thread target — receive packets, ACK reliable ones."""
        server_addr = ("127.0.0.1", sender_port)
        self.udp.settimeout(0.5)
        self.running = True

        while self.running:
            try:
                data, addr = self.udp.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            pkt = Packet.unpack(data)
            if pkt is None:
                continue

            now = time.time()

            if pkt.pkt_type == PKT_BEST_EFFORT:
                if random.random() >= self.loss_rate:        # apply loss
                    with self.lock:
                        self.received_be[pkt.seq_no] = now

            elif pkt.pkt_type == PKT_NOTIFY:
                if random.random() >= self.loss_rate:        # apply loss
                    with self.lock:
                        self.received_rel[pkt.seq_no] = now
                    # Send ACK
                    ack = Packet(PKT_ACK, pkt.seq_no, pkt.group_id, self.sub_id)
                    self.udp.sendto(ack.pack(), server_addr)
                # else: intentionally drop → server retransmits

    def stop(self):
        self.running = False
        self.udp.close()


# ── Sender ────────────────────────────────────────────────────────────────

class Sender:
    """Simulates the server's sending + retransmission logic directly."""

    def __init__(self, subscribers: List[TestSubscriber]):
        self.subs = subscribers
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.retransmit_count = 0
        self.bytes_sent = 0

    def _targets(self):
        return [("127.0.0.1", s.port) for s in self.subs]

    def _send_pkt(self, pkt: Packet):
        raw = pkt.pack()
        for addr in self._targets():
            self.sock.sendto(raw, addr)
            self.bytes_sent += len(raw)

    # ── Best-effort send ──────────────────────────────────────────────────

    def send_best_effort(self, n_msgs: int, payload: bytes) -> Dict[int, float]:
        """Send n_msgs best-effort datagrams.  Returns {seq_no: send_time}."""
        send_times: Dict[int, float] = {}
        for i in range(n_msgs):
            seq = SEQ_BASE_BE + i
            pkt = Packet(PKT_BEST_EFFORT, seq, GROUP_ALL, payload)
            send_times[seq] = time.time()
            self._send_pkt(pkt)
            time.sleep(0.005)                 # 5 ms inter-packet gap
        return send_times

    # ── Reliable send with retransmission ────────────────────────────────

    def send_reliable(self, n_msgs: int, payload: bytes,
                      wait_sec: float = 10.0) -> Dict[int, float]:
        """
        Send n_msgs reliable datagrams.
        Block until all ACKs collected or wait_sec elapses.
        Returns {seq_no: first_send_time}.
        """
        send_times: Dict[int, float] = {}
        pending: Dict[int, dict]     = {}   # seq → {pkt, last_sent, attempts}

        # Initial send
        for i in range(n_msgs):
            seq = SEQ_BASE_REL + i
            pkt = Packet(PKT_NOTIFY, seq, GROUP_ALL, payload)
            t   = time.time()
            send_times[seq] = t
            self._send_pkt(pkt)
            pending[seq] = {"pkt": pkt, "last_sent": t, "attempts": 1}
            time.sleep(0.005)

        # Collect ACKs + retransmit loop
        deadline = time.time() + wait_sec
        while pending and time.time() < deadline:
            # Check which seqs have been ACKed (any subscriber received them)
            acked = set()
            for seq in list(pending):
                for sub in self.subs:
                    with sub.lock:
                        if seq in sub.received_rel:
                            acked.add(seq)
                            break
            for seq in acked:
                pending.pop(seq, None)

            # Retransmit timed-out entries
            now = time.time()
            for seq, info in list(pending.items()):
                if now - info["last_sent"] >= RETRANSMIT_INTERVAL:
                    if info["attempts"] < MAX_RETRANSMISSIONS:
                        self._send_pkt(info["pkt"])
                        info["last_sent"] = now
                        info["attempts"] += 1
                        self.retransmit_count += 1

            time.sleep(0.05)

        return send_times

    def close(self):
        self.sock.close()


# ── Result analysis ───────────────────────────────────────────────────────

def analyse(label: str, n_msgs: int, subscribers: List[TestSubscriber],
            send_times: Dict[int, float], key: str, total_bytes: int):
    payload_bytes = n_msgs * len(subscribers) * PAYLOAD_SIZE

    print(f"\n  ── {label} ──")
    for sub in subscribers:
        with sub.lock:
            received = dict(getattr(sub, key))

        delivered = len(received)
        rate      = delivered / n_msgs * 100

        latencies = [
            (recv_t - send_times[seq]) * 1000
            for seq, recv_t in received.items()
            if seq in send_times
        ]

        avg_lat = statistics.mean(latencies)    if latencies else float("nan")
        med_lat = statistics.median(latencies)  if latencies else float("nan")
        p99_lat = (sorted(latencies)[int(len(latencies)*0.99)-1]
                   if len(latencies) >= 100 else max(latencies, default=float("nan")))

        elapsed  = (max(latencies)/1000) if latencies else 1
        tput     = delivered / elapsed if elapsed else 0

        print(f"    {sub.sub_id:<12}  "
              f"delivered={delivered}/{n_msgs} ({rate:.1f}%)  "
              f"avg={avg_lat:.2f}ms  med={med_lat:.2f}ms  "
              f"p99={p99_lat:.2f}ms  tput={tput:.0f} pkt/s")

    overhead = total_bytes / payload_bytes if payload_bytes else 0
    print(f"    Bytes on wire: {total_bytes}  "
          f"Payload: {payload_bytes}  "
          f"Overhead ratio: {overhead:.2f}x")


# ── Main test runner ──────────────────────────────────────────────────────

def run(n_msgs: int, n_subs: int, loss: float):
    print(f"\n{'═'*64}")
    print(f"  Performance Test")
    print(f"  Messages per run : {n_msgs}")
    print(f"  Subscribers      : {n_subs}")
    print(f"  Simulated loss   : {loss*100:.0f}%")
    print(f"  Payload size     : {PAYLOAD_SIZE} bytes")
    print(f"{'═'*64}")

    payload = b"X" * PAYLOAD_SIZE

    # Create subscribers
    subs = [TestSubscriber(f"sub-{i}", loss_rate=loss) for i in range(n_subs)]

    # Create sender
    sender = Sender(subs)

    # Start subscriber listener threads
    threads = [
        threading.Thread(target=s.listen, args=(sender.port,), daemon=True)
        for s in subs
    ]
    for t in threads:
        t.start()
    time.sleep(0.2)

    # ── Experiment 1: Best-effort ─────────────────────────────────────────
    print("\n[1/2] Best-effort UDP — sending …")
    sender.bytes_sent = 0
    be_times = sender.send_best_effort(n_msgs, payload)
    time.sleep(1.0)           # let last packets arrive
    analyse("Best-Effort UDP", n_msgs, subs, be_times,
            "received_be", sender.bytes_sent)
    bytes_be = sender.bytes_sent

    # ── Experiment 2: Reliable ────────────────────────────────────────────
    sender.retransmit_count = 0
    sender.bytes_sent       = 0
    print("\n[2/2] Reliable UDP — sending + waiting for ACKs …")
    rel_times = sender.send_reliable(n_msgs, payload)
    time.sleep(1.5)           # let stragglers finish
    analyse("Reliable UDP (ACK + retransmission)", n_msgs, subs, rel_times,
            "received_rel", sender.bytes_sent)

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n{'─'*64}")
    print("  SUMMARY")
    print(f"  Retransmissions (reliable): {sender.retransmit_count}")
    print(f"  Best-effort wire bytes    : {bytes_be}")
    print(f"  Reliable   wire bytes     : {sender.bytes_sent}")
    print()
    print("  Interpretation:")
    print(f"  • At {loss*100:.0f}% loss, best-effort permanently drops ~{loss*100:.0f}% of packets.")
    print(f"  • Reliable mode retransmits until delivery, at the cost of extra")
    print(f"    latency (≈{RETRANSMIT_INTERVAL*1000:.0f} ms/retry) and {sender.retransmit_count} extra datagrams.")
    print(f"  • Trade-off: reliability vs. latency/bandwidth overhead.")
    print(f"{'═'*64}\n")

    # Cleanup
    for s in subs:
        s.stop()
    sender.close()


# ── Entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Reliable vs Best-Effort UDP performance test")
    p.add_argument("--msgs", type=int,   default=100, help="Number of messages (default 100)")
    p.add_argument("--subs", type=int,   default=5,   help="Number of subscribers (default 5)")
    p.add_argument("--loss", type=float, default=0.3,
                   help="Simulated packet-loss probability 0–1 (default 0.3)")
    args = p.parse_args()
    run(args.msgs, args.subs, args.loss)
