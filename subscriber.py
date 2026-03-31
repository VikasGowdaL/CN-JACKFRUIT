"""
subscriber.py – Reliable Group Notification Subscriber
======================================================

Each subscriber:
  1. Opens a TLS/TCP connection to the server for registration & group control.
  2. Binds a UDP socket on a random ephemeral port.
  3. Listens for UDP notifications and sends back ACKs.
  4. Detects and discards duplicate packets (idempotent delivery).
  5. Optionally simulates packet loss (--loss <rate>) for testing.

Usage
─────
  python subscriber.py <subscriber_id> [--loss 0.0] [--groups all,alerts]

Examples
────────
  python subscriber.py alice
  python subscriber.py bob --loss 0.3 --groups alerts,critical
  python subscriber.py carol --loss 0.5 --groups all

Interactive commands (while running)
─────────────────────────────────────
  sub   <group>    subscribe to group
  unsub <group>    unsubscribe from group
  stats            show local counters
  quit             disconnect and exit
"""

import argparse
import json
import logging
import random
import socket
import ssl
import sys
import threading
import time

from config import (
    SERVER_HOST, TCP_PORT, UDP_PORT,
    CA_FILE, CLIENT_CERT, CLIENT_KEY,
    GROUP_ALL, GROUP_NAMES,
    PKT_NOTIFY, PKT_ACK, PKT_NACK, PKT_BEST_EFFORT,
)
from packet import Packet

# ── Logging ────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("subscriber.log", mode="w", encoding="utf-8"),
        logging.StreamHandler(
            open(sys.stdout.fileno(), mode="w", encoding="utf-8", closefd=False)
        ),
    ],
)


class ReliableSubscriber:
    """
    A subscriber that registers with the server over TLS, then
    receives UDP notifications and acknowledges each one.
    """

    def __init__(self, sub_id: str, groups: list[int] | None = None,
                 loss_rate: float = 0.0):
        self.sub_id    = sub_id
        self.groups    = list(groups or [GROUP_ALL])
        self.loss_rate = max(0.0, min(1.0, loss_rate))  # clamp to [0,1]
        self.log       = logging.getLogger(f"Sub:{sub_id}")

        self._running    = False
        self._tls: ssl.SSLSocket | None = None

        # UDP socket — OS picks a free ephemeral port
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.bind(("", 0))
        self._udp_port = self._udp.getsockname()[1]
        self.log.info(f"UDP listener on port {self._udp_port}")

        # Deduplication: track every seq_no we have already delivered
        self._seen:      set[int]       = set()
        self._seen_lock  = threading.Lock()

        # Local stats
        self.stats = {
            "delivered":     0,
            "duplicates":    0,
            "loss_simulated":0,
            "acks_sent":     0,
            "best_effort":   0,
        }

    # ── TLS control channel ───────────────────────────────────────────────

    def _build_tls_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(CA_FILE)              # verify server cert
        ctx.load_cert_chain(CLIENT_CERT, CLIENT_KEY)    # present our cert (mutual TLS)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    def _connect_tls(self):
        ctx = self._build_tls_context()
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tls = ctx.wrap_socket(raw, server_hostname=SERVER_HOST)
        self._tls.connect((SERVER_HOST, TCP_PORT))
        self.log.info(f"TLS connected to {SERVER_HOST}:{TCP_PORT}")

        # Registration
        reg = {
            "type":          "REGISTER",
            "subscriber_id": self.sub_id,
            "udp_port":      self._udp_port,
            "groups":        self.groups,
        }
        self._send_ctrl(reg)
        resp = self._recv_ctrl()
        if not resp or resp.get("status") != "OK":
            raise ConnectionError(f"Registration failed: {resp}")
        self.log.info(f"Registered successfully as '{self.sub_id}'")

    def _reconnect_tls(self):
        """Exponential back-off reconnect on TLS drop."""
        for attempt in range(6):
            delay = 2 ** attempt
            self.log.warning(f"Reconnecting in {delay}s (attempt {attempt+1}) …")
            time.sleep(delay)
            try:
                self._connect_tls()
                return
            except Exception as exc:
                self.log.error(f"Reconnect failed: {exc}")
        self.log.error("Could not reconnect — stopping subscriber.")
        self._running = False

    def subscribe(self, group_id: int):
        resp = self._ctrl_cmd({"type": "SUBSCRIBE", "group_id": group_id})
        if resp and resp.get("status") == "OK":
            if group_id not in self.groups:
                self.groups.append(group_id)
            self.log.info(f"Subscribed to group {group_id:#06x}")
        return resp

    def unsubscribe(self, group_id: int):
        resp = self._ctrl_cmd({"type": "UNSUBSCRIBE", "group_id": group_id})
        if resp and resp.get("status") == "OK":
            self.groups = [g for g in self.groups if g != group_id]
            self.log.info(f"Unsubscribed from group {group_id:#06x}")
        return resp

    def _ctrl_cmd(self, obj: dict) -> dict | None:
        self._send_ctrl(obj)
        return self._recv_ctrl()

    def _send_ctrl(self, obj: dict):
        try:
            self._tls.sendall((json.dumps(obj) + "\n").encode())
        except Exception as exc:
            self.log.warning(f"TLS send error: {exc}")

    def _recv_ctrl(self) -> dict | None:
        buf = b""
        try:
            while b"\n" not in buf:
                chunk = self._tls.recv(4096)
                if not chunk:
                    return None
                buf += chunk
            return json.loads(buf.split(b"\n")[0].decode())
        except Exception:
            return None

    # ── Keepalive thread ─────────────────────────────────────────────────

    def _keepalive_loop(self):
        """Send a KEEPALIVE every 30 s to hold the TLS connection open."""
        while self._running:
            time.sleep(30)
            resp = self._ctrl_cmd({"type": "KEEPALIVE"})
            if resp is None:
                self.log.warning("TLS keepalive failed — reconnecting …")
                self._reconnect_tls()

    # ── UDP listener ─────────────────────────────────────────────────────

    def _udp_listener(self):
        """
        Core UDP receive loop.

        For each datagram:
          • Unpack and validate the custom packet header + CRC
          • Discard if simulated loss fires
          • Deliver if seq not already seen (idempotency)
          • Send ACK back to the server
        """
        self._udp.settimeout(1.0)
        self.log.info("UDP listener started.")

        while self._running:
            try:
                data, server_addr = self._udp.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            pkt = Packet.unpack(data)
            if pkt is None:
                self.log.warning("Received invalid/corrupt packet — discarded.")
                continue

            if pkt.pkt_type == PKT_NOTIFY:
                self._handle_reliable(pkt, server_addr)
            elif pkt.pkt_type == PKT_BEST_EFFORT:
                self._handle_best_effort(pkt)
            # PKT_HEARTBEAT etc. can be added here

    def _handle_reliable(self, pkt: Packet, server_addr):
        """Handle a reliable notification that requires an ACK."""

        # ── Simulate packet loss ────────────────────────────────────────
        if self.loss_rate > 0 and random.random() < self.loss_rate:
            self.stats["loss_simulated"] += 1
            self.log.info(
                f"[SIMULATED LOSS] seq={pkt.seq_no} — not ACKing "
                f"(server will retransmit)"
            )
            return   # intentionally do NOT send ACK

        # ── Idempotency check ───────────────────────────────────────────
        with self._seen_lock:
            is_dup = pkt.seq_no in self._seen
            if not is_dup:
                self._seen.add(pkt.seq_no)

        if is_dup:
            self.stats["duplicates"] += 1
            self.log.info(f"[DUPLICATE] seq={pkt.seq_no} — sending ACK again")
        else:
            self.stats["delivered"] += 1
            self.log.info(
                f"[NOTIFY] seq={pkt.seq_no} group={pkt.group_id:#06x}: {pkt.text}"
            )

        # ── Send ACK ────────────────────────────────────────────────────
        ack = pkt.make_ack(self.sub_id)
        self._udp.sendto(ack.pack(), server_addr)
        self.stats["acks_sent"] += 1
        self.log.debug(f"ACK sent for seq={pkt.seq_no}")

    def _handle_best_effort(self, pkt: Packet):
        """Handle best-effort notification — no ACK, no dedup needed."""
        self.stats["best_effort"] += 1
        self.log.info(
            f"[BEST-EFFORT] seq={pkt.seq_no} group={pkt.group_id:#06x}: {pkt.text}"
        )

    # ── Start / stop ──────────────────────────────────────────────────────

    def start(self):
        self._connect_tls()
        self._running = True

        for target, name in [
            (self._udp_listener,  "UDPListener"),
            (self._keepalive_loop,"TLSKeepalive"),
        ]:
            threading.Thread(target=target, name=name, daemon=True).start()

        self.log.info(
            f"Subscriber '{self.sub_id}' running  "
            f"[loss={self.loss_rate*100:.0f}%  groups={self.groups}]"
        )
        try:
            self._cli()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        self._running = False
        self.log.info(f"Final stats: {self.stats}")
        for s in (self._udp, self._tls):
            try:
                s.close()
            except Exception:
                pass

    # ── Interactive CLI ───────────────────────────────────────────────────

    def _cli(self):
        print(f"\n{'═'*52}")
        print(f"  Subscriber: {self.sub_id}")
        print(f"{'═'*52}")
        print("  sub   <group>   subscribe to a group")
        print("  unsub <group>   unsubscribe from a group")
        print("  stats           show counters")
        print("  quit            exit")
        print(f"  groups: {', '.join(GROUP_NAMES)}")
        print(f"{'═'*52}\n")

        while self._running:
            try:
                line = input(f"{self.sub_id}> ").strip()
            except EOFError:
                break

            if not line:
                continue
            parts = line.split()
            cmd   = parts[0].lower()

            if cmd == "quit":
                break
            elif cmd == "stats":
                print(f"  {self.stats}")
            elif cmd == "sub" and len(parts) > 1:
                gid = GROUP_NAMES.get(parts[1].lower(), GROUP_ALL)
                self.subscribe(gid)
            elif cmd == "unsub" and len(parts) > 1:
                gid = GROUP_NAMES.get(parts[1].lower(), GROUP_ALL)
                self.unsubscribe(gid)
            else:
                print("  Unknown command")


# ── Entry point ───────────────────────────────────────────────────────────

def _parse_args():
    p = argparse.ArgumentParser(description="Reliable Group Notification Subscriber")
    p.add_argument("sub_id",          help="Unique subscriber ID (e.g. alice)")
    p.add_argument("--loss",  type=float, default=0.0,
                   help="Simulated packet-loss rate 0.0–1.0 (default: 0)")
    p.add_argument("--groups", default="all",
                   help="Comma-separated group names: all,alerts,updates,critical")
    return p.parse_args()


if __name__ == "__main__":
    args   = _parse_args()
    groups = [GROUP_NAMES.get(g.strip().lower(), GROUP_ALL)
              for g in args.groups.split(",")]
    sub = ReliableSubscriber(args.sub_id, groups=groups, loss_rate=args.loss)
    sub.start()