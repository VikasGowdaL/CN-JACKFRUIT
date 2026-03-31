"""
server.py – Reliable Group Notification Server
===============================================

Architecture
────────────
                    ┌──────────────────────────────────┐
  Subscribers       │           SERVER                 │
  ──────────        │                                  │
  [Sub A] ←──TLS──→ │  TLS/TCP Control Channel         │  ← registration,
  [Sub B] ←──TLS──→ │  (port 9000)                     │    group mgmt,
  [Sub C] ←──TLS──→ │                                  │    commands
                    │  UDP Data Channel (port 9001)     │
  [Sub A] ←──UDP──→ │  ┌──────────────────────────┐   │  ← reliable notify
  [Sub B] ←──UDP──→ │  │ Seq counter              │   │     + ACK/NACK
  [Sub C] ←──UDP──→ │  │ Pending ACK tracker      │   │
                    │  │ Retransmission loop       │   │
                    │  └──────────────────────────┘   │
                    └──────────────────────────────────┘

Threads
───────
  TLSAccept      – blocks on tls_server.accept(), spawns one thread per client
  TLSClient-N    – per-subscriber control thread (registration + commands)
  UDPReceiver    – receives ACK/NACK packets from subscribers
  Retransmitter  – scans pending table, retransmits un-ACKed notifications
  StatsPrinter   – logs periodic statistics

Deliverable coverage
────────────────────
  ✓ Custom packet format with sequence numbers   (packet.py)
  ✓ Group membership management                  (_process_command)
  ✓ Loss detection and retransmission            (_retransmission_loop)
  ✓ TLS/SSL mandatory secure communication       (_setup_tls_server)
  ✓ Multiple concurrent clients                  (threading, per-client threads)
  ✓ Direct socket API (no high-level frameworks) (socket, ssl stdlib only)
"""

import json
import logging
import socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Set, Tuple, Optional

from config import (
    SERVER_HOST, TCP_PORT, UDP_PORT,
    CA_FILE, SERVER_CERT, SERVER_KEY,
    MAX_RETRANSMISSIONS, RETRANSMIT_INTERVAL,
    GROUP_ALL, GROUP_NAMES, PKT_NOTIFY, PKT_ACK, PKT_NACK, PKT_BEST_EFFORT,
)
from packet import Packet

# ── Logging ────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("server.log", mode="w", encoding="utf-8"),
        # Force UTF-8 on Windows (default cp1252 can't encode arrows/boxes)
        logging.StreamHandler(
            open(sys.stdout.fileno(), mode="w", encoding="utf-8", closefd=False)
        ),
    ],
)
log = logging.getLogger("Server")


# ── Data classes ──────────────────────────────────────────────────────────

@dataclass
class SubscriberInfo:
    """Everything the server knows about a registered subscriber."""
    sub_id:   str
    udp_addr: Tuple[str, int]        # (ip, udp_port) for delivery
    groups:   Set[int] = field(default_factory=set)
    tls_conn: Optional[ssl.SSLSocket] = field(default=None, repr=False)
    active:   bool = True
    last_seen: float = field(default_factory=time.time)

    def in_group(self, group_id: int) -> bool:
        return group_id == GROUP_ALL or group_id in self.groups


@dataclass
class PendingEntry:
    """One notification awaiting ACK from one subscriber."""
    packet:     Packet
    sub_id:     str
    udp_addr:   Tuple[str, int]
    attempts:   int   = 0
    last_sent:  float = 0.0
    acked:      bool  = False


# ── Server ────────────────────────────────────────────────────────────────

class ReliableGroupNotificationServer:

    def __init__(self):
        # Subscriber registry
        self._subs:      Dict[str, SubscriberInfo] = {}
        self._subs_lock  = threading.RLock()

        # Sequence counter (global, monotonically increasing)
        self._seq        = 0
        self._seq_lock   = threading.Lock()

        # Pending ACK table  key=(seq_no, sub_id)
        self._pending:     Dict[Tuple[int,str], PendingEntry] = {}
        self._pending_lock = threading.Lock()

        self._running = False

        # Performance counters
        self._stats = {
            "sent":           0,
            "acks_received":  0,
            "retransmissions":0,
            "dropped":        0,
        }
        self._stats_lock = threading.Lock()

        self._setup_udp()
        self._setup_tls()

    # ── Socket setup ──────────────────────────────────────────────────────

    def _setup_udp(self):
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp.bind((SERVER_HOST, UDP_PORT))
        log.info(f"UDP socket bound to {SERVER_HOST}:{UDP_PORT}")

    def _setup_tls(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(SERVER_CERT, SERVER_KEY)
        ctx.load_verify_locations(CA_FILE)
        ctx.verify_mode      = ssl.CERT_REQUIRED     # mutual TLS
        ctx.minimum_version  = ssl.TLSVersion.TLSv1_2

        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind((SERVER_HOST, TCP_PORT))
        raw.listen(50)

        self._tls_server = ctx.wrap_socket(raw, server_side=True)
        log.info(f"TLS server listening on {SERVER_HOST}:{TCP_PORT}")

    # ── Helpers ───────────────────────────────────────────────────────────

    def _next_seq(self) -> int:
        with self._seq_lock:
            self._seq += 1
            return self._seq

    def _stat(self, key: str, n: int = 1):
        with self._stats_lock:
            self._stats[key] += n

    # ── TLS control channel ───────────────────────────────────────────────

    def _accept_loop(self):
        """Main thread: accept TLS connections, hand off to per-client thread."""
        log.info("Accepting TLS connections …")
        while self._running:
            try:
                conn, addr = self._tls_server.accept()
                t = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    daemon=True,
                    name=f"TLSClient-{addr}",
                )
                t.start()
            except OSError:
                if self._running:
                    raise

    def _handle_client(self, conn: ssl.SSLSocket, addr):
        """
        Per-subscriber thread.

        Protocol (all messages are JSON terminated by newline):
          CLIENT → SERVER:  {"type":"REGISTER","subscriber_id":"...","udp_port":N,"groups":[...]}
          SERVER → CLIENT:  {"status":"OK","subscriber_id":"..."}
          CLIENT → SERVER:  {"type":"SUBSCRIBE","group_id":N}   (etc.)
        """
        sub_id = None
        try:
            # ── Registration handshake ──────────────────────────────────
            raw  = self._recv_json(conn)
            if not raw or raw.get("type") != "REGISTER":
                self._send_json(conn, {"status": "ERROR", "reason": "Expected REGISTER"})
                return

            sub_id   = raw["subscriber_id"]
            udp_port = int(raw["udp_port"])
            groups   = set(raw.get("groups", [GROUP_ALL]))
            udp_addr = (addr[0], udp_port)

            with self._subs_lock:
                self._subs[sub_id] = SubscriberInfo(
                    sub_id=sub_id, udp_addr=udp_addr, groups=groups, tls_conn=conn
                )

            log.info(f"[+] Registered  '{sub_id}'  UDP={udp_addr}  groups={groups}")
            self._send_json(conn, {"status": "OK", "subscriber_id": sub_id})

            # ── Command loop ─────────────────────────────────────────────
            conn.settimeout(90.0)
            while self._running:
                try:
                    msg = self._recv_json(conn)
                    if msg is None:
                        break
                    self._process_command(sub_id, msg, conn)
                except socket.timeout:
                    self._send_json(conn, {"type": "KEEPALIVE"})
                except (ConnectionResetError, BrokenPipeError):
                    break

        except Exception as exc:
            log.warning(f"Client handler error ({addr}): {exc}")
        finally:
            if sub_id:
                with self._subs_lock:
                    if sub_id in self._subs:
                        self._subs[sub_id].active = False
                        del self._subs[sub_id]
                log.info(f"[-] Disconnected '{sub_id}'")
            try:
                conn.close()
            except Exception:
                pass

    def _process_command(self, sub_id: str, msg: dict, conn: ssl.SSLSocket):
        """Handle SUBSCRIBE / UNSUBSCRIBE / LIST_GROUPS / KEEPALIVE commands."""
        cmd = msg.get("type", "")
        with self._subs_lock:
            sub = self._subs.get(sub_id)
            if sub is None:
                return

            if cmd == "SUBSCRIBE":
                gid = int(msg["group_id"])
                sub.groups.add(gid)
                log.info(f"  '{sub_id}' subscribed   → group {gid:#06x}")
                self._send_json(conn, {"status": "OK", "action": "SUBSCRIBED", "group_id": gid})

            elif cmd == "UNSUBSCRIBE":
                gid = int(msg["group_id"])
                sub.groups.discard(gid)
                log.info(f"  '{sub_id}' unsubscribed → group {gid:#06x}")
                self._send_json(conn, {"status": "OK", "action": "UNSUBSCRIBED", "group_id": gid})

            elif cmd == "LIST_GROUPS":
                self._send_json(conn, {"status": "OK", "groups": sorted(sub.groups)})

            elif cmd == "KEEPALIVE":
                sub.last_seen = time.time()
                self._send_json(conn, {"status": "OK"})

            else:
                self._send_json(conn, {"status": "ERROR", "reason": f"Unknown command: {cmd}"})

    # ── UDP delivery ──────────────────────────────────────────────────────

    def send_notification(self, message: str, group_id: int = GROUP_ALL,
                          reliable: bool = True) -> int:
        """
        Broadcast a notification to all subscribers in *group_id*.

        reliable=True  → PKT_NOTIFY, tracked in pending table, retransmitted on timeout
        reliable=False → PKT_BEST_EFFORT, fire-and-forget
        Returns the sequence number assigned.
        """
        seq      = self._next_seq()
        pkt_type = PKT_NOTIFY if reliable else PKT_BEST_EFFORT
        pkt      = Packet(pkt_type, seq, group_id, message)

        with self._subs_lock:
            targets = [
                s for s in self._subs.values()
                if s.active and s.in_group(group_id)
            ]

        if not targets:
            log.warning("No active subscribers in group — notification not sent.")
            return seq

        log.info(
            f"[NOTIFY] seq={seq} group={group_id:#06x} "
            f"{'reliable' if reliable else 'best-effort'} → {len(targets)} subscriber(s)"
        )

        raw = pkt.pack()
        for sub in targets:
            self._udp.sendto(raw, sub.udp_addr)
            self._stat("sent")

            if reliable:
                entry = PendingEntry(
                    packet=pkt, sub_id=sub.sub_id, udp_addr=sub.udp_addr,
                    attempts=1, last_sent=time.time(),
                )
                with self._pending_lock:
                    self._pending[(seq, sub.sub_id)] = entry

        return seq

    # ── UDP receiver (ACK / NACK) ─────────────────────────────────────────

    def _udp_receiver(self):
        """Receive ACK and NACK datagrams from subscribers."""
        self._udp.settimeout(1.0)
        log.info("UDP receiver started.")
        while self._running:
            try:
                data, addr = self._udp.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            pkt = Packet.unpack(data)
            if pkt is None:
                log.debug(f"Malformed packet from {addr} — discarded.")
                continue

            if pkt.pkt_type == PKT_ACK:
                self._on_ack(pkt)
            elif pkt.pkt_type == PKT_NACK:
                self._on_nack(pkt)

    def _on_ack(self, pkt: Packet):
        sub_id = pkt.text.strip()
        key    = (pkt.seq_no, sub_id)
        with self._pending_lock:
            if key in self._pending:
                del self._pending[key]
                self._stat("acks_received")
                log.debug(f"ACK  seq={pkt.seq_no} from '{sub_id}'")

    def _on_nack(self, pkt: Packet):
        """Subscriber explicitly requested retransmission."""
        sub_id = pkt.text.strip()
        key    = (pkt.seq_no, sub_id)
        with self._pending_lock:
            entry = self._pending.get(key)
            if entry:
                log.info(f"NACK seq={pkt.seq_no} from '{sub_id}' — retransmitting immediately")
                self._udp.sendto(entry.packet.pack(), entry.udp_addr)
                entry.last_sent = time.time()
                entry.attempts += 1
                self._stat("retransmissions")

    # ── Retransmission loop ───────────────────────────────────────────────

    def _retransmission_loop(self):
        """
        Scans the pending table every 100 ms.
        Re-sends un-ACKed packets whose RETRANSMIT_INTERVAL has expired.
        Drops entries that have exceeded MAX_RETRANSMISSIONS.
        """
        log.info("Retransmission loop started.")
        while self._running:
            now     = time.time()
            expired = []

            with self._pending_lock:
                for key, entry in list(self._pending.items()):
                    if entry.acked:
                        expired.append(key)
                        continue

                    if now - entry.last_sent < RETRANSMIT_INTERVAL:
                        continue

                    if entry.attempts >= MAX_RETRANSMISSIONS:
                        log.warning(
                            f"DROPPED seq={entry.packet.seq_no} to '{entry.sub_id}' "
                            f"after {entry.attempts} attempts"
                        )
                        self._stat("dropped")
                        expired.append(key)
                    else:
                        log.info(
                            f"RETRANSMIT seq={entry.packet.seq_no} → '{entry.sub_id}' "
                            f"(attempt {entry.attempts + 1}/{MAX_RETRANSMISSIONS})"
                        )
                        self._udp.sendto(entry.packet.pack(), entry.udp_addr)
                        entry.last_sent = now
                        entry.attempts += 1
                        self._stat("retransmissions")

                for key in expired:
                    self._pending.pop(key, None)

            time.sleep(0.1)

    # ── Stats printer ─────────────────────────────────────────────────────

    def _stats_printer(self):
        while self._running:
            time.sleep(15)
            with self._stats_lock:
                s = dict(self._stats)
            with self._subs_lock:
                n = len(self._subs)
            log.info(f"[STATS] subscribers={n} | {s}")

    # ── Start / stop ──────────────────────────────────────────────────────

    def start(self):
        self._running = True

        for target, name in [
            (self._accept_loop,       "TLSAccept"),
            (self._udp_receiver,      "UDPReceiver"),
            (self._retransmission_loop,"Retransmitter"),
            (self._stats_printer,     "StatsPrinter"),
        ]:
            threading.Thread(target=target, name=name, daemon=True).start()

        log.info("Server ready.")
        try:
            self._cli()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        log.info("Shutting down …")
        self._running = False
        try:
            self._udp.close()
        except Exception:
            pass
        try:
            self._tls_server.close()
        except Exception:
            pass

    # ── Interactive CLI ───────────────────────────────────────────────────

    def _cli(self):
        print("\n" + "═" * 58)
        print("  Reliable Group Notification Server — Operator CLI")
        print("═" * 58)
        print("  send   <group> <message>   reliable notification")
        print("  blast  <group> <message>   best-effort (no ACK)")
        print("  stats                       show counters")
        print("  subs                        list subscribers")
        print("  groups  — group names: all, alerts, updates, critical")
        print("  quit")
        print("═" * 58 + "\n")

        while self._running:
            try:
                line = input("server> ").strip()
            except EOFError:
                break

            if not line:
                continue
            parts = line.split(None, 2)
            cmd   = parts[0].lower()

            if cmd == "quit":
                break

            elif cmd == "stats":
                with self._stats_lock:
                    print("  Counters:", self._stats)
                with self._pending_lock:
                    print(f"  Pending ACKs: {len(self._pending)}")

            elif cmd == "subs":
                with self._subs_lock:
                    if not self._subs:
                        print("  (no subscribers)")
                    for s in self._subs.values():
                        print(f"  {s.sub_id:<20} UDP={s.udp_addr}  groups={sorted(s.groups)}")

            elif cmd in ("send", "blast") and len(parts) == 3:
                group_id = GROUP_NAMES.get(parts[1].lower(), GROUP_ALL)
                message  = parts[2]
                reliable = (cmd == "send")
                seq      = self.send_notification(message, group_id, reliable)
                mode     = "reliable" if reliable else "best-effort"
                print(f"  Sent seq={seq} ({mode}) to group '{parts[1]}'")

            else:
                print("  Unknown command — try: send all Hello World")

    # ── JSON helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _send_json(conn: ssl.SSLSocket, obj: dict):
        try:
            conn.sendall((json.dumps(obj) + "\n").encode())
        except Exception:
            pass

    @staticmethod
    def _recv_json(conn: ssl.SSLSocket) -> dict | None:
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return None
            buf += chunk
        try:
            return json.loads(buf.split(b"\n")[0].decode())
        except json.JSONDecodeError:
            return None


# ── Entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    srv = ReliableGroupNotificationServer()
    srv.start()