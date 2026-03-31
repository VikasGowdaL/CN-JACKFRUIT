# Reliable Group Notification System

A **UDP-based group notification system** that delivers alerts to multiple subscribers with **acknowledgement, retransmission, and timeout**, secured over a **TLS/TCP control channel**.

---

## Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│                            SERVER                                     │
│                                                                       │
│  ┌──────────────────────────────┐  ┌──────────────────────────────┐  │
│  │    TLS/TCP Control Channel   │  │     UDP Data Channel          │  │
│  │         Port 9000            │  │         Port 9001             │  │
│  │                              │  │                               │  │
│  │  • Subscriber registration   │  │  • Notification delivery      │  │
│  │  • Group management          │  │  • ACK / NACK reception       │  │
│  │  • Keepalive                 │  │  • Retransmission engine       │  │
│  └──────────────────────────────┘  └──────────────────────────────┘  │
└────────┬───────────────────────────────────────┬──────────────────────┘
         │ TLS (mutual auth)                     │ UDP
         ▼                                       ▼
┌─────────────────┐                    ┌─────────────────┐
│  Subscriber A   │                    │  Subscriber B   │
│  (alice)        │                    │  (bob, 30% loss)│
│                 │                    │                 │
│  Groups:        │                    │  Groups:        │
│  • all          │                    │  • alerts       │
│  • alerts       │                    │  • critical     │
└─────────────────┘                    └─────────────────┘
```

### Packet Wire Format (15-byte header)

```
┌──────────┬──────┬────────────┬──────────┬─────────────┬──────────┬──────────────────┐
│  Magic   │ Type │  Seq No    │ Group ID │ Payload Len │ Checksum │     Payload      │
│  2 bytes │ 1 B  │  4 bytes   │  2 bytes │   2 bytes   │  4 bytes │  variable length │
└──────────┴──────┴────────────┴──────────┴─────────────┴──────────┴──────────────────┘
```

- **Magic**: `0xABCD` — every valid packet starts with these bytes  
- **Seq No**: monotonically increasing, used for deduplication and ACK matching  
- **Checksum**: CRC-32 over (type + seq + group + payload) — detects corruption  
- **Types**: `PKT_NOTIFY (0x01)`, `PKT_ACK (0x02)`, `PKT_NACK (0x03)`, `PKT_BEST_EFFORT (0x05)`

---

## Project Files

| File | Purpose |
|------|---------|
| `config.py` | All constants (ports, timeouts, group IDs, packet types) |
| `packet.py` | Custom packet format — pack / unpack / CRC-32 |
| `server.py` | Main server: TLS accept loop, UDP receiver, retransmission engine |
| `subscriber.py` | Subscriber: TLS registration + UDP listener + ACK sender |
| `performance_test.py` | Automated best-effort vs reliable comparison (standalone) |
| `generate_certs.py` | Generates CA + server + client TLS certificates |

---

## Setup

### 1. Install dependencies

```bash
pip install cryptography
```

Standard library only for the main code (`socket`, `ssl`, `threading`, `json`).

### 2. Generate TLS certificates

```bash
python generate_certs.py
```

This creates `certs/` with:
- `ca.crt` — Certificate Authority (trusted by both sides)
- `server.crt` / `server.key` — Server identity
- `client.crt` / `client.key` — Subscriber identity (mutual TLS)

---

## Running the System

### Terminal 1 — Start the server

```bash
python server.py
```

### Terminal 2 — Start subscriber alice (no loss)

```bash
python subscriber.py alice --groups all,alerts
```

### Terminal 3 — Start subscriber bob (30% simulated loss)

```bash
python subscriber.py bob --loss 0.3 --groups alerts,critical
```

### Terminal 4 — Start subscriber carol (50% loss, for stress testing)

```bash
python subscriber.py carol --loss 0.5 --groups all
```

---

## Server Commands

Once the server is running, type commands at the `server>` prompt:

| Command | Description |
|---------|-------------|
| `send all Hello World` | Reliable notification → all subscribers |
| `send alerts FIRE ALERT` | Reliable → only `alerts` group |
| `blast all Quick update` | Best-effort → all (no ACK expected) |
| `stats` | Show sent / ACKed / retransmitted / dropped counters |
| `subs` | List all active subscribers and their groups |
| `quit` | Shutdown the server |

**Groups**: `all`, `alerts`, `updates`, `critical`

---

## Subscriber Commands

At the `<sub_id>>` prompt:

| Command | Description |
|---------|-------------|
| `sub alerts` | Subscribe to the `alerts` group |
| `unsub updates` | Unsubscribe from `updates` |
| `stats` | Show local delivery / ACK counters |
| `quit` | Disconnect |

---

## Performance Test (Standalone)

Runs a self-contained test — does **not** require `server.py`:

```bash
# Default: 100 msgs, 5 subscribers, 30% loss
python performance_test.py

# Custom parameters
python performance_test.py --msgs 200 --subs 10 --loss 0.4
```

**Sample output:**

```
══════════════════════════════════════════════════════════════════
  Performance Test
  Messages per run : 100
  Subscribers      : 5
  Simulated loss   : 30%
  Payload size     : 64 bytes
══════════════════════════════════════════════════════════════════

[1/2] Best-Effort UDP — sending …
  ── Best-Effort UDP ──
    sub-0        delivered=70/100 (70.0%)  avg=2.45ms  med=2.31ms  tput=28571 pkt/s
    sub-1        delivered=71/100 (71.0%)  avg=2.51ms  med=2.40ms  tput=28333 pkt/s

[2/2] Reliable UDP — sending + waiting for ACKs …
  ── Reliable UDP (ACK + retransmission) ──
    sub-0        delivered=100/100 (100.0%)  avg=412.3ms  med=3.2ms  tput=243 pkt/s
    sub-1        delivered=100/100 (100.0%)  avg=398.1ms  med=3.1ms  tput=251 pkt/s

SUMMARY
  Retransmissions (reliable): 87
  Trade-off: reliability vs. latency/bandwidth overhead.
```

---

## Rubric Coverage

| Component | How it's met |
|-----------|-------------|
| **Problem Definition & Architecture** | UDP data channel + TLS control channel; custom protocol design; group membership |
| **Core Implementation** | Raw `socket` + `ssl` stdlib; explicit `bind`, `listen`, `accept`, `recvfrom`, `sendto`; no high-level frameworks |
| **Deliverable 1 — Features** | Seq numbers, ACK/NACK, retransmission, group management, TLS mutual auth, multiple concurrent clients |
| **Performance Evaluation** | `performance_test.py` — delivery rate, latency (avg/median/p99), throughput, overhead ratio |
| **Optimization & Fixes** | CRC-32 corruption detection; duplicate deduplication; exponential reconnect back-off; NACK for immediate retransmit; edge-case handling (abrupt disconnect, SSL failure, malformed packets) |
| **Final Demo / GitHub** | All source on GitHub; README with setup steps, architecture diagram, usage |

---

## Security

- **Mutual TLS (mTLS)**: both server and subscriber present certificates signed by the shared CA
- **TLS 1.2 minimum**: enforced via `ctx.minimum_version = ssl.TLSVersion.TLSv1_2`
- **CRC-32 checksum**: every UDP packet verified; corrupt packets silently dropped
- Control plane (group commands, registration) is fully encrypted over TLS/TCP
- Data plane (notifications) is unencrypted UDP — acceptable because payload is non-sensitive notification content; add DTLS for production

---

## Extending the Project

- **Add DTLS** (`dtls` Python package) to encrypt the UDP channel as well
- **Multicast** — change `udp_addr` to a multicast group to reduce server fan-out
- **Persistence** — store pending notifications in SQLite so the server survives crashes
- **Web dashboard** — Flask endpoint to call `send_notification()` via HTTP
