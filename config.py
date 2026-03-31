"""
config.py – Central configuration for the Reliable Group Notification System.

All tuneable parameters live here so nothing is scattered across files.
"""

# ── Network ────────────────────────────────────────────────────────────────
SERVER_HOST = "127.0.0.1"
TCP_PORT    = 9000          # TLS/TCP control channel  (registration, commands)
UDP_PORT    = 9001          # UDP data channel          (notifications + ACKs)

# ── TLS Certificates ──────────────────────────────────────────────────────
CA_FILE     = "certs/ca.crt"
SERVER_CERT = "certs/server.crt"
SERVER_KEY  = "certs/server.key"
CLIENT_CERT = "certs/client.crt"
CLIENT_KEY  = "certs/client.key"

# ── Reliability parameters ────────────────────────────────────────────────
MAX_RETRANSMISSIONS = 5     # give up after this many attempts
RETRANSMIT_INTERVAL = 1.0   # seconds between retry attempts
ACK_TIMEOUT         = 2.0   # seconds before first retry

# ── Packet magic & types ──────────────────────────────────────────────────
MAGIC_BYTES     = b"\xAB\xCD"   # every valid packet starts with these 2 bytes

PKT_NOTIFY      = 0x01   # reliable notification  → subscriber must ACK
PKT_ACK         = 0x02   # acknowledgement        → from subscriber to server
PKT_NACK        = 0x03   # negative-ACK / request retransmit
PKT_HEARTBEAT   = 0x04   # keepalive probe
PKT_BEST_EFFORT = 0x05   # fire-and-forget        → no ACK expected

# ── Group IDs ─────────────────────────────────────────────────────────────
GROUP_ALL      = 0x0000   # broadcast to every subscriber
GROUP_ALERTS   = 0x0001   # high-priority alerts
GROUP_UPDATES  = 0x0002   # informational updates
GROUP_CRITICAL = 0x0003   # critical / emergency messages

# Human-readable names (used in CLI prompts)
GROUP_NAMES = {
    "all":      GROUP_ALL,
    "alerts":   GROUP_ALERTS,
    "updates":  GROUP_UPDATES,
    "critical": GROUP_CRITICAL,
}
