"""
generate_certs.py – Generate all TLS certificates for the project.
==================================================================

Creates:
  certs/ca.crt      — Self-signed Certificate Authority
  certs/ca.key      — CA private key
  certs/server.crt  — Server certificate (signed by CA)
  certs/server.key  — Server private key
  certs/client.crt  — Client certificate (signed by CA, used by subscribers)
  certs/client.key  — Client private key

Run once before starting server or subscribers:
  python generate_certs.py

Requires:  pip install cryptography
"""

import datetime
import ipaddress
import os
import sys

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    sys.exit(
        "[ERROR] 'cryptography' package not found.\n"
        "Install it with:  pip install cryptography\n"
    )


CERTS_DIR   = "certs"
VALIDITY    = datetime.timedelta(days=3650)   # 10 years — plenty for a project
KEY_SIZE    = 2048
NOW         = datetime.datetime.utcnow()


# ── Helpers ────────────────────────────────────────────────────────────────

def _gen_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)


def _save_key(path: str, key: rsa.RSAPrivateKey):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    print(f"  Saved key  → {path}")


def _save_cert(path: str, cert: x509.Certificate):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  Saved cert → {path}")


# ── Certificate generators ────────────────────────────────────────────────

def generate_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Create a self-signed CA certificate."""
    key  = _gen_key()
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,         "GroupNotify-CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,   "GroupNotify"),
        x509.NameAttribute(NameOID.COUNTRY_NAME,        "IN"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)                     # self-signed
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW)
        .not_valid_after(NOW + VALIDITY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def generate_leaf(
    cn: str,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    is_server: bool = True,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """
    Create a leaf certificate signed by the CA.
    For the server cert we add SAN for localhost/127.0.0.1 so Python's
    hostname-verification passes when connecting to 127.0.0.1.
    """
    key  = _gen_key()
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,       cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GroupNotify"),
        x509.NameAttribute(NameOID.COUNTRY_NAME,      "IN"),
    ])

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW)
        .not_valid_after(NOW + VALIDITY)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )

    # Extended Key Usage
    if is_server:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        # Subject Alternative Names — required for Python's hostname check
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
    else:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )

    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    os.makedirs(CERTS_DIR, exist_ok=True)
    print(f"\nGenerating TLS certificates in ./{CERTS_DIR}/\n")

    print("1/3  Certificate Authority …")
    ca_key, ca_cert = generate_ca()
    _save_key(f"{CERTS_DIR}/ca.key",   ca_key)
    _save_cert(f"{CERTS_DIR}/ca.crt",  ca_cert)

    print("\n2/3  Server certificate …")
    srv_key, srv_cert = generate_leaf("localhost", ca_key, ca_cert, is_server=True)
    _save_key(f"{CERTS_DIR}/server.key",  srv_key)
    _save_cert(f"{CERTS_DIR}/server.crt", srv_cert)

    print("\n3/3  Client certificate (for subscribers) …")
    cli_key, cli_cert = generate_leaf("subscriber", ca_key, ca_cert, is_server=False)
    _save_key(f"{CERTS_DIR}/client.key",  cli_key)
    _save_cert(f"{CERTS_DIR}/client.crt", cli_cert)

    print(f"\n✓  All certificates generated in ./{CERTS_DIR}/")
    print("  (CA key certs/ca.key is sensitive — do not share it)\n")


if __name__ == "__main__":
    main()
