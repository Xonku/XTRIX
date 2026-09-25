"""Standalone demo target generator for the hackathon presentation.

Creates six HTTPS services on ports 8443..8448+ with certificates covering
every state required by the demo scenario (TZ 5.2):

  8443  valid certificate (well-known CA not possible offline -> uses a local
        demo CA that is trusted only if you install demo_certs/demo_ca.crt)
  8444  expiring soon (short validity)
  8445  expired certificate
  8446  self-signed certificate
  8447  broken chain (leaf signed by an intermediate whose CA is missing)
  8448  hostname mismatch (certificate for other-name.local)

All services listen on 127.0.0.1 and use the name "localhost", which resolves
on every OS without touching the hosts file.
"""
from __future__ import annotations

import datetime as dt
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERT_DIR = Path(__file__).parent.parent / "demo_certs"
PORTS = {
    8443: ("valid", 365),
    8444: ("expiring", 10),     # expires in 10 days -> Critical
    8445: ("expired", -5),      # expired 5 days ago
    8446: ("selfsigned", 200),
    8447: ("brokenchain", 300),
    8448: ("mismatch", 400),    # CN = other-name.local
}
HOST = "127.0.0.1"


def _name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Certificate Radar Demo"),
    ])


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _cert(cn: str, days: int, issuer_key=None, issuer_name: x509.Name | None = None,
          san: list[str] | None = None) -> tuple[object, bytes]:
    key = _key()
    ik = issuer_key or key
    iname = issuer_name or _name(cn)
    now = dt.datetime.now(dt.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(_name(cn))
               .issuer_name(iname)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - dt.timedelta(days=max(2, abs(days) + 2)))
               .not_valid_after(now + dt.timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True))
    names = san if san is not None else [cn]
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
    cert = builder.sign(ik, hashes.SHA256())
    return key, cert.public_bytes(serialization.Encoding.PEM)


def generate_all() -> dict[int, Path]:
    """Write demo certificates to demo_certs/ and return port -> pem path."""
    CERT_DIR.mkdir(exist_ok=True)
    paths: dict[int, Path] = {}

    ca_key, ca_cert = None, None
    ca_key = _key()
    now = dt.datetime.now(dt.timezone.utc)
    ca_cert = (x509.CertificateBuilder()
               .subject_name(_name("Certificate Radar Demo CA"))
               .issuer_name(_name("Certificate Radar Demo CA"))
               .public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - dt.timedelta(days=1))
               .not_valid_after(now + dt.timedelta(days=3650))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .sign(ca_key, hashes.SHA256()))
    (CERT_DIR / "demo_ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)

    inter_key, inter_cert = None, None
    inter_key = _key()
    inter_cert = (x509.CertificateBuilder()
                  .subject_name(_name("Demo Intermediate CA"))
                  .issuer_name(ca_cert.subject)
                  .public_key(inter_key.public_key())
                  .serial_number(x509.random_serial_number())
                  .not_valid_before(now - dt.timedelta(days=1))
                  .not_valid_after(now + dt.timedelta(days=1825))
                  .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                  .sign(ca_key, hashes.SHA256()))
    inter_pem = inter_cert.public_bytes(serialization.Encoding.PEM)

    for port, (kind, days) in PORTS.items():
        if kind == "valid":
            key, leaf = _cert("localhost", days, ca_key, ca_cert.subject)
            pem = leaf + ca_pem
        elif kind == "expiring":
            key, leaf = _cert("localhost", days, ca_key, ca_cert.subject)
            pem = leaf + ca_pem
        elif kind == "expired":
            key, leaf = _cert("localhost", days, ca_key, ca_cert.subject)
            pem = leaf + ca_pem
        elif kind == "selfsigned":
            key, leaf = _cert("localhost", days)
            pem = leaf
        elif kind == "brokenchain":
            # leaf signed by intermediate, but intermediate is NOT served
            key, leaf = _cert("localhost", days, inter_key, inter_cert.subject)
            pem = leaf  # chain deliberately incomplete
        else:  # mismatch
            key, leaf = _cert("other-name.local", days, ca_key, ca_cert.subject,
                              san=["other-name.local"])
            pem = leaf + ca_pem

        out = CERT_DIR / f"{kind}.pem"
        out.write_bytes(pem + key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        paths[port] = out
    print(f"[demo] certificates written to {CERT_DIR}")
    print(f"[demo] optional: install {CERT_DIR / 'demo_ca.crt'} into OS trust store "
          f"so 'valid' demo shows a trusted chain")
    return paths


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"Certificate Radar demo service"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence
        pass


def serve(port: int, pem: Path) -> None:
    httpd = ThreadingHTTPServer((HOST, port), _Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pem)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"[demo] https://{HOST}:{port}  ({pem.stem})")
    httpd.serve_forever()


def main() -> None:
    paths = generate_all()
    threads = []
    for port, pem in paths.items():
        t = threading.Thread(target=serve, args=(port, pem), daemon=True)
        t.start()
        threads.append(t)
    print("[demo] all services running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\n[demo] stopped")


if __name__ == "__main__":
    main()
