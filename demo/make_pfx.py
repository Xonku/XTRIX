"""Generate .pfx certificate bundles ready to import into IIS (Windows Server).

Creates demo_certs/pfx/ with:
  demo_ca.crt         - demo root CA: install into "Trusted Root CAs" to make
                        the 'valid' demo show a green chain
  01_valid.pfx        - proper certificate for iis-demo.local (1 year)
  02_expiring.pfx     - expires in 10 days  -> Critical
  03_expired.pfx      - expired 5 days ago    -> Expired
  04_selfsigned.pfx   - self-signed          -> self-signed finding
  05_brokenchain.pfx  - leaf signed by an intermediate that will NOT be
                        installed -> incomplete chain
  06_mismatch.pfx     - certificate for other-name.local -> DNS mismatch

All .pfx passwords: demo

Run:  python -m demo.make_pfx
Copy the whole demo_certs/pfx folder to the VM (e.g. C:\\Certs) and follow
iis_setup.txt (or just run demo/iis_setup.ps1 on the VM).
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption
from cryptography.x509.oid import NameOID

OUT_DIR = Path(__file__).parent.parent / "demo_certs" / "pfx"
PFX_PASSWORD = b"demo"
MAIN_NAME = "iis-demo.local"


def _name(cn: str, org: str = "Certificate Radar Demo") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
    ])


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _cert(cn: str, days: int, issuer_key, issuer_name: x509.Name,
          san: list[str] | None = None, ca: bool = False):
    key = _key()
    now = dt.datetime.now(dt.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(_name(cn))
               .issuer_name(issuer_name)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - dt.timedelta(days=max(2, abs(days) + 2)))
               .not_valid_after(now + dt.timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None),
                              critical=True))
    if not ca:
        names = san if san is not None else [cn]
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
    return key, builder.sign(issuer_key, hashes.SHA256())


def _pfx(path: Path, name: str, key, cert, cas: list) -> None:
    data = pkcs12.serialize_key_and_certificates(
        name=name.encode(), key=key, cert=cert, cas=cas,
        encryption_algorithm=BestAvailableEncryption(PFX_PASSWORD))
    path.write_bytes(data)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)

    # --- demo root CA ---
    ca_key = _key()
    ca_cert = (x509.CertificateBuilder()
               .subject_name(_name("Certificate Radar Demo CA"))
               .issuer_name(_name("Certificate Radar Demo CA"))
               .public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - dt.timedelta(days=2))
               .not_valid_after(now + dt.timedelta(days=3650))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .sign(ca_key, hashes.SHA256()))
    (OUT_DIR / "demo_ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    # --- intermediate CA for the broken-chain demo (NOT distributed) ---
    inter_key, inter_cert = _cert("Demo Intermediate CA", 1825, ca_key, ca_cert.subject, ca=True)

    def leaf(cn: str, days: int, ik=None, iname=None, san=None):
        return _cert(cn, days, ik or ca_key, iname or ca_cert.subject, san=san)

    def save(pfx_name: str, key, cert, cas: list) -> None:
        _pfx(OUT_DIR / pfx_name, pfx_name, key, cert, cas)
        print(f"  + {pfx_name:22} (CN={cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value})")

    print(f"Writing certificates to {OUT_DIR}\n")

    key, cert = leaf(MAIN_NAME, 365)
    save("01_valid.pfx", key, cert, [ca_cert])

    key, cert = leaf(MAIN_NAME, 10)
    save("02_expiring.pfx", key, cert, [ca_cert])

    key, cert = leaf(MAIN_NAME, -5)
    save("03_expired.pfx", key, cert, [ca_cert])

    # self-signed: issuer == subject, signed with own key
    key = _key()
    self_cert = (x509.CertificateBuilder()
                 .subject_name(_name(MAIN_NAME))
                 .issuer_name(_name(MAIN_NAME))
                 .public_key(key.public_key())
                 .serial_number(x509.random_serial_number())
                 .not_valid_before(now - dt.timedelta(days=2))
                 .not_valid_after(now + dt.timedelta(days=365))
                 .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                 .add_extension(x509.SubjectAlternativeName([x509.DNSName(MAIN_NAME)]),
                                critical=False)
                 .sign(key, hashes.SHA256()))
    save("04_selfsigned.pfx", key, self_cert, [])

    # broken chain: signed by intermediate, intermediate is NOT in the pfx
    key, cert = _cert(MAIN_NAME, 365, inter_key, inter_cert.subject)
    save("05_brokenchain.pfx", key, cert, [])

    key, cert = leaf("other-name.local", 365)
    save("06_mismatch.pfx", key, cert, [ca_cert])

    print(f"""
Ready. PFX password for all files: demo
Next steps:
  1) Copy this folder ({OUT_DIR}) to the VM, e.g. to C:\\Certs
  2) Copy demo/iis_setup.ps1 to the VM too
  3) On the VM (PowerShell as Administrator):  powershell -ExecutionPolicy Bypass -File C:\\Certs\\iis_setup.ps1
  4) Read iis_setup.txt for the manual (GUI) way and network setup
""")


if __name__ == "__main__":
    main()
