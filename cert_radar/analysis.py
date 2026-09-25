"""Certificate analysis: parsing, trust chain, hostname match, weak crypto.

Chain trust (TZ 3.4 "chain state", 3.6) is checked in two steps:
  1. structural: build leaf -> intermediates -> root path and verify each
     signature with `verify_directly_issued_by` (cryptography >= 40);
  2. trust: the top of the chain must be present in the OS trust store
     (ssl.create_default_context().get_ca_certs(binary_form=True)), which on
     Windows/Linux/macOS reflects the system root CA store.
Validity dates are deliberately NOT part of chain verification: an expired
certificate with a valid chain is reported through `days_left`/status, not as
a broken chain.
"""
from __future__ import annotations

import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import oid as xoid

from .models import CertInfo
from .tls_client import thumbprint

WEAK_KEY_SIZES = {"RSA": 2048, "DSA": 2048, "EC": 256}
WEAK_SIGNATURES = ("md5", "sha1")

_trust_store_cache: set[bytes] | None = None


def parse_cert(cert: x509.Certificate) -> CertInfo:
    """Extract all attributes required by TZ 3.4."""
    info = CertInfo()

    def cn(name) -> str | None:  # noqa: ANN001
        attrs = name.get_attributes_for_oid(xoid.NameOID.COMMON_NAME)
        return attrs[0].value if attrs else None

    info.subject_cn = cn(cert.subject)
    info.issuer_cn = cn(cert.issuer)
    info.issuer = cert.issuer.rfc4514_string()
    info.thumbprint_sha256 = thumbprint(cert)
    info.serial = format(cert.serial_number, "x").upper()

    try:
        info.not_before = _utc(cert.not_valid_before_utc)
        info.not_after = _utc(cert.not_valid_after_utc)
    except AttributeError:  # cryptography < 42
        info.not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        info.not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    info.self_signed = cert.issuer == cert.subject

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        info.san_dns = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        info.san_dns = []

    pub = cert.public_key()
    info.key_algorithm = type(pub).__name__
    if info.key_algorithm in {"RSAPublicKey", "DSAPublicKey", "EllipticCurvePublicKey"}:
        info.key_size = pub.key_size
    info.signature_algorithm = cert.signature_algorithm_oid._name
    return info


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def days_left(cert: CertInfo, now: datetime | None = None) -> int:
    now = now or datetime.now(timezone.utc)
    return (cert.not_after - now).days


def check_hostname(cert: CertInfo | None, host: str) -> bool | None:
    """Does the service name match CN/SAN? Wildcards supported. None = no data."""
    if not cert or (not cert.san_dns and not cert.subject_cn):
        return None
    names = list(cert.san_dns) or [cert.subject_cn or ""]
    host_l = host.lower().rstrip(".")
    for name in names:
        name_l = str(name).lower().rstrip(".")
        if name_l.startswith("*."):
            # RFC 6125: a wildcard covers exactly one left-most label,
            # so the host must have the same label count as "*.domain.kz"
            suffix = name_l[1:]  # ".domain.kz"
            if host_l.endswith(suffix) and host_l.count(".") == name_l.count("."):
                return True
        elif host_l == name_l:
            return True
    return False


def build_chain(leaf: x509.Certificate,
                intermediates: list[x509.Certificate]) -> tuple[list[x509.Certificate], str | None]:
    """Walk leaf -> ... -> self-signed root verifying each signature link.

    Returns (chain, error). error is None when the chain is structurally
    complete, otherwise a human-readable reason (TZ 3.6 "chain of trust error").
    """
    chain = [leaf]
    current = leaf
    for _ in range(10):
        if current.issuer == current.subject:
            return chain, None  # reached a self-signed root
        nxt = next((c for c in intermediates if c.subject == current.issuer), None)
        if nxt is None:
            return chain, ("incomplete chain: issuer '{}' of '{}' not provided"
                           .format(_cn(current.issuer), _cn(current.subject)))
        try:
            current.verify_directly_issued_by(nxt)
        except ValueError as exc:
            return chain, f"issuer name mismatch: {exc}"
        except Exception:  # noqa: BLE001 - InvalidSignature & friends
            return chain, ("signature verification failed: '{}' was not signed by '{}'"
                           .format(_cn(current.subject), _cn(nxt.subject)))
        chain.append(nxt)
        current = nxt
    return chain, "chain too deep (>10 levels)"


def os_trust_store() -> set[bytes]:
    """DER bytes of all root CAs trusted by the OS (cached)."""
    global _trust_store_cache
    if _trust_store_cache is None:
        ctx = ssl.create_default_context()
        try:
            certs = ctx.get_ca_certs(binary_form=True)
        except TypeError:  # pragma: no cover - exotic builds
            certs = []
        _trust_store_cache = {der for der in certs if der}
    return _trust_store_cache


def verify_chain(leaf: x509.Certificate,
                 intermediates: list[x509.Certificate]) -> tuple[bool | None, str | None]:
    """Full trust decision: structural chain + root in OS store.

    Returns (ok, error); ok=True means the chain terminates in a trusted root.
    """
    try:
        chain, err = build_chain(leaf, intermediates)
        if err:
            return False, err
        store = os_trust_store()
        top = chain[-1]
        if top.public_bytes(Encoding.DER) in store:
            return True, None
        # cross-signed alternative paths: any chain element trusted as anchor
        for c in chain[:-1]:
            if c.public_bytes(Encoding.DER) in store:
                return True, None
        return False, ("root '{}' is not in the OS trust store"
                       .format(_cn(top.subject)))
    except Exception as exc:  # noqa: BLE001 - diagnostics must never crash a scan
        return None, f"chain check unavailable: {exc}"


def _cn(name) -> str:  # noqa: ANN001
    attrs = name.get_attributes_for_oid(xoid.NameOID.COMMON_NAME)
    return attrs[0].value if attrs else name.rfc4514_string()


def is_weak(cert: CertInfo) -> str | None:
    """Return a human description of weak cryptography, or None (TZ 3.2)."""
    if cert.key_size:
        base = cert.key_algorithm or ""
        if base in {"RSAPublicKey", "DSAPublicKey"} and cert.key_size < 2048:
            return f"weak key: {base.replace('PublicKey', '')} {cert.key_size} bits"
        if base == "EllipticCurvePublicKey" and cert.key_size < 256:
            return f"weak EC key: {cert.key_size} bits"
    if cert.signature_algorithm:
        sig = cert.signature_algorithm.lower()
        for weak in WEAK_SIGNATURES:
            if weak in sig:
                return f"weak signature algorithm: {cert.signature_algorithm}"
    return None
