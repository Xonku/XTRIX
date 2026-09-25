"""Async TLS probe: connects to a service and downloads the presented certificate.

The connection intentionally does NOT verify the chain here (we want to see the
certificate even if it is expired or self-signed). Trust analysis is done
separately in `analysis.py` with full chain retrieval (unverified) so that we
can report exact chain problems instead of a bare ssl error.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

log = logging.getLogger("cert_radar.tls")


async def resolve_ip(host: str) -> str | None:
    """Best-effort IPv4 resolution (None on failure)."""

    def _resolve() -> str | None:
        try:
            infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
            return infos[0][4][0] if infos else None
        except OSError:
            return None

    return await asyncio.to_thread(_resolve)


async def fetch_cert(host: str, port: int, timeout: float = 5.0
                     ) -> tuple[x509.Certificate | None, str | None]:
    """Connect to host:port, return (leaf certificate, error).

    Exactly one of the two is not None.
    """
    loop = asyncio.get_running_loop()

    def _do_tls() -> x509.Certificate:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # deliberate: we must see bad certs too
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                if not der:
                    raise ConnectionError("no certificate presented")
                return x509.load_der_x509_certificate(der)

    try:
        cert = await asyncio.wait_for(loop.run_in_executor(None, _do_tls), timeout=timeout + 2)
        return cert, None
    except asyncio.TimeoutError:
        return None, f"timeout after {timeout:.0f}s"
    except (ConnectionRefusedError, TimeoutError):
        return None, "connection refused or timed out"
    except socket.gaierror as exc:
        return None, f"DNS resolution failed: {exc.reason or exc}"
    except (ssl.SSLError, OSError, ConnectionError) as exc:
        return None, _friendly_error(exc)


def _friendly_error(exc: Exception) -> str:
    text = str(exc).strip()
    lowered = text.lower()
    if "certificate" in lowered and ("expired" in lowered or "not yet valid" in lowered):
        return "TLS handshake rejected by client (certificate validity problem)"
    if "handshake failure" in lowered:
        return "TLS handshake failure (no common protocol/cipher or non-TLS service)"
    if "connection reset" in lowered or "eof" in lowered:
        return "connection reset during handshake (service is not TLS on this port?)"
    return text or exc.__class__.__name__


async def fetch_chain_unverified(host: str, port: int, timeout: float = 5.0
                                 ) -> list[x509.Certificate]:
    """Return the full chain as sent by the server (order: leaf -> root).

    Used for chain diagnostics: we can pinpoint which issuer is missing.
    """
    loop = asyncio.get_running_loop()

    def _do_tls() -> list[x509.Certificate]:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        chain: list[x509.Certificate] = []

        def sn_cb(sock, addr, _ctx):
            sock.getpeercert(True) and chain.append(
                x509.load_der_x509_certificate(sock.getpeercert(True)))
            return True

        ctx.set_servername_callback(sn_cb)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                peers = sock.getpeercert(chain=True) or ()
                for der in peers:
                    try:
                        chain.append(x509.load_der_x509_certificate(der))
                    except Exception:  # noqa: BLE001 - skip malformed chain item
                        log.debug("Skipping unparsable chain element")
        return chain

    try:
        return await asyncio.wait_for(loop.run_in_executor(None, _do_tls), timeout=timeout + 2)
    except Exception:  # noqa: BLE001 - diagnostics only, never fatal
        return []


def thumbprint(cert: x509.Certificate) -> str:
    """SHA-256 thumbprint, uppercase hex without separators."""
    return cert.fingerprint(hashes.SHA256()).hex(":").upper()


def to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()
