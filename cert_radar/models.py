"""Domain models for scan results."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class CertInfo:
    """Parsed X.509 certificate as presented by a TLS service."""
    subject_cn: str | None = None
    san_dns: list[str] = field(default_factory=list)
    issuer: str | None = None
    issuer_cn: str | None = None
    thumbprint_sha256: str | None = None
    serial: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    self_signed: bool = False
    key_algorithm: str | None = None
    key_size: int | None = None
    signature_algorithm: str | None = None

    def to_dict(self) -> dict:
        return {
            "subject_cn": self.subject_cn,
            "san_dns": self.san_dns,
            "issuer": self.issuer,
            "issuer_cn": self.issuer_cn,
            "thumbprint_sha256": self.thumbprint_sha256,
            "serial": self.serial,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "self_signed": self.self_signed,
            "key_algorithm": self.key_algorithm,
            "key_size": self.key_size,
            "signature_algorithm": self.signature_algorithm,
        }


@dataclass
class Finding:
    """A single detected problem (TZ 3.6) with human reasons."""
    code: str            # e.g. "EXPIRED", "SELF_SIGNED", "HOSTNAME_MISMATCH"
    severity: str        # Critical | High | Medium | Low | Info
    message: str         # human readable explanation
    recommendation: str  # suggested action (TZ 2.6 style)


@dataclass
class ScanResult:
    """Full result of scanning one service endpoint."""
    host: str
    port: int
    ip: str | None = None
    reachable: bool = False
    error: str | None = None
    cert: CertInfo | None = None
    days_left: int | None = None
    status: str = "Unknown"          # OK | Information | Warning | Critical | Expired
    risk_score: int = 0              # 0..100
    risk_level: str = "Low"          # Low | Medium | High | Critical
    chain_valid: bool | None = None
    chain_error: str | None = None
    hostname_matches: bool | None = None
    criticality: str = "normal"      # normal | critical (per-service tag)
    owner: str = ""                  # responsible person / team
    findings: list[Finding] = field(default_factory=list)
    scanned_at: datetime = field(default_factory=datetime.now)

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "ip": self.ip,
            "endpoint": self.endpoint,
            "reachable": self.reachable,
            "error": self.error,
            "cert": self.cert.to_dict() if self.cert else None,
            "days_left": self.days_left,
            "status": self.status,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "chain_valid": self.chain_valid,
            "chain_error": self.chain_error,
            "hostname_matches": self.hostname_matches,
            "criticality": self.criticality,
            "owner": self.owner,
            "findings": [f.__dict__ for f in self.findings],
            "scanned_at": self.scanned_at.isoformat(),
        }
