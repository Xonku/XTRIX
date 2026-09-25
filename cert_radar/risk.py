"""Risk scoring (TZ 3.9) and expiration status (TZ 3.5).

Risk Score 0..100 combines:
  - days until expiry (dominant factor),
  - chain-of-trust problems,
  - hostname mismatch,
  - weak cryptography,
  - service criticality (bonus for tagged critical services).

Status buckets (configurable thresholds in settings):
  >60d OK | 31-60 Information | 15-30 Warning | 0-14 Critical | <0 Expired
"""
from __future__ import annotations

from . import analysis
from .models import CertInfo, Finding, ScanResult

FINDING_SEVERITY_WEIGHT = {"Critical": 100, "High": 70, "Medium": 40, "Low": 15, "Info": 5}


def expiry_status(days: int, thresholds: tuple[int, int, int] = (60, 30, 14)) -> str:
    """Map days-left to TZ 3.5 status. thresholds = (info, warning, critical)."""
    info_t, warn_t, crit_t = thresholds
    if days < 0:
        return "Expired"
    if days <= crit_t:
        return "Critical"
    if days <= warn_t:
        return "Warning"
    if days <= info_t:
        return "Information"
    return "OK"


def _findings(res: ScanResult, weak: str | None) -> list[Finding]:
    f: list[Finding] = []
    d = res.days_left

    if d is not None and d < 0:
        f.append(Finding("EXPIRED", "Critical",
                         f"certificate expired {-d} day(s) ago",
                         "Renew the certificate immediately; service may be rejected by clients"))
    elif d is not None and d <= 14:
        f.append(Finding("EXPIRING_SOON", "Critical",
                         f"certificate expires in {d} day(s)",
                         "Start the renewal process now and schedule replacement"))
    elif d is not None and d <= 30:
        f.append(Finding("EXPIRING_WARNING", "Warning",
                         f"certificate expires in {d} day(s)",
                         "Plan certificate renewal within the current maintenance window"))
    elif d is not None and d <= 60:
        f.append(Finding("EXPIRING_INFO", "Info",
                         f"certificate expires in {d} day(s)",
                         "Add the certificate to the renewal backlog"))

    if res.chain_valid is False:
        f.append(Finding("CHAIN_BROKEN", "High",
                         res.chain_error or "certificate chain of trust is broken",
                         "Install the full chain (intermediates) or reissue from a trusted CA"))
    if res.hostname_matches is False:
        f.append(Finding("HOSTNAME_MISMATCH", "High",
                         "service name does not match certificate CN/SAN",
                         "Reissue the certificate with the correct SAN entry for this service"))
    if res.cert and res.cert.self_signed:
        f.append(Finding("SELF_SIGNED", "High",
                         "self-signed certificate in use",
                         "Replace with a certificate issued by the corporate or public CA"))
    if weak:
        f.append(Finding("WEAK_CRYPTO", "Medium", weak,
                         "Reissue the certificate with modern parameters (RSA>=2048/EC>=256, SHA-256+)"))
    if res.error:
        f.append(Finding("UNREACHABLE", "Medium",
                         f"service unavailable: {res.error}",
                         "Check that the service is running and speaks TLS on this port"))
    return f


def evaluate(res: ScanResult, settings) -> ScanResult:
    """Fill status, findings and risk score for one scan result (in place)."""
    d = res.days_left
    res.status = expiry_status(d) if d is not None else "Unknown"

    weak = analysis.is_weak(res.cert) if res.cert else None
    res.findings = _findings(res, weak)

    # ---------------- risk score ----------------
    score = 0
    if d is not None:
        if d < 0:
            score = max(score, 90)
        elif d <= 14:
            score = max(score, 70 + (14 - d))          # 70..84
        elif d <= 30:
            score = max(score, 55 + (30 - d) // 2)     # 55..62
        elif d <= 60:
            score = max(score, 35 + (60 - d) // 3)     # 35..48

    if res.chain_valid is False:
        score += settings.weight_trust
    if res.hostname_matches is False:
        score += settings.weight_hostname
    if weak:
        score += settings.weight_crypto
    if res.cert and res.cert.self_signed:
        score += settings.weight_hostname  # self-signed implies untrusted naming anchor

    if res.criticality == "critical":
        score += settings.criticality_bonus
    if res.error and d is None:
        score = max(score, 50)

    res.risk_score = min(100, score)
    res.risk_level = ("Critical" if res.risk_score >= 75
                      else "High" if res.risk_score >= 50
                      else "Medium" if res.risk_score >= 25
                      else "Low")
    return res
