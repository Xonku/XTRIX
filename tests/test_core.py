"""Unit tests for parsing, risk and analysis logic (no network needed)."""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cert_radar import analysis, risk
from cert_radar.models import CertInfo, ScanResult
from cert_radar.targets import Target, parse_targets


# ---------------------------------------------------------------- targets
def test_parse_mixed_targets():
    t = parse_targets("example.com\nhttps://site.kz:8443/\n10.0.0.1:8443")
    assert Target("example.com", 443) in t
    assert Target("site.kz", 8443) in t
    assert Target("10.0.0.1", 8443) in t


def test_parse_cidr_and_dedup():
    t = parse_targets("192.168.10.0/30, 192.168.10.1")
    hosts = {x.host for x in t}
    assert hosts == {"192.168.10.1", "192.168.10.2"}
    assert len(t) == len(set(t))


def test_parse_ip_range_last_octet():
    t = parse_targets("10.1.1.5-7")
    assert [x.host for x in t] == ["10.1.1.5", "10.1.1.6", "10.1.1.7"]


def test_parse_rejects_huge_network():
    with pytest.raises(ValueError):
        parse_targets("10.0.0.0/8")


# ---------------------------------------------------------------- expiry status (TZ 3.5)
@pytest.mark.parametrize("days,expected", [
    (90, "OK"), (61, "OK"), (60, "Information"), (31, "Information"),
    (30, "Warning"), (15, "Warning"), (14, "Critical"), (0, "Critical"),
    (-1, "Expired"), (-30, "Expired"),
])
def test_expiry_status_buckets(days, expected):
    assert risk.expiry_status(days) == expected


# ---------------------------------------------------------------- hostname match
def test_hostname_exact_and_wildcard():
    cert = CertInfo(subject_cn="demo.local", san_dns=["demo.local", "www.demo.local"])
    assert analysis.check_hostname(cert, "demo.local") is True
    assert analysis.check_hostname(cert, "other.local") is False
    wild = CertInfo(san_dns=["*.company.kz"])
    assert analysis.check_hostname(wild, "portal.company.kz") is True
    # RFC 6125: wildcard covers exactly one label - no more, no less
    assert analysis.check_hostname(wild, "a.b.company.kz") is False
    assert analysis.check_hostname(wild, "company.kz") is False


# ---------------------------------------------------------------- risk score (TZ 3.9)
class S:
    weight_expiry = 55
    weight_trust = 20
    weight_hostname = 10
    weight_crypto = 10
    weight_criticality = 5
    criticality_bonus = 25


def _res(**kw) -> ScanResult:
    r = ScanResult(host="svc.local", port=443)
    r.reachable = True
    r.cert = CertInfo(subject_cn="svc.local", san_dns=["svc.local"],
                      not_after=datetime.now(timezone.utc) + timedelta(days=kw.pop("days", 100)))
    r.days_left = analysis.days_left(r.cert)
    for k, v in kw.items():
        setattr(r, k, v)
    return r


def test_score_critical_like_spec_example():
    r = risk.evaluate(_res(days=5, criticality="critical"), S())
    assert r.status == "Critical"
    assert r.risk_score >= 90          # "expires in 5 days; service critical" ~ 90/100
    assert r.risk_level == "Critical"
    codes = {f.code for f in r.findings}
    assert "EXPIRING_SOON" in codes


def test_score_expired():
    r = risk.evaluate(_res(days=-3), S())
    assert r.status == "Expired"
    assert r.risk_score >= 90
    assert any(f.code == "EXPIRED" for f in r.findings)


def test_score_healthy_is_low():
    r = risk.evaluate(_res(days=200), S())
    assert r.status == "OK"
    assert r.risk_score == 0 and r.risk_level == "Low" and r.findings == []


def test_score_chain_and_mismatch_stack():
    r = risk.evaluate(_res(days=100, chain_valid=False,
                           chain_error="broken", hostname_matches=False), S())
    assert r.risk_score == S.weight_trust + S.weight_hostname
    codes = {f.code for f in r.findings}
    assert {"CHAIN_BROKEN", "HOSTNAME_MISMATCH"} <= codes


# ---------------------------------------------------------------- chain building
def _mk_cert(cn: str, issuer_key=None, issuer_name=None, ca=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ik = issuer_key or key
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    b = (x509.CertificateBuilder()
         .subject_name(name)
         .issuer_name(issuer_name or name)
         .public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
         .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365)))
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return key, b.sign(ik, hashes.SHA256())


def test_build_chain_complete_and_broken():
    root_key, root = _mk_cert("Test Root CA", ca=True)
    inter_key, inter = _mk_cert("Test Intermediate", root_key, root.subject, ca=True)
    _, leaf = _mk_cert("leaf.test", inter_key, inter.subject)

    chain, err = analysis.build_chain(leaf, [inter, root])
    assert err is None and len(chain) == 3

    # missing intermediate -> structural break
    _, err2 = analysis.build_chain(leaf, [])
    assert err2 and "incomplete" in err2

    # wrong signature link: same subject name, different key -> detectable
    forged_key, forged = _mk_cert("Test Intermediate", ca=True)
    _, err3 = analysis.build_chain(leaf, [forged])
    assert err3 and "signature" in err3


# ---------------------------------------------------------------- weak crypto
def test_weak_crypto_detection():
    weak = CertInfo(key_algorithm="RSAPublicKey", key_size=1024, signature_algorithm="sha256WithRSAEncryption")
    assert analysis.is_weak(weak) and "1024" in analysis.is_weak(weak)
    good = CertInfo(key_algorithm="RSAPublicKey", key_size=2048, signature_algorithm="sha256WithRSAEncryption")
    assert analysis.is_weak(good) is None
    sha1 = CertInfo(key_algorithm="RSAPublicKey", key_size=2048, signature_algorithm="sha1WithRSAEncryption")
    assert analysis.is_weak(sha1) and "sha1" in analysis.is_weak(sha1).lower()
