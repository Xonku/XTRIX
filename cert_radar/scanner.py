"""Scan orchestrator: parse targets -> probe TLS concurrently -> analyze -> risk.

Read-only by design: the scanner only opens TLS connections and reads the
presented certificates. Nothing is ever written to the scanned services
(TZ 4.2 "Read Only").
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from . import analysis, tls_client
from .models import ScanResult
from .risk import evaluate
from .storage import Store
from .targets import Target, parse_targets

log = logging.getLogger("cert_radar.scanner")


@dataclass
class ScanOptions:
    concurrency: int = 32
    timeout: float = 5.0
    verify_trust: bool = True


async def scan_target(target: Target, opts: ScanOptions, meta: dict | None = None) -> ScanResult:
    """Scan a single endpoint: connect, parse, check chain/hostname, score."""
    meta = meta or {}
    res = ScanResult(host=target.host, port=target.port)
    res.criticality = meta.get("criticality", "normal")
    res.owner = meta.get("owner", "")

    res.ip = await tls_client.resolve_ip(target.host)
    if res.ip is None:
        res.error = "DNS resolution failed"
        return evaluate(res, _NullSettings())

    leaf, err = await tls_client.fetch_cert(target.host, target.port, opts.timeout)
    if leaf is None:
        res.error = err
        return evaluate(res, _NullSettings())

    res.reachable = True
    res.cert = analysis.parse_cert(leaf)
    res.days_left = analysis.days_left(res.cert)

    # hostname match (SAN first, CN fallback) - TZ 3.4/3.6
    res.hostname_matches = analysis.check_hostname(res.cert, target.host)

    # trust chain: full chain as sent by server + OS trust decision
    chain_certs = await tls_client.fetch_chain_unverified(target.host, target.port, opts.timeout)
    intermediates = chain_certs[1:] if len(chain_certs) > 1 else []
    if opts.verify_trust:
        res.chain_valid, res.chain_error = analysis.verify_chain(leaf, intermediates)
    else:
        res.chain_valid, res.chain_error = None, None

    return evaluate(res, _NullSettings())


class _NullSettings:
    """Fallback settings for direct scanner use without the app context."""
    weight_expiry = 55
    weight_trust = 20
    weight_hostname = 10
    weight_crypto = 10
    weight_criticality = 5
    criticality_bonus = 25


async def run_scan(raw_targets: str | list[str], store: Store | None = None,
                   opts: ScanOptions | None = None,
                   meta_by_endpoint: dict[str, dict] | None = None) -> list[ScanResult]:
    """Scan all targets concurrently; optionally persist results + history."""
    opts = opts or ScanOptions()
    targets = parse_targets(raw_targets)
    if not targets:
        return []

    meta_by_endpoint = meta_by_endpoint or {}
    sem = asyncio.Semaphore(opts.concurrency)
    results: list[ScanResult] = []

    async def _one(t: Target) -> ScanResult:
        async with sem:
            return await scan_target(t, opts, meta_by_endpoint.get(str(t)))

    run_id = store.start_run(len(targets)) if store else None
    try:
        results = list(await asyncio.gather(*(_one(t) for t in targets)))
    finally:
        if store and run_id is not None:
            ok = sum(1 for r in results if r.reachable)
            store.finish_run(run_id, ok, len(results) - ok)
            for r in results:
                store.upsert_service(r)
            store.save_history(run_id, results)

    results.sort(key=lambda r: (-r.risk_score, r.endpoint))
    log.info("Scanned %d targets: %d ok, %d failed",
             len(results), sum(1 for r in results if r.reachable),
             sum(1 for r in results if not r.reachable))
    return results
