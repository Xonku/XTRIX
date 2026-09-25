"""Certificate Radar - FastAPI application (API + dashboard)."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, Response

from . import exporters, notifications
from .config import STATIC_DIR, ensure_dirs, load_settings
from .scanner import ScanOptions, run_scan
from .storage import Store
from .targets import parse_targets

ensure_dirs()
store = Store(STATIC_DIR.parent / "data" / "cert_radar.db")
settings = load_settings(store)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger("cert_radar.app")

_scan_lock = asyncio.Lock()   # one scan at a time
_last_results: list = []      # in-memory cache of the latest scan


@asynccontextmanager
async def _lifespan(app: FastAPI):
    yield
    store.close()


app = FastAPI(title="Certificate Radar", version="1.0.0", lifespan=_lifespan)


# ---------------------------------------------------------------- dashboard
@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse((STATIC_DIR / "index.html").read_text(encoding="utf-8"))


# ---------------------------------------------------------------- scanning
class ScanRequest:
    pass


@app.post("/api/scan")
async def api_scan(body: dict):
    """Start a scan. body: {targets: "...", timeout?: float, concurrency?: int}."""
    raw = body.get("targets", "")
    if isinstance(raw, list):
        raw = "\n".join(str(x) for x in raw)
    try:
        targets = parse_targets(raw)
    except ValueError as exc:
        raise HTTPException(400, f"Invalid target list: {exc}") from exc
    if not targets:
        raise HTTPException(400, "No valid targets parsed")

    if _scan_lock.locked():
        raise HTTPException(409, "Scan already in progress")

    opts = ScanOptions(
        timeout=float(body.get("timeout", settings.connect_timeout)),
        concurrency=int(body.get("concurrency", 32)),
        verify_trust=settings.verify_trust,
    )
    meta = {}
    for svc in store.list_services():
        meta[svc["endpoint"]] = {"criticality": svc["criticality"], "owner": svc["owner"]}

    async with _scan_lock:
        global _last_results
        _last_results = await run_scan([str(t) for t in targets], store, opts, meta)

    msgs = await notifications.notify_if_needed(_last_results, store, settings)
    return {"run": store.runs(1)[0], "results": [r.to_dict() for r in _last_results],
            "notifications_sent": msgs}


@app.get("/api/results")
async def api_results() -> dict:
    """Latest scan results (in-memory, empty until first scan)."""
    return {"results": [r.to_dict() for r in _last_results]}


# ---------------------------------------------------------------- dashboard data
@app.get("/api/services")
async def api_services() -> dict:
    return {"services": store.list_services()}


@app.get("/api/summary")
async def api_summary() -> dict:
    services = store.list_services()
    by_status = {"OK": 0, "Information": 0, "Warning": 0, "Critical": 0, "Expired": 0,
                 "Unknown": 0}
    for s in services:
        by_status[s["last_status"] or "Unknown"] = by_status.get(s["last_status"] or "Unknown", 0) + 1
    soon = [s for s in services
            if s["last_days_left"] is not None and s["last_days_left"] <= 30]
    soon.sort(key=lambda s: s["last_days_left"])
    return {
        "total": len(services),
        "by_status": by_status,
        "avg_risk": round(sum(s["last_risk"] or 0 for s in services) / len(services), 1)
                    if services else 0,
        "max_risk": max((s["last_risk"] or 0 for s in services), default=0),
        "expiring_soon": [
            {"endpoint": s["endpoint"], "days_left": s["last_days_left"],
             "status": s["last_status"], "owner": s["owner"]} for s in soon[:10]],
        "criticality_count": sum(1 for s in services if s["criticality"] == "critical"),
        "ownerless": sum(1 for s in services if not s["owner"]),
    }


@app.get("/api/trend")
async def api_trend() -> dict:
    return {"trend": store.score_trend(30)}


@app.get("/api/runs")
async def api_runs() -> dict:
    return {"runs": store.runs(20)}


# ---------------------------------------------------------------- inventory
@app.post("/api/services/{endpoint:path}/owner")
async def api_set_owner(endpoint: str, body: dict):
    owner = str(body.get("owner", "")).strip()
    criticality = body.get("criticality")
    if criticality is not None and criticality not in {"normal", "critical"}:
        raise HTTPException(400, "criticality must be 'normal' or 'critical'")
    if not store.set_owner(endpoint, owner, criticality):
        raise HTTPException(404, f"Unknown service: {endpoint}")
    return {"ok": True, "endpoint": endpoint, "owner": owner,
            "criticality": criticality or "unchanged"}


# ---------------------------------------------------------------- exports
@app.get("/api/export/{fmt}")
async def api_export(fmt: str) -> Response:
    results = _last_results or []
    if not results:
        services = store.list_services()
        if not services:
            raise HTTPException(404, "Nothing to export: run a scan first")
        # reconstruct minimal ScanResult-like dicts via exporter rows
        return _export_from_inventory(fmt, services)
    if fmt == "csv":
        return Response(exporters.to_csv(results), media_type="text/csv",
                        headers={"Content-Disposition":
                                 "attachment; filename=certificate_radar.csv"})
    if fmt == "xlsx":
        return Response(exporters.to_xlsx(results),
                        media_type="application/vnd.openxmlformats-officedocument"
                                   ".spreadsheetml.sheet",
                        headers={"Content-Disposition":
                                 "attachment; filename=certificate_radar.xlsx"})
    if fmt == "html":
        return Response(exporters.to_html(results), media_type="text/html",
                        headers={"Content-Disposition":
                                 "attachment; filename=certificate_radar.html"})
    raise HTTPException(400, f"Unknown format: {fmt} (use csv|xlsx|html)")


def _export_from_inventory(fmt: str, services: list[dict]) -> Response:
    """Fallback export from DB inventory (after server restart)."""
    import io, csv as _csv
    if fmt == "csv":
        buf = io.StringIO()
        w = _csv.writer(buf, delimiter=";")
        w.writerow(["Service", "Status", "Risk", "Days Left", "Owner", "Error"])
        for s in services:
            w.writerow([s["endpoint"], s["last_status"], s["last_risk"],
                        s["last_days_left"], s["owner"], s["last_error"]])
        return Response(buf.getvalue().encode("utf-8-sig"), media_type="text/csv",
                        headers={"Content-Disposition":
                                 "attachment; filename=certificate_radar.csv"})
    raise HTTPException(400, "Run a scan first for xlsx/html export after restart")


# ---------------------------------------------------------------- settings & notifications
@app.get("/api/settings")
async def api_get_settings() -> dict:
    return settings.as_dict()


@app.post("/api/settings")
async def api_set_settings(body: dict):
    settings.update_from_dict(body)
    store.set_setting("settings", __import__("json").dumps(
        {k: getattr(settings, k) for k in vars(settings)}))
    return settings.as_dict()


@app.get("/api/notifications")
async def api_notifications() -> dict:
    return {"notifications": store.notifications(100)}


# ---------------------------------------------------------------- demo helper
@app.post("/api/validate-targets")
async def api_validate(body: dict):
    raw = body.get("targets", "")
    try:
        targets = parse_targets(raw)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"count": len(targets), "targets": [str(t) for t in targets[:500]]}
