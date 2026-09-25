"""SQLite persistence: scan history, service inventory, owners, settings, notifications.

Uses the standard library sqlite3 (WAL mode) - no ORM dependency, schema is
small and explicit. Stored per scan: one row per endpoint (latest state) plus
an append-only history for the dashboard trend.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS services (
    endpoint        TEXT PRIMARY KEY,
    host            TEXT NOT NULL,
    port            INTEGER NOT NULL,
    criticality     TEXT NOT NULL DEFAULT 'normal',
    owner           TEXT NOT NULL DEFAULT '',
    last_seen       TEXT,
    last_status     TEXT,
    last_risk       INTEGER,
    last_days_left  INTEGER,
    last_cert_json  TEXT,
    last_error      TEXT,
    chain_valid     INTEGER,
    hostname_match  INTEGER,
    updated_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    targets     INTEGER NOT NULL DEFAULT 0,
    ok          INTEGER NOT NULL DEFAULT 0,
    failed      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES scan_runs(id),
    endpoint    TEXT NOT NULL,
    host        TEXT NOT NULL,
    ts          TEXT NOT NULL,
    status      TEXT,
    risk_score  INTEGER,
    days_left   INTEGER,
    cert_json   TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notifications_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    channel    TEXT NOT NULL,
    endpoint   TEXT NOT NULL,
    threshold  INTEGER,
    message    TEXT NOT NULL,
    ok         INTEGER NOT NULL
);
"""


class Store:
    """Thread-safe thin wrapper over sqlite3."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.executescript(_SCHEMA)

    # ---------------- settings ----------------
    def get_setting(self, key: str, default: str = "") -> str:
        row = self._conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    # ---------------- service inventory ----------------
    def upsert_service(self, res) -> None:  # noqa: ANN001 - ScanResult
        q = """INSERT INTO services(endpoint,host,port,criticality,owner,last_seen,
                 last_status,last_risk,last_days_left,last_cert_json,last_error,
                 chain_valid,hostname_match,updated_at)
               VALUES(:endpoint,:host,:port,:criticality,:owner,:last_seen,:last_status,
                 :last_risk,:last_days_left,:last_cert_json,:last_error,
                 :chain_valid,:hostname_match,:updated_at)
               ON CONFLICT(endpoint) DO UPDATE SET
                 criticality=excluded.criticality, owner=excluded.owner,
                 last_seen=excluded.last_seen, last_status=excluded.last_status,
                 last_risk=excluded.last_risk, last_days_left=excluded.last_days_left,
                 last_cert_json=excluded.last_cert_json, last_error=excluded.last_error,
                 chain_valid=excluded.chain_valid, hostname_match=excluded.hostname_match,
                 updated_at=excluded.updated_at"""
        params = {
            "endpoint": res.endpoint, "host": res.host, "port": res.port,
            "criticality": res.criticality, "owner": res.owner,
            "last_seen": res.scanned_at.isoformat() if res.reachable else None,
            "last_status": res.status, "last_risk": res.risk_score,
            "last_days_left": res.days_left,
            "last_cert_json": json.dumps(res.cert.to_dict()) if res.cert else None,
            "last_error": res.error,
            "chain_valid": None if res.chain_valid is None else int(res.chain_valid),
            "hostname_match": None if res.hostname_matches is None else int(res.hostname_matches),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock, self._conn:
            self._conn.execute(q, params)

    def set_owner(self, endpoint: str, owner: str, criticality: str | None = None) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE services SET owner=?, criticality=COALESCE(?,criticality) "
                "WHERE endpoint=?", (owner, criticality, endpoint))
            return cur.rowcount > 0

    def list_services(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM services ORDER BY last_risk DESC").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["cert"] = json.loads(d.pop("last_cert_json")) if d["last_cert_json"] else None
            out.append(d)
        return out

    # ---------------- scan runs & history ----------------
    def start_run(self, n_targets: int) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO scan_runs(started_at,targets) VALUES(?,?)",
                (datetime.now(timezone.utc).isoformat(), n_targets))
            return int(cur.lastrowid)

    def finish_run(self, run_id: int, ok: int, failed: int) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE scan_runs SET finished_at=?, ok=?, failed=? WHERE id=?",
                (datetime.now(timezone.utc).isoformat(), ok, failed, run_id))

    def save_history(self, run_id: int, results: list) -> None:  # noqa: ANN001
        ts = datetime.now(timezone.utc).isoformat()
        rows = [(run_id, r.endpoint, r.host, ts, r.status, r.risk_score, r.days_left,
                 json.dumps(r.cert.to_dict()) if r.cert else None) for r in results]
        with self._lock, self._conn:
            self._conn.executemany(
                "INSERT INTO history(run_id,endpoint,host,ts,status,risk_score,days_left,cert_json) "
                "VALUES(?,?,?,?,?,?,?,?)", rows)

    def runs(self, limit: int = 50) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def score_trend(self, limit: int = 30) -> list[dict]:
        """Average risk score per run - dashboard 'dynamics' (TZ 2.5-style)."""
        rows = self._conn.execute(
            """SELECT r.id, r.started_at, ROUND(AVG(h.risk_score),1) AS avg_risk,
                      SUM(h.status='Expired') AS expired,
                      SUM(h.status='Critical') AS critical,
                      SUM(h.status='Warning') AS warning
               FROM scan_runs r JOIN history h ON h.run_id=r.id
               WHERE r.finished_at IS NOT NULL
               GROUP BY r.id ORDER BY r.id DESC LIMIT ?""", (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ---------------- notifications log ----------------
    def log_notification(self, channel: str, endpoint: str, threshold: int,
                         message: str, ok: bool) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO notifications_log(ts,channel,endpoint,threshold,message,ok) "
                "VALUES(?,?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(), channel, endpoint, threshold,
                 message, int(ok)))

    def notified_endpoints(self, channel: str) -> set[str]:
        rows = self._conn.execute(
            "SELECT endpoint FROM notifications_log WHERE channel=? AND ok=1", (channel,)).fetchall()
        return {r["endpoint"] for r in rows}

    def notifications(self, limit: int = 100) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM notifications_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        self._conn.close()
