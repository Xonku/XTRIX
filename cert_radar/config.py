"""Application configuration.

All thresholds are configurable (TZ 3.5 / 3.10): expiration buckets, risk
weights and notification thresholds can be overridden via environment
variables without touching the code.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = APP_ROOT / "data"
LOGS_DIR = APP_ROOT / "logs"
STATIC_DIR = APP_ROOT / "static"

DB_PATH = Path(os.getenv("CERT_RADAR_DB", DATA_DIR / "cert_radar.db"))

# Expiration buckets in days (TZ 3.5). Ordered from small to large.
DEFAULT_EXPIRY_BUCKETS = [
    (0, "Expired"),      # < 0 days handled in risk module
    (14, "Critical"),
    (30, "Warning"),
    (60, "Information"),
    (10**6, "OK"),
]
DEFAULT_EXPIRY_BUCKETS.reverse()  # from large to small: first match wins


def _env_int_list(name: str, default: list[int]) -> list[int]:
    raw = os.getenv(name, "")
    if not raw:
        return default
    try:
        return sorted({int(x) for x in raw.replace(";", ",").split(",") if x.strip()},
                      reverse=True)
    except ValueError:
        return default


@dataclass
class Settings:
    """Runtime settings, persisted in SQLite and editable via API."""

    # --- expiration warning thresholds (days left) ----------------------
    notify_thresholds: list[int] = field(
        default_factory=lambda: _env_int_list("CERT_RADAR_THRESHOLDS", [60, 30, 14, 7, 1]))

    # --- risk scoring weights (sum 0..100 contribution caps) ------------
    weight_expiry: int = 55
    weight_trust: int = 20
    weight_crypto: int = 10
    weight_hostname: int = 10
    weight_criticality: int = 5
    criticality_bonus: int = 25

    # --- scanning --------------------------------------------------------
    connect_timeout: float = float(os.getenv("CERT_RADAR_TIMEOUT", "5.0"))
    verify_trust: bool = os.getenv("CERT_RADAR_VERIFY", "1") not in {"0", "false", "no"}

    # --- notifications ----------------------------------------------------
    telegram_bot_token: str = os.getenv("CERT_RADAR_TG_TOKEN", "")
    telegram_chat_id: str = os.getenv("CERT_RADAR_TG_CHAT", "")
    smtp_host: str = os.getenv("CERT_RADAR_SMTP_HOST", "")
    smtp_port: int = int(os.getenv("CERT_RADAR_SMTP_PORT", "587"))
    smtp_user: str = os.getenv("CERT_RADAR_SMTP_USER", "")
    smtp_password: str = os.getenv("CERT_RADAR_SMTP_PASSWORD", "")
    smtp_from: str = os.getenv("CERT_RADAR_SMTP_FROM", "")
    smtp_to: str = os.getenv("CERT_RADAR_SMTP_TO", "")  # comma-separated

    def as_dict(self) -> dict:
        d = self.__dict__.copy()
        # never leak secrets in API responses
        for k in ("telegram_bot_token", "smtp_password"):
            if d.get(k):
                d[k] = "***"
        return d

    def update_from_dict(self, data: dict) -> None:
        for key, value in data.items():
            if key in {"telegram_bot_token", "smtp_password"} and value == "***":
                continue  # masked value from UI - keep current secret
            if hasattr(self, key) and key not in {"as_dict", "update_from_dict"}:
                current = getattr(self, key)
                try:
                    setattr(self, key, type(current)(value))
                except (TypeError, ValueError):
                    logging.getLogger("cert_radar").warning(
                        "Ignoring invalid setting %s=%r", key, value)


def load_settings(store) -> Settings:
    """Build settings, overlaying persisted JSON overrides from the store."""
    settings = Settings()
    try:
        saved = json.loads(store.get_setting("settings", "{}"))
        settings.update_from_dict(saved)
    except Exception:  # noqa: BLE001 - settings must never crash startup
        logging.getLogger("cert_radar").exception("Failed to load saved settings")
    return settings


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
