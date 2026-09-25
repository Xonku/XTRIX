"""Notifications for certificates approaching expiry (TZ 3.8).

Channels: log (always), Telegram bot API, SMTP email. Deduplication: an
endpoint is notified once per threshold level (the highest applicable
threshold reached) until its days-left value increases again (renewal).
"""
from __future__ import annotations

import asyncio
import logging
import smtplib
from email.message import EmailMessage

from .models import ScanResult
from .storage import Store

log = logging.getLogger("cert_radar.notify")

def _severity(days: int) -> str:
    """Severity follows the certificate state, not the notification threshold."""
    if days <= 14:
        return "Critical"
    if days <= 30:
        return "Warning"
    return "Info"


def _applicable_threshold(days: int, thresholds: list[int]) -> int | None:
    """The highest configured threshold that this certificate has reached."""
    hit = [t for t in thresholds if days <= t]
    return max(hit) if hit else None


def _format(res: ScanResult, threshold: int) -> str:
    sev = _severity(res.days_left)
    title = "EXPIRED" if res.days_left < 0 else f"expires in {res.days_left} day(s)"
    owner = f", owner: {res.owner}" if res.owner else ""
    crit = ", CRITICAL service" if res.criticality == "critical" else ""
    return (f"[{sev}] {res.endpoint} {title} "
            f"(threshold {threshold}d) - {res.cert.subject_cn if res.cert else res.error}"
            f"{owner}{crit}")


async def send_telegram(token: str, chat_id: str, text: str) -> bool:
    try:
        import httpx  # lazy: core works without httpx installed
    except ImportError:
        log.warning("httpx is not installed - Telegram notifications skipped")
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(url, json={"chat_id": chat_id, "text": text})
            return r.status_code == 200
    except Exception:  # noqa: BLE001
        log.exception("Telegram send failed")
        return False


def send_email(settings, text: str) -> bool:  # noqa: ANN001
    if not (settings.smtp_host and settings.smtp_to):
        return False
    msg = EmailMessage()
    msg["Subject"] = "Certificate Radar: expiring certificates"
    msg["From"] = settings.smtp_from or settings.smtp_user
    msg["To"] = settings.smtp_to
    msg.set_content(text)
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as s:
            if settings.smtp_user:
                s.starttls()
                s.login(settings.smtp_user, settings.smtp_password)
            s.send_message(msg)
        return True
    except Exception:  # noqa: BLE001
        log.exception("Email send failed")
        return False


async def notify_if_needed(results: list[ScanResult], store: Store, settings) -> list[str]:  # noqa: ANN001
    """Check all results against thresholds, dedupe, send via all channels.

    Dedupe rule (TZ 3.8 "upon reaching specified thresholds"): each endpoint
    is notified once per threshold value. Renewal resets it because a renewed
    cert has larger days_left and stops matching smaller thresholds.
    """
    messages: list[str] = []
    log_msgs: list[str] = []

    for res in results:
        if res.days_left is None:
            continue
        threshold = _applicable_threshold(res.days_left, settings.notify_thresholds)
        if threshold is None:
            continue
        already = store.notified_endpoints("log")
        key = f"{res.endpoint}#{threshold}"
        # endpoint already notified at this or an equal/lower threshold
        if any(k.startswith(f"{res.endpoint}#") and int(k.rsplit('#', 1)[1]) <= threshold
               for k in already):
            continue

        text = _format(res, threshold)
        store.log_notification("log", res.endpoint, threshold, text, ok=True)
        log_msgs.append(text)
        messages.append(text)

        if settings.telegram_bot_token and settings.telegram_chat_id:
            sent = await send_telegram(settings.telegram_bot_token,
                                       settings.telegram_chat_id, text)
            store.log_notification("telegram", res.endpoint, threshold, text, ok=sent)
        if settings.smtp_host and settings.smtp_to:
            sent = await asyncio.to_thread(send_email, settings, text)
            store.log_notification("email", res.endpoint, threshold, text, ok=sent)

    return log_msgs
