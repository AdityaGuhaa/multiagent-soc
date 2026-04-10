"""
integrations/telegram_alert.py — Telegram alert notifications
Sends SOC alerts to a Telegram chat via bot API.
"""

import requests
import logging
from config import CONFIG

logger = logging.getLogger("SOC.Telegram")

TELEGRAM_BOT_TOKEN = CONFIG.get("telegram_bot_token", "")
TELEGRAM_CHAT_ID   = CONFIG.get("telegram_chat_id", "")


def send_alert(ip: str, detection_type: str, action: str, reason: str, confidence: float):
    """Send a formatted SOC alert to Telegram."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning("Telegram not configured — skipping notification.")
        return False

    emoji = "🚨" if action == "BLOCK" else "✅"
    message = (
        f"{emoji} *SOC ALERT*\n"
        f"━━━━━━━━━━━━━━━━\n"
        f"🌐 IP: `{ip}`\n"
        f"🔍 Type: `{detection_type}`\n"
        f"⚡ Action: `{action}`\n"
        f"📊 Confidence: `{confidence:.0%}`\n"
        f"📝 Reason: {reason}"
    )

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown",
    }

    try:
        resp = requests.post(url, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info(f"Telegram alert sent for {ip}")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Telegram send failed: {e}")
        return False
