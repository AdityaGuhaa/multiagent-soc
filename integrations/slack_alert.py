"""
integrations/slack_alert.py — Slack alert sender for SOC system
Sends formatted alerts to a Slack channel via Incoming Webhooks.
"""

import json
import logging
import requests
from config import CONFIG

logger = logging.getLogger("SOC.Slack")


def send_alert(ip: str, detection_type: str, action: str, reason: str, confidence: float):
    """Send a formatted SOC alert to Slack."""

    webhook_url = CONFIG.get("slack_webhook_url", "")
    if not webhook_url:
        logger.warning("Slack webhook URL not configured — skipping alert.")
        return

    # Pick emoji based on action
    action_emoji = "🚨" if action == "BLOCK" else "✅"
    confidence_pct = f"{confidence * 100:.0f}%"

    # Slack Block Kit message — rich formatted layout
    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{action_emoji} SOC ALERT — {action}",
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*IP Address*\n`{ip}`"},
                    {"type": "mrkdwn", "text": f"*Detection Type*\n`{detection_type}`"},
                    {"type": "mrkdwn", "text": f"*Action Taken*\n*{action}*"},
                    {"type": "mrkdwn", "text": f"*AI Confidence*\n{confidence_pct}"},
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Reason*\n{reason}"
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "🛡️ AI-Powered SOC Automation System"
                    }
                ]
            }
        ]
    }

    try:
        response = requests.post(
            webhook_url,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if response.status_code == 200:
            logger.info(f"Slack alert sent for {ip} — {action}")
        else:
            logger.warning(f"Slack alert failed: {response.status_code} — {response.text}")
    except requests.exceptions.Timeout:
        logger.error("Slack alert timed out.")
    except requests.exceptions.RequestException as exc:
        logger.error(f"Slack alert error: {exc}")
