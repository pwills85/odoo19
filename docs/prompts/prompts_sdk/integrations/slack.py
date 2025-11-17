"""Slack integration for sending audit notifications."""

import os
import json
from typing import Optional, Dict, Any
try:
    import requests
except ImportError:
    requests = None


class SlackNotifier:
    """
    Send Slack notifications for audit events.

    Example:
        >>> notifier = SlackNotifier(webhook_url="https://hooks.slack.com/...")
        >>> notifier.send_audit_complete(audit_result)
    """

    def __init__(self, webhook_url: Optional[str] = None):
        """
        Initialize Slack notifier.

        Args:
            webhook_url: Slack webhook URL (or set SLACK_WEBHOOK_URL env var)
        """
        self.webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL")

        if not self.webhook_url:
            raise ValueError("Slack webhook URL not provided")

        if requests is None:
            raise ImportError("requests library required: pip install requests")

    def send_audit_complete(self, audit_result: Any) -> bool:
        """Send notification that audit completed."""
        emoji = "✅" if audit_result.score >= 90 else "⚠️" if audit_result.score >= 70 else "❌"

        message = {
            "text": f"{emoji} Audit Complete: {audit_result.module_path}",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*{emoji} Audit Complete*\n\n"
                                f"*Module:* `{audit_result.module_path}`\n"
                                f"*Score:* {audit_result.score:.1f}/100\n"
                                f"*P0 Findings:* {audit_result.critical_count}\n"
                                f"*P1 Findings:* {audit_result.high_count}\n"
                                f"*Session:* {audit_result.session_id}"
                    }
                }
            ]
        }

        response = requests.post(self.webhook_url, json=message)
        return response.status_code == 200

    def send_custom(self, message: str) -> bool:
        """Send custom message."""
        payload = {"text": message}
        response = requests.post(self.webhook_url, json=payload)
        return response.status_code == 200
