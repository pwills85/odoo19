#!/usr/bin/env python3
"""
Multi-Channel Notification System for Audit Completions
Supports Slack webhooks and Email (SMTP) with throttling and rich formatting.

Usage:
    python notify.py --event audit_complete --score 8.5 --findings 12 --sprint h1
    python notify.py --event p0_detected --file models/account.py --line 145
    python notify.py --test  # Test mode (dry run)
"""

import os
import sys
import json
import time
import smtplib
import argparse
from pathlib import Path
from datetime import datetime, time as dt_time
from typing import Dict, List, Optional, Any
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from dataclasses import dataclass
import yaml

try:
    from slack_sdk.webhook import WebhookClient
    SLACK_AVAILABLE = True
except ImportError:
    SLACK_AVAILABLE = False
    print("Warning: slack-sdk not installed. Slack notifications disabled.")
    print("Install with: pip install slack-sdk")

try:
    from jinja2 import Template
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False
    print("Warning: jinja2 not installed. Using basic templates.")
    print("Install with: pip install jinja2")


@dataclass
class NotificationEvent:
    """Represents a notification event"""
    event_type: str
    timestamp: datetime
    data: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_type': self.event_type,
            'timestamp': self.timestamp.isoformat(),
            'data': self.data
        }


class ThrottleManager:
    """Manages notification throttling to prevent spam"""

    def __init__(self, config: Dict[str, Any]):
        self.min_interval = config.get('throttling', {}).get('min_interval_seconds', 300)
        self.quiet_hours = config.get('throttling', {}).get('quiet_hours', {})
        self.state_file = Path(__file__).parent / '.notify_state.json'
        self.last_notifications = self._load_state()

    def _load_state(self) -> Dict[str, float]:
        """Load last notification timestamps"""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_state(self):
        """Save notification state"""
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self.last_notifications, f)
        except Exception as e:
            print(f"Warning: Could not save throttle state: {e}")

    def is_quiet_hours(self) -> bool:
        """Check if current time is within quiet hours"""
        if not self.quiet_hours:
            return False

        try:
            start = dt_time.fromisoformat(self.quiet_hours.get('start', '22:00'))
            end = dt_time.fromisoformat(self.quiet_hours.get('end', '08:00'))
            now = datetime.now().time()

            if start <= end:
                return start <= now <= end
            else:  # Crosses midnight
                return now >= start or now <= end
        except Exception:
            return False

    def should_send(self, channel: str, event_type: str, force: bool = False) -> bool:
        """Check if notification should be sent based on throttling rules"""
        if force:
            return True

        # Check quiet hours
        if self.is_quiet_hours():
            return False

        # Check throttle interval
        key = f"{channel}:{event_type}"
        last_time = self.last_notifications.get(key, 0)
        current_time = time.time()

        if current_time - last_time < self.min_interval:
            return False

        return True

    def record_notification(self, channel: str, event_type: str):
        """Record that a notification was sent"""
        key = f"{channel}:{event_type}"
        self.last_notifications[key] = time.time()
        self._save_state()


class SlackNotifier:
    """Handles Slack webhook notifications with rich formatting"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config.get('slack', {})
        self.webhook_url = os.environ.get('SLACK_WEBHOOK_URL',
                                         self.config.get('webhook_url', ''))
        self.channel = self.config.get('channel', '#odoo-audits')
        self.mention_on_p0 = self.config.get('mention_on_p0', True)
        self.templates_dir = Path(__file__).parent / 'templates'

        if not self.webhook_url:
            print("Warning: SLACK_WEBHOOK_URL not configured")

    def _load_template(self, template_name: str) -> Optional[str]:
        """Load Slack message template"""
        template_path = self.templates_dir / template_name
        if template_path.exists():
            with open(template_path, 'r') as f:
                return f.read()
        return None

    def _get_severity_color(self, severity: str) -> str:
        """Get color code for severity level"""
        colors = {
            'P0': '#FF0000',  # Red
            'P1': '#FFA500',  # Orange
            'P2': '#FFFF00',  # Yellow
            'P3': '#00FF00',  # Green
            'INFO': '#0000FF' # Blue
        }
        return colors.get(severity, '#808080')

    def _format_score(self, score: float) -> str:
        """Format score with emoji indicator"""
        if score >= 9.0:
            return f"{score} :star2:"
        elif score >= 8.0:
            return f"{score} :white_check_mark:"
        elif score >= 7.0:
            return f"{score} :warning:"
        else:
            return f"{score} :x:"

    def _create_audit_complete_message(self, event: NotificationEvent) -> Dict[str, Any]:
        """Create Slack message for audit completion"""
        data = event.data
        score = data.get('score', 0)
        findings = data.get('findings', 0)
        sprint = data.get('sprint_id', 'unknown')
        duration = data.get('duration_minutes', 0)

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f":clipboard: Audit Complete - {sprint.upper()}",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Score:*\n{self._format_score(score)}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Findings:*\n{findings} issues"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Duration:*\n{duration} minutes"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Timestamp:*\n<!date^{int(event.timestamp.timestamp())}^{{date_short_pretty}} at {{time}}|{event.timestamp.isoformat()}>"
                    }
                ]
            }
        ]

        # Add P0/P1 breakdown if present
        if 'breakdown' in data:
            breakdown = data['breakdown']
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Severity Breakdown:*\n• P0: {breakdown.get('P0', 0)} Critical\n• P1: {breakdown.get('P1', 0)} High\n• P2: {breakdown.get('P2', 0)} Medium\n• P3: {breakdown.get('P3', 0)} Low"
                }
            })

        # Add actions
        if 'report_url' in data:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "View Report",
                            "emoji": True
                        },
                        "url": data['report_url'],
                        "style": "primary"
                    }
                ]
            })

        return {"blocks": blocks}

    def _create_p0_detected_message(self, event: NotificationEvent) -> Dict[str, Any]:
        """Create Slack message for P0 detection"""
        data = event.data
        file_path = data.get('file', 'unknown')
        line = data.get('line', 0)
        issue = data.get('issue', 'Unknown issue')
        code_snippet = data.get('code_snippet', '')

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": ":rotating_light: Critical P0 Issue Detected",
                    "emoji": True
                }
            }
        ]

        # Add mention if configured
        if self.mention_on_p0:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "<!channel> A critical P0 issue requires immediate attention!"
                }
            })

        blocks.extend([
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*File:*\n`{file_path}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Line:*\n{line}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Issue:*\n{issue}"
                }
            }
        ])

        # Add code snippet if available
        if code_snippet:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Code Snippet:*\n```python\n{code_snippet}\n```"
                }
            })

        return {"blocks": blocks}

    def _create_regression_message(self, event: NotificationEvent) -> Dict[str, Any]:
        """Create Slack message for regression detection"""
        data = event.data
        previous_score = data.get('previous_score', 0)
        current_score = data.get('current_score', 0)
        delta = current_score - previous_score

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": ":warning: Regression Detected",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Previous Score:*\n{previous_score}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Current Score:*\n{current_score}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Delta:*\n{delta:+.2f} :chart_with_downwards_trend:"
                    }
                ]
            }
        ]

        return {"blocks": blocks}

    def send(self, event: NotificationEvent, dry_run: bool = False) -> bool:
        """Send Slack notification"""
        if not SLACK_AVAILABLE:
            print("Slack SDK not available")
            return False

        if not self.webhook_url:
            print("Slack webhook URL not configured")
            return False

        # Create message based on event type
        if event.event_type == 'audit_complete':
            message = self._create_audit_complete_message(event)
        elif event.event_type == 'p0_detected':
            message = self._create_p0_detected_message(event)
        elif event.event_type == 'regression':
            message = self._create_regression_message(event)
        else:
            print(f"Unknown event type: {event.event_type}")
            return False

        if dry_run:
            print(f"[DRY RUN] Would send to Slack: {json.dumps(message, indent=2)}")
            return True

        try:
            client = WebhookClient(self.webhook_url)
            response = client.send(**message)

            if response.status_code == 200:
                print(f"Slack notification sent successfully")
                return True
            else:
                print(f"Slack notification failed: {response.status_code} - {response.body}")
                return False
        except Exception as e:
            print(f"Error sending Slack notification: {e}")
            return False


class EmailNotifier:
    """Handles email notifications via SMTP"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config.get('email', {})
        self.smtp_server = self.config.get('smtp_server', 'smtp.gmail.com')
        self.smtp_port = self.config.get('smtp_port', 587)
        self.smtp_user = os.environ.get('SMTP_USER', self.config.get('from', ''))
        self.smtp_password = os.environ.get('SMTP_PASSWORD', '')
        self.from_addr = self.config.get('from', '')
        self.to_addrs = self.config.get('to', [])
        self.templates_dir = Path(__file__).parent / 'templates'

    def _load_template(self, template_name: str) -> Optional[str]:
        """Load email HTML template"""
        template_path = self.templates_dir / template_name
        if template_path.exists():
            with open(template_path, 'r') as f:
                return f.read()
        return None

    def _render_template(self, template_str: str, context: Dict[str, Any]) -> str:
        """Render template with context"""
        if JINJA_AVAILABLE:
            template = Template(template_str)
            return template.render(**context)
        else:
            # Simple string substitution fallback
            for key, value in context.items():
                template_str = template_str.replace(f'{{{{{key}}}}}', str(value))
            return template_str

    def _create_score_graph_ascii(self, score: float) -> str:
        """Create ASCII bar graph for score"""
        filled = int(score)
        empty = 10 - filled
        return f"[{'█' * filled}{'░' * empty}] {score}/10"

    def send(self, event: NotificationEvent, dry_run: bool = False) -> bool:
        """Send email notification"""
        if not self.smtp_user or not self.smtp_password:
            print("SMTP credentials not configured")
            return False

        if not self.to_addrs:
            print("No recipient email addresses configured")
            return False

        # Load and render template
        template_name = f'email_{event.event_type}.html'
        template_str = self._load_template(template_name)

        if not template_str:
            print(f"Template not found: {template_name}")
            return False

        # Prepare context
        context = {
            'TIMESTAMP': event.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            **event.data
        }

        # Add score graph if score is present
        if 'score' in event.data:
            context['SCORE_GRAPH'] = self._create_score_graph_ascii(event.data['score'])

        html_body = self._render_template(template_str, context)

        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"Audit {event.event_type.replace('_', ' ').title()}"
        msg['From'] = self.from_addr
        msg['To'] = ', '.join(self.to_addrs)

        # Attach HTML body
        msg.attach(MIMEText(html_body, 'html'))

        # Attach PDF report if provided
        if 'report_pdf_path' in event.data:
            pdf_path = Path(event.data['report_pdf_path'])
            if pdf_path.exists():
                with open(pdf_path, 'rb') as f:
                    pdf = MIMEApplication(f.read(), _subtype='pdf')
                    pdf.add_header('Content-Disposition', 'attachment',
                                 filename=pdf_path.name)
                    msg.attach(pdf)

        if dry_run:
            print(f"[DRY RUN] Would send email to: {self.to_addrs}")
            print(f"Subject: {msg['Subject']}")
            print(f"Body preview: {html_body[:200]}...")
            return True

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)

            print(f"Email sent successfully to {len(self.to_addrs)} recipients")
            return True
        except Exception as e:
            print(f"Error sending email: {e}")
            return False


class NotificationManager:
    """Main notification manager orchestrating all channels"""

    def __init__(self, config_path: Optional[Path] = None):
        self.config = self._load_config(config_path)
        self.throttle = ThrottleManager(self.config)
        self.slack = SlackNotifier(self.config)
        self.email = EmailNotifier(self.config)

    def _load_config(self, config_path: Optional[Path] = None) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        if config_path is None:
            config_path = Path(__file__).parent / 'notify_config.yaml'

        if not config_path.exists():
            print(f"Warning: Config file not found at {config_path}")
            return {}

        with open(config_path, 'r') as f:
            return yaml.safe_load(f)

    def notify(self, event: NotificationEvent, channels: List[str] = None,
               force: bool = False, dry_run: bool = False) -> Dict[str, bool]:
        """Send notification to specified channels"""
        if channels is None:
            channels = ['slack', 'email']

        results = {}

        for channel in channels:
            # Check throttling
            if not force and not self.throttle.should_send(channel, event.event_type):
                print(f"Skipping {channel} notification due to throttling")
                results[channel] = False
                continue

            # Send notification
            if channel == 'slack':
                success = self.slack.send(event, dry_run)
            elif channel == 'email':
                success = self.email.send(event, dry_run)
            else:
                print(f"Unknown channel: {channel}")
                success = False

            results[channel] = success

            # Record if successful
            if success and not dry_run:
                self.throttle.record_notification(channel, event.event_type)

        return results


def main():
    parser = argparse.ArgumentParser(description='Multi-channel notification system')
    parser.add_argument('--event', required=True,
                       choices=['audit_complete', 'p0_detected', 'regression', 're_audit'],
                       help='Event type to notify')
    parser.add_argument('--channels', nargs='+', default=['slack', 'email'],
                       choices=['slack', 'email'],
                       help='Notification channels to use')
    parser.add_argument('--config', type=Path, help='Path to config file')
    parser.add_argument('--force', action='store_true',
                       help='Force send (bypass throttling)')
    parser.add_argument('--test', action='store_true',
                       help='Test mode (dry run, no actual sending)')

    # Event-specific arguments
    parser.add_argument('--score', type=float, help='Audit score')
    parser.add_argument('--findings', type=int, help='Number of findings')
    parser.add_argument('--sprint', dest='sprint_id', help='Sprint ID')
    parser.add_argument('--duration', dest='duration_minutes', type=int,
                       help='Audit duration in minutes')
    parser.add_argument('--file', help='File path (for P0 detection)')
    parser.add_argument('--line', type=int, help='Line number (for P0 detection)')
    parser.add_argument('--issue', help='Issue description (for P0 detection)')
    parser.add_argument('--code-snippet', dest='code_snippet',
                       help='Code snippet (for P0 detection)')
    parser.add_argument('--previous-score', dest='previous_score', type=float,
                       help='Previous score (for regression)')
    parser.add_argument('--current-score', dest='current_score', type=float,
                       help='Current score (for regression)')
    parser.add_argument('--report-url', dest='report_url', help='URL to full report')
    parser.add_argument('--report-pdf', dest='report_pdf_path',
                       help='Path to PDF report')

    args = parser.parse_args()

    # Build event data from arguments
    event_data = {k: v for k, v in vars(args).items()
                  if v is not None and k not in ['event', 'channels', 'config',
                                                  'force', 'test']}

    # Create event
    event = NotificationEvent(
        event_type=args.event,
        timestamp=datetime.now(),
        data=event_data
    )

    # Create manager and send notifications
    manager = NotificationManager(args.config)
    results = manager.notify(event, args.channels, args.force, args.test)

    # Print results
    print("\nNotification Results:")
    for channel, success in results.items():
        status = "✓ Sent" if success else "✗ Failed"
        print(f"  {channel}: {status}")

    # Exit with error code if any channel failed
    if not all(results.values()):
        sys.exit(1)


if __name__ == '__main__':
    main()
