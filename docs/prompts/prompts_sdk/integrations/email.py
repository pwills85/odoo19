"""Email integration for sending audit reports."""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional


class EmailNotifier:
    """
    Send email notifications for audit events.

    Example:
        >>> notifier = EmailNotifier(smtp_host="smtp.gmail.com", smtp_port=587)
        >>> notifier.login("user@example.com", "password")
        >>> notifier.send_audit_report(audit_result, to=["team@example.com"])
    """

    def __init__(self, smtp_host: str, smtp_port: int = 587):
        """Initialize email notifier."""
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = None
        self.password = None

    def login(self, username: str, password: str) -> None:
        """Set SMTP credentials."""
        self.username = username
        self.password = password

    def send_audit_report(
        self,
        audit_result: any,
        to: List[str],
        subject: Optional[str] = None,
    ) -> bool:
        """Send audit report via email."""
        if not self.username or not self.password:
            raise ValueError("Must call login() first")

        subject = subject or f"Audit Report: {audit_result.module_path}"

        body = f"""
Audit completed for {audit_result.module_path}

Score: {audit_result.score:.1f}/100
Critical Findings (P0): {audit_result.critical_count}
High Priority Findings (P1): {audit_result.high_count}
Total Findings: {len(audit_result.findings)}

Session ID: {audit_result.session_id}
Timestamp: {audit_result.timestamp}
        """

        msg = MIMEMultipart()
        msg["From"] = self.username
        msg["To"] = ", ".join(to)
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            return True
        except Exception:
            return False
