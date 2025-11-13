"""
Metrics module for tracking and visualizing audit metrics over time.

This module provides MetricsManager for tracking sprint metrics and
Dashboard for generating visual reports.
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SprintMetrics:
    """Metrics for a single sprint."""

    sprint_id: int
    timestamp: datetime
    audit_type: str  # initial_audit, re_audit, validation
    score: float
    findings_by_priority: Dict[str, int]
    odoo19_compliance_rate: float
    execution_time_seconds: float
    token_usage: Dict[str, int]
    gaps_closed: int = 0
    gaps_remaining: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "sprint_id": self.sprint_id,
            "timestamp": self.timestamp.isoformat(),
            "audit_type": self.audit_type,
            "score": self.score,
            "findings_by_priority": self.findings_by_priority,
            "odoo19_compliance_rate": self.odoo19_compliance_rate,
            "execution_time_seconds": self.execution_time_seconds,
            "token_usage": self.token_usage,
            "gaps_closed": self.gaps_closed,
            "gaps_remaining": self.gaps_remaining,
            "metadata": self.metadata,
        }


class MetricsManager:
    """
    Manage audit metrics across sprints.

    Example:
        >>> metrics = MetricsManager()
        >>> metrics.add_sprint(
        ...     sprint_id=1,
        ...     audit_result=result,
        ...     audit_type="initial_audit"
        ... )
        >>> dashboard = metrics.generate_dashboard()
        >>> dashboard.export_markdown("METRICS.md")
    """

    def __init__(self, storage_path: Optional[str] = None):
        """
        Initialize metrics manager.

        Args:
            storage_path: Path to store metrics JSON (default: ./metrics.json)
        """
        self.storage_path = storage_path or "metrics.json"
        self.sprints: List[SprintMetrics] = []
        self._load_metrics()

    def _load_metrics(self) -> None:
        """Load metrics from storage."""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, "r") as f:
                    data = json.load(f)
                    self.sprints = [
                        SprintMetrics(
                            sprint_id=s["sprint_id"],
                            timestamp=datetime.fromisoformat(s["timestamp"]),
                            audit_type=s["audit_type"],
                            score=s["score"],
                            findings_by_priority=s["findings_by_priority"],
                            odoo19_compliance_rate=s["odoo19_compliance_rate"],
                            execution_time_seconds=s["execution_time_seconds"],
                            token_usage=s["token_usage"],
                            gaps_closed=s.get("gaps_closed", 0),
                            gaps_remaining=s.get("gaps_remaining", 0),
                            metadata=s.get("metadata", {}),
                        )
                        for s in data.get("sprints", [])
                    ]
            except Exception as e:
                print(f"Warning: Failed to load metrics: {e}")

    def _save_metrics(self) -> None:
        """Save metrics to storage."""
        data = {
            "last_updated": datetime.now().isoformat(),
            "sprints": [s.to_dict() for s in self.sprints],
        }
        with open(self.storage_path, "w") as f:
            json.dump(data, f, indent=2)

    def add_sprint(
        self,
        sprint_id: int,
        audit_result: Any,  # AuditResult
        audit_type: str,
        gaps_closed: int = 0,
        gaps_remaining: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Add sprint metrics.

        Args:
            sprint_id: Sprint identifier
            audit_result: AuditResult from audit run
            audit_type: Type of audit (initial_audit, re_audit, validation)
            gaps_closed: Number of gaps closed this sprint
            gaps_remaining: Number of gaps remaining
            metadata: Additional metadata
        """
        # Count findings by priority
        findings_by_priority = {}
        for finding in audit_result.findings:
            severity = finding.severity
            findings_by_priority[severity] = findings_by_priority.get(severity, 0) + 1

        sprint_metrics = SprintMetrics(
            sprint_id=sprint_id,
            timestamp=audit_result.timestamp,
            audit_type=audit_type,
            score=audit_result.score,
            findings_by_priority=findings_by_priority,
            odoo19_compliance_rate=audit_result.odoo19_compliance_rate or 0.0,
            execution_time_seconds=audit_result.execution_time_seconds,
            token_usage=audit_result.token_usage,
            gaps_closed=gaps_closed,
            gaps_remaining=gaps_remaining,
            metadata=metadata or {},
        )

        self.sprints.append(sprint_metrics)
        self._save_metrics()

    def get_sprint(self, sprint_id: int) -> Optional[SprintMetrics]:
        """Get metrics for specific sprint."""
        for sprint in self.sprints:
            if sprint.sprint_id == sprint_id:
                return sprint
        return None

    def get_latest_sprint(self) -> Optional[SprintMetrics]:
        """Get most recent sprint metrics."""
        if not self.sprints:
            return None
        return max(self.sprints, key=lambda s: s.timestamp)

    def generate_dashboard(self) -> "Dashboard":
        """Generate dashboard with visualizations."""
        return Dashboard(self.sprints)


class Dashboard:
    """
    Dashboard for visualizing metrics.

    Example:
        >>> dashboard = Dashboard(sprints)
        >>> dashboard.export_markdown("DASHBOARD.md")
        >>> dashboard.export_html("dashboard.html")
    """

    def __init__(self, sprints: List[SprintMetrics]):
        """
        Initialize dashboard.

        Args:
            sprints: List of sprint metrics
        """
        self.sprints = sorted(sprints, key=lambda s: s.sprint_id)

    def export_markdown(self, file_path: str) -> None:
        """
        Export dashboard as Markdown.

        Args:
            file_path: Output file path
        """
        lines = [
            "# Audit Metrics Dashboard",
            "",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Total Sprints:** {len(self.sprints)}",
            "",
            "## Sprint Overview",
            "",
            "| Sprint | Date | Type | Score | P0 | P1 | P2 | Compliance | Gaps Closed | Gaps Remaining |",
            "|--------|------|------|-------|----|----|----|-----------|-----------|----|",
        ]

        for sprint in self.sprints:
            p0 = sprint.findings_by_priority.get("P0", 0)
            p1 = sprint.findings_by_priority.get("P1", 0)
            p2 = sprint.findings_by_priority.get("P2", 0)

            lines.append(
                f"| {sprint.sprint_id} | "
                f"{sprint.timestamp.strftime('%Y-%m-%d')} | "
                f"{sprint.audit_type} | "
                f"{sprint.score:.1f} | "
                f"{p0} | {p1} | {p2} | "
                f"{sprint.odoo19_compliance_rate:.1f}% | "
                f"{sprint.gaps_closed} | "
                f"{sprint.gaps_remaining} |"
            )

        # Trend analysis
        if len(self.sprints) >= 2:
            first = self.sprints[0]
            latest = self.sprints[-1]

            lines.extend([
                "",
                "## Trend Analysis",
                "",
                f"- **Score Improvement:** {latest.score - first.score:+.1f} points",
                f"- **Compliance Improvement:** {latest.odoo19_compliance_rate - first.odoo19_compliance_rate:+.1f}%",
                f"- **P0 Findings Reduction:** {first.findings_by_priority.get('P0', 0) - latest.findings_by_priority.get('P0', 0)}",
                f"- **P1 Findings Reduction:** {first.findings_by_priority.get('P1', 0) - latest.findings_by_priority.get('P1', 0)}",
                f"- **Total Gaps Closed:** {sum(s.gaps_closed for s in self.sprints)}",
            ])

        # Token usage stats
        total_input = sum(s.token_usage.get("input", 0) for s in self.sprints)
        total_output = sum(s.token_usage.get("output", 0) for s in self.sprints)

        lines.extend([
            "",
            "## Resource Usage",
            "",
            f"- **Total Input Tokens:** {total_input:,}",
            f"- **Total Output Tokens:** {total_output:,}",
            f"- **Total Execution Time:** {sum(s.execution_time_seconds for s in self.sprints):.1f}s",
            f"- **Avg Execution Time:** {sum(s.execution_time_seconds for s in self.sprints) / len(self.sprints):.1f}s",
        ])

        # Latest sprint details
        if self.sprints:
            latest = self.sprints[-1]
            lines.extend([
                "",
                "## Latest Sprint Details",
                "",
                f"- **Sprint ID:** {latest.sprint_id}",
                f"- **Date:** {latest.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
                f"- **Type:** {latest.audit_type}",
                f"- **Score:** {latest.score:.1f}/100",
                f"- **Odoo 19 Compliance:** {latest.odoo19_compliance_rate:.1f}%",
                "",
                "**Findings Breakdown:**",
            ])

            for priority in ["P0", "P1", "P2", "P3", "P4"]:
                count = latest.findings_by_priority.get(priority, 0)
                if count > 0:
                    lines.append(f"- **{priority}:** {count}")

        # Write file
        with open(file_path, "w") as f:
            f.write("\n".join(lines))

    def export_html(self, file_path: str) -> None:
        """
        Export dashboard as HTML with charts.

        Args:
            file_path: Output file path
        """
        # Generate simple HTML with inline charts
        html = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "    <title>Audit Metrics Dashboard</title>",
            "    <meta charset='utf-8'>",
            "    <style>",
            "        body { font-family: Arial, sans-serif; margin: 20px; }",
            "        table { border-collapse: collapse; width: 100%; margin: 20px 0; }",
            "        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }",
            "        th { background-color: #4CAF50; color: white; }",
            "        tr:nth-child(even) { background-color: #f2f2f2; }",
            "        .metric { display: inline-block; margin: 10px 20px; }",
            "        .metric-value { font-size: 32px; font-weight: bold; color: #4CAF50; }",
            "        .metric-label { font-size: 14px; color: #666; }",
            "    </style>",
            "</head>",
            "<body>",
            "    <h1>Audit Metrics Dashboard</h1>",
            f"    <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
            f"    <p><strong>Total Sprints:</strong> {len(self.sprints)}</p>",
        ]

        # Key metrics
        if self.sprints:
            latest = self.sprints[-1]
            html.extend([
                "    <h2>Key Metrics</h2>",
                "    <div>",
                f"        <div class='metric'>",
                f"            <div class='metric-value'>{latest.score:.1f}</div>",
                f"            <div class='metric-label'>Latest Score</div>",
                f"        </div>",
                f"        <div class='metric'>",
                f"            <div class='metric-value'>{latest.odoo19_compliance_rate:.1f}%</div>",
                f"            <div class='metric-label'>Compliance</div>",
                f"        </div>",
                f"        <div class='metric'>",
                f"            <div class='metric-value'>{latest.findings_by_priority.get('P0', 0)}</div>",
                f"            <div class='metric-label'>P0 Findings</div>",
                f"        </div>",
                f"        <div class='metric'>",
                f"            <div class='metric-value'>{sum(s.gaps_closed for s in self.sprints)}</div>",
                f"            <div class='metric-label'>Total Gaps Closed</div>",
                f"        </div>",
                "    </div>",
            ])

        # Sprint table
        html.extend([
            "    <h2>Sprint History</h2>",
            "    <table>",
            "        <thead>",
            "            <tr>",
            "                <th>Sprint</th>",
            "                <th>Date</th>",
            "                <th>Type</th>",
            "                <th>Score</th>",
            "                <th>P0</th>",
            "                <th>P1</th>",
            "                <th>P2</th>",
            "                <th>Compliance</th>",
            "                <th>Gaps Closed</th>",
            "            </tr>",
            "        </thead>",
            "        <tbody>",
        ])

        for sprint in self.sprints:
            html.append(
                f"            <tr>"
                f"<td>{sprint.sprint_id}</td>"
                f"<td>{sprint.timestamp.strftime('%Y-%m-%d')}</td>"
                f"<td>{sprint.audit_type}</td>"
                f"<td>{sprint.score:.1f}</td>"
                f"<td>{sprint.findings_by_priority.get('P0', 0)}</td>"
                f"<td>{sprint.findings_by_priority.get('P1', 0)}</td>"
                f"<td>{sprint.findings_by_priority.get('P2', 0)}</td>"
                f"<td>{sprint.odoo19_compliance_rate:.1f}%</td>"
                f"<td>{sprint.gaps_closed}</td>"
                f"</tr>"
            )

        html.extend([
            "        </tbody>",
            "    </table>",
            "</body>",
            "</html>",
        ])

        # Write file
        with open(file_path, "w") as f:
            f.write("\n".join(html))

    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics."""
        if not self.sprints:
            return {}

        first = self.sprints[0]
        latest = self.sprints[-1]

        return {
            "total_sprints": len(self.sprints),
            "first_sprint": first.sprint_id,
            "latest_sprint": latest.sprint_id,
            "score_improvement": latest.score - first.score,
            "compliance_improvement": latest.odoo19_compliance_rate - first.odoo19_compliance_rate,
            "total_gaps_closed": sum(s.gaps_closed for s in self.sprints),
            "current_score": latest.score,
            "current_compliance": latest.odoo19_compliance_rate,
            "p0_findings_remaining": latest.findings_by_priority.get("P0", 0),
            "p1_findings_remaining": latest.findings_by_priority.get("P1", 0),
        }
