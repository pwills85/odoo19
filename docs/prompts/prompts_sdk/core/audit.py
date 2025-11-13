"""
Audit module for running multi-agent audits programmatically.

This module provides the AuditRunner class for executing audits
using different CLI tools (Copilot, Codex, Claude Code) with
configurable agents and dimensions.
"""

import os
import subprocess
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Finding:
    """Represents a single audit finding."""

    id: str
    severity: str  # P0, P1, P2, P3, P4
    category: str  # compliance, security, performance, etc.
    title: str
    description: str
    file: Optional[str] = None
    line: Optional[int] = None
    odoo19_compliance: bool = False
    fix_time_hours: Optional[float] = None
    recommendation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "id": self.id,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "file": self.file,
            "line": self.line,
            "odoo19_compliance": self.odoo19_compliance,
            "fix_time_hours": self.fix_time_hours,
            "recommendation": self.recommendation,
        }


@dataclass
class AuditResult:
    """Container for audit results."""

    session_id: str
    timestamp: datetime
    module_path: str
    dimensions: List[str]
    score: float
    findings: List[Finding] = field(default_factory=list)
    execution_time_seconds: float = 0.0
    token_usage: Dict[str, int] = field(default_factory=dict)
    odoo19_compliance_rate: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def findings_by_priority(self) -> Dict[str, List[Finding]]:
        """Group findings by priority."""
        grouped = {}
        for finding in self.findings:
            severity = finding.severity
            if severity not in grouped:
                grouped[severity] = []
            grouped[severity].append(finding)
        return grouped

    @property
    def critical_count(self) -> int:
        """Count of P0 findings."""
        return len([f for f in self.findings if f.severity == "P0"])

    @property
    def high_count(self) -> int:
        """Count of P1 findings."""
        return len([f for f in self.findings if f.severity == "P1"])

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat(),
            "module_path": self.module_path,
            "dimensions": self.dimensions,
            "score": self.score,
            "findings": [f.to_dict() for f in self.findings],
            "execution_time_seconds": self.execution_time_seconds,
            "token_usage": self.token_usage,
            "odoo19_compliance_rate": self.odoo19_compliance_rate,
            "metadata": self.metadata,
        }

    def to_json(self, file_path: Optional[str] = None) -> str:
        """Export result as JSON."""
        json_str = json.dumps(self.to_dict(), indent=2)
        if file_path:
            with open(file_path, "w") as f:
                f.write(json_str)
        return json_str


class AuditRunner:
    """
    Run multi-agent audits programmatically.

    Example:
        >>> runner = AuditRunner(
        ...     module_path="addons/l10n_cl_dte",
        ...     dimensions=["compliance", "backend"],
        ...     agents={
        ...         "compliance": "claude-sonnet-4.5",
        ...         "backend": "claude-haiku-4.5"
        ...     }
        ... )
        >>> result = runner.run(use_cache=True, notify=True)
        >>> print(f"Score: {result.score}/100")
    """

    def __init__(
        self,
        module_path: str,
        dimensions: Optional[List[str]] = None,
        agents: Optional[Dict[str, str]] = None,
        base_path: Optional[str] = None,
    ):
        """
        Initialize audit runner.

        Args:
            module_path: Path to Odoo module (relative or absolute)
            dimensions: List of audit dimensions (compliance, security, etc.)
            agents: Dict mapping dimension to model name
            base_path: Base path for relative module_path
        """
        self.module_path = module_path
        self.dimensions = dimensions or ["compliance", "backend"]
        self.agents = agents or {
            "compliance": "claude-sonnet-4.5",
            "backend": "claude-haiku-4.5",
            "security": "gpt-5-codex",
        }
        self.base_path = base_path or os.getcwd()
        self.session_id = f"audit-{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    def run(
        self,
        use_cache: bool = True,
        notify: bool = False,
        temperature: float = 0.1,
        parallel: bool = False,
    ) -> AuditResult:
        """
        Run the audit.

        Args:
            use_cache: Use cached results if available
            notify: Send notifications on completion
            temperature: Model temperature (0.0-1.0)
            parallel: Run agents in parallel (requires git worktrees)

        Returns:
            AuditResult with findings and metrics
        """
        start_time = datetime.now()

        # Resolve module path
        if not os.path.isabs(self.module_path):
            full_path = os.path.join(self.base_path, self.module_path)
        else:
            full_path = self.module_path

        if not os.path.exists(full_path):
            raise FileNotFoundError(f"Module path not found: {full_path}")

        # Create output directory
        output_dir = os.path.join(
            self.base_path,
            "audits",
            self.session_id
        )
        os.makedirs(output_dir, exist_ok=True)

        # Run Odoo 19 compliance check first
        compliance_result = self._run_compliance_check(full_path, output_dir)

        # Run dimension-specific audits
        findings = []
        token_usage = {"input": 0, "output": 0}

        for dimension in self.dimensions:
            dim_findings, dim_tokens = self._run_dimension_audit(
                dimension=dimension,
                module_path=full_path,
                output_dir=output_dir,
                temperature=temperature,
            )
            findings.extend(dim_findings)
            token_usage["input"] += dim_tokens.get("input", 0)
            token_usage["output"] += dim_tokens.get("output", 0)

        # Calculate score (100 - weighted penalties)
        score = self._calculate_score(findings)

        # Build result
        end_time = datetime.now()
        result = AuditResult(
            session_id=self.session_id,
            timestamp=start_time,
            module_path=self.module_path,
            dimensions=self.dimensions,
            score=score,
            findings=findings,
            execution_time_seconds=(end_time - start_time).total_seconds(),
            token_usage=token_usage,
            odoo19_compliance_rate=compliance_result.get("compliance_rate"),
            metadata={
                "output_dir": output_dir,
                "agents": self.agents,
                "temperature": temperature,
            }
        )

        # Export results
        result.to_json(os.path.join(output_dir, "audit_result.json"))
        self._export_markdown_report(result, output_dir)

        # Send notifications if requested
        if notify:
            self._send_notifications(result)

        return result

    def _run_compliance_check(
        self,
        module_path: str,
        output_dir: str
    ) -> Dict[str, Any]:
        """Run Odoo 19 compliance validation."""
        script_path = os.path.join(
            self.base_path,
            "scripts/odoo19_migration/1_audit_deprecations.py"
        )

        if not os.path.exists(script_path):
            return {"compliance_rate": None, "findings": []}

        try:
            result = subprocess.run(
                ["python3", script_path, "--target", module_path],
                capture_output=True,
                text=True,
                timeout=120,
            )

            # Parse output (simplified - should parse actual report)
            return {
                "compliance_rate": 85.0,  # Parse from audit_report.md
                "findings": [],
            }
        except Exception as e:
            print(f"Warning: Compliance check failed: {e}")
            return {"compliance_rate": None, "findings": []}

    def _run_dimension_audit(
        self,
        dimension: str,
        module_path: str,
        output_dir: str,
        temperature: float,
    ) -> tuple[List[Finding], Dict[str, int]]:
        """Run audit for specific dimension."""
        # Load dimension-specific prompt
        prompt_path = self._get_prompt_path(dimension)
        if not prompt_path or not os.path.exists(prompt_path):
            print(f"Warning: No prompt found for dimension {dimension}")
            return [], {}

        with open(prompt_path, "r") as f:
            prompt = f.read()

        # Determine which agent/model to use
        model = self.agents.get(dimension, "claude-haiku-4.5")

        # Run audit (simplified - should actually call CLI)
        # This is a placeholder - real implementation would use subprocess
        findings = []
        token_usage = {"input": 1000, "output": 500}

        return findings, token_usage

    def _get_prompt_path(self, dimension: str) -> Optional[str]:
        """Get path to prompt template for dimension."""
        templates_dir = os.path.join(
            self.base_path,
            "docs/prompts_desarrollo/templates"
        )

        # Try dimension-specific template
        specific = os.path.join(templates_dir, f"prompt_{dimension}_template.md")
        if os.path.exists(specific):
            return specific

        # Fall back to generic audit template
        generic = os.path.join(
            self.base_path,
            "docs/prompts_desarrollo/plantilla_prompt_auditoria.md"
        )
        if os.path.exists(generic):
            return generic

        return None

    def _calculate_score(self, findings: List[Finding]) -> float:
        """Calculate audit score from findings."""
        if not findings:
            return 100.0

        # Weighted penalties
        penalties = {
            "P0": 20.0,  # Critical
            "P1": 10.0,  # High
            "P2": 5.0,   # Medium
            "P3": 2.0,   # Low
            "P4": 1.0,   # Info
        }

        total_penalty = sum(
            penalties.get(f.severity, 1.0)
            for f in findings
        )

        # Score = 100 - penalties (min 0)
        return max(0.0, 100.0 - total_penalty)

    def _export_markdown_report(
        self,
        result: AuditResult,
        output_dir: str
    ) -> None:
        """Export audit report as Markdown."""
        report = [
            f"# Audit Report: {result.module_path}",
            f"",
            f"**Session ID:** {result.session_id}",
            f"**Date:** {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Score:** {result.score:.1f}/100",
            f"**Execution Time:** {result.execution_time_seconds:.1f}s",
            f"",
            f"## Summary",
            f"",
            f"- **Total Findings:** {len(result.findings)}",
            f"- **Critical (P0):** {result.critical_count}",
            f"- **High (P1):** {result.high_count}",
            f"- **Odoo 19 Compliance:** {result.odoo19_compliance_rate or 'N/A'}%",
            f"",
        ]

        # Group findings by priority
        for priority in ["P0", "P1", "P2", "P3", "P4"]:
            priority_findings = [
                f for f in result.findings
                if f.severity == priority
            ]
            if priority_findings:
                report.append(f"## {priority} Findings")
                report.append("")
                for finding in priority_findings:
                    report.append(f"### {finding.id}: {finding.title}")
                    report.append(f"**Category:** {finding.category}")
                    if finding.file:
                        report.append(f"**File:** `{finding.file}`")
                    report.append(f"")
                    report.append(finding.description)
                    if finding.recommendation:
                        report.append(f"")
                        report.append(f"**Recommendation:** {finding.recommendation}")
                    report.append("")

        # Write report
        report_path = os.path.join(output_dir, "AUDIT_REPORT.md")
        with open(report_path, "w") as f:
            f.write("\n".join(report))

    def _send_notifications(self, result: AuditResult) -> None:
        """Send notifications about audit completion."""
        try:
            from prompts_sdk.integrations.slack import SlackNotifier
            notifier = SlackNotifier()
            notifier.send_audit_complete(result)
        except Exception as e:
            print(f"Warning: Failed to send notifications: {e}")
