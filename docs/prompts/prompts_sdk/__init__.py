"""
Odoo 19 Prompts SDK - Python API for automated prompt system management.

This SDK provides programmatic access to the prompt system for:
- Running multi-agent audits
- Managing metrics and dashboards
- Loading and validating prompt templates
- Integrating with CI/CD pipelines
- Custom automation workflows

Example:
    >>> from prompts_sdk import AuditRunner, MetricsManager
    >>> runner = AuditRunner(
    ...     module_path="addons/l10n_cl_dte",
    ...     dimensions=["compliance", "backend"]
    ... )
    >>> result = runner.run()
    >>> print(f"Score: {result.score}/100")
"""

__version__ = "1.0.0"
__author__ = "Pedro Troncoso (@pwills85)"
__license__ = "MIT"

# Core imports
from prompts_sdk.core.audit import AuditRunner, AuditResult
from prompts_sdk.core.metrics import MetricsManager, Dashboard
from prompts_sdk.core.templates import TemplateLoader, TemplateValidator
from prompts_sdk.core.cache import CacheManager

# Agent imports
from prompts_sdk.agents.base import BaseAgent
from prompts_sdk.agents.copilot import CopilotAgent
from prompts_sdk.agents.orchestrator import (
    MultiAgentOrchestrator,
    IterativeOrchestrator,
    OrchestrationConfig,
    OrchestrationSession,
)

# Integration imports
from prompts_sdk.integrations.slack import SlackNotifier
from prompts_sdk.integrations.email import EmailNotifier
from prompts_sdk.integrations.github import GitHubIntegration

__all__ = [
    # Core
    "AuditRunner",
    "AuditResult",
    "MetricsManager",
    "Dashboard",
    "TemplateLoader",
    "TemplateValidator",
    "CacheManager",
    # Agents
    "BaseAgent",
    "CopilotAgent",
    "MultiAgentOrchestrator",
    "IterativeOrchestrator",
    "OrchestrationConfig",
    "OrchestrationSession",
    # Integrations
    "SlackNotifier",
    "EmailNotifier",
    "GitHubIntegration",
]
