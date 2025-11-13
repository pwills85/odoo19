"""Integration modules for external services."""

from prompts_sdk.integrations.slack import SlackNotifier
from prompts_sdk.integrations.email import EmailNotifier
from prompts_sdk.integrations.github import GitHubIntegration

__all__ = [
    "SlackNotifier",
    "EmailNotifier",
    "GitHubIntegration",
]
