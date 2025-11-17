"""
Base agent abstract class for implementing custom agents.

This module provides BaseAgent as an abstract base class for creating
custom agents with consistent interfaces.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime


@dataclass
class AgentConfig:
    """Configuration for an agent."""

    name: str
    model: str  # claude-sonnet-4.5, gpt-5-codex, etc.
    cli_tool: str  # copilot, codex, claude-code
    temperature: float = 0.1
    max_tokens: Optional[int] = None
    timeout_seconds: int = 300
    retry_count: int = 3
    custom_instructions: Optional[str] = None


@dataclass
class AgentResult:
    """Result from agent execution."""

    agent_name: str
    success: bool
    output: str
    error: Optional[str] = None
    execution_time_seconds: float = 0.0
    token_usage: Dict[str, int] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        """Initialize default values."""
        if self.token_usage is None:
            self.token_usage = {"input": 0, "output": 0}
        if self.metadata is None:
            self.metadata = {}


class BaseAgent(ABC):
    """
    Abstract base class for agents.

    Subclass this to create custom agents with specific capabilities.

    Example:
        >>> class CustomAgent(BaseAgent):
        ...     def execute(self, task: str, context: Dict) -> AgentResult:
        ...         # Custom implementation
        ...         return AgentResult(...)
        ...
        >>> agent = CustomAgent(config)
        >>> result = agent.execute("Audit module X", {})
    """

    def __init__(self, config: AgentConfig):
        """
        Initialize agent.

        Args:
            config: Agent configuration
        """
        self.config = config
        self.name = config.name
        self.model = config.model
        self.cli_tool = config.cli_tool

    @abstractmethod
    def execute(
        self,
        task: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResult:
        """
        Execute task.

        Args:
            task: Task description/prompt
            context: Additional context (file paths, etc.)

        Returns:
            AgentResult with execution results
        """
        pass

    def validate_config(self) -> bool:
        """
        Validate agent configuration.

        Returns:
            True if configuration is valid
        """
        if not self.config.name:
            return False

        if not self.config.model:
            return False

        if not self.config.cli_tool:
            return False

        if not 0.0 <= self.config.temperature <= 1.0:
            return False

        return True

    def get_capabilities(self) -> List[str]:
        """
        Get agent capabilities.

        Returns:
            List of capability strings
        """
        return [
            "execute_task",
            "validate_config",
        ]

    def __repr__(self) -> str:
        """String representation."""
        return f"{self.__class__.__name__}(name='{self.name}', model='{self.model}')"
