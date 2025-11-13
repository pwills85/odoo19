"""
Copilot agent wrapper for executing tasks with GitHub Copilot CLI.

This module provides CopilotAgent for running audits and tasks using
the Copilot CLI with custom agents and models.
"""

import os
import subprocess
import time
from typing import Dict, Optional, Any
from datetime import datetime

from prompts_sdk.agents.base import BaseAgent, AgentConfig, AgentResult


class CopilotAgent(BaseAgent):
    """
    Wrapper for GitHub Copilot CLI.

    Example:
        >>> config = AgentConfig(
        ...     name="compliance_agent",
        ...     model="claude-sonnet-4.5",
        ...     cli_tool="copilot",
        ...     temperature=0.1
        ... )
        >>> agent = CopilotAgent(config)
        >>> result = agent.execute(
        ...     task="Audit DTE module for SII compliance",
        ...     context={"module_path": "addons/l10n_cl_dte"}
        ... )
        >>> print(result.output)
    """

    def __init__(
        self,
        config: AgentConfig,
        agent_file: Optional[str] = None,
    ):
        """
        Initialize Copilot agent.

        Args:
            config: Agent configuration
            agent_file: Path to custom agent file (.mda)
        """
        super().__init__(config)
        self.agent_file = agent_file

    def execute(
        self,
        task: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResult:
        """
        Execute task using Copilot CLI.

        Args:
            task: Task prompt
            context: Additional context (module_path, etc.)

        Returns:
            AgentResult with execution results
        """
        context = context or {}
        start_time = time.time()

        # Build command
        cmd = self._build_command(task, context)

        try:
            # Execute Copilot CLI
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds,
                cwd=context.get("working_dir"),
            )

            execution_time = time.time() - start_time

            # Parse output
            output = result.stdout
            error = result.stderr if result.returncode != 0 else None

            # Extract token usage (if available in output)
            token_usage = self._parse_token_usage(output)

            return AgentResult(
                agent_name=self.name,
                success=result.returncode == 0,
                output=output,
                error=error,
                execution_time_seconds=execution_time,
                token_usage=token_usage,
                metadata={
                    "return_code": result.returncode,
                    "command": " ".join(cmd),
                },
            )

        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            return AgentResult(
                agent_name=self.name,
                success=False,
                output="",
                error=f"Timeout after {self.config.timeout_seconds}s",
                execution_time_seconds=execution_time,
            )

        except Exception as e:
            execution_time = time.time() - start_time
            return AgentResult(
                agent_name=self.name,
                success=False,
                output="",
                error=str(e),
                execution_time_seconds=execution_time,
            )

    def _build_command(
        self,
        task: str,
        context: Dict[str, Any],
    ) -> list:
        """Build Copilot CLI command."""
        cmd = ["copilot"]

        # Add prompt
        cmd.extend(["-p", task])

        # Add model
        cmd.extend(["--model", self.config.model])

        # Add temperature
        cmd.extend(["--temperature", str(self.config.temperature)])

        # Add agent file if specified
        if self.agent_file and os.path.exists(self.agent_file):
            cmd.extend(["--agent", self.agent_file])

        # Add allow-all-tools for full capabilities
        cmd.append("--allow-all-tools")

        # Add max tokens if specified
        if self.config.max_tokens:
            cmd.extend(["--max-tokens", str(self.config.max_tokens)])

        return cmd

    def _parse_token_usage(self, output: str) -> Dict[str, int]:
        """
        Parse token usage from Copilot output.

        Args:
            output: CLI output

        Returns:
            Dict with input/output token counts
        """
        # Try to parse token usage from output
        # Format may vary, this is a simplified parser
        import re

        token_usage = {"input": 0, "output": 0}

        # Look for patterns like "Tokens: 1234 in, 567 out"
        match = re.search(r"(\d+)\s*(?:in|input)", output, re.IGNORECASE)
        if match:
            token_usage["input"] = int(match.group(1))

        match = re.search(r"(\d+)\s*(?:out|output)", output, re.IGNORECASE)
        if match:
            token_usage["output"] = int(match.group(1))

        return token_usage

    def load_agent_from_file(self, agent_file: str) -> None:
        """
        Load custom agent from file.

        Args:
            agent_file: Path to .mda file
        """
        if not os.path.exists(agent_file):
            raise FileNotFoundError(f"Agent file not found: {agent_file}")

        self.agent_file = agent_file

    def get_capabilities(self) -> list:
        """Get agent capabilities."""
        capabilities = super().get_capabilities()
        capabilities.extend([
            "copilot_cli",
            "custom_agents",
            "temperature_control",
        ])
        return capabilities
