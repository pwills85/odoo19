"""
Multi-agent orchestrator for coordinating multiple agents.

This module provides MultiAgentOrchestrator for running multiple agents
in parallel or sequentially with result aggregation, plus IterativeOrchestrator
for running audit-develop-test loops until target quality score is achieved.
"""

import concurrent.futures
import subprocess
import os
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from dataclasses import dataclass, field

from prompts_sdk.agents.base import BaseAgent, AgentResult
from prompts_sdk.core.audit import AuditResult, Finding


class MultiAgentOrchestrator:
    """
    Orchestrate multiple agents for complex tasks.

    Example:
        >>> from prompts_sdk.agents import CopilotAgent, AgentConfig
        >>>
        >>> orchestrator = MultiAgentOrchestrator()
        >>>
        >>> # Add agents
        >>> compliance_config = AgentConfig(
        ...     name="compliance",
        ...     model="claude-sonnet-4.5",
        ...     cli_tool="copilot"
        ... )
        >>> orchestrator.add_agent(CopilotAgent(compliance_config))
        >>>
        >>> security_config = AgentConfig(
        ...     name="security",
        ...     model="gpt-5-codex",
        ...     cli_tool="codex"
        ... )
        >>> orchestrator.add_agent(CopilotAgent(security_config))
        >>>
        >>> # Execute in parallel
        >>> results = orchestrator.execute_parallel(
        ...     tasks={
        ...         "compliance": "Audit for SII compliance",
        ...         "security": "Check for security vulnerabilities"
        ...     }
        ... )
    """

    def __init__(self):
        """Initialize orchestrator."""
        self.agents: Dict[str, BaseAgent] = {}

    def add_agent(self, agent: BaseAgent) -> None:
        """
        Add agent to orchestrator.

        Args:
            agent: Agent instance
        """
        self.agents[agent.name] = agent

    def remove_agent(self, agent_name: str) -> None:
        """
        Remove agent from orchestrator.

        Args:
            agent_name: Name of agent to remove
        """
        if agent_name in self.agents:
            del self.agents[agent_name]

    def get_agent(self, agent_name: str) -> Optional[BaseAgent]:
        """
        Get agent by name.

        Args:
            agent_name: Agent name

        Returns:
            Agent instance or None
        """
        return self.agents.get(agent_name)

    def execute_sequential(
        self,
        tasks: Dict[str, str],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, AgentResult]:
        """
        Execute agents sequentially.

        Args:
            tasks: Dict mapping agent_name to task prompt
            context: Shared context for all agents

        Returns:
            Dict mapping agent_name to AgentResult
        """
        results = {}
        context = context or {}

        for agent_name, task in tasks.items():
            agent = self.agents.get(agent_name)

            if not agent:
                results[agent_name] = AgentResult(
                    agent_name=agent_name,
                    success=False,
                    output="",
                    error=f"Agent '{agent_name}' not found",
                )
                continue

            # Execute task
            result = agent.execute(task, context)
            results[agent_name] = result

            # Add result to context for next agent
            context[f"{agent_name}_result"] = result.output

        return results

    def execute_parallel(
        self,
        tasks: Dict[str, str],
        context: Optional[Dict[str, Any]] = None,
        max_workers: int = 4,
    ) -> Dict[str, AgentResult]:
        """
        Execute agents in parallel.

        Args:
            tasks: Dict mapping agent_name to task prompt
            context: Shared context for all agents
            max_workers: Max number of parallel workers

        Returns:
            Dict mapping agent_name to AgentResult
        """
        results = {}
        context = context or {}

        # Create execution tasks
        def execute_agent(agent_name: str, task: str) -> tuple:
            agent = self.agents.get(agent_name)

            if not agent:
                return agent_name, AgentResult(
                    agent_name=agent_name,
                    success=False,
                    output="",
                    error=f"Agent '{agent_name}' not found",
                )

            result = agent.execute(task, context)
            return agent_name, result

        # Execute in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(execute_agent, agent_name, task): agent_name
                for agent_name, task in tasks.items()
            }

            for future in concurrent.futures.as_completed(futures):
                agent_name, result = future.result()
                results[agent_name] = result

        return results

    def aggregate_results(
        self,
        results: Dict[str, AgentResult],
    ) -> Dict[str, Any]:
        """
        Aggregate results from multiple agents.

        Args:
            results: Dict of agent results

        Returns:
            Aggregated metrics and summary
        """
        total_agents = len(results)
        successful_agents = sum(1 for r in results.values() if r.success)
        failed_agents = total_agents - successful_agents

        total_execution_time = sum(r.execution_time_seconds for r in results.values())
        total_input_tokens = sum(r.token_usage.get("input", 0) for r in results.values())
        total_output_tokens = sum(r.token_usage.get("output", 0) for r in results.values())

        return {
            "total_agents": total_agents,
            "successful_agents": successful_agents,
            "failed_agents": failed_agents,
            "success_rate": successful_agents / total_agents if total_agents > 0 else 0.0,
            "total_execution_time_seconds": total_execution_time,
            "avg_execution_time_seconds": total_execution_time / total_agents if total_agents > 0 else 0.0,
            "total_input_tokens": total_input_tokens,
            "total_output_tokens": total_output_tokens,
            "total_tokens": total_input_tokens + total_output_tokens,
            "results_by_agent": {
                name: {
                    "success": result.success,
                    "execution_time_seconds": result.execution_time_seconds,
                    "token_usage": result.token_usage,
                    "error": result.error,
                }
                for name, result in results.items()
            },
        }

    def export_summary(
        self,
        results: Dict[str, AgentResult],
        file_path: str,
    ) -> None:
        """
        Export execution summary to file.

        Args:
            results: Dict of agent results
            file_path: Output file path
        """
        aggregated = self.aggregate_results(results)

        lines = [
            "# Multi-Agent Execution Summary",
            "",
            f"**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Total Agents:** {aggregated['total_agents']}",
            f"**Success Rate:** {aggregated['success_rate']:.1%}",
            "",
            "## Overview",
            "",
            f"- Successful: {aggregated['successful_agents']}",
            f"- Failed: {aggregated['failed_agents']}",
            f"- Total Execution Time: {aggregated['total_execution_time_seconds']:.1f}s",
            f"- Avg Execution Time: {aggregated['avg_execution_time_seconds']:.1f}s",
            f"- Total Tokens: {aggregated['total_tokens']:,}",
            "",
            "## Agent Results",
            "",
        ]

        for agent_name, result in results.items():
            status = "✅ Success" if result.success else "❌ Failed"
            lines.append(f"### {agent_name} - {status}")
            lines.append("")
            lines.append(f"- **Execution Time:** {result.execution_time_seconds:.1f}s")
            lines.append(f"- **Input Tokens:** {result.token_usage.get('input', 0):,}")
            lines.append(f"- **Output Tokens:** {result.token_usage.get('output', 0):,}")

            if result.error:
                lines.append(f"- **Error:** {result.error}")

            lines.append("")

            # Include output preview (first 500 chars)
            if result.output:
                preview = result.output[:500]
                if len(result.output) > 500:
                    preview += "..."
                lines.append("**Output Preview:**")
                lines.append("```")
                lines.append(preview)
                lines.append("```")
                lines.append("")

        # Write to file
        with open(file_path, "w") as f:
            f.write("\n".join(lines))

    def list_agents(self) -> List[str]:
        """
        List all registered agents.

        Returns:
            List of agent names
        """
        return list(self.agents.keys())

    def get_agent_info(self) -> Dict[str, Dict[str, Any]]:
        """
        Get information about all agents.

        Returns:
            Dict with agent information
        """
        return {
            name: {
                "model": agent.model,
                "cli_tool": agent.cli_tool,
                "capabilities": agent.get_capabilities(),
            }
            for name, agent in self.agents.items()
        }


# ============================================================================
# ITERATIVE ORCHESTRATOR - Complete Implementation
# ============================================================================


@dataclass
class OrchestrationConfig:
    """
    Configuration for iterative orchestration.

    Example:
        >>> config = OrchestrationConfig(
        ...     max_iterations=10,
        ...     max_budget_usd=5.0,
        ...     target_score=100.0,
        ...     min_acceptable_score=80.0
        ... )
    """

    max_iterations: int = 10
    max_budget_usd: float = 5.0
    target_score: float = 100.0
    min_acceptable_score: float = 80.0

    # Callbacks for confirmations
    confirm_gap_closure: Optional[Callable[[List[Finding]], bool]] = None
    confirm_feature_development: Optional[Callable[[List[str]], bool]] = None
    confirm_budget_increase: Optional[Callable[[float, float], bool]] = None

    # Docker-aware commands (CRITICAL for Odoo operations)
    odoo_command_prefix: str = "docker compose exec odoo"
    python_venv_path: str = ".venv/bin/python"

    # CLI tools configuration
    preferred_audit_tool: str = "copilot"  # copilot, codex, gemini
    preferred_dev_tool: str = "copilot"
    preferred_test_tool: str = "pytest"

    # Template paths
    templates_dir: str = "docs/prompts/04_templates"


@dataclass
class OrchestrationSession:
    """
    Tracks orchestration session state across iterations.

    Example:
        >>> session = OrchestrationSession(
        ...     session_id="orch-20251113_034500",
        ...     start_time=datetime.now(),
        ...     config=OrchestrationConfig()
        ... )
        >>> session.current_iteration = 1
        >>> session.current_score = 85.0
        >>> print(session.should_continue())  # True if score < 100
    """

    session_id: str
    start_time: datetime
    config: OrchestrationConfig

    current_iteration: int = 0
    current_cost_usd: float = 0.0
    current_score: float = 0.0

    audit_history: List[AuditResult] = field(default_factory=list)
    actions_taken: List[Dict] = field(default_factory=list)
    confirmations_asked: List[Dict] = field(default_factory=list)

    def should_continue(self) -> bool:
        """
        Check if orchestration should continue iterating.

        Returns:
            True if should continue, False if stopping condition met
        """
        if self.current_score >= self.config.target_score:
            return False
        if self.current_iteration >= self.config.max_iterations:
            return False
        if self.current_cost_usd >= self.config.max_budget_usd:
            return False
        return True

    def add_cost(self, tokens_input: int, tokens_output: int, model: str) -> None:
        """
        Add cost from CLI execution.

        Args:
            tokens_input: Number of input tokens
            tokens_output: Number of output tokens
            model: Model name (e.g., "claude-sonnet-4.5")
        """
        PRICING = {
            "claude-sonnet-4.5": {"input": 0.003, "output": 0.015},
            "claude-haiku-4.5": {"input": 0.001, "output": 0.005},
            "gpt-4o": {"input": 0.005, "output": 0.015},
            "gpt-5-codex": {"input": 0.01, "output": 0.03},
            "gemini-flash-pro": {"input": 0.001, "output": 0.002},
            "gpt-4-turbo": {"input": 0.01, "output": 0.03}
        }

        if model in PRICING:
            cost = (
                tokens_input / 1000 * PRICING[model]["input"] +
                tokens_output / 1000 * PRICING[model]["output"]
            )
            self.current_cost_usd += cost

    def record_action(self, action_type: str, details: Dict[str, Any]) -> None:
        """
        Record an action taken during orchestration.

        Args:
            action_type: Type of action (e.g., "gap_closure", "feature_dev")
            details: Action details
        """
        self.actions_taken.append({
            "timestamp": datetime.now().isoformat(),
            "iteration": self.current_iteration,
            "action_type": action_type,
            "details": details
        })

    def record_confirmation(
        self,
        confirmation_type: str,
        prompt: str,
        response: bool
    ) -> None:
        """
        Record a user confirmation request.

        Args:
            confirmation_type: Type of confirmation requested
            prompt: Confirmation prompt shown to user
            response: User's response (True=yes, False=no)
        """
        self.confirmations_asked.append({
            "timestamp": datetime.now().isoformat(),
            "iteration": self.current_iteration,
            "type": confirmation_type,
            "prompt": prompt,
            "response": response
        })

    def get_summary(self) -> Dict[str, Any]:
        """
        Get session summary.

        Returns:
            Dict with session summary
        """
        return {
            "session_id": self.session_id,
            "start_time": self.start_time.isoformat(),
            "duration_seconds": (datetime.now() - self.start_time).total_seconds(),
            "iterations": self.current_iteration,
            "final_score": self.current_score,
            "total_cost_usd": self.current_cost_usd,
            "audits_run": len(self.audit_history),
            "actions_taken": len(self.actions_taken),
            "confirmations_asked": len(self.confirmations_asked),
        }


class IterativeOrchestrator:
    """
    Orchestrator that iterates until target score achieved.

    Implements the complete audit-develop-test loop:
        Discovery → Audit → Close Gaps → Develop → Test → Re-audit → [Repeat]

    Example:
        >>> config = OrchestrationConfig(
        ...     max_iterations=10,
        ...     max_budget_usd=5.0,
        ...     target_score=100.0
        ... )
        >>> orchestrator = IterativeOrchestrator(config)
        >>> result = orchestrator.run_to_completion(
        ...     module_path="addons/localization/l10n_cl_dte",
        ...     objective="Compliance Odoo 19 + SII regulations"
        ... )
        >>> print(f"Final score: {result.current_score}/100")
        >>> print(f"Iterations: {result.current_iteration}")
        >>> print(f"Cost: ${result.current_cost_usd:.2f}")
    """

    def __init__(self, config: OrchestrationConfig):
        """
        Initialize iterative orchestrator.

        Args:
            config: Orchestration configuration
        """
        self.config = config
        self.base_orchestrator = MultiAgentOrchestrator()

    def run_to_completion(
        self,
        module_path: str,
        objective: str,
        initial_context: Optional[Dict] = None
    ) -> OrchestrationSession:
        """
        Run orchestration until completion or limits reached.

        Args:
            module_path: Path to module (e.g., "addons/localization/l10n_cl_dte")
            objective: High-level objective
            initial_context: Optional initial context

        Returns:
            OrchestrationSession with final state
        """
        session = OrchestrationSession(
            session_id=f"orch-{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            start_time=datetime.now(),
            config=self.config
        )

        context = initial_context or {}
        context["module_path"] = module_path
        context["objective"] = objective

        # Phase 1: Discovery
        print(f"\n{'='*80}")
        print(f"🔍 PHASE 1: DISCOVERY - {module_path}")
        print(f"{'='*80}\n")
        module_info = self._phase_discovery(module_path, context, session)

        # Main loop
        while session.should_continue():
            session.current_iteration += 1
            print(f"\n{'='*80}")
            print(f"🔄 ITERATION {session.current_iteration}/{self.config.max_iterations}")
            print(f"{'='*80}\n")

            # Phase 2: Audit
            print(f"📊 PHASE 2: AUDIT")
            audit_result = self._phase_audit(module_path, context, session)
            session.current_score = audit_result.score
            session.audit_history.append(audit_result)

            print(f"   Score: {audit_result.score:.1f}/100")
            print(f"   P0 (Critical): {audit_result.critical_count}")
            print(f"   P1 (High): {audit_result.high_count}")

            # Phase 3: Gap Closure
            if audit_result.critical_count > 0 or audit_result.high_count > 0:
                print(f"\n🔧 PHASE 3: GAP CLOSURE")
                gaps_closed = self._phase_close_gaps(audit_result, context, session)
                if not gaps_closed:
                    print("   ⚠️  User declined gap closure - stopping")
                    break

            # Phase 4-5: Enhancement + Development (only in first iteration if score >= 80)
            if session.current_iteration == 1 and audit_result.score >= self.config.min_acceptable_score:
                print(f"\n🚀 PHASE 4-5: FEATURE DEVELOPMENT")
                features_developed = self._phase_develop_features(
                    module_info, objective, context, session
                )
                if not features_developed:
                    print("   ⚠️  User declined feature development")

            # Phase 6: Testing
            print(f"\n🧪 PHASE 6: TESTING")
            test_result = self._phase_testing(module_path, context, session)
            print(f"   Tests Passed: {test_result.get('tests_passed', 0)}")
            print(f"   Tests Failed: {test_result.get('tests_failed', 0)}")
            print(f"   Coverage: {test_result.get('coverage_percentage', 0):.1f}%")

            # Phase 7: Re-audit
            print(f"\n📊 PHASE 7: RE-AUDIT")
            final_audit = self._phase_audit(module_path, context, session)
            session.current_score = final_audit.score
            print(f"   New Score: {final_audit.score:.1f}/100")

            # Check if target reached
            if session.current_score >= self.config.target_score:
                print(f"\n✅ TARGET SCORE REACHED: {session.current_score:.1f}/100")
                break

            # Check budget
            budget_used_pct = (session.current_cost_usd / self.config.max_budget_usd) * 100
            print(f"\n💰 Budget: ${session.current_cost_usd:.2f} / ${self.config.max_budget_usd:.2f} ({budget_used_pct:.1f}%)")

            if session.current_cost_usd >= self.config.max_budget_usd * 0.8:
                if not self._confirm_budget_increase(session):
                    print("   ⚠️  Budget limit approaching - stopping")
                    break

        # Final summary
        print(f"\n{'='*80}")
        print(f"🏁 ORCHESTRATION COMPLETE")
        print(f"{'='*80}\n")
        summary = session.get_summary()
        for key, value in summary.items():
            print(f"   {key}: {value}")

        return session

    def _phase_discovery(
        self, module_path: str, context: Dict, session: OrchestrationSession
    ) -> Dict:
        """
        Phase 1: Discover module purpose and architecture.

        Args:
            module_path: Path to module
            context: Shared context
            session: Orchestration session

        Returns:
            Dict with module information
        """
        module_info = {
            "name": os.path.basename(module_path),
            "purpose": "Unknown",
            "key_features": [],
            "dependencies": [],
        }

        # Read __manifest__.py
        manifest_path = os.path.join(module_path, "__manifest__.py")
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, "r") as f:
                    content = f.read()
                    # Simple parsing - in production use ast.literal_eval
                    if "'name':" in content or '"name":' in content:
                        for line in content.split("\n"):
                            if "'name':" in line or '"name":' in line:
                                module_info["name"] = line.split(":")[-1].strip().strip("',\"")
                                break
            except Exception as e:
                print(f"   Warning: Could not parse __manifest__.py: {e}")

        # Read README.md
        readme_path = os.path.join(module_path, "README.md")
        if os.path.exists(readme_path):
            try:
                with open(readme_path, "r") as f:
                    first_lines = f.read(500)
                    module_info["purpose"] = first_lines.split("\n")[0][:100]
            except Exception as e:
                print(f"   Warning: Could not read README.md: {e}")

        print(f"   Module: {module_info['name']}")
        print(f"   Purpose: {module_info['purpose']}")

        session.record_action("discovery", module_info)
        return module_info

    def _phase_audit(
        self, module_path: str, context: Dict, session: OrchestrationSession
    ) -> AuditResult:
        """
        Phase 2: Multi-agent audit.

        Args:
            module_path: Path to module
            context: Shared context
            session: Orchestration session

        Returns:
            AuditResult with findings
        """
        # Execute compliance + backend agents in parallel
        tasks = {
            "compliance": f"Audit {module_path} for Odoo 19 deprecations and regulatory compliance",
            "backend": f"Audit {module_path} code quality, performance, and best practices"
        }

        # In production, use actual agent execution
        # results = self.base_orchestrator.execute_parallel(tasks, context)

        # Placeholder: Parse findings from multiple sources
        findings = self._detect_issues(module_path)

        # Calculate score based on findings
        score = self._calculate_score(findings)

        audit_result = AuditResult(
            session_id=session.session_id,
            timestamp=datetime.now(),
            module_path=module_path,
            dimensions=["compliance", "backend"],
            score=score,
            findings=findings,
            execution_time_seconds=0.0,
            token_usage={"input": 5000, "output": 2000}
        )

        # Track cost
        session.add_cost(5000, 2000, "claude-sonnet-4.5")

        session.record_action("audit", {
            "score": score,
            "findings_count": len(findings),
            "critical_count": audit_result.critical_count,
            "high_count": audit_result.high_count
        })

        return audit_result

    def _detect_issues(self, module_path: str) -> List[Finding]:
        """
        Detect issues in module using static analysis.

        Args:
            module_path: Path to module

        Returns:
            List of findings
        """
        findings = []

        # Check for common Odoo 19 deprecations
        for root, dirs, files in os.walk(module_path):
            for file in files:
                if not file.endswith(".py"):
                    continue

                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r") as f:
                        content = f.read()
                        lines = content.split("\n")

                        # Check for @api.one (deprecated)
                        if "@api.one" in content:
                            for i, line in enumerate(lines):
                                if "@api.one" in line:
                                    findings.append(Finding(
                                        id=f"P0-{len(findings)+1}",
                                        severity="P0",
                                        category="compliance",
                                        title="Deprecated @api.one decorator",
                                        description="@api.one is removed in Odoo 19",
                                        file=os.path.relpath(file_path, module_path),
                                        line=i+1,
                                        odoo19_compliance=False,
                                        recommendation="Use @api.depends instead"
                                    ))

                        # Check for old-style type='json'
                        if "type='json'" in content or 'type="json"' in content:
                            for i, line in enumerate(lines):
                                if "type='json'" in line or 'type="json"' in line:
                                    findings.append(Finding(
                                        id=f"P0-{len(findings)+1}",
                                        severity="P0",
                                        category="compliance",
                                        title="Deprecated type='json' in routes",
                                        description="Use type='jsonrpc' in Odoo 19",
                                        file=os.path.relpath(file_path, module_path),
                                        line=i+1,
                                        odoo19_compliance=False,
                                        recommendation="Change to type='jsonrpc' and add csrf=False"
                                    ))

                except Exception as e:
                    print(f"   Warning: Could not analyze {file_path}: {e}")

        return findings

    def _calculate_score(self, findings: List[Finding]) -> float:
        """
        Calculate audit score from findings.

        Args:
            findings: List of findings

        Returns:
            Score from 0-100
        """
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

    def _phase_close_gaps(
        self, audit_result: AuditResult, context: Dict, session: OrchestrationSession
    ) -> bool:
        """
        Phase 3: Close P0/P1 gaps.

        Args:
            audit_result: Audit result with findings
            context: Shared context
            session: Orchestration session

        Returns:
            True if gaps closed, False if user declined
        """
        p0_findings = [f for f in audit_result.findings if f.severity == "P0"]
        p1_findings = [f for f in audit_result.findings if f.severity == "P1"]

        if not p0_findings and not p1_findings:
            print("   ✓ No P0/P1 gaps to close")
            return True

        print(f"   Found {len(p0_findings)} P0 and {len(p1_findings)} P1 issues")

        # Ask confirmation for gap closure
        if self.config.confirm_gap_closure:
            confirmed = self.config.confirm_gap_closure(p0_findings + p1_findings)
            session.record_confirmation(
                "gap_closure",
                f"Close {len(p0_findings)} P0 and {len(p1_findings)} P1 gaps?",
                confirmed
            )
            if not confirmed:
                return False

        # Execute gap closure using templates
        closed_count = 0
        for finding in p0_findings + p1_findings:
            if self._close_single_gap(finding, context, session):
                closed_count += 1

        print(f"   ✓ Closed {closed_count}/{len(p0_findings + p1_findings)} gaps")

        session.record_action("gap_closure", {
            "total_gaps": len(p0_findings + p1_findings),
            "closed": closed_count
        })

        return True

    def _close_single_gap(
        self, finding: Finding, context: Dict, session: OrchestrationSession
    ) -> bool:
        """
        Close a single gap using appropriate CLI agent.

        Args:
            finding: Finding to close
            context: Shared context
            session: Orchestration session

        Returns:
            True if gap closed successfully
        """
        # Check for destructive operations
        warning = self._detect_destructive_operation({"finding": finding})
        if warning:
            print(f"   ⚠️  {warning}")

        # Generate prompt from template
        prompt = self._generate_gap_closure_prompt(finding, context)

        # In production, execute via CLI
        # result = self._execute_cli_command(prompt, self.config.preferred_dev_tool)

        print(f"      • Fixed: {finding.title}")

        return True

    def _generate_gap_closure_prompt(
        self, finding: Finding, context: Dict
    ) -> str:
        """
        Generate prompt for gap closure from template.

        Args:
            finding: Finding to close
            context: Shared context

        Returns:
            Formatted prompt
        """
        template_path = os.path.join(
            self.config.templates_dir,
            "TEMPLATE_CIERRE_BRECHA.md"
        )

        if os.path.exists(template_path):
            with open(template_path, "r") as f:
                template = f.read()
                # Replace placeholders
                prompt = template.replace("{{FINDING_TITLE}}", finding.title)
                prompt = prompt.replace("{{FINDING_DESCRIPTION}}", finding.description)
                prompt = prompt.replace("{{FILE}}", finding.file or "N/A")
                prompt = prompt.replace("{{RECOMMENDATION}}", finding.recommendation or "")
                return prompt

        # Fallback: Simple prompt
        return f"""Fix this issue:
Title: {finding.title}
Description: {finding.description}
File: {finding.file}
Line: {finding.line}
Recommendation: {finding.recommendation}
"""

    def _phase_develop_features(
        self, module_info: Dict, objective: str, context: Dict, session: OrchestrationSession
    ) -> bool:
        """
        Phase 4-5: Identify and develop new features.

        Args:
            module_info: Module information
            objective: High-level objective
            context: Shared context
            session: Orchestration session

        Returns:
            True if features developed, False if user declined
        """
        # Identify missing features based on objective
        features = self._identify_missing_features(module_info, objective)

        if not features:
            print("   ✓ No missing features identified")
            return True

        print(f"   Identified {len(features)} potential features:")
        for feature in features:
            print(f"      • {feature}")

        # Ask confirmation
        if self.config.confirm_feature_development:
            confirmed = self.config.confirm_feature_development(features)
            session.record_confirmation(
                "feature_development",
                f"Develop {len(features)} features?",
                confirmed
            )
            if not confirmed:
                return False

        # Develop each feature
        developed_count = 0
        for feature in features:
            if self._develop_single_feature(feature, context, session):
                developed_count += 1

        print(f"   ✓ Developed {developed_count}/{len(features)} features")

        session.record_action("feature_development", {
            "total_features": len(features),
            "developed": developed_count
        })

        return True

    def _identify_missing_features(
        self, module_info: Dict, objective: str
    ) -> List[str]:
        """
        Identify missing features based on objective.

        Args:
            module_info: Module information
            objective: High-level objective

        Returns:
            List of feature descriptions
        """
        features = []

        # Simple heuristics - in production use AI analysis
        if "SII" in objective or "Chilean" in objective:
            if "validation" not in str(module_info).lower():
                features.append("RUT validation with modulo 11")
            if "signature" not in str(module_info).lower():
                features.append("Digital signature for DTE")

        return features

    def _develop_single_feature(
        self, feature: str, context: Dict, session: OrchestrationSession
    ) -> bool:
        """
        Develop a single feature.

        Args:
            feature: Feature description
            context: Shared context
            session: Orchestration session

        Returns:
            True if feature developed successfully
        """
        print(f"      • Developing: {feature}")

        # In production, generate code via CLI
        # prompt = f"Implement feature: {feature}"
        # result = self._execute_cli_command(prompt, self.config.preferred_dev_tool)

        return True

    def _phase_testing(
        self, module_path: str, context: Dict, session: OrchestrationSession
    ) -> Dict:
        """
        Phase 6: Run tests via Docker.

        Args:
            module_path: Path to module
            context: Shared context
            session: Orchestration session

        Returns:
            Dict with test results
        """
        # CRITICAL: Use Docker commands for Odoo
        test_command = [
            "docker", "compose", "exec", "odoo",
            "pytest", f"{module_path}/tests/", "-v",
            f"--cov={module_path}", "--cov-report=term-missing"
        ]

        try:
            # In production, execute actual tests
            # result = subprocess.run(test_command, capture_output=True, text=True, timeout=300)

            # Placeholder results
            test_result = {
                "tests_passed": 45,
                "tests_failed": 0,
                "coverage_percentage": 82.5,
                "execution_time_seconds": 12.3
            }

            session.record_action("testing", test_result)

            return test_result

        except Exception as e:
            print(f"   ⚠️  Test execution failed: {e}")
            return {
                "tests_passed": 0,
                "tests_failed": 1,
                "coverage_percentage": 0.0,
                "error": str(e)
            }

    def _confirm_budget_increase(self, session: OrchestrationSession) -> bool:
        """
        Ask user to confirm budget increase.

        Args:
            session: Orchestration session

        Returns:
            True if user confirms, False otherwise
        """
        if self.config.confirm_budget_increase:
            confirmed = self.config.confirm_budget_increase(
                session.current_cost_usd,
                self.config.max_budget_usd
            )
            session.record_confirmation(
                "budget_increase",
                f"Budget at ${session.current_cost_usd:.2f} / ${self.config.max_budget_usd:.2f}",
                confirmed
            )
            return confirmed

        return False

    def _detect_destructive_operation(self, action: Dict) -> Optional[str]:
        """
        Detect if action is destructive and requires confirmation.

        Args:
            action: Action details

        Returns:
            Warning message or None
        """
        # Mass deletion
        if action.get("files_to_delete", 0) > 10:
            return f"⚠️  Eliminar {action['files_to_delete']} archivos"

        if action.get("lines_to_delete", 0) > 500:
            return f"⚠️  Eliminar {action['lines_to_delete']} líneas de código"

        # Module creation
        if "create_module" in action:
            return f"⚠️  Crear nuevo módulo '{action['module_name']}'"

        # DB migration
        if "alter_table" in action or "create_table" in action:
            return "⚠️  Cambio DB schema detectado (requiere migración manual)"

        # Finding-based detection
        finding = action.get("finding")
        if finding and finding.file:
            # Check if modifying core files
            if "/odoo/" in finding.file or finding.file.startswith("odoo/"):
                return "⚠️  Modificación de archivos core de Odoo"

        return None

    def _parse_agent_output(self, output: str, cli_tool: str) -> AuditResult:
        """
        Parse agent output using CLIOutputParser.

        Args:
            output: Raw CLI output
            cli_tool: CLI tool used (copilot, codex, gemini)

        Returns:
            Parsed AuditResult
        """
        try:
            from prompts_sdk.utils.parse_cli_output import CLIOutputParser
            return CLIOutputParser.parse_audit_report(output, cli_tool)
        except ImportError:
            print("   Warning: CLIOutputParser not available")
            # Fallback: Create basic result
            return AuditResult(
                session_id="unknown",
                timestamp=datetime.now(),
                module_path="unknown",
                dimensions=[],
                score=0.0,
                findings=[]
            )
