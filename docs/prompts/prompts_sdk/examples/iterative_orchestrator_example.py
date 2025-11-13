"""
Example: Using IterativeOrchestrator for automated module improvement.

This example shows how to use IterativeOrchestrator to automatically:
1. Audit a module for compliance and quality issues
2. Close P0/P1 gaps automatically
3. Develop missing features
4. Run tests
5. Re-audit until target score reached

Usage:
    PYTHONPATH=/path/to/odoo19/docs/prompts python examples/iterative_orchestrator_example.py
"""

from prompts_sdk.agents.orchestrator import (
    IterativeOrchestrator,
    OrchestrationConfig,
    OrchestrationSession
)
from prompts_sdk.core.audit import Finding
from typing import List


def confirm_gap_closure(findings: List[Finding]) -> bool:
    """
    User confirmation for gap closure.

    Args:
        findings: List of findings to close

    Returns:
        True to proceed, False to skip
    """
    print("\n🔍 Gap Closure Confirmation:")
    print(f"   Found {len(findings)} issues to fix:")
    for finding in findings[:5]:  # Show first 5
        print(f"      • [{finding.severity}] {finding.title}")
    if len(findings) > 5:
        print(f"      ... and {len(findings) - 5} more")

    # Auto-confirm for demo (in production, ask user)
    return True


def confirm_feature_development(features: List[str]) -> bool:
    """
    User confirmation for feature development.

    Args:
        features: List of features to develop

    Returns:
        True to proceed, False to skip
    """
    print("\n🚀 Feature Development Confirmation:")
    print(f"   Identified {len(features)} features:")
    for feature in features:
        print(f"      • {feature}")

    # Auto-confirm for demo (in production, ask user)
    return True


def confirm_budget_increase(current: float, limit: float) -> bool:
    """
    User confirmation for budget increase.

    Args:
        current: Current cost in USD
        limit: Budget limit in USD

    Returns:
        True to continue, False to stop
    """
    print(f"\n💰 Budget Warning:")
    print(f"   Current: ${current:.2f}")
    print(f"   Limit: ${limit:.2f}")
    print(f"   Usage: {(current/limit)*100:.1f}%")

    # Auto-decline for demo (in production, ask user)
    return False


def main():
    """Run iterative orchestration example."""
    print("=" * 80)
    print("ITERATIVE ORCHESTRATOR EXAMPLE")
    print("=" * 80)

    # Configure orchestration
    config = OrchestrationConfig(
        max_iterations=10,
        max_budget_usd=5.0,
        target_score=100.0,
        min_acceptable_score=80.0,
        # User confirmation callbacks
        confirm_gap_closure=confirm_gap_closure,
        confirm_feature_development=confirm_feature_development,
        confirm_budget_increase=confirm_budget_increase,
        # Docker-aware commands (CRITICAL for Odoo)
        odoo_command_prefix="docker compose exec odoo",
        python_venv_path=".venv/bin/python",
        # CLI tools
        preferred_audit_tool="copilot",
        preferred_dev_tool="copilot",
        # Templates
        templates_dir="docs/prompts/04_templates"
    )

    # Create orchestrator
    orchestrator = IterativeOrchestrator(config)

    # Run to completion
    print("\n🚀 Starting orchestration...")
    print(f"   Module: addons/localization/l10n_cl_dte")
    print(f"   Objective: Full Odoo 19 + SII compliance")
    print(f"   Target Score: {config.target_score}/100")
    print(f"   Max Iterations: {config.max_iterations}")
    print(f"   Max Budget: ${config.max_budget_usd}")

    # Note: This is a demo - run_to_completion does actual work
    # In production, this would:
    # - Scan module for issues
    # - Execute CLI tools (Copilot/Codex/Gemini)
    # - Apply fixes automatically
    # - Run tests via Docker
    # - Re-audit until target reached

    session = orchestrator.run_to_completion(
        module_path="addons/localization/l10n_cl_dte",
        objective="Full Odoo 19 + SII compliance",
        initial_context={
            "regulatory_framework": "SII Resolution 80/2014",
            "odoo_version": "19.0",
            "test_database": "odoo19_db"
        }
    )

    # Print final summary
    print("\n" + "=" * 80)
    print("FINAL SUMMARY")
    print("=" * 80)
    summary = session.get_summary()
    for key, value in summary.items():
        print(f"   {key}: {value}")

    # Export detailed report
    output_file = f"orchestration_{session.session_id}.json"
    print(f"\n📄 Detailed report: {output_file}")

    # Show actions taken
    print(f"\n🔧 Actions Taken: {len(session.actions_taken)}")
    for action in session.actions_taken[:5]:
        print(f"   • [{action['action_type']}] at iteration {action['iteration']}")

    # Show confirmations
    print(f"\n❓ Confirmations Asked: {len(session.confirmations_asked)}")
    for conf in session.confirmations_asked:
        print(f"   • [{conf['type']}] Response: {'Yes' if conf['response'] else 'No'}")

    print("\n✅ Orchestration complete!")


if __name__ == "__main__":
    main()
