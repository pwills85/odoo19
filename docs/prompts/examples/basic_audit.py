#!/usr/bin/env python3
"""
Basic audit example using Prompts SDK.

This script demonstrates:
- Running a simple audit
- Viewing results
- Exporting reports
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from prompts_sdk import AuditRunner


def main():
    """Run basic audit example."""
    print("Running basic audit example...")

    # Configure audit runner
    runner = AuditRunner(
        module_path="addons/l10n_cl_dte",
        dimensions=["compliance", "backend"],
        agents={
            "compliance": "claude-sonnet-4.5",
            "backend": "claude-haiku-4.5"
        }
    )

    # Run audit with cache and notifications
    result = runner.run(
        use_cache=True,
        notify=False,  # Set to True to send Slack notifications
        temperature=0.1
    )

    # Display results
    print("\n" + "="*60)
    print("AUDIT RESULTS")
    print("="*60)
    print(f"Module: {result.module_path}")
    print(f"Score: {result.score:.1f}/100")
    print(f"Session ID: {result.session_id}")
    print(f"\nFindings Breakdown:")
    print(f"  P0 (Critical): {result.critical_count}")
    print(f"  P1 (High):     {result.high_count}")
    print(f"  Total:         {len(result.findings)}")

    if result.odoo19_compliance_rate:
        print(f"\nOdoo 19 Compliance: {result.odoo19_compliance_rate:.1f}%")

    print(f"\nExecution Time: {result.execution_time_seconds:.1f}s")
    print(f"Token Usage: {result.token_usage['input']:,} in / {result.token_usage['output']:,} out")

    # Export results
    output_dir = result.metadata.get("output_dir")
    if output_dir:
        print(f"\nResults saved to: {output_dir}/")
        print("  - audit_result.json")
        print("  - AUDIT_REPORT.md")

    return result


if __name__ == "__main__":
    result = main()

    # Exit code based on score
    if result.score >= 90:
        sys.exit(0)  # Success
    elif result.score >= 70:
        sys.exit(1)  # Warning
    else:
        sys.exit(2)  # Failure
