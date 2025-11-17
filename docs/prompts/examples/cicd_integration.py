#!/usr/bin/env python3
"""
CI/CD pipeline integration example.

This script demonstrates:
- Running audit in CI/CD context
- Configuring thresholds
- Exporting machine-readable results
- Integration with GitHub Actions
"""

import sys
import os
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from prompts_sdk import AuditRunner, MetricsManager


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run audit in CI/CD pipeline")
    parser.add_argument("--module", required=True, help="Module path to audit")
    parser.add_argument("--min-score", type=float, default=80.0, help="Minimum passing score")
    parser.add_argument("--fail-on-p0", action="store_true", help="Fail if any P0 findings")
    parser.add_argument("--sprint", type=int, help="Sprint number for metrics tracking")
    parser.add_argument("--github-output", help="Path to GitHub Actions output file")
    return parser.parse_args()


def main():
    """Run CI/CD audit."""
    args = parse_args()

    print(f"[CI/CD] Running audit on {args.module}...")

    # Run audit
    runner = AuditRunner(
        module_path=args.module,
        dimensions=["compliance", "backend", "security"],
        agents={
            "compliance": "claude-sonnet-4.5",
            "backend": "claude-haiku-4.5",
            "security": "gpt-5-codex",
        }
    )

    result = runner.run(
        use_cache=True,
        notify=True,  # Send Slack notifications in CI
        temperature=0.1
    )

    # Check thresholds
    passed = True
    failure_reasons = []

    if result.score < args.min_score:
        passed = False
        failure_reasons.append(
            f"Score {result.score:.1f} below minimum {args.min_score}"
        )

    if args.fail_on_p0 and result.critical_count > 0:
        passed = False
        failure_reasons.append(
            f"Found {result.critical_count} P0 (critical) findings"
        )

    # Update metrics if sprint provided
    if args.sprint:
        metrics = MetricsManager()
        metrics.add_sprint(
            sprint_id=args.sprint,
            audit_result=result,
            audit_type="ci_cd_validation"
        )
        print(f"[CI/CD] Metrics updated for sprint {args.sprint}")

    # Export for GitHub Actions
    if args.github_output:
        github_data = {
            "score": result.score,
            "p0_findings": result.critical_count,
            "p1_findings": result.high_count,
            "total_findings": len(result.findings),
            "passed": passed,
            "session_id": result.session_id,
        }

        with open(args.github_output, "w") as f:
            for key, value in github_data.items():
                f.write(f"{key}={value}\n")

        print(f"[CI/CD] GitHub Actions outputs written to {args.github_output}")

    # Print summary
    print("\n" + "="*60)
    print("CI/CD AUDIT SUMMARY")
    print("="*60)
    print(f"Module:    {result.module_path}")
    print(f"Score:     {result.score:.1f}/100 (min: {args.min_score})")
    print(f"P0:        {result.critical_count}")
    print(f"P1:        {result.high_count}")
    print(f"Status:    {'✅ PASSED' if passed else '❌ FAILED'}")

    if failure_reasons:
        print("\nFailure Reasons:")
        for reason in failure_reasons:
            print(f"  - {reason}")

    # Export JSON for other tools
    json_path = f"audit_result_{result.session_id}.json"
    result.to_json(json_path)
    print(f"\nFull results: {json_path}")

    # Exit with appropriate code
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
