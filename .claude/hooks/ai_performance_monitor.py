#!/usr/bin/env python3
"""
AI Performance Monitoring Hook
Tracks accuracy, confidence, and performance metrics
"""

import json
import sys
from datetime import datetime
from pathlib import Path

METRICS_FILE = Path.home() / '.claude' / 'ai_metrics' / 'performance.jsonl'
METRICS_FILE.parent.mkdir(parents=True, exist_ok=True)

# Thresholds
MIN_CONFIDENCE_THRESHOLD = 70.0  # %
MAX_LATENCY_THRESHOLD = 5.0      # seconds

def load_hook_input():
    try:
        return json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        return {}

def log_metric(metric):
    """Append metric to JSONL file"""
    with open(METRICS_FILE, 'a') as f:
        f.write(json.dumps(metric) + '\n')

def main():
    hook_input = load_hook_input()

    tool_name = hook_input.get('tool_name', '')
    tool_input = hook_input.get('tool_input', {})

    # Check if editing AI validation code
    if tool_name in ['Write', 'Edit']:
        file_path = tool_input.get('file_path', '')

        if 'ai-service' in file_path:
            warnings = []

            # Check for validation endpoints
            if 'validate' in file_path:
                warnings.append("🎯 Validation logic modified")
                warnings.append("→ Update tests in tests/integration/")
                warnings.append("→ Measure accuracy on test set")
                warnings.append("→ Monitor confidence scores")

            # Check for Claude API client
            if 'anthropic_client' in file_path:
                warnings.append("🤖 Claude API client modified")
                warnings.append("→ Verify prompt caching still works")
                warnings.append("→ Test streaming functionality")
                warnings.append("→ Check cost tracking")

            # Check for plugin system
            if 'plugin' in file_path:
                warnings.append("🔌 Plugin system modified")
                warnings.append("→ Test plugin selection accuracy")
                warnings.append("→ Verify keyword matching")
                warnings.append("→ Update plugin documentation")

            if warnings:
                output = {
                    "systemMessage": "\n".join(warnings)
                }
                print(json.dumps(output))

    sys.exit(0)

if __name__ == '__main__':
    main()
