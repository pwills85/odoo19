#!/bin/bash
# Test Extended Thinking functionality
# This script validates that Extended Thinking agents are properly configured

set -euo pipefail

CLAUDE_DIR="/Users/pedro/Documents/odoo19/.claude"
RESULTS_FILE="$CLAUDE_DIR/tests/extended_thinking_test_results.txt"

echo "🧠 TESTING EXTENDED THINKING CONFIGURATION"
echo "==========================================="
echo ""

# Create results file
mkdir -p "$(dirname "$RESULTS_FILE")"
echo "Extended Thinking Test Results - $(date)" > "$RESULTS_FILE"
echo "=========================================" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

PASS_COUNT=0
FAIL_COUNT=0

# Test function
test_agent() {
    local agent_file=$1
    local agent_path="$CLAUDE_DIR/agents/$agent_file"

    echo "Testing: $agent_file"

    if [ ! -f "$agent_path" ]; then
        echo "  ❌ FAIL: File not found"
        echo "FAIL: $agent_file - File not found" >> "$RESULTS_FILE"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 1
    fi

    if grep -q "extended_thinking: true" "$agent_path"; then
        echo "  ✅ PASS: Extended Thinking enabled"
        echo "PASS: $agent_file - Extended Thinking enabled" >> "$RESULTS_FILE"
        PASS_COUNT=$((PASS_COUNT + 1))
        return 0
    else
        echo "  ❌ FAIL: Extended Thinking NOT found"
        echo "FAIL: $agent_file - Extended Thinking NOT enabled" >> "$RESULTS_FILE"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 1
    fi
}

# Test each agent
echo "📋 Testing agents with Extended Thinking requirement:"
echo ""

test_agent "odoo-dev-precision.md"
test_agent "test-automation.md"
test_agent "docker-devops.md"
test_agent "ai-fastapi-dev.md"

echo ""
echo "Summary:"
echo "--------"
echo "✅ Passed: $PASS_COUNT"
echo "❌ Failed: $FAIL_COUNT"
echo ""
echo "SUMMARY:" >> "$RESULTS_FILE"
echo "  Passed: $PASS_COUNT" >> "$RESULTS_FILE"
echo "  Failed: $FAIL_COUNT" >> "$RESULTS_FILE"

echo "📄 Results saved to: $RESULTS_FILE"

# Exit with error if any tests failed
if [ $FAIL_COUNT -gt 0 ]; then
    echo ""
    echo "❌ SOME TESTS FAILED"
    exit 1
else
    echo ""
    echo "✅ ALL TESTS PASSED"
    exit 0
fi
