#!/bin/bash
# Test Haiku-optimized agents
# This script validates Haiku agent configuration for cost optimization

set -euo pipefail

CLAUDE_DIR="/Users/pedro/Documents/odoo19/.claude"
RESULTS_FILE="$CLAUDE_DIR/tests/haiku_agents_test_results.txt"

echo "⚡ TESTING HAIKU AGENTS CONFIGURATION"
echo "====================================="
echo ""

# Create results file
mkdir -p "$(dirname "$RESULTS_FILE")"
echo "Haiku Agents Test Results - $(date)" > "$RESULTS_FILE"
echo "====================================" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

PASS_COUNT=0
FAIL_COUNT=0

# Test function
test_haiku_agent() {
    local agent_file=$1
    local agent_path="$CLAUDE_DIR/agents/$agent_file"

    echo "Testing: $agent_file"

    # Test 1: File exists
    if [ ! -f "$agent_path" ]; then
        echo "  ❌ FAIL: File not found"
        echo "FAIL: $agent_file - File not found" >> "$RESULTS_FILE"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 1
    fi

    local tests_passed=0

    # Test 2: Has model: haiku
    if grep -q "model: haiku" "$agent_path"; then
        echo "  ✅ model: haiku found"
        tests_passed=$((tests_passed + 1))
    else
        echo "  ❌ model: haiku NOT found"
    fi

    # Test 3: Has tools defined
    if grep -q "tools:" "$agent_path"; then
        echo "  ✅ tools configured"
        tests_passed=$((tests_passed + 1))
    else
        echo "  ❌ tools NOT configured"
    fi

    # Test 4: Has cost_category
    if grep -q "cost_category: low" "$agent_path"; then
        echo "  ✅ cost_category: low"
        tests_passed=$((tests_passed + 1))
    else
        echo "  ⚠️  cost_category not set (optional)"
    fi

    # Test 5: Has max_tokens (should be lower)
    if grep -q "max_tokens:" "$agent_path"; then
        MAX_TOKENS=$(grep "max_tokens:" "$agent_path" | awk '{print $2}')
        if [ "$MAX_TOKENS" -le 4096 ]; then
            echo "  ✅ max_tokens optimized ($MAX_TOKENS)"
            tests_passed=$((tests_passed + 1))
        else
            echo "  ⚠️  max_tokens high ($MAX_TOKENS)"
        fi
    fi

    # Overall result
    if [ $tests_passed -ge 2 ]; then
        echo "  ✅ PASS: Agent properly configured"
        echo "PASS: $agent_file - $tests_passed/4 checks passed" >> "$RESULTS_FILE"
        PASS_COUNT=$((PASS_COUNT + 1))
        return 0
    else
        echo "  ❌ FAIL: Agent not properly configured"
        echo "FAIL: $agent_file - Only $tests_passed/4 checks passed" >> "$RESULTS_FILE"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 1
    fi
}

# Test each Haiku agent
echo "📋 Testing Haiku-optimized agents:"
echo ""

test_haiku_agent "quick-status-checker.md"
echo ""
test_haiku_agent "quick-file-finder.md"
echo ""
test_haiku_agent "quick-code-validator.md"
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
