#!/bin/bash
# Test MCP Servers configuration
# This script validates MCP servers setup and availability

set -euo pipefail

CLAUDE_DIR="/Users/pedro/Documents/odoo19/.claude"
MCP_CONFIG="$CLAUDE_DIR/mcp.json"
RESULTS_FILE="$CLAUDE_DIR/tests/mcp_servers_test_results.txt"

echo "🔌 TESTING MCP SERVERS CONFIGURATION"
echo "====================================="
echo ""

# Create results file
mkdir -p "$(dirname "$RESULTS_FILE")"
echo "MCP Servers Test Results - $(date)" > "$RESULTS_FILE"
echo "====================================" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

# Test 1: Check if mcp.json exists
echo "Test 1: Configuration file exists"
if [ -f "$MCP_CONFIG" ]; then
    echo "  ✅ PASS: $MCP_CONFIG found"
    echo "PASS: mcp.json exists" >> "$RESULTS_FILE"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ❌ FAIL: $MCP_CONFIG not found"
    echo "FAIL: mcp.json not found" >> "$RESULTS_FILE"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    exit 1
fi

# Test 2: Validate JSON syntax
echo "Test 2: Valid JSON syntax"
if python3 -m json.tool "$MCP_CONFIG" > /dev/null 2>&1; then
    echo "  ✅ PASS: Valid JSON"
    echo "PASS: Valid JSON syntax" >> "$RESULTS_FILE"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ❌ FAIL: Invalid JSON"
    echo "FAIL: Invalid JSON syntax" >> "$RESULTS_FILE"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    exit 1
fi

# Test 3: Check for required servers
echo "Test 3: Required servers configured"

check_server() {
    local server_name=$1

    if jq -e ".mcpServers.\"$server_name\"" "$MCP_CONFIG" > /dev/null 2>&1; then
        echo "  ✅ PASS: $server_name configured"
        echo "PASS: $server_name server configured" >> "$RESULTS_FILE"
        PASS_COUNT=$((PASS_COUNT + 1))
        return 0
    else
        echo "  ❌ FAIL: $server_name not configured"
        echo "FAIL: $server_name server NOT configured" >> "$RESULTS_FILE"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 1
    fi
}

# Check if jq is available
if ! command -v jq &> /dev/null; then
    echo "  ⚠️  WARN: jq not installed, using grep fallback"
    echo "WARN: jq not available" >> "$RESULTS_FILE"
    WARN_COUNT=$((WARN_COUNT + 1))

    # Fallback to grep
    for server in "postgres" "filesystem" "git"; do
        if grep -q "\"$server\"" "$MCP_CONFIG"; then
            echo "  ✅ PASS: $server found (grep)"
            echo "PASS: $server server found" >> "$RESULTS_FILE"
            PASS_COUNT=$((PASS_COUNT + 1))
        else
            echo "  ❌ FAIL: $server not found"
            echo "FAIL: $server server NOT found" >> "$RESULTS_FILE"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
    done
else
    check_server "postgres"
    check_server "filesystem"
    check_server "git"
fi

# Test 4: Check npx availability
echo "Test 4: npx command available"
if command -v npx &> /dev/null; then
    NPX_VERSION=$(npx --version)
    echo "  ✅ PASS: npx available (version: $NPX_VERSION)"
    echo "PASS: npx available (v$NPX_VERSION)" >> "$RESULTS_FILE"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ⚠️  WARN: npx not available (MCP servers won't work)"
    echo "WARN: npx not available" >> "$RESULTS_FILE"
    WARN_COUNT=$((WARN_COUNT + 1))
fi

# Test 5: Check Node.js availability
echo "Test 5: Node.js available"
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    echo "  ✅ PASS: Node.js available ($NODE_VERSION)"
    echo "PASS: Node.js available ($NODE_VERSION)" >> "$RESULTS_FILE"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  ⚠️  WARN: Node.js not available"
    echo "WARN: Node.js not available" >> "$RESULTS_FILE"
    WARN_COUNT=$((WARN_COUNT + 1))
fi

echo ""
echo "Summary:"
echo "--------"
echo "✅ Passed: $PASS_COUNT"
echo "⚠️  Warnings: $WARN_COUNT"
echo "❌ Failed: $FAIL_COUNT"
echo ""
echo "SUMMARY:" >> "$RESULTS_FILE"
echo "  Passed: $PASS_COUNT" >> "$RESULTS_FILE"
echo "  Warnings: $WARN_COUNT" >> "$RESULTS_FILE"
echo "  Failed: $FAIL_COUNT" >> "$RESULTS_FILE"

echo "📄 Results saved to: $RESULTS_FILE"

# Exit with error if any critical tests failed
if [ $FAIL_COUNT -gt 0 ]; then
    echo ""
    echo "❌ SOME TESTS FAILED"
    exit 1
elif [ $WARN_COUNT -gt 0 ]; then
    echo ""
    echo "⚠️  TESTS PASSED WITH WARNINGS"
    exit 0
else
    echo ""
    echo "✅ ALL TESTS PASSED"
    exit 0
fi
